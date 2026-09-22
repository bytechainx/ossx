//! 生产 [`OssClient`]：`reqwest` + OSS Signature V1 + multipart 状态机 + 有界重试。

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::ETAG;
use reqwest::{Client, Method, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
use url::Url;

use crate::config::OssConfig;
use crate::error::{OssError, OssResult};
use crate::presign::{self, PresignOptions};
use crate::retry::{default_retry_config, with_retry_deadline, RetryConfig};
use crate::sign::{canonicalized_resource, canonicalized_resource_with_subresources, split_parts};
use crate::types::{ObjectMeta, OssHealth};

/// 阿里云 OSS multipart 最小非末片大小（100 KiB）。
pub const MIN_MULTIPART_PART_BYTES: usize = 100 * 1024;
/// 本客户端允许的最大单片大小（512 MiB），受内存缓冲硬上界约束。
pub const MAX_MULTIPART_PART_BYTES: usize = 512 * 1024 * 1024;
/// 阿里云 OSS multipart 最大分片数。
pub const MAX_MULTIPART_PARTS: usize = 10_000;
/// 阿里云 OSS 对象 key 的 UTF-8 字节硬上界。
pub const MAX_OBJECT_KEY_BYTES: usize = 1_023;
/// 进程内保留的 multipart orphan 审计记录硬上界。
pub const ORPHAN_AUDIT_CAPACITY: usize = 1_024;

/// multipart part number 上界（与 [`MAX_MULTIPART_PARTS`] 保持一致）。
const MAX_PART_NUMBER: u32 = 10_000;
const MAX_UPLOAD_ID_BYTES: usize = 2 * 1024;
const MAX_ETAG_BYTES: usize = 1_024;
/// 远端错误体在错误消息中的截断长度，避免日志爆炸。
const ERROR_SNIPPET_CHARS: usize = 512;
/// 读缓冲初始容量上限。
const READ_BUFFER_FLOOR: usize = 8 * 1024;

const SSE_HEADER_NAME: &str = "x-oss-server-side-encryption";
const SSE_HEADER_VALUE: &str = "AES256";
/// STS 临时安全令牌头（同样必须参与 V1 签名）。
const SECURITY_TOKEN_HEADER: &str = "x-oss-security-token";

/// 可克隆的阿里云 OSS 客户端（内部共享 `reqwest::Client` + 配置 + 并发许可）。
///
/// 构造不会发起网络请求：`new` / `connect` 只做本地校验与连接池预热；
/// 可用 [`OssClient::ping`] / [`OssClient::health_check`] 显式探活。
///
/// ```
/// use ossx::{OssClient, OssConfig};
///
/// # fn main() -> Result<(), ossx::OssError> {
/// let config = OssConfig::builder()
///     .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
///     .bucket("demo-bucket")
///     .access_key_id("LTAI5tExample")
///     .access_key_secret("secret")
///     .build()?;
/// let client = OssClient::new(config)?;
/// assert_eq!(client.config().bucket, "demo-bucket");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct OssClient {
    inner: Arc<Inner>,
}

struct Inner {
    http: Client,
    config: OssConfig,
    /// 虚拟主机：`https://{bucket}.{endpoint_host}`
    base: Url,
    closed: AtomicBool,
    retry: RetryConfig,
    permits: Arc<Semaphore>,
    orphan_audits: Mutex<VecDeque<MultipartOrphanAudit>>,
    orphan_audit_overflow: AtomicU64,
}

/// multipart future 被取消或清理失败后留下的补偿记录。
///
/// UploadId 不是凭据，但仍属于运维敏感标识；调用方只应将其交给受控清理流程
/// （[`OssClient::abort_multipart`]），禁止写入公共日志或低基数指标标签。
#[derive(Clone, PartialEq, Eq)]
pub struct MultipartOrphanAudit {
    key: String,
    upload_id: String,
}

impl fmt::Debug for MultipartOrphanAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipartOrphanAudit")
            .field("key", &"<redacted>")
            .field("upload_id", &"<redacted>")
            .finish()
    }
}

impl MultipartOrphanAudit {
    /// 待清理对象 key；仅交给受控补偿流程。
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 待清理 UploadId；仅交给 [`OssClient::abort_multipart`]。
    #[must_use]
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }
}

/// `Drop` 兜底：调用方未显式登记审计时（cancel / panic）写入有界注册表。
struct MultipartAuditGuard {
    inner: Arc<Inner>,
    audit: Option<MultipartOrphanAudit>,
}

impl MultipartAuditGuard {
    fn new(client: &OssClient, key: &str, upload_id: &str) -> Self {
        Self {
            inner: Arc::clone(&client.inner),
            audit: Some(MultipartOrphanAudit {
                key: key.to_owned(),
                upload_id: upload_id.to_owned(),
            }),
        }
    }

    fn disarm(&mut self) {
        self.audit = None;
    }
}

impl Drop for MultipartAuditGuard {
    fn drop(&mut self) {
        let Some(audit) = self.audit.take() else {
            return;
        };
        push_orphan_audit_inner(&self.inner, audit);
    }
}

fn push_orphan_audit_inner(inner: &Inner, audit: MultipartOrphanAudit) {
    let mut audits = match inner.orphan_audits.lock() {
        Ok(audits) => audits,
        Err(poisoned) => poisoned.into_inner(),
    };
    if audits.len() < ORPHAN_AUDIT_CAPACITY {
        audits.push_back(audit);
    } else {
        inner.orphan_audit_overflow.fetch_add(1, Ordering::Relaxed);
    }
}

impl fmt::Debug for OssClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OssClient")
            .field("config", &self.inner.config)
            .field("base", &self.inner.base.as_str())
            .field("closed", &self.inner.closed.load(Ordering::Relaxed))
            .field("retry_max_attempts", &self.inner.retry.max_attempts)
            .field("available_permits", &self.inner.permits.available_permits())
            .finish()
    }
}

// `src/client.rs` 下沉后，`pub(crate)` 辅助经此转出，保持以下两处路径不变：
//   - 各子模块（`client/*.rs`）的 `use super::*`
//   - `src/pool.rs` 的 `use crate::client::{…}` 显式导入列表
pub(crate) use self::endpoint::{normalize_key, object_url, virtual_host_base};
pub(crate) use self::http::{
    header_value, map_network, map_status, object_meta_from_headers, read_limited_body,
    signed_headers, status_error,
};
pub(crate) use self::xml::{
    build_complete_xml, parse_upload_id, validate_complete_parts, validate_etag,
    validate_part_number, validate_upload_id,
};

// ── 分页解析与 multipart 计划 / 孤儿风险辅助（crate 内共享） ──────────────────

/// ListObjects V2 单页结果。
struct ListPage {
    keys: Vec<String>,
    next_token: Option<String>,
    truncated: bool,
}

/// 解析 ListObjects V2 响应 XML（quick-xml 流式）。
fn parse_list_result(bytes: &[u8]) -> OssResult<ListPage> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_reader(bytes);
    let mut buf = Vec::new();
    let mut keys = Vec::new();
    let mut next_token = None;
    let mut truncated = false;
    let mut in_key = false;
    let mut in_next_token = false;
    let mut in_truncated = false;
    let mut text = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                in_key = name == "Key";
                in_next_token = name == "NextContinuationToken";
                in_truncated = name == "IsTruncated";
                text.clear();
            }
            Ok(Event::Text(value)) => {
                text = String::from_utf8_lossy(value.as_ref()).to_string();
            }
            Ok(Event::End(_)) => {
                if in_key {
                    if !text.is_empty() {
                        keys.push(text.clone());
                    }
                } else if in_next_token {
                    next_token = Some(text.clone());
                } else if in_truncated {
                    truncated = text.trim() == "true";
                }
                in_key = false;
                in_next_token = false;
                in_truncated = false;
                text.clear();
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(OssError::Serialization(format!(
                    "oss list XML 解析失败: {error}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(ListPage {
        keys,
        next_token,
        truncated,
    })
}

/// 校验 multipart 计划并返回分片数。
fn validate_multipart_plan(object_size: usize, part_size: usize) -> OssResult<usize> {
    if object_size == 0 {
        return Err(OssError::Config("multipart 数据不得为空".into()));
    }
    if part_size == 0 || part_size > MAX_MULTIPART_PART_BYTES {
        return Err(OssError::Config(format!(
            "multipart part_size 必须在 1..={MAX_MULTIPART_PART_BYTES} 范围内"
        )));
    }
    if object_size > part_size && part_size < MIN_MULTIPART_PART_BYTES {
        return Err(OssError::Config(format!(
            "multipart 非末片不得小于 {MIN_MULTIPART_PART_BYTES} 字节"
        )));
    }
    let part_count = object_size.div_ceil(part_size);
    if part_count > MAX_MULTIPART_PARTS {
        return Err(OssError::Config(format!(
            "multipart 分片数 {part_count} 超过上限 {MAX_MULTIPART_PARTS}"
        )));
    }
    Ok(part_count)
}

fn remaining_deadline(started: Instant, total: Duration, op: &str) -> OssResult<Duration> {
    total
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            OssError::Timeout(format!(
                "oss {op} 超过 multipart 总 deadline {}ms",
                total.as_millis()
            ))
        })
}

fn mark_unknown_initiate_orphan_risk(error: OssError) -> OssError {
    if matches!(error, OssError::Connection(_) | OssError::Timeout(_)) {
        return OssError::Backend(format!(
            "multipart orphan_risk=true upload_id=unknown; initiate={error}"
        ));
    }
    error
}

fn mark_known_orphan_risk(primary: OssError, upload_id: &str) -> OssError {
    let context = format!(
        "multipart orphan_risk=true upload_id={upload_id}; cleanup deadline exhausted; primary={primary}"
    );
    match primary {
        OssError::Timeout(_) => OssError::Timeout(context),
        OssError::Unsupported(_) => OssError::Unsupported(context),
        _ => OssError::Backend(context),
    }
}

fn merge_abort_result(primary: OssError, abort: OssResult<()>, upload_id: &str) -> OssError {
    match abort {
        Ok(()) => primary,
        Err(abort_error) => OssError::Backend(format!(
            "multipart orphan_risk=true upload_id={upload_id}; primary={primary}; abort={abort_error}"
        )),
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

mod endpoint;
mod http;
mod lifecycle;
mod multipart;
mod object;
mod xml;

#[cfg(test)]
mod tests {
    use super::*;
    // 仅测试用到的项写在测试模块内（避免非测试构建 unused import）。
    use bytes::BytesMut;
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, DATE};

    use crate::sign::sign_v1;

    use super::http::{append_limited, apply_oss_headers};

    #[test]
    fn virtual_host_builds() {
        let url = virtual_host_base("https://oss-ap-northeast-1.aliyuncs.com", "x-go")
            .expect("virtual host");
        assert_eq!(
            url.as_str(),
            "https://x-go.oss-ap-northeast-1.aliyuncs.com/"
        );
        assert_eq!(
            virtual_host_base("http://localhost:9000", "b")
                .expect("http")
                .as_str(),
            "http://b.localhost:9000/"
        );
        assert!(
            virtual_host_base("oss.example.com", "b").is_err(),
            "缺少 scheme"
        );
        // IP 端点无法承载虚拟主机风格前缀 → fail-closed 并给出可操作提示
        let error = virtual_host_base("http://127.0.0.1:9000", "b").expect_err("IP endpoint");
        assert!(error.to_string().contains("虚拟主机"), "{error}");
        assert!(error.to_string().contains("localhost"), "{error}");
    }

    #[test]
    fn object_url_nested() {
        let base = Url::parse("https://b.oss.example.com").expect("base");
        let url = object_url(&base, "infra-draft/a/b.txt").expect("object url");
        assert_eq!(
            url.as_str(),
            "https://b.oss.example.com/infra-draft/a/b.txt"
        );
    }

    #[test]
    fn parse_list_result_parses_keys_and_paging() {
        let xml = br#"<?xml version="1.0"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok123</NextContinuationToken>
  <Contents><Key>fred-raw/2026/08/09/series/observations/WALCL/a.json</Key></Contents>
  <Contents><Key>fred-raw/2026/08/09/series/observations/WALCL/b.json</Key></Contents>
</ListBucketResult>"#;
        let page = parse_list_result(xml).expect("parse list XML");
        assert_eq!(page.keys.len(), 2);
        assert!(page.keys[0].starts_with("fred-raw/"));
        assert_eq!(page.next_token.as_deref(), Some("tok123"));
        assert!(page.truncated);
    }

    #[test]
    fn parse_list_result_untruncated_has_no_token() {
        let xml = br#"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a</Key></Contents></ListBucketResult>"#;
        let page = parse_list_result(xml).expect("parse");
        assert_eq!(page.keys, vec!["a".to_string()]);
        assert!(!page.truncated);
        assert!(page.next_token.is_none());
    }

    #[test]
    fn parse_list_result_handles_empty_document() {
        let page = parse_list_result(b"").expect("空文档应按空页处理");
        assert!(page.keys.is_empty());
        assert!(!page.truncated);
        assert!(page.next_token.is_none());
    }

    #[test]
    fn normalize_key_bounds() {
        assert!(normalize_key("").is_err());
        assert!(normalize_key("  /  ").is_err());
        assert!(normalize_key("a/../b").is_err());
        assert_eq!(normalize_key("/a/b").expect("trim"), "a/b");
        assert!(normalize_key(&"x".repeat(MAX_OBJECT_KEY_BYTES)).is_ok());
        assert!(normalize_key(&"x".repeat(MAX_OBJECT_KEY_BYTES + 1)).is_err());
    }

    #[test]
    fn parse_upload_id_from_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
  <Bucket>b</Bucket>
  <Key>k</Key>
  <UploadId>0004B9894A22E5B1888A1E29F8236E2D</UploadId>
</InitiateMultipartUploadResult>"#;
        assert_eq!(
            parse_upload_id(xml).expect("upload id"),
            "0004B9894A22E5B1888A1E29F8236E2D"
        );
        assert!(parse_upload_id("<root/>").is_err());
        assert!(parse_upload_id("<UploadId>&xxe;</UploadId>").is_err());
    }

    #[test]
    fn complete_xml_orders_and_escapes_parts() {
        let xml = build_complete_xml(&[(1, "\"etag1\"".into()), (2, "\"etag2\"".into())])
            .expect("complete XML");
        assert!(xml.contains("<PartNumber>1</PartNumber>"));
        assert!(xml.contains("<ETag>&quot;etag1&quot;</ETag>"));
        assert!(xml.starts_with("<CompleteMultipartUpload>"));
        assert!(xml.ends_with("</CompleteMultipartUpload>"));

        let escaped = build_complete_xml(&[(1, "\"a&<b>\"".into())]).expect("escaped");
        assert!(escaped.contains("&amp;"));
        assert!(escaped.contains("&lt;"));
        assert!(escaped.contains("&gt;"));
        assert!(!escaped.contains("<ETag>\"a&<b>\"</ETag>"));

        let error = build_complete_xml(&[(1, "a".into()), (1, "b".into())])
            .expect_err("重复 part_number 必须被拒绝");
        assert!(error.to_string().contains("重复"));
        assert!(build_complete_xml(&[]).is_err());
    }

    #[test]
    fn multipart_plan_enforces_part_size_and_count() {
        assert!(validate_multipart_plan(MIN_MULTIPART_PART_BYTES + 1, 0).is_err());
        assert!(validate_multipart_plan(MIN_MULTIPART_PART_BYTES + 1, 1).is_err());
        assert!(validate_multipart_plan(1, 1).is_ok());
        assert_eq!(
            validate_multipart_plan(MIN_MULTIPART_PART_BYTES * 2, MIN_MULTIPART_PART_BYTES)
                .expect("plan"),
            2
        );
        let oversized = (MAX_MULTIPART_PARTS + 1) * MIN_MULTIPART_PART_BYTES;
        assert!(validate_multipart_plan(oversized, MIN_MULTIPART_PART_BYTES).is_err());
        assert!(validate_multipart_plan(0, 1).is_err());
        assert!(validate_multipart_plan(1, MAX_MULTIPART_PART_BYTES + 1).is_err());
    }

    #[test]
    fn chunked_body_buffer_stops_at_hard_limit() {
        let mut body = BytesMut::new();
        append_limited(&mut body, b"abcd", 5, "error body").expect("first chunk");
        let error = append_limited(&mut body, b"ef", 5, "error body")
            .expect_err("chunked body 必须在追加前拒绝超限");
        assert!(error.to_string().contains("上限 5"));
        assert_eq!(&body[..], b"abcd");
    }

    #[test]
    fn multipart_field_validators() {
        validate_upload_id("abc-123").expect("ok");
        assert!(validate_upload_id("").is_err());
        assert!(validate_upload_id(&"x".repeat(MAX_UPLOAD_ID_BYTES + 1)).is_err());
        assert!(validate_upload_id("bad<id>").is_err());
        assert!(validate_upload_id("bad&id").is_err());

        validate_etag("\"etag\"").expect("ok");
        assert!(validate_etag("").is_err());
        assert!(validate_etag("a\nb").is_err());

        validate_part_number(1).expect("1");
        assert!(validate_part_number(0).is_err());
        validate_part_number(MAX_PART_NUMBER).expect("max");
        assert!(validate_part_number(MAX_PART_NUMBER + 1).is_err());
        assert_eq!(
            usize::try_from(MAX_PART_NUMBER).expect("cast"),
            MAX_MULTIPART_PARTS
        );

        validate_complete_parts(&[(1, "e1".into()), (2, "e2".into())]).expect("ok");
        assert!(validate_complete_parts(&[]).is_err());
        assert!(validate_complete_parts(&[(1, "a".into()), (1, "b".into())]).is_err());
        assert!(validate_complete_parts(&[(0, "a".into())]).is_err());
    }

    #[test]
    fn status_error_is_classified_and_never_retried_for_auth() {
        use crate::retry::is_oss_retryable;
        let unauthorized = status_error("get", "k", StatusCode::UNAUTHORIZED, "x");
        assert!(matches!(unauthorized, OssError::Backend(_)));
        assert!(!is_oss_retryable(&unauthorized));

        let forbidden = status_error("get", "k", StatusCode::FORBIDDEN, "x");
        assert!(matches!(forbidden, OssError::Backend(_)));
        assert!(!is_oss_retryable(&forbidden));

        let missing = status_error("get", "k", StatusCode::NOT_FOUND, "x");
        assert!(matches!(missing, OssError::Backend(_)));
        assert!(!is_oss_retryable(&missing));

        let server = status_error("get", "k", StatusCode::INTERNAL_SERVER_ERROR, "x");
        assert!(matches!(server, OssError::Connection(_)));
        assert!(is_oss_retryable(&server));

        let bad_request = status_error("get", "k", StatusCode::BAD_REQUEST, "x");
        assert!(matches!(bad_request, OssError::Backend(_)));
        assert!(!is_oss_retryable(&bad_request));

        let odd = status_error("get", "k", StatusCode::from_u16(599).expect("599"), "x");
        assert!(matches!(odd, OssError::Connection(_)));
    }

    #[test]
    fn orphan_risk_markers() {
        let unknown = mark_unknown_initiate_orphan_risk(OssError::Connection("t".into()));
        assert!(matches!(unknown, OssError::Backend(_)));
        assert!(unknown.to_string().contains("orphan_risk=true"));
        let kept = mark_unknown_initiate_orphan_risk(OssError::Config("i".into()));
        assert!(matches!(kept, OssError::Config(_)));

        let timed_out = mark_known_orphan_risk(OssError::Timeout("d".into()), "up-1");
        assert!(matches!(timed_out, OssError::Timeout(_)));
        assert!(timed_out.to_string().contains("up-1"));
        let cancelled = mark_known_orphan_risk(OssError::Unsupported("c".into()), "up-2");
        assert!(matches!(cancelled, OssError::Unsupported(_)));
        let other = mark_known_orphan_risk(OssError::Connection("t".into()), "up-3");
        assert!(matches!(other, OssError::Backend(_)));

        let merged = merge_abort_result(
            OssError::Connection("primary".into()),
            Err(OssError::Connection("abort".into())),
            "upload-123",
        );
        assert!(matches!(merged, OssError::Backend(_)));
        assert!(merged.to_string().contains("orphan_risk=true"));
        assert!(merged.to_string().contains("upload-123"));
        let kept_primary =
            merge_abort_result(OssError::Connection("primary".into()), Ok(()), "upload-123");
        assert!(matches!(kept_primary, OssError::Connection(_)));
    }

    #[test]
    fn remaining_deadline_shrinks_and_expires() {
        let remaining =
            remaining_deadline(Instant::now(), Duration::from_secs(5), "put").expect("remaining");
        assert!(remaining > Duration::ZERO);
        let spent = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .expect("clock");
        assert!(remaining_deadline(spent, Duration::from_millis(1), "put").is_err());
    }

    #[test]
    fn oss_headers_are_canonicalized_and_signed() {
        let mut none = HeaderMap::new();
        assert_eq!(
            apply_oss_headers(&mut none, false, None).expect("empty"),
            ""
        );
        assert!(none.is_empty());

        let mut sse_only = HeaderMap::new();
        assert_eq!(
            apply_oss_headers(&mut sse_only, true, None).expect("sse"),
            "x-oss-server-side-encryption:AES256\n"
        );
        assert!(sse_only.contains_key("x-oss-server-side-encryption"));

        // 多值时按头名字典序排列：security-token 在 server-side-encryption 之前
        let mut both = HeaderMap::new();
        assert_eq!(
            apply_oss_headers(&mut both, true, Some("sts-token")).expect("both"),
            "x-oss-security-token:sts-token\nx-oss-server-side-encryption:AES256\n"
        );
        assert_eq!(
            both.get("x-oss-security-token")
                .and_then(|value| value.to_str().ok()),
            Some("sts-token")
        );
    }

    #[test]
    fn signed_headers_cover_canonicalized_inputs() {
        fn authorization_of(headers: &HeaderMap) -> String {
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .expect("authorization header")
                .to_string()
        }

        // 无 x-oss-* 头：CanonicalizedOSSHeaders 为空，签名等同裸 sign_v1
        let headers = signed_headers(
            "id",
            "secret",
            None,
            "PUT",
            "application/octet-stream",
            "/bucket/key",
            false,
        )
        .expect("headers");
        let date = headers
            .get(DATE)
            .and_then(|value| value.to_str().ok())
            .expect("date");
        let plain = sign_v1(
            "secret",
            "PUT",
            "",
            "application/octet-stream",
            date,
            "",
            "/bucket/key",
        );
        assert_eq!(authorization_of(&headers), format!("OSS id:{plain}"));

        // 带 STS token：签名内容必须包含该头
        let with_token =
            signed_headers("id", "secret", Some("sts"), "GET", "", "/bucket/key", false)
                .expect("headers");
        let date = with_token
            .get(DATE)
            .and_then(|value| value.to_str().ok())
            .expect("date");
        let signed = sign_v1(
            "secret",
            "GET",
            "",
            "",
            date,
            "x-oss-security-token:sts\n",
            "/bucket/key",
        );
        assert_eq!(authorization_of(&with_token), format!("OSS id:{signed}"));
        assert_ne!(plain, signed, "STS token 必须改变签名");
    }

    #[test]
    fn object_meta_from_headers_parses_all_fields() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("128"));
        headers.insert("etag", HeaderValue::from_static("\"abc\""));
        headers.insert("x-oss-version-id", HeaderValue::from_static("v1"));
        headers.insert("x-oss-hash-crc64ecma", HeaderValue::from_static("1234"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        let meta = object_meta_from_headers(&headers);
        assert_eq!(meta.size, 128);
        assert_eq!(meta.etag.as_deref(), Some("abc"));
        assert_eq!(meta.version_id.as_deref(), Some("v1"));
        assert_eq!(meta.checksum.as_deref(), Some("1234"));
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            object_meta_from_headers(&HeaderMap::new()),
            ObjectMeta::default()
        );
    }

    fn loopback_config() -> OssConfig {
        OssConfig::builder()
            .endpoint("http://localhost:9000")
            .bucket("bucket")
            .access_key_id("test-id")
            .access_key_secret("super-secret-value")
            .build()
            .expect("config")
    }

    #[tokio::test]
    async fn acquire_is_bounded_by_concurrency_and_timeout() {
        let config = OssConfig::builder()
            .endpoint("http://localhost:9000")
            .bucket("bucket")
            .access_key_id("id")
            .access_key_secret("sec")
            .max_in_flight(1)
            .acquire_timeout(Duration::from_millis(200))
            .build()
            .expect("config");
        let client = OssClient::new(config).expect("client");
        let permit = client.acquire().await.expect("first permit");
        let error = client
            .acquire()
            .await
            .expect_err("second permit must time out");
        assert!(matches!(error, OssError::Timeout(_)));
        drop(permit);
        let _permit = client.acquire().await.expect("permit released");
    }

    #[tokio::test]
    async fn close_is_an_unsupported_boundary() {
        let client = OssClient::new(loopback_config()).expect("client");
        assert!(!client.is_closed());
        client.close();
        client.close();
        assert!(client.is_closed());
        let error = client
            .acquire()
            .await
            .expect_err("closed client must reject acquire");
        assert!(matches!(error, OssError::Unsupported(_)));
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn closed_client_reports_health_check_error() {
        let client = OssClient::new(loopback_config()).expect("client");
        client.close();
        assert!(client.health_check().await.is_err());
    }

    #[test]
    fn orphan_registry_capacity_and_overflow_are_bounded() {
        let client = OssClient::new(loopback_config()).expect("client");
        for index in 0..=ORPHAN_AUDIT_CAPACITY {
            drop(MultipartAuditGuard::new(
                &client,
                "object",
                &format!("upload-{index}"),
            ));
        }
        assert_eq!(
            client.multipart_orphan_audits().len(),
            ORPHAN_AUDIT_CAPACITY
        );
        assert_eq!(client.orphan_audit_overflow_count(), 1);
    }

    #[test]
    fn client_is_clone_and_debug_keeps_secret_hidden() {
        let client = OssClient::new(loopback_config()).expect("client");
        let cloned = client.clone();
        assert_eq!(cloned.config().bucket, "bucket");
        let debug = format!("{client:?}");
        assert!(debug.contains("<redacted>"));
        assert!(
            !debug.contains("super-secret-value"),
            "secret 绝不能出现在 Debug 中"
        );
        assert_eq!(client.retry_config(), default_retry_config());
    }

    #[tokio::test]
    async fn presign_uses_client_credentials() {
        let config = OssConfig::builder()
            .endpoint("https://oss.example.com")
            .bucket("bucket")
            .access_key_id("id")
            .access_key_secret("sec")
            .build()
            .expect("config");
        let client = OssClient::new(config).expect("client");
        let url = client
            .presign_url("dir/object.txt", &PresignOptions::default())
            .expect("presign");
        assert!(url.starts_with("https://bucket.oss.example.com/dir/object.txt?"));
        assert!(url.contains("OSSAccessKeyId=id"));
    }
}
