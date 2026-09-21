//! 生产 [`OssClient`]：`reqwest` + OSS Signature V1 + multipart 状态机 + 有界重试。

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use chrono::Utc;
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, DATE, ETAG,
};
use reqwest::{Client, Method, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
use url::Url;

use crate::config::OssConfig;
use crate::error::{OssError, OssResult};
use crate::presign::{self, PresignOptions};
use crate::retry::{default_retry_config, with_retry_deadline, RetryConfig};
use crate::sign::{
    authorization_header, canonicalized_resource, canonicalized_resource_with_subresources,
    sign_v1, split_parts,
};
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

// ── 内部辅助（crate 内共享，供 pool 复用） ───────────────────────────────────

/// 构造虚拟主机 base URL：`https://{bucket}.{endpoint_host}/`。
///
/// OSS 只支持虚拟主机风格访问，因此 `endpoint` 的 host 必须是可加前缀的**域名**；
/// IP 端点（如 `http://127.0.0.1:9000`）会被拒绝——WHATWG URL 规范不接受末尾为数字的域名。
/// 本地联调请使用 `*.localhost`（多数系统解析到回环地址）。
pub(crate) fn virtual_host_base(endpoint: &str, bucket: &str) -> OssResult<Url> {
    let mut parsed = Url::parse(endpoint.trim_end_matches('/'))
        .map_err(|error| OssError::Config(format!("oss endpoint URL 非法: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| OssError::Config("oss endpoint 缺少 host".into()))?
        .to_string();
    let virtual_host = format!("{bucket}.{host}");
    parsed.set_host(Some(&virtual_host)).map_err(|_| {
        OssError::Config(format!(
            "oss virtual host URL 非法：endpoint host `{host}` 无法承载 bucket 前缀（IP 端点不支持 OSS 虚拟主机风格，本地联调请用 *.localhost）"
        ))
    })?;
    parsed.set_path("/");
    Ok(parsed)
}

/// 按 key 逐段拼接对象 URL（保留 key 内的 `/`）。
pub(crate) fn object_url(base: &Url, key: &str) -> OssResult<Url> {
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| OssError::Config("oss base URL 不能作为 path base".into()))?;
        segments.clear();
        for part in key.split('/') {
            if !part.is_empty() {
                segments.push(part);
            }
        }
    }
    Ok(url)
}

/// key 归一化与校验：去首尾空白与前导 `/`，拒绝空、`..` 与超长。
pub(crate) fn normalize_key(key: &str) -> OssResult<String> {
    let normalized = key.trim().trim_start_matches('/');
    if normalized.is_empty() {
        return Err(OssError::Config("object key 不得为空".into()));
    }
    if normalized.contains("..") {
        return Err(OssError::Config("object key 不得包含 '..'".into()));
    }
    if normalized.len() > MAX_OBJECT_KEY_BYTES {
        return Err(OssError::Config(format!(
            "object key 超过 {MAX_OBJECT_KEY_BYTES} 字节上限"
        )));
    }
    Ok(normalized.to_string())
}

/// 当前 GMT 时间（RFC 1123），OSS V1 `Date` 头格式。
pub(crate) fn gmt_now() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// 由字符串构造 header 值。
pub(crate) fn header_value(value: &str) -> OssResult<HeaderValue> {
    HeaderValue::from_str(value)
        .map_err(|error| OssError::Config(format!("oss header value 非法: {error}")))
}

/// 若启用 SSE-S3，则写入 `x-oss-server-side-encryption` 头并返回参与签名的
/// CanonicalizedOSSHeaders；未启用且无 STS token 时返回空串。
///
/// 注意：`x-oss-*` 头必须参与 V1 签名，否则服务端重算签名会 403。
pub(crate) fn apply_oss_headers(
    headers: &mut HeaderMap,
    sse: bool,
    security_token: Option<&str>,
) -> OssResult<String> {
    let mut pairs: Vec<(&'static str, String)> = Vec::new();
    if sse {
        pairs.push((SSE_HEADER_NAME, SSE_HEADER_VALUE.to_string()));
    }
    if let Some(token) = security_token {
        pairs.push((SECURITY_TOKEN_HEADER, token.to_string()));
    }
    // CanonicalizedOSSHeaders 要求按小写头名字典序，每行以 `\n` 结尾
    pairs.sort_by(|left, right| left.0.cmp(right.0));
    let mut canonicalized = String::new();
    for (name, value) in pairs {
        headers.insert(HeaderName::from_static(name), header_value(&value)?);
        canonicalized.push_str(name);
        canonicalized.push(':');
        canonicalized.push_str(&value);
        canonicalized.push('\n');
    }
    Ok(canonicalized)
}

/// 组装并签名一次 OSS 请求头：`Date` + `x-oss-*` + `Authorization`。
///
/// 所有请求路径都走这里，保证「签名内容」与「实际发送的头」不可能脱节。
pub(crate) fn signed_headers(
    access_key_id: &str,
    access_key_secret: &str,
    security_token: Option<&str>,
    verb: &str,
    content_type: &str,
    resource: &str,
    sse: bool,
) -> OssResult<HeaderMap> {
    let date = gmt_now();
    let mut headers = HeaderMap::new();
    headers.insert(DATE, header_value(&date)?);
    if !content_type.is_empty() {
        headers.insert(CONTENT_TYPE, header_value(content_type)?);
    }
    let canonicalized_oss_headers = apply_oss_headers(&mut headers, sse, security_token)?;
    let signature = sign_v1(
        access_key_secret,
        verb,
        "",
        content_type,
        &date,
        &canonicalized_oss_headers,
        resource,
    );
    let authorization = authorization_header(access_key_id, &signature);
    headers.insert(AUTHORIZATION, header_value(&authorization)?);
    Ok(headers)
}

/// 由响应头解析对象元数据。
pub(crate) fn object_meta_from_headers(headers: &HeaderMap) -> ObjectMeta {
    ObjectMeta {
        size: headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        etag: headers
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim_matches('"').to_string()),
        version_id: headers
            .get("x-oss-version-id")
            .and_then(|value| value.to_str().ok())
            .map(String::from),
        checksum: headers
            .get("x-oss-hash-crc64ecma")
            .and_then(|value| value.to_str().ok())
            .map(String::from),
        content_type: headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(String::from),
    }
}

/// 成功直接返回；失败读取有界错误体并映射为分类错误。
pub(crate) async fn map_status(
    op: &str,
    key: &str,
    status: StatusCode,
    response: reqwest::Response,
    max_error_body_bytes: usize,
) -> OssResult<()> {
    if status.is_success() {
        return Ok(());
    }
    let body = read_limited_body(response, max_error_body_bytes, "OSS error body").await?;
    Err(status_error(
        op,
        key,
        status,
        &String::from_utf8_lossy(&body),
    ))
}

/// 有界读取响应体：`Content-Length` 与流式累计都不得超过 `limit`。
pub(crate) async fn read_limited_body(
    mut response: reqwest::Response,
    limit: usize,
    label: &str,
) -> OssResult<Bytes> {
    if let Some(length) = response.content_length() {
        let length = usize::try_from(length)
            .map_err(|_| OssError::Config(format!("oss {label} Content-Length 超出平台范围")))?;
        if length > limit {
            return Err(OssError::Config(format!(
                "oss {label} 大小 {length} 超过上限 {limit}"
            )));
        }
    }
    let mut body = BytesMut::with_capacity(limit.min(READ_BUFFER_FLOOR));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| OssError::Connection(format!("oss {label} 读取失败: {error}")))?
    {
        append_limited(&mut body, &chunk, limit, label)?;
    }
    Ok(body.freeze())
}

fn append_limited(body: &mut BytesMut, chunk: &[u8], limit: usize, label: &str) -> OssResult<()> {
    let next_len = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| OssError::Config(format!("oss {label} 大小溢出")))?;
    if next_len > limit {
        return Err(OssError::Config(format!(
            "oss {label} 流式读取超过上限 {limit}"
        )));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// 网络错误映射：超时 → [`OssError::Timeout`]，其余视为可重试的 [`OssError::Connection`]。
pub(crate) fn map_network(op: &str, error: &reqwest::Error) -> OssError {
    if error.is_timeout() {
        return OssError::Timeout(format!("oss {op} 请求超时: {error}"));
    }
    OssError::Connection(format!("oss {op} 网络失败: {error}"))
}

/// HTTP 状态映射：
/// - 401/403 → 鉴权降级（[`OssError::Backend`]，永不可重试）
/// - 404 → 远端不存在
/// - 5xx → 瞬时不可用（[`OssError::Connection`]，可重试）
/// - 其余 4xx → 远端协议错误
pub(crate) fn status_error(op: &str, key: &str, status: StatusCode, body: &str) -> OssError {
    // 截断响应，避免日志爆炸；不回显凭据
    let snippet: String = body.chars().take(ERROR_SNIPPET_CHARS).collect();
    if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
        return OssError::Backend(format!(
            "oss {op} auth/forbidden status={status} key={key} body={snippet}"
        ));
    }
    if status == StatusCode::NOT_FOUND {
        return OssError::Backend(format!("oss {op} not found key={key}"));
    }
    if status.is_server_error() {
        return OssError::Connection(format!(
            "oss {op} server status={status} key={key} body={snippet}"
        ));
    }
    if status.is_client_error() {
        return OssError::Backend(format!(
            "oss {op} client status={status} key={key} body={snippet}"
        ));
    }
    OssError::Backend(format!(
        "oss {op} failed status={status} key={key} body={snippet}"
    ))
}

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

/// 从 InitiateMultipartUploadResult XML 中提取并校验 UploadId。
pub(crate) fn parse_upload_id(xml: &str) -> OssResult<String> {
    const OPEN: &str = "<UploadId>";
    const CLOSE: &str = "</UploadId>";
    let start = xml
        .find(OPEN)
        .map(|index| index + OPEN.len())
        .ok_or_else(|| OssError::Serialization("InitiateMultipart 响应缺 UploadId".into()))?;
    let end = xml[start..]
        .find(CLOSE)
        .map(|index| index + start)
        .ok_or_else(|| OssError::Serialization("InitiateMultipart UploadId 未闭合".into()))?;
    let upload_id = xml[start..end].trim();
    validate_upload_id(upload_id)?;
    Ok(upload_id.to_owned())
}

/// 构造 CompleteMultipartUpload XML（含 XML 转义与分片校验）。
pub(crate) fn build_complete_xml(parts: &[(u32, String)]) -> OssResult<String> {
    validate_complete_parts(parts)?;
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&number.to_string());
        xml.push_str("</PartNumber><ETag>");
        xml.push_str(&escape_xml_text(etag));
        xml.push_str("</ETag></Part>");
    }
    xml.push_str("</CompleteMultipartUpload>");
    Ok(xml)
}

fn escape_xml_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn validate_upload_id(upload_id: &str) -> OssResult<()> {
    if upload_id.is_empty()
        || upload_id.len() > MAX_UPLOAD_ID_BYTES
        || upload_id.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '&' | '"' | '\'')
        })
    {
        return Err(OssError::Config(
            "multipart upload_id 非法或超过上限".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_etag(etag: &str) -> OssResult<()> {
    if etag.is_empty() || etag.len() > MAX_ETAG_BYTES || etag.chars().any(char::is_control) {
        return Err(OssError::Config("multipart ETag 非法或超过上限".into()));
    }
    Ok(())
}

pub(crate) fn validate_part_number(part_number: u32) -> OssResult<()> {
    if part_number == 0 || part_number > MAX_PART_NUMBER {
        return Err(OssError::Config(format!(
            "multipart part_number 必须在 1..={MAX_PART_NUMBER} 范围内"
        )));
    }
    Ok(())
}

pub(crate) fn validate_complete_parts(parts: &[(u32, String)]) -> OssResult<()> {
    if parts.is_empty() || parts.len() > MAX_MULTIPART_PARTS {
        return Err(OssError::Config(format!(
            "complete_multipart part 数必须在 1..={MAX_MULTIPART_PARTS} 范围内"
        )));
    }
    let mut seen = HashSet::with_capacity(parts.len());
    for (part_number, etag) in parts {
        validate_part_number(*part_number)?;
        validate_etag(etag)?;
        if !seen.insert(*part_number) {
            return Err(OssError::Config(format!(
                "complete_multipart 含重复 part_number={part_number}"
            )));
        }
    }
    Ok(())
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

mod lifecycle;
mod multipart;
mod object;

#[cfg(test)]
mod tests;
