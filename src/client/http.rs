//! 请求头组装与签名、有界响应读取、错误映射。
//!
//! 自 `src/client.rs` 下沉而来；`pub(crate)` 项经门面 `pub(crate) use` 转出，
//! 故 `src/pool.rs` 的显式导入列表与各子模块的 `use super::*` 路径均不变。

use bytes::{Bytes, BytesMut};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, DATE};
use reqwest::StatusCode;

use crate::error::{OssError, OssResult};
use crate::sign::{authorization_header, sign_v1};
use crate::types::ObjectMeta;

use super::{
    ERROR_SNIPPET_CHARS, READ_BUFFER_FLOOR, SECURITY_TOKEN_HEADER, SSE_HEADER_NAME,
    SSE_HEADER_VALUE,
};

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

pub(crate) fn append_limited(
    body: &mut BytesMut,
    chunk: &[u8],
    limit: usize,
    label: &str,
) -> OssResult<()> {
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
