//! Signature V1 预签名 URL。
//!
//! 生成的 URL 采用虚拟主机风格（`https://{bucket}.{endpoint_host}/{key}`），
//! query 中携带 `OSSAccessKeyId` / `Expires` / `Signature`，
//! 通过 `Date` 位为「过期时间戳（epoch 秒）」的方式签名，详见
//! [`presign_url`]。

use std::time::Duration;

use crate::error::{OssError, OssResult};
use crate::sign;

/// 预签名选项。
#[derive(Clone, Debug)]
pub struct PresignOptions {
    /// HTTP 方法（`GET` / `PUT` / ...）；参与签名，必须与实际请求一致。
    pub method: String,
    /// 相对当前时间的有效期。
    pub expires: Duration,
    /// Content-Type；`PUT` 预签名上传时应与实际请求头一致。
    pub content_type: Option<String>,
}

impl Default for PresignOptions {
    fn default() -> Self {
        Self {
            method: "GET".into(),
            expires: Duration::from_secs(3600),
            content_type: None,
        }
    }
}

/// 生成 Signature V1 预签名 URL。
///
/// - `endpoint` 必须是 `https://` 前缀（预签名 URL 会被带出可信边界，
///   明文 HTTP 一律 fail-closed）；尾随 `/` 会被忽略；
/// - 过期时间由 `options.expires` 相对**当前时间**计算；
/// - 签名使用 `canonicalized_resource(bucket, key)`，与直连请求一致；
/// - 签名中的 `+` / `/` 按 URL 语义转义为 `%2B` / `%2F`；
/// - `key` 按原样拼入 URL 路径（与源实现一致）。含空格、`#`、非 ASCII 字符的 key
///   需要调用方自行做百分号编码，编码只影响 URL 路径、不影响 `CanonicalizedResource`。
///
/// 需要确定性输出的场景（测试、向量比对）请使用 crate 内部的时间注入版本。
///
/// ```
/// use ossx::{PresignOptions, presign_url};
///
/// # fn main() -> Result<(), ossx::OssError> {
/// let url = presign_url(
///     "https://oss-cn-hangzhou.aliyuncs.com",
///     "demo-bucket",
///     "dir/object.txt",
///     "LTAI5tExample",
///     "secret",
///     &PresignOptions::default(),
/// )?;
/// assert!(url.starts_with("https://demo-bucket.oss-cn-hangzhou.aliyuncs.com/dir/object.txt?"));
/// # Ok(())
/// # }
/// ```
pub fn presign_url(
    endpoint: &str,
    bucket: &str,
    key: &str,
    access_key_id: &str,
    access_key_secret: &str,
    options: &PresignOptions,
) -> OssResult<String> {
    let ttl = i64::try_from(options.expires.as_secs()).unwrap_or(i64::MAX);
    let expires_at = chrono::Utc::now().timestamp().saturating_add(ttl);
    build_presign_url(
        endpoint,
        bucket,
        key,
        access_key_id,
        access_key_secret,
        options,
        expires_at,
    )
}

/// 按显式过期时间戳（epoch 秒）构造预签名 URL。
fn build_presign_url(
    endpoint: &str,
    bucket: &str,
    key: &str,
    access_key_id: &str,
    access_key_secret: &str,
    options: &PresignOptions,
    expires_at: i64,
) -> OssResult<String> {
    let host = endpoint
        .trim_end_matches('/')
        .strip_prefix("https://")
        .ok_or_else(|| OssError::Config("预签名 URL 要求 https:// endpoint".into()))?;
    if host.is_empty() {
        return Err(OssError::Config("预签名 URL 缺少 endpoint host".into()));
    }
    if bucket.trim().is_empty() {
        return Err(OssError::Config("预签名 URL 缺少 bucket".into()));
    }
    let resource = sign::canonicalized_resource(bucket, key);
    let signature = sign::sign_v1(
        access_key_secret,
        &options.method,
        "",
        options.content_type.as_deref().unwrap_or(""),
        &expires_at.to_string(),
        "",
        &resource,
    );
    let encoded = signature.replace('+', "%2B").replace('/', "%2F");
    Ok(format!(
        "https://{bucket}.{host}/{key}?OSSAccessKeyId={access_key_id}&Expires={expires_at}&Signature={encoded}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presign_url_has_expected_shape() {
        let url = presign_url(
            "https://oss.example.com",
            "test-bucket",
            "test-key",
            "test-id",
            "test-secret",
            &PresignOptions::default(),
        )
        .expect("presign");
        assert!(url.starts_with("https://test-bucket.oss.example.com/test-key?"));
        assert!(url.contains("OSSAccessKeyId=test-id"));
        assert!(url.contains("&Expires="));
        assert!(url.contains("&Signature="));
    }

    #[test]
    fn presign_ignores_trailing_slash_and_accepts_put() {
        let options = PresignOptions {
            method: "PUT".into(),
            expires: Duration::from_secs(600),
            content_type: Some("application/octet-stream".into()),
        };
        let url = presign_url(
            "https://oss.example.com/",
            "bucket",
            "key",
            "id",
            "sec",
            &options,
        )
        .expect("presign");
        assert!(url.starts_with("https://bucket.oss.example.com/key?"));
    }

    #[test]
    fn presign_rejects_http_and_empty_bucket() {
        assert!(presign_url(
            "http://oss.example.com",
            "b",
            "k",
            "id",
            "sec",
            &PresignOptions::default()
        )
        .is_err());
        assert!(presign_url(
            "https://oss.example.com",
            "  ",
            "k",
            "id",
            "sec",
            &Default::default()
        )
        .is_err());
        assert!(presign_url(
            "https://",
            "b",
            "k",
            "id",
            "sec",
            &PresignOptions::default()
        )
        .is_err());
    }

    /// 固定过期时间戳 → 固定签名摘要（纯函数，确定性可回归）。
    #[test]
    fn presign_signature_is_deterministic_for_fixed_expiry() {
        let url = build_presign_url(
            "https://oss.example.com",
            "bucket",
            "key",
            "id",
            "sec",
            &PresignOptions::default(),
            1_700_000_000,
        )
        .expect("presign");
        assert_eq!(
            url,
            "https://bucket.oss.example.com/key?OSSAccessKeyId=id&Expires=1700000000&Signature=XJoxjdtVX%2FXjwahbL2e3NwMIJ7Y="
        );
    }

    #[test]
    fn presign_escapes_base64_reserved_characters() {
        // 已知向量 "C/Z+oEWx2wstp6ES//XafsrRoxo=" 含 '/' 与 '+'，必须转义。
        let resource = sign::canonicalized_resource("bucket", "key");
        let raw = sign::sign_v1("sk", "GET", "", "", "1893456000", "", &resource);
        assert_eq!(raw, "C/Z+oEWx2wstp6ES//XafsrRoxo=");
        let url = build_presign_url(
            "https://oss.example.com",
            "bucket",
            "key",
            "id",
            "sk",
            &PresignOptions::default(),
            1_893_456_000,
        )
        .expect("presign");
        assert_eq!(
            url,
            "https://bucket.oss.example.com/key?OSSAccessKeyId=id&Expires=1893456000&Signature=C%2FZ%2BoEWx2wstp6ES%2F%2FXafsrRoxo="
        );
    }

    #[test]
    fn presign_options_defaults() {
        let options = PresignOptions::default();
        assert_eq!(options.method, "GET");
        assert_eq!(options.expires, Duration::from_secs(3600));
        assert!(options.content_type.is_none());
    }

    #[test]
    fn presign_url_is_stable_within_same_second() {
        let options = PresignOptions {
            expires: Duration::from_secs(9999),
            ..Default::default()
        };
        // Expires = now + TTL；跨秒时会变化，同一秒内必须完全一致。
        for _ in 0..32 {
            let first = presign_url("https://oss.example.com", "b", "k", "id", "sec", &options)
                .expect("presign");
            let second = presign_url("https://oss.example.com", "b", "k", "id", "sec", &options)
                .expect("presign");
            if first == second {
                assert!(first.contains("Signature="));
                return;
            }
        }
        panic!("同一秒内 presign_url 必须确定性相等");
    }

    #[test]
    fn huge_ttl_saturates_without_panic() {
        let options = PresignOptions {
            expires: Duration::from_secs(u64::MAX),
            ..Default::default()
        };
        let url = presign_url("https://oss.example.com", "b", "k", "id", "sec", &options)
            .expect("presign");
        assert!(url.contains("&Expires="));
    }
}
