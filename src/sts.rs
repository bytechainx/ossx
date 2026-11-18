//! 阿里云 STS `AssumeRole` 凭据提供者。
//!
//! 用长期 RAM 用户凭据（`OssCredentials`）调用 STS RPC 接口换取
//! `security_token` 临时凭据，并在到期前自动刷新。返回的凭据可直接交给
//! [`crate::OssPool::connect_with_provider`]，此后每次 OSS 请求都会拿到
//! 当前有效的临时凭据。
//!
//! STS RPC 采用与 OSS V1 不同的签名方案（`SignatureVersion=1.0` /
//! `SignatureMethod=HMAC-SHA1`）：参数按 key 字典序排序、逐段百分号编码后
//! 拼成 `StringToSign = "GET&%2F&" + encoded(query)`，签名密钥为
//! `AccessKeySecret + "&"`。本模块的实现与阿里云《签名机制》文档对齐。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};

use crate::credential::{CredentialProvider, OssCredentials};
use crate::error::{OssError, OssResult};
use crate::sign::hmac_sha1;

/// STS API 版本（`AssumeRole` 要求）。
const STS_API_VERSION: &str = "2015-04-01";
/// STS RPC Action。
const STS_ACTION_ASSUME_ROLE: &str = "AssumeRole";
/// `AssumeRole` 允许的最小时长（15 分钟）。
const MIN_DURATION_SECONDS: u32 = 900;
/// `AssumeRole` 允许的最大时长（12 小时）。
const MAX_DURATION_SECONDS: u32 = 43_200;
/// 默认临时凭据时长（1 小时）。
const DEFAULT_DURATION_SECONDS: u32 = 3_600;
/// 默认 STS endpoint。
const DEFAULT_ENDPOINT: &str = "https://sts.aliyuncs.com";
/// 默认会话名。
const DEFAULT_SESSION_NAME: &str = "ossx-session";
/// 默认提前刷新窗口：剩余有效期低于该值时重新调用 AssumeRole。
const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(300);
/// STS 请求超时默认值。
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `AssumeRole` 参数与行为配置。
#[derive(Clone, Debug)]
pub struct StsConfig {
    /// STS endpoint，默认 `https://sts.aliyuncs.com`。
    pub endpoint: String,
    /// 要扮演的 RAM 角色 ARN（`acs:ram::<account>:role/<name>`）。
    pub role_arn: String,
    /// 会话名，默认 `ossx-session`；同一角色下需唯一性由调用方保证。
    pub role_session_name: String,
    /// 临时凭据时长（秒），默认 3600，合法范围 `900..=43200`。
    pub duration_seconds: u32,
    /// 提前刷新窗口：剩余有效期低于该值即重新 AssumeRole，默认 300 秒。
    pub refresh_skew: Duration,
    /// 单次 STS 请求超时，默认 30 秒。
    pub request_timeout: Duration,
}

impl Default for StsConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.into(),
            role_arn: String::new(),
            role_session_name: DEFAULT_SESSION_NAME.into(),
            duration_seconds: DEFAULT_DURATION_SECONDS,
            refresh_skew: DEFAULT_REFRESH_SKEW,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

impl StsConfig {
    /// 链式构造：设置角色 ARN（必填项）。
    #[must_use]
    pub fn role_arn(mut self, role_arn: impl Into<String>) -> Self {
        self.role_arn = role_arn.into();
        self
    }

    /// 校验配置；`role_arn` 必填且形如 `acs:ram::` 前缀。
    pub fn validate(&self) -> OssResult<()> {
        if self.endpoint.trim().is_empty() {
            return Err(OssError::Config("sts endpoint 为空".into()));
        }
        if !self.endpoint.starts_with("https://") {
            return Err(OssError::Config("远程 STS endpoint 必须使用 HTTPS".into()));
        }
        if !self.role_arn.starts_with("acs:ram::") || self.role_arn.len() <= "acs:ram::".len() {
            return Err(OssError::Config(
                "sts role_arn 必须形如 acs:ram::<account>:role/<name>".into(),
            ));
        }
        if self.role_session_name.trim().is_empty() {
            return Err(OssError::Config("sts role_session_name 为空".into()));
        }
        if !(MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&self.duration_seconds) {
            return Err(OssError::Config(format!(
                "sts duration_seconds 必须在 {MIN_DURATION_SECONDS}..={MAX_DURATION_SECONDS} 范围内"
            )));
        }
        if self.request_timeout.is_zero() {
            return Err(OssError::Config("sts request_timeout 必须大于零".into()));
        }
        Ok(())
    }
}

/// 从 `FOUNDATIONX_OSSX_STS_*` 环境变量加载 [`StsConfig`]。
///
/// `FOUNDATIONX_OSSX_STS_ROLE_ARN` 必填；其余项缺省时使用 [`StsConfig::default`]。
pub fn sts_config_from_env() -> OssResult<StsConfig> {
    let mut config = StsConfig::default();
    if let Ok(value) = std::env::var("FOUNDATIONX_OSSX_STS_ENDPOINT") {
        if !value.trim().is_empty() {
            config.endpoint = value;
        }
    }
    config.role_arn = std::env::var("FOUNDATIONX_OSSX_STS_ROLE_ARN")
        .map_err(|_| OssError::Config("环境变量 FOUNDATIONX_OSSX_STS_ROLE_ARN 缺失".into()))?;
    if let Ok(value) = std::env::var("FOUNDATIONX_OSSX_STS_SESSION_NAME") {
        if !value.trim().is_empty() {
            config.role_session_name = value;
        }
    }
    if let Ok(value) = std::env::var("FOUNDATIONX_OSSX_STS_DURATION_SECONDS") {
        config.duration_seconds = value.trim().parse::<u32>().map_err(|_| {
            OssError::Config("环境变量 FOUNDATIONX_OSSX_STS_DURATION_SECONDS 不是整数".into())
        })?;
    }
    config.validate()?;
    Ok(config)
}

struct CachedCredentials {
    credentials: OssCredentials,
    /// 过期时刻（UTC）。
    expires_at: DateTime<Utc>,
}

struct StsInner {
    config: StsConfig,
    /// 用于签名 STS 请求的基线凭据（RAM 用户 AK/SK）。
    base_credentials: OssCredentials,
    http: reqwest::Client,
    cache: tokio::sync::Mutex<Option<CachedCredentials>>,
}

/// STS `AssumeRole` 凭据提供者：实现 [`CredentialProvider`]，自动刷新。
///
/// ```
/// use ossx::{OssCredentials, StsConfig, StsCredentialProvider};
///
/// # fn main() -> Result<(), ossx::OssError> {
/// let provider = StsCredentialProvider::new(
///     StsConfig::default().role_arn("acs:ram::123456789012:role/oss-reader"),
///     OssCredentials {
///         access_key_id: "LTAI5tRamUser".into(),
///         access_key_secret: "ram-secret".into(),
///         security_token: None,
///     },
/// )?;
/// # let _ = provider;
/// # Ok(())
/// # }
/// ```
pub struct StsCredentialProvider {
    inner: Arc<StsInner>,
}

impl StsCredentialProvider {
    /// 按 [`StsConfig`] 与基线凭据构造；`base_credentials` 不能带
    /// `security_token`（STS AssumeRole 只接受长期 AK/SK 签名）。
    pub fn new(config: StsConfig, base_credentials: OssCredentials) -> OssResult<Self> {
        config.validate()?;
        if base_credentials.security_token.is_some() {
            return Err(OssError::Config(
                "sts base credentials 不允许携带 security_token".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|error| OssError::Backend(format!("sts http client 构建失败: {error}")))?;
        Ok(Self {
            inner: Arc::new(StsInner {
                config,
                base_credentials,
                http,
                cache: tokio::sync::Mutex::new(None),
            }),
        })
    }

    /// 当前缓存凭据的剩余有效秒数（无缓存返回 `None`）；仅供观测，不触发刷新。
    pub async fn cached_ttl_seconds(&self) -> Option<i64> {
        let guard = self.inner.cache.lock().await;
        let cached = guard.as_ref()?;
        Some((cached.expires_at - Utc::now()).num_seconds())
    }

    /// 调用 STS `AssumeRole` 并解析临时凭据（不缓存）。
    async fn assume_role_once(&self) -> OssResult<CachedCredentials> {
        let params = build_assume_role_params(&self.inner.config, &self.inner.base_credentials)?;
        let url = format!(
            "{}?{}",
            self.inner.config.endpoint.trim_end_matches('/'),
            params
        );
        let response = self
            .inner
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| map_sts_network(&error))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| OssError::Backend(format!("sts 响应体读取失败: {error}")))?;
        if !status.is_success() {
            return Err(sts_status_error(status.as_u16(), &body));
        }
        parse_assume_role_response(&body)
    }
}

impl CredentialProvider for StsCredentialProvider {
    fn get_credentials(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OssResult<OssCredentials>> + Send + '_>>
    {
        Box::pin(async move {
            let mut guard = self.inner.cache.lock().await;
            let now = Utc::now();
            let fresh = guard.as_ref().is_some_and(|cached| {
                now < cached.expires_at
                    - chrono::Duration::from_std(self.inner.config.refresh_skew)
                        .unwrap_or_else(|_| chrono::Duration::seconds(300))
            });
            if !fresh {
                let cached = self.assume_role_once().await?;
                *guard = Some(cached);
            }
            guard
                .as_ref()
                .map(|cached| cached.credentials.clone())
                .ok_or_else(|| OssError::Backend("sts 缓存凭据缺失".into()))
        })
    }

    fn provider_name(&self) -> &'static str {
        "sts-assume-role"
    }
}

/// 组装已签名的 AssumeRole query string（含 `Signature`）。
pub(crate) fn build_assume_role_params(
    config: &StsConfig,
    base: &OssCredentials,
) -> OssResult<String> {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let nonce = next_nonce();
    let mut pairs: Vec<(String, String)> = vec![
        ("AccessKeyId".into(), base.access_key_id.clone()),
        ("Action".into(), STS_ACTION_ASSUME_ROLE.into()),
        (
            "DurationSeconds".into(),
            config.duration_seconds.to_string(),
        ),
        ("RoleArn".into(), config.role_arn.clone()),
        ("RoleSessionName".into(), config.role_session_name.clone()),
        ("SignatureMethod".into(), "HMAC-SHA1".into()),
        ("SignatureNonce".into(), nonce),
        ("SignatureVersion".into(), "1.0".into()),
        ("Timestamp".into(), timestamp),
        ("Version".into(), STS_API_VERSION.into()),
    ];
    // RPC StringToSign：参数按 key 字典序排序后编码拼接。
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_query: String = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", rpc_encode(k), rpc_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("GET&%2F&{}", rpc_encode(&canonical_query));
    let signature = hmac_sha1(
        format!("{}&", base.access_key_secret).as_bytes(),
        string_to_sign.as_bytes(),
    );
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let signature_encoded = rpc_encode(&signature_b64);
    Ok(format!("{canonical_query}&Signature={signature_encoded}"))
}

/// 阿里云 RPC 百分号编码：除 `A-Z a-z 0-9 - _ . ~` 外全部 `%XX`（大写十六进制）。
fn rpc_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 进程内单调 nonce：纳秒时间戳 + 原子计数 + pid，足以保证同一秒内唯一。
fn next_nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{seq}-{}", std::process::id())
}

/// 解析 AssumeRole XML 响应为缓存凭据。
fn parse_assume_role_response(xml: &str) -> OssResult<CachedCredentials> {
    // STS 错误响应：<Error><Code>..</Code><Message>..</Message></Error>
    if let Some(code) = xml_find(xml, "<Code>", "</Code>") {
        let message = xml_find(xml, "<Message>", "</Message>").unwrap_or_default();
        return Err(OssError::Backend(format!(
            "sts AssumeRole 失败: {code}: {message}"
        )));
    }
    let access_key_id = xml_find(xml, "<AccessKeyId>", "</AccessKeyId>")
        .ok_or_else(|| OssError::Serialization("sts 响应缺 AccessKeyId".into()))?;
    let access_key_secret = xml_find(xml, "<AccessKeySecret>", "</AccessKeySecret>")
        .ok_or_else(|| OssError::Serialization("sts 响应缺 AccessKeySecret".into()))?;
    let security_token = xml_find(xml, "<SecurityToken>", "</SecurityToken>")
        .ok_or_else(|| OssError::Serialization("sts 响应缺 SecurityToken".into()))?;
    let expiration_text = xml_find(xml, "<Expiration>", "</Expiration>")
        .ok_or_else(|| OssError::Serialization("sts 响应缺 Expiration".into()))?;
    let expires_at = DateTime::parse_from_rfc3339(&expiration_text)
        .map_err(|error| OssError::Serialization(format!("sts Expiration 解析失败: {error}")))?
        .with_timezone(&Utc);
    Ok(CachedCredentials {
        credentials: OssCredentials {
            access_key_id,
            access_key_secret,
            security_token: Some(security_token),
        },
        expires_at,
    })
}

/// 与 `client::xml::parse_upload_id` 同款的字符串定位解析（应答 XML 由 STS 服务端生成）。
fn xml_find(xml: &str, open: &str, close: &str) -> Option<String> {
    let start = xml.find(open)? + open.len();
    let end = xml[start..].find(close)? + start;
    Some(xml[start..end].trim().to_owned())
}

fn map_sts_network(error: &reqwest::Error) -> OssError {
    if error.is_timeout() {
        OssError::Timeout(format!("sts 请求超时: {error}"))
    } else {
        OssError::Connection(format!("sts 连接失败: {error}"))
    }
}

fn sts_status_error(status: u16, body: &str) -> OssError {
    let snippet: String = body.chars().take(512).collect();
    OssError::Backend(format!("sts HTTP {status}: {snippet}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> OssCredentials {
        OssCredentials {
            access_key_id: "LTAI5tBase".into(),
            access_key_secret: "base-secret".into(),
            security_token: None,
        }
    }

    #[test]
    fn rpc_encode_follows_aliyun_rules() {
        assert_eq!(
            rpc_encode("acs:ram::1:role/x"),
            "acs%3Aram%3A%3A1%3Arole%2Fx"
        );
        assert_eq!(rpc_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(rpc_encode("a b"), "a%20b");
        assert_eq!(rpc_encode("100%"), "100%25");
    }

    #[test]
    fn assume_role_params_are_sorted_and_signed() {
        let config = StsConfig::default().role_arn("acs:ram::1:role/r");
        let params = build_assume_role_params(&config, &base()).expect("params");
        assert!(params.contains("Action=AssumeRole"));
        assert!(params.contains("Version=2015-04-01"));
        assert!(params.contains("SignatureMethod=HMAC-SHA1"));
        assert!(params.contains("SignatureVersion=1.0"));
        assert!(params.contains("SignatureNonce="));
        assert!(params.contains("Timestamp="));
        assert!(params.contains("&Signature="));
        // 参数按 key 排序：AccessKeyId 最先，Version 在 Timestamp 之后。
        let ak_pos = params.find("AccessKeyId=").expect("ak");
        let ts_pos = params.find("Timestamp=").expect("ts");
        let ver_pos = params.find("&Version=").expect("ver");
        assert!(ak_pos < ts_pos && ts_pos < ver_pos);
    }

    #[test]
    fn parse_assume_role_response_extracts_credentials() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse><AssumeRoleResult><Credentials>
<AccessKeyId>STS.xxx</AccessKeyId>
<AccessKeySecret>sts-secret</AccessKeySecret>
<SecurityToken>token-value</SecurityToken>
<Expiration>2030-01-01T00:00:00Z</Expiration>
</Credentials></AssumeRoleResult></AssumeRoleResponse>"#;
        let cached = parse_assume_role_response(xml).expect("parse");
        assert_eq!(cached.credentials.access_key_id, "STS.xxx");
        assert_eq!(
            cached.credentials.security_token.as_deref(),
            Some("token-value")
        );
        assert_eq!(cached.expires_at.to_rfc3339(), "2030-01-01T00:00:00+00:00");
    }

    #[test]
    fn parse_error_response_fails() {
        let xml = "<ErrorResponse><Error><Code>InvalidRoleArn</Code><Message>bad arn</Message></Error></ErrorResponse>";
        let Err(error) = parse_assume_role_response(xml) else {
            panic!("必须失败");
        };
        assert!(error.to_string().contains("InvalidRoleArn"));
    }

    #[test]
    fn config_validate_rejects_bad_role_arn() {
        assert!(StsConfig::default().validate().is_err());
        assert!(StsConfig::default()
            .role_arn("not-an-arn")
            .validate()
            .is_err());
        assert!(StsConfig::default()
            .role_arn("acs:ram::123:role/ok")
            .validate()
            .is_ok());
    }

    #[test]
    fn new_rejects_token_base_credentials() {
        let mut base = base();
        base.security_token = Some("t".into());
        assert!(StsCredentialProvider::new(
            StsConfig::default().role_arn("acs:ram::1:role/r"),
            base
        )
        .is_err());
    }

    #[tokio::test]
    async fn provider_name_is_stable() {
        let provider =
            StsCredentialProvider::new(StsConfig::default().role_arn("acs:ram::1:role/r"), base())
                .expect("provider");
        assert_eq!(provider.provider_name(), "sts-assume-role");
        assert_eq!(provider.cached_ttl_seconds().await, None);
    }
}
