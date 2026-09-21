//! 凭据模型与凭据提供者抽象。
//!
//! 提供者是**可刷新**的：每次请求都会调用 [`CredentialProvider::get_credentials`]，
//! 因此接入 STS 或自建凭据服务时只需替换实现，无需重建客户端。

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::error::OssResult;

/// OSS 凭据。
///
/// `Debug` 隐藏 `access_key_secret` 与 `security_token` 的值，
/// 只暴露 `access_key_id` 与 token 是否存在。
#[derive(Clone)]
pub struct OssCredentials {
    /// AccessKeyId。
    pub access_key_id: String,
    /// AccessKeySecret（敏感）。
    pub access_key_secret: String,
    /// STS 临时安全令牌。
    pub security_token: Option<String>,
}

impl fmt::Debug for OssCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OssCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"<redacted>")
            .field(
                "security_token",
                &self.security_token.as_ref().map(|_| "<present>"),
            )
            .finish()
    }
}

/// 凭据提供者。
///
/// 返回装箱 future 而非 `async fn`，以保持 trait 对象安全且不引入额外依赖：
/// 实现方返回 `Box::pin(async move { .. })` 即可。
pub trait CredentialProvider: Send + Sync {
    /// 取当前有效凭据。
    fn get_credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = OssResult<OssCredentials>> + Send + '_>>;

    /// 提供者名称（用于日志/指标，不含凭据）。
    fn provider_name(&self) -> &'static str;
}

/// 静态凭据提供者：固定返回构造时注入的凭据。
#[derive(Clone, Debug)]
pub struct StaticCredentialProvider {
    credentials: OssCredentials,
}

impl StaticCredentialProvider {
    /// 按显式凭据构造。
    #[must_use]
    pub fn new(
        access_key_id: impl Into<String>,
        access_key_secret: impl Into<String>,
        security_token: Option<String>,
    ) -> Self {
        Self {
            credentials: OssCredentials {
                access_key_id: access_key_id.into(),
                access_key_secret: access_key_secret.into(),
                security_token,
            },
        }
    }
}

impl CredentialProvider for StaticCredentialProvider {
    fn get_credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = OssResult<OssCredentials>> + Send + '_>> {
        let credentials = self.credentials.clone();
        Box::pin(async move { Ok(credentials) })
    }

    fn provider_name(&self) -> &'static str {
        "static"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_returns_credentials() {
        let provider = StaticCredentialProvider::new("test-id", "test-secret", None);
        let credentials = provider.get_credentials().await.expect("credentials");
        assert_eq!(credentials.access_key_id, "test-id");
        assert_eq!(credentials.access_key_secret, "test-secret");
        assert!(credentials.security_token.is_none());
        assert_eq!(provider.provider_name(), "static");
    }

    #[tokio::test]
    async fn static_provider_with_security_token() {
        let provider = StaticCredentialProvider::new("id", "sec", Some("sts-token".to_string()));
        let credentials = provider.get_credentials().await.expect("credentials");
        assert_eq!(credentials.security_token.as_deref(), Some("sts-token"));
    }

    #[test]
    fn credentials_debug_does_not_leak_secret() {
        let credentials = OssCredentials {
            access_key_id: "AK123".into(),
            access_key_secret: "super-secret".into(),
            security_token: Some("sts".into()),
        };
        let debug = format!("{credentials:?}");
        assert!(debug.contains("AK123"), "id 可见");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("<present>"));
        assert!(!debug.contains("super-secret"), "secret 绝不能泄露");
        assert!(!debug.contains("sts"), "token 值绝不能泄露");
    }

    #[test]
    fn provider_is_object_safe() {
        fn assert_object_safe(_: &dyn CredentialProvider) {}
        let provider = StaticCredentialProvider::new("id", "sec", None);
        assert_object_safe(&provider);
        let boxed: std::sync::Arc<dyn CredentialProvider> = std::sync::Arc::new(provider);
        assert_eq!(boxed.provider_name(), "static");
    }
}
