//! `OssConfigBuilder`：`OssConfig` 的链式构建器。
//!
//! 自 `src/config.rs` 下沉而来。公开类型经门面 `pub use` 导出，路径不变；
//! 构建器只收集 `Option` 字段，非法组合在 `build()` 里由 `OssConfig::validate` 与
//! `validate_limit` 统一 fail-closed。

use std::time::Duration;

use crate::error::{OssError, OssResult};

use super::{
    OssConfig, DEFAULT_ACQUIRE_TIMEOUT, DEFAULT_MAX_BUFFER_BYTES, DEFAULT_MAX_ERROR_BODY_BYTES,
    DEFAULT_MAX_IN_FLIGHT, DEFAULT_MAX_OBJECT_BYTES, DEFAULT_OPERATION_DEADLINE, DEFAULT_REGION,
    DEFAULT_REQUEST_TIMEOUT,
};

/// [`OssConfig`] 构建器。
///
/// ```no_run
/// use ossx::OssConfig;
///
/// # fn main() -> Result<(), ossx::OssError> {
/// let cfg = OssConfig::builder()
///     .endpoint("https://oss.example.com")
///     .bucket("example-bucket")
///     .access_key_id("id")
///     .access_key_secret("secret")
///     .max_in_flight(8)
///     .build()?;
/// assert_eq!(cfg.max_in_flight, 8);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default, Clone)]
pub struct OssConfigBuilder {
    endpoint: Option<String>,
    bucket: Option<String>,
    access_key_id: Option<String>,
    access_key_secret: Option<String>,
    region: Option<String>,
    request_timeout: Option<Duration>,
    operation_deadline: Option<Duration>,
    acquire_timeout: Option<Duration>,
    max_in_flight: Option<usize>,
    max_object_bytes: Option<usize>,
    max_buffer_bytes: Option<usize>,
    max_error_body_bytes: Option<usize>,
    security_token: Option<String>,
    sse_enabled: Option<bool>,
}

impl OssConfigBuilder {
    /// 设置地域 endpoint。
    #[must_use]
    pub fn endpoint(mut self, value: impl Into<String>) -> Self {
        self.endpoint = Some(value.into());
        self
    }

    /// 设置 bucket。
    #[must_use]
    pub fn bucket(mut self, value: impl Into<String>) -> Self {
        self.bucket = Some(value.into());
        self
    }

    /// 设置 AccessKeyId。
    #[must_use]
    pub fn access_key_id(mut self, value: impl Into<String>) -> Self {
        self.access_key_id = Some(value.into());
        self
    }

    /// 设置 AccessKeySecret。
    #[must_use]
    pub fn access_key_secret(mut self, value: impl Into<String>) -> Self {
        self.access_key_secret = Some(value.into());
        self
    }

    /// 设置区域 id。
    #[must_use]
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.region = Some(value.into());
        self
    }

    /// 设置单请求超时。
    #[must_use]
    pub fn request_timeout(mut self, value: Duration) -> Self {
        self.request_timeout = Some(value);
        self
    }

    /// 设置含重试在内的单操作 deadline。
    #[must_use]
    pub fn operation_deadline(mut self, value: Duration) -> Self {
        self.operation_deadline = Some(value);
        self
    }

    /// 设置获取 in-flight 许可超时。
    #[must_use]
    pub fn acquire_timeout(mut self, value: Duration) -> Self {
        self.acquire_timeout = Some(value);
        self
    }

    /// 设置全局 in-flight 上限。
    #[must_use]
    pub fn max_in_flight(mut self, value: usize) -> Self {
        self.max_in_flight = Some(value);
        self
    }

    /// 设置对象大小上限。
    #[must_use]
    pub fn max_object_bytes(mut self, value: usize) -> Self {
        self.max_object_bytes = Some(value);
        self
    }

    /// 设置单次内存缓冲上限。
    #[must_use]
    pub fn max_buffer_bytes(mut self, value: usize) -> Self {
        self.max_buffer_bytes = Some(value);
        self
    }

    /// 设置错误响应体读取上限。
    #[must_use]
    pub fn max_error_body_bytes(mut self, value: usize) -> Self {
        self.max_error_body_bytes = Some(value);
        self
    }

    /// 设置 STS 临时安全令牌（可选）。
    #[must_use]
    pub fn security_token(mut self, value: impl Into<String>) -> Self {
        self.security_token = Some(value.into());
        self
    }

    /// 设置是否启用 SSE-S3 加密（默认 `false`）。
    #[must_use]
    pub fn sse_enabled(mut self, value: bool) -> Self {
        self.sse_enabled = Some(value);
        self
    }

    /// 构建并校验；缺必填项或超限时返回 [`OssError::Config`]。
    pub fn build(self) -> OssResult<OssConfig> {
        let config = OssConfig {
            endpoint: self
                .endpoint
                .ok_or_else(|| OssError::Config("oss endpoint required".into()))?,
            bucket: self
                .bucket
                .ok_or_else(|| OssError::Config("oss bucket required".into()))?,
            access_key_id: self
                .access_key_id
                .ok_or_else(|| OssError::Config("oss access_key_id required".into()))?,
            access_key_secret: self
                .access_key_secret
                .ok_or_else(|| OssError::Config("oss access_key_secret required".into()))?,
            region: self.region.unwrap_or_else(|| DEFAULT_REGION.into()),
            request_timeout: self.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            operation_deadline: self
                .operation_deadline
                .unwrap_or(DEFAULT_OPERATION_DEADLINE),
            acquire_timeout: self.acquire_timeout.unwrap_or(DEFAULT_ACQUIRE_TIMEOUT),
            max_in_flight: self.max_in_flight.unwrap_or(DEFAULT_MAX_IN_FLIGHT),
            max_object_bytes: self.max_object_bytes.unwrap_or(DEFAULT_MAX_OBJECT_BYTES),
            max_buffer_bytes: self.max_buffer_bytes.unwrap_or(DEFAULT_MAX_BUFFER_BYTES),
            max_error_body_bytes: self
                .max_error_body_bytes
                .unwrap_or(DEFAULT_MAX_ERROR_BODY_BYTES),
            security_token: self.security_token,
            sse_enabled: self.sse_enabled.unwrap_or(false),
        };
        config.validate()?;
        Ok(config)
    }
}
