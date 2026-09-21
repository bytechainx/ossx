//! OSS 连接配置：环境变量、TOML 与 Builder 三种装载方式。
//!
//! - 环境变量前缀固定为 `FOUNDATIONX_OSSX_*`，常量以 [`ENV_ENDPOINT`] 等 `ENV_*` 公开；
//! - TOML 只允许承载**非 secret** 调参，出现 `access_key_id` / `access_key_secret`
//!   直接 fail-closed；凭据始终来自环境变量；
//! - 所有资源上界都在构建期校验，零值或超过 `HARD_MAX_*` 一律拒绝。

use std::env;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::error::{OssError, OssResult};

/// endpoint 环境变量（形如 `https://oss-ap-northeast-1.aliyuncs.com`）。
pub const ENV_ENDPOINT: &str = "FOUNDATIONX_OSSX_ENDPOINT";
/// bucket 环境变量。
pub const ENV_BUCKET: &str = "FOUNDATIONX_OSSX_BUCKET";
/// AccessKeyId 环境变量。
pub const ENV_ACCESS_KEY_ID: &str = "FOUNDATIONX_OSSX_ACCESS_KEY_ID";
/// AccessKeySecret 环境变量（禁止写入源码或日志）。
pub const ENV_ACCESS_KEY_SECRET: &str = "FOUNDATIONX_OSSX_ACCESS_KEY_SECRET";
/// 区域 id 环境变量（元数据；Signature V1 不强制使用）。
pub const ENV_REGION: &str = "FOUNDATIONX_OSSX_REGION";
/// 单请求超时环境变量（毫秒）。
pub const ENV_REQUEST_TIMEOUT_MS: &str = "FOUNDATIONX_OSSX_REQUEST_TIMEOUT_MS";
/// 含重试在内的单操作 deadline 环境变量（毫秒）。
pub const ENV_OPERATION_DEADLINE_MS: &str = "FOUNDATIONX_OSSX_OPERATION_DEADLINE_MS";
/// 获取并发许可超时环境变量（毫秒）。
pub const ENV_ACQUIRE_TIMEOUT_MS: &str = "FOUNDATIONX_OSSX_ACQUIRE_TIMEOUT_MS";
/// 最大并发请求数环境变量。
pub const ENV_MAX_IN_FLIGHT: &str = "FOUNDATIONX_OSSX_MAX_IN_FLIGHT";
/// 最大对象字节数环境变量。
pub const ENV_MAX_OBJECT_BYTES: &str = "FOUNDATIONX_OSSX_MAX_OBJECT_BYTES";
/// 最大单次内存缓冲字节数环境变量。
pub const ENV_MAX_BUFFER_BYTES: &str = "FOUNDATIONX_OSSX_MAX_BUFFER_BYTES";
/// 最大错误响应体字节数环境变量。
pub const ENV_MAX_ERROR_BODY_BYTES: &str = "FOUNDATIONX_OSSX_MAX_ERROR_BODY_BYTES";

/// 并发请求数硬上界。
pub const HARD_MAX_IN_FLIGHT: usize = 1_024;
/// 对象字节数硬上界（5 GiB，阿里云单对象上限）。
pub const HARD_MAX_OBJECT_BYTES: usize = 5 * 1024 * 1024 * 1024;
/// 单次内存缓冲硬上界（512 MiB）。
pub const HARD_MAX_BUFFER_BYTES: usize = 512 * 1024 * 1024;
/// 错误响应体读取硬上界（1 MiB）。
pub const HARD_MAX_ERROR_BODY_BYTES: usize = 1024 * 1024;

const DEFAULT_REGION: &str = "ap-northeast-1";
const DEFAULT_MAX_IN_FLIGHT: usize = 64;
const DEFAULT_MAX_OBJECT_BYTES: usize = HARD_MAX_BUFFER_BYTES;
const DEFAULT_MAX_BUFFER_BYTES: usize = HARD_MAX_BUFFER_BYTES;
const DEFAULT_MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_OPERATION_DEADLINE: Duration = Duration::from_secs(90);
const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// 阿里云 OSS 配置。
///
/// `Debug` 对 `access_key_id` 做中间脱敏、对 `access_key_secret` 与
/// `security_token` 完全隐藏，可安全打印到日志。
///
/// 非 secret 字段为 `pub`；`access_key_secret` 与 `security_token` 仅经
/// [`OssConfig::access_key_secret`] / [`OssConfig::security_token`] 在 crate 内读取，
/// 带外分享配置（例如日志、指标、序列化）不会泄露凭据。
///
/// ```
/// use ossx::OssConfig;
///
/// # fn main() -> Result<(), ossx::OssError> {
/// let cfg = OssConfig::builder()
///     .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
///     .bucket("demo-bucket")
///     .access_key_id("LTAI5tExample")
///     .access_key_secret("secret")
///     .build()?;
/// assert_eq!(cfg.region, "ap-northeast-1");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, serde::Deserialize)]
#[serde(default)]
pub struct OssConfig {
    /// 地域 endpoint，例如 `https://oss-ap-northeast-1.aliyuncs.com`。
    pub endpoint: String,
    /// Bucket 名称（小写字母、数字与连字符，3..=63 字节）。
    pub bucket: String,
    /// AccessKeyId。
    pub access_key_id: String,
    /// AccessKeySecret（敏感，不公开读取）。
    access_key_secret: String,
    /// 区域 id（元数据；Signature V1 不强制使用）。
    pub region: String,
    /// 单请求超时。
    pub request_timeout: Duration,
    /// 含重试在内的单操作 deadline。
    pub operation_deadline: Duration,
    /// 获取 in-flight 许可超时。
    pub acquire_timeout: Duration,
    /// 全局 in-flight 请求上限。
    pub max_in_flight: usize,
    /// 对象大小上限。
    pub max_object_bytes: usize,
    /// 单次内存缓冲上限。
    pub max_buffer_bytes: usize,
    /// 错误响应体读取上限。
    pub max_error_body_bytes: usize,
    /// STS 临时安全令牌（可选，敏感）。
    security_token: Option<String>,
    /// 是否启用 SSE-S3 服务端加密。
    pub sse_enabled: bool,
}

impl fmt::Debug for OssConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OssConfig")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("access_key_id", &redact_mid(&self.access_key_id))
            .field("access_key_secret", &"<redacted>")
            .field("region", &self.region)
            .field("request_timeout", &self.request_timeout)
            .field("operation_deadline", &self.operation_deadline)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("max_in_flight", &self.max_in_flight)
            .field("max_object_bytes", &self.max_object_bytes)
            .field("max_buffer_bytes", &self.max_buffer_bytes)
            .field("max_error_body_bytes", &self.max_error_body_bytes)
            .finish()
    }
}

impl Default for OssConfig {
    /// 仅填充可调参数默认值；`endpoint` / `bucket` / 凭据为空，
    /// 必须经 Builder 或环境变量补齐后 [`OssConfig::validate`] 才会通过。
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            bucket: String::new(),
            access_key_id: String::new(),
            access_key_secret: String::new(),
            region: DEFAULT_REGION.into(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            operation_deadline: DEFAULT_OPERATION_DEADLINE,
            acquire_timeout: DEFAULT_ACQUIRE_TIMEOUT,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            max_error_body_bytes: DEFAULT_MAX_ERROR_BODY_BYTES,
            security_token: None,
            sse_enabled: false,
        }
    }
}

impl OssConfig {
    /// 返回 AccessKeySecret；仅供 crate 内签名实现使用，不对外公开。
    #[must_use]
    pub(crate) fn access_key_secret(&self) -> &str {
        &self.access_key_secret
    }

    /// 返回 STS token；仅供 crate 内请求头实现使用，不对外公开。
    #[must_use]
    pub(crate) fn security_token(&self) -> Option<&str> {
        self.security_token.as_deref()
    }

    /// 从 `FOUNDATIONX_OSSX_*` 环境变量加载；缺项 fail-closed。
    ///
    /// endpoint / bucket / AccessKeyId / AccessKeySecret 必填，
    /// region 默认 `ap-northeast-1`，其余可调参数缺省时使用默认值。
    pub fn from_env() -> OssResult<Self> {
        let endpoint = require_env(ENV_ENDPOINT)?;
        let bucket = require_env(ENV_BUCKET)?;
        let access_key_id = require_env(ENV_ACCESS_KEY_ID)?;
        let access_key_secret = require_env(ENV_ACCESS_KEY_SECRET)?;
        let region = match env::var(ENV_REGION) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => DEFAULT_REGION.into(),
            Err(_) => return Err(OssError::Config(format!("环境变量 {ENV_REGION} 读取失败"))),
        };
        let mut builder = Self::builder()
            .endpoint(endpoint)
            .bucket(bucket)
            .access_key_id(access_key_id)
            .access_key_secret(access_key_secret)
            .region(region);
        builder = apply_optional_env_overrides(builder)?;
        builder.build()
    }

    /// 从 TOML 字符串加载非 secret 字段，凭据与覆盖项仍从 `FOUNDATIONX_OSSX_*` 读取。
    ///
    /// 文件不得包含 `access_key_id` / `access_key_secret`。
    pub fn from_toml(content: &str) -> OssResult<Self> {
        Self::parse_toml(content)?.into_config_with_env()
    }

    /// 从 TOML 文件加载；凭据与覆盖项从环境变量合并。
    pub fn from_toml_file(path: impl AsRef<Path>) -> OssResult<Self> {
        let content = fs::read_to_string(path.as_ref()).map_err(|error| {
            OssError::Io(std::io::Error::new(
                error.kind(),
                format!("oss toml 文件不可读: {} ({error})", path.as_ref().display()),
            ))
        })?;
        Self::from_toml(&content)
    }

    /// 仅解析 TOML 非 secret 字段，不合并环境变量。
    fn parse_toml(content: &str) -> OssResult<OssTomlFile> {
        reject_secret_keys_in_toml(content)?;
        let file: OssTomlFile = toml::from_str(content)
            .map_err(|error| OssError::Serialization(format!("oss toml 解析失败: {error}")))?;
        if file.schema_version != 1 {
            return Err(OssError::Config(format!(
                "oss toml schema_version 不支持: {}",
                file.schema_version
            )));
        }
        Ok(file)
    }

    /// Builder 入口。
    #[must_use]
    pub fn builder() -> OssConfigBuilder {
        OssConfigBuilder::default()
    }

    /// 校验传输安全与所有资源硬上界。
    ///
    /// 规则：必填字段非空、endpoint 为 HTTPS（HTTP 仅允许 loopback）、
    /// endpoint 不带 userinfo/path/query/fragment、bucket 命名合法、
    /// 超时与 deadline 均为正且 `operation_deadline >= request_timeout`、
    /// 所有上界落在 `1..=HARD_MAX_*`、`max_object_bytes <= max_buffer_bytes`。
    pub fn validate(&self) -> OssResult<()> {
        for (name, value) in [
            ("endpoint", self.endpoint.as_str()),
            ("bucket", self.bucket.as_str()),
            ("access_key_id", self.access_key_id.as_str()),
            ("access_key_secret", self.access_key_secret.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(OssError::Config(format!("oss config {name} 为空")));
            }
        }
        let endpoint = Url::parse(&self.endpoint)
            .map_err(|error| OssError::Config(format!("oss endpoint URL 非法: {error}")))?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| OssError::Config("oss endpoint 缺少 host".into()))?;
        if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && host_is_loopback(host))
        {
            return Err(OssError::Config("远程 OSS endpoint 必须使用 HTTPS".into()));
        }
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(OssError::Config(
                "oss endpoint 禁止 userinfo、path、query 或 fragment".into(),
            ));
        }
        if !valid_bucket(&self.bucket) {
            return Err(OssError::Config(
                "oss bucket 只能包含小写字母、数字和连字符，且首尾为字母或数字".into(),
            ));
        }
        if self.request_timeout.is_zero()
            || self.operation_deadline.is_zero()
            || self.acquire_timeout.is_zero()
        {
            return Err(OssError::Config("oss timeout/deadline 必须大于零".into()));
        }
        if self.operation_deadline < self.request_timeout {
            return Err(OssError::Config(
                "operation_deadline 不得小于 request_timeout".into(),
            ));
        }
        validate_limit("max_in_flight", self.max_in_flight, HARD_MAX_IN_FLIGHT)?;
        validate_limit(
            "max_object_bytes",
            self.max_object_bytes,
            HARD_MAX_OBJECT_BYTES,
        )?;
        validate_limit(
            "max_buffer_bytes",
            self.max_buffer_bytes,
            HARD_MAX_BUFFER_BYTES,
        )?;
        validate_limit(
            "max_error_body_bytes",
            self.max_error_body_bytes,
            HARD_MAX_ERROR_BODY_BYTES,
        )?;
        if self.max_object_bytes > self.max_buffer_bytes {
            return Err(OssError::Config(
                "当前 Bytes API 要求 max_object_bytes 不得超过 max_buffer_bytes".into(),
            ));
        }
        Ok(())
    }
}

/// 拒绝 TOML 中出现凭据字段（根级与 `[oss]` 节均检查）。
fn reject_secret_keys_in_toml(text: &str) -> OssResult<()> {
    let value: toml::Value = toml::from_str(text)
        .map_err(|error| OssError::Serialization(format!("oss toml 解析失败: {error}")))?;
    let Some(table) = value.as_table() else {
        return Err(OssError::Config("oss toml 根必须为表".into()));
    };
    for key in ["access_key_id", "access_key_secret"] {
        if table.contains_key(key) {
            return Err(OssError::Config(format!("oss toml 禁止根级字段 {key}")));
        }
    }
    if let Some(oss) = table.get("oss").and_then(|value| value.as_table()) {
        for key in ["access_key_id", "access_key_secret"] {
            if oss.contains_key(key) {
                return Err(OssError::Config(format!("oss toml 禁止字段 {key}")));
            }
        }
    }
    Ok(())
}

/// 环境配置文件根结构（无凭据字段）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OssTomlFile {
    schema_version: u32,
    oss: OssTomlSection,
}

/// 环境配置文件 `[oss]` 节。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OssTomlSection {
    endpoint: String,
    bucket: String,
    #[serde(default = "default_region")]
    region: String,
    #[serde(default)]
    request_timeout_ms: Option<u64>,
    #[serde(default)]
    operation_deadline_ms: Option<u64>,
    #[serde(default)]
    acquire_timeout_ms: Option<u64>,
    #[serde(default)]
    max_in_flight: Option<usize>,
    #[serde(default)]
    max_object_bytes: Option<usize>,
    #[serde(default)]
    max_buffer_bytes: Option<usize>,
    #[serde(default)]
    max_error_body_bytes: Option<usize>,
    #[serde(default)]
    sse_enabled: Option<bool>,
}

fn default_region() -> String {
    DEFAULT_REGION.into()
}

impl OssTomlFile {
    fn into_config_with_env(self) -> OssResult<OssConfig> {
        let section = self.oss;
        let mut builder = OssConfig::builder()
            .endpoint(section.endpoint)
            .bucket(section.bucket)
            .region(section.region);
        if let Some(value) = section.request_timeout_ms {
            builder = builder.request_timeout(Duration::from_millis(value));
        }
        if let Some(value) = section.operation_deadline_ms {
            builder = builder.operation_deadline(Duration::from_millis(value));
        }
        if let Some(value) = section.acquire_timeout_ms {
            builder = builder.acquire_timeout(Duration::from_millis(value));
        }
        if let Some(value) = section.max_in_flight {
            builder = builder.max_in_flight(value);
        }
        if let Some(value) = section.max_object_bytes {
            builder = builder.max_object_bytes(value);
        }
        if let Some(value) = section.max_buffer_bytes {
            builder = builder.max_buffer_bytes(value);
        }
        if let Some(value) = section.max_error_body_bytes {
            builder = builder.max_error_body_bytes(value);
        }
        if let Some(value) = section.sse_enabled {
            builder = builder.sse_enabled(value);
        }
        let builder = builder
            .access_key_id(require_env(ENV_ACCESS_KEY_ID)?)
            .access_key_secret(require_env(ENV_ACCESS_KEY_SECRET)?);
        apply_optional_env_overrides(builder)?.build()
    }
}

/// TOML 基线之上合并环境变量：数值/超时 env 可覆盖 TOML 调参。
fn apply_optional_env_overrides(mut builder: OssConfigBuilder) -> OssResult<OssConfigBuilder> {
    if let Ok(value) = env::var(ENV_REGION) {
        builder = builder.region(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_IN_FLIGHT)? {
        builder = builder.max_in_flight(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_OBJECT_BYTES)? {
        builder = builder.max_object_bytes(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_BUFFER_BYTES)? {
        builder = builder.max_buffer_bytes(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_ERROR_BODY_BYTES)? {
        builder = builder.max_error_body_bytes(value);
    }
    if let Some(value) = optional_duration_env(ENV_REQUEST_TIMEOUT_MS)? {
        builder = builder.request_timeout(value);
    }
    if let Some(value) = optional_duration_env(ENV_OPERATION_DEADLINE_MS)? {
        builder = builder.operation_deadline(value);
    }
    if let Some(value) = optional_duration_env(ENV_ACQUIRE_TIMEOUT_MS)? {
        builder = builder.acquire_timeout(value);
    }
    Ok(builder)
}

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

fn require_env(key: &str) -> OssResult<String> {
    env::var(key).map_err(|_| OssError::Config(format!("环境变量 {key} 未设置")))
}

fn optional_usize_env(key: &str) -> OssResult<Option<usize>> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<usize>()
            .map(Some)
            .map_err(|error| OssError::Config(format!("环境变量 {key} 非法: {error}"))),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(OssError::Config(format!("环境变量 {key} 读取失败"))),
    }
}

fn optional_duration_env(key: &str) -> OssResult<Option<Duration>> {
    match optional_usize_env(key)? {
        Some(value) => {
            let millis = u64::try_from(value)
                .map_err(|error| OssError::Config(format!("环境变量 {key} 过大: {error}")))?;
            Ok(Some(Duration::from_millis(millis)))
        }
        None => Ok(None),
    }
}

fn validate_limit(name: &str, value: usize, hard_max: usize) -> OssResult<()> {
    if value == 0 || value > hard_max {
        return Err(OssError::Config(format!(
            "{name} 必须在 1..={hard_max} 范围内"
        )));
    }
    Ok(())
}

fn host_is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn valid_bucket(bucket: &str) -> bool {
    let bytes = bucket.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// 中间脱敏（保留首 3 与末 2 个字符）。
fn redact_mid(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 6 {
        return "***".into();
    }
    format!(
        "{}***{}",
        chars[..3].iter().collect::<String>(),
        chars[chars.len() - 2..].iter().collect::<String>()
    )
}

#[cfg(test)]
mod tests;
