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
use crate::pool::OssHealth;
use crate::presign::{self, PresignOptions};
use crate::retry::{default_retry_config, with_retry_deadline, RetryConfig};
use crate::sign::{
    authorization_header, canonicalized_resource, canonicalized_resource_with_subresources,
    sign_v1, split_parts,
};
use crate::types::ObjectMeta;

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

impl OssClient {
    /// 同步构造：只做配置校验与连接池预热，不发起网络请求。
    ///
    /// 使用默认重试配置（3 次尝试、指数退避、±25% 抖动）。
    pub fn new(config: OssConfig) -> OssResult<Self> {
        Self::new_with_retry(config, default_retry_config())
    }

    /// 按配置建立连接（异步入口，语义同 [`OssClient::new`]）。
    pub async fn connect(config: OssConfig) -> OssResult<Self> {
        Self::new(config)
    }

    /// 同步构造并使用自定义重试配置。
    pub fn new_with_retry(config: OssConfig, retry: RetryConfig) -> OssResult<Self> {
        config.validate()?;
        retry.validate()?;
        let http = Client::builder()
            .timeout(config.request_timeout)
            .pool_max_idle_per_host(config.max_in_flight)
            .user_agent(concat!("ossx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| OssError::Connection(format!("oss http client 构建失败: {error}")))?;
        let base = virtual_host_base(&config.endpoint, &config.bucket)?;
        let permits = Arc::new(Semaphore::new(config.max_in_flight));
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                config,
                base,
                closed: AtomicBool::new(false),
                retry,
                permits,
                orphan_audits: Mutex::new(VecDeque::new()),
                orphan_audit_overflow: AtomicU64::new(0),
            }),
        })
    }

    /// 异步构造并使用自定义重试配置。
    pub async fn connect_with_retry(config: OssConfig, retry: RetryConfig) -> OssResult<Self> {
        Self::new_with_retry(config, retry)
    }

    /// 从 `FOUNDATIONX_OSSX_*` 环境变量构造。
    pub fn from_env() -> OssResult<Self> {
        Self::new(OssConfig::from_env()?)
    }

    /// 配置只读视图。
    #[must_use]
    pub fn config(&self) -> &OssConfig {
        &self.inner.config
    }

    /// 当前重试配置。
    #[must_use]
    pub fn retry_config(&self) -> RetryConfig {
        self.inner.retry
    }

    /// 客户端是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// 返回当前进程已发现的 multipart orphan 候选快照。
    ///
    /// 记录在成功补偿前不会自动删除；调用方可据此执行受控
    /// [`OssClient::abort_multipart`]。
    #[must_use]
    pub fn multipart_orphan_audits(&self) -> Vec<MultipartOrphanAudit> {
        let audits = match self.inner.orphan_audits.lock() {
            Ok(audits) => audits,
            Err(poisoned) => poisoned.into_inner(),
        };
        audits.iter().cloned().collect()
    }

    /// 审计队列达到硬上界后未能保存详细记录的累计数。
    #[must_use]
    pub fn orphan_audit_overflow_count(&self) -> u64 {
        self.inner.orphan_audit_overflow.load(Ordering::Relaxed)
    }

    /// 标记关闭（HTTP 连接池随 drop 释放；幂等）。
    ///
    /// 关闭后所有数据面操作立即返回 [`OssError::Unsupported`]。
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.permits.close();
    }

    /// 健康检查：HEAD bucket 成功返回 `Ok(())`，否则返回映射后的错误。
    pub async fn ping(&self) -> OssResult<()> {
        self.ensure_open()?;
        let config = &self.inner.config;
        let resource = canonicalized_resource(&config.bucket, "");
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "HEAD",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let mut url = self.inner.base.clone();
        url.set_path("/");
        let response = self
            .inner
            .http
            .request(Method::HEAD, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("HEAD bucket", &error))?;
        map_status(
            "HEAD bucket",
            "/",
            response.status(),
            response,
            self.inner.config.max_error_body_bytes,
        )
        .await
    }

    /// 健康检查：返回结构化结果。
    ///
    /// 远端不可达/无权限会返回 `Ok(OssHealth { ready: false, .. })`
    /// （探活结论本身是“可报告结果”）；只有本地生命周期拒绝
    /// （如客户端已关闭）才返回 `Err`。
    pub async fn health_check(&self) -> OssResult<OssHealth> {
        let started = Instant::now();
        match self.ping().await {
            Ok(()) => Ok(OssHealth {
                ready: true,
                bucket_accessible: true,
                latency_ms: elapsed_millis(started),
                detail: format!(
                    "{} bucket={}",
                    self.inner.config.endpoint, self.inner.config.bucket
                ),
            }),
            Err(error) if matches!(error, OssError::Unsupported(_) | OssError::Config(_)) => {
                Err(error)
            }
            Err(error) => Ok(OssHealth {
                ready: false,
                bucket_accessible: false,
                latency_ms: elapsed_millis(started),
                detail: error.to_string(),
            }),
        }
    }

    /// 生成预签名 URL（复用客户端凭据，避免调用方另行保存 secret）。
    pub fn presign_url(&self, key: &str, options: &PresignOptions) -> OssResult<String> {
        presign::presign_url(
            &self.inner.config.endpoint,
            &self.inner.config.bucket,
            key,
            &self.inner.config.access_key_id,
            self.inner.config.access_key_secret(),
            options,
        )
    }

    fn ensure_open(&self) -> OssResult<()> {
        if self.is_closed() {
            return Err(OssError::Unsupported("oss client 已关闭".into()));
        }
        Ok(())
    }

    async fn acquire(&self) -> OssResult<OwnedSemaphorePermit> {
        self.ensure_open()?;
        match timeout(
            self.inner.config.acquire_timeout,
            self.inner.permits.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => {
                if self.is_closed() {
                    drop(permit);
                    return Err(OssError::Unsupported("oss client 已关闭".into()));
                }
                Ok(permit)
            }
            Ok(Err(_)) => Err(OssError::Unsupported("oss in-flight 信号量已关闭".into())),
            Err(_) => Err(OssError::Timeout(format!(
                "oss 获取 in-flight 许可超时（max={}）",
                self.inner.config.max_in_flight
            ))),
        }
    }

    fn validate_object_size(&self, size: usize) -> OssResult<()> {
        if size > self.inner.config.max_object_bytes {
            return Err(OssError::Config(format!(
                "oss 对象大小 {size} 超过上限 {}",
                self.inner.config.max_object_bytes
            )));
        }
        if size > self.inner.config.max_buffer_bytes {
            return Err(OssError::Config(format!(
                "oss 缓冲大小 {size} 超过上限 {}",
                self.inner.config.max_buffer_bytes
            )));
        }
        Ok(())
    }

    /// 上传对象（含重试）。
    ///
    /// `data` 必须整体驻留内存；大于 [`OssConfig::max_buffer_bytes`] 的对象
    /// 请改用 [`OssClient::put_object_multipart`]。
    pub async fn put_object(&self, key: &str, data: Bytes) -> OssResult<()> {
        self.validate_object_size(data.len())?;
        let key = key.to_string();
        let this = self.clone();
        let retry = self.inner.retry;
        with_retry_deadline(
            &retry,
            "put_object",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                let key = key.clone();
                let data = data.clone();
                async move { this.put_object_once(&key, data).await }
            },
        )
        .await
    }

    async fn put_object_once(&self, key: &str, data: Bytes) -> OssResult<()> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let content_type = "application/octet-stream";
        let resource = canonicalized_resource(&config.bucket, &key);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "PUT",
            content_type,
            &resource,
            config.sse_enabled,
        )?;

        let url = object_url(&self.inner.base, &key)?;
        let response = self
            .inner
            .http
            .request(Method::PUT, url)
            .headers(headers)
            .body(data)
            .send()
            .await
            .map_err(|error| map_network("PUT", &error))?;

        map_status(
            "PUT",
            key.as_str(),
            response.status(),
            response,
            self.inner.config.max_error_body_bytes,
        )
        .await
    }

    /// 下载对象（含重试）。
    pub async fn get_object(&self, key: &str) -> OssResult<Bytes> {
        let key = key.to_string();
        let this = self.clone();
        let retry = self.inner.retry;
        with_retry_deadline(
            &retry,
            "get_object",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                let key = key.clone();
                async move { this.get_object_once(&key).await }
            },
        )
        .await
    }

    async fn get_object_once(&self, key: &str) -> OssResult<Bytes> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let resource = canonicalized_resource(&config.bucket, &key);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "GET",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let url = object_url(&self.inner.base, &key)?;
        let response = self
            .inner
            .http
            .request(Method::GET, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("GET", &error))?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(OssError::Backend(format!("oss GET not found key={key}")));
        }
        if !status.is_success() {
            let body = read_limited_body(
                response,
                self.inner.config.max_error_body_bytes,
                "GET error body",
            )
            .await?;
            return Err(status_error(
                "GET",
                &key,
                status,
                &String::from_utf8_lossy(&body),
            ));
        }
        let limit = self.read_limit();
        read_limited_body(response, limit, "GET object body").await
    }

    /// 取对象元数据（HEAD，含重试）。
    pub async fn head_object(&self, key: &str) -> OssResult<ObjectMeta> {
        let key = key.to_string();
        let this = self.clone();
        let retry = self.inner.retry;
        with_retry_deadline(
            &retry,
            "head_object",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                let key = key.clone();
                async move { this.head_object_once(&key).await }
            },
        )
        .await
    }

    async fn head_object_once(&self, key: &str) -> OssResult<ObjectMeta> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let resource = canonicalized_resource(&config.bucket, &key);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "HEAD",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let url = object_url(&self.inner.base, &key)?;
        let response = self
            .inner
            .http
            .request(Method::HEAD, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("HEAD", &error))?;

        let status = response.status();
        if status.is_success() {
            return Ok(object_meta_from_headers(response.headers()));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(OssError::Backend(format!("oss HEAD not found key={key}")));
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "HEAD error body",
        )
        .await?;
        Err(status_error(
            "HEAD",
            &key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    /// 删除对象（幂等：不存在亦视为成功；含重试）。
    pub async fn delete_object(&self, key: &str) -> OssResult<()> {
        let key = key.to_string();
        let this = self.clone();
        let retry = self.inner.retry;
        with_retry_deadline(
            &retry,
            "delete_object",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                let key = key.clone();
                async move { this.delete_object_once(&key).await }
            },
        )
        .await
    }

    async fn delete_object_once(&self, key: &str) -> OssResult<()> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let resource = canonicalized_resource(&config.bucket, &key);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "DELETE",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let url = object_url(&self.inner.base, &key)?;
        let response = self
            .inner
            .http
            .request(Method::DELETE, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("DELETE", &error))?;

        let status = response.status();
        // OSS：204 No Content / 200 / 404 均视为删除成功（幂等）
        if status == StatusCode::NOT_FOUND
            || status == StatusCode::NO_CONTENT
            || status.is_success()
        {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "DELETE error body",
        )
        .await?;
        Err(status_error(
            "DELETE",
            &key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    /// 列出对象（ListObjects V2，含 continuation-token 翻页；含重试）。
    ///
    /// 返回对象 key 列表；`prefix` 为空时列 bucket 全部对象。
    pub async fn list_objects(&self, prefix: &str) -> OssResult<Vec<String>> {
        let this = self.clone();
        let prefix = prefix.to_string();
        with_retry_deadline(
            &self.inner.retry,
            "list_objects",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                let prefix = prefix.clone();
                async move { this.list_objects_paged(&prefix, None).await }
            },
        )
        .await
    }

    async fn list_objects_paged(
        &self,
        prefix: &str,
        token: Option<&str>,
    ) -> OssResult<Vec<String>> {
        let mut keys = Vec::new();
        let mut current = token.map(str::to_string);
        loop {
            let page = self.list_objects_once(prefix, current.as_deref()).await?;
            keys.extend(page.keys);
            match page.next_token {
                Some(next) if !next.is_empty() && page.truncated => current = Some(next),
                _ => break,
            }
        }
        Ok(keys)
    }

    async fn list_objects_once(
        &self,
        prefix: &str,
        continuation_token: Option<&str>,
    ) -> OssResult<ListPage> {
        let _permit = self.acquire().await?;
        let config = &self.inner.config;
        // OSS bucket 根 GET 签名：canonicalized resource 为 /{bucket}/（尾斜杠）。
        // query 参数（list-type/prefix/max-keys）只进 URL、不参与签名；但
        // continuation-token 是参与签名的子资源（经真实 OSS 实测：翻页请求漏签
        // token → 403 SignatureDoesNotMatch；签 /{bucket}/?continuation-token=<token> → 200）。
        let resource = match continuation_token {
            Some(token) if !token.is_empty() => canonicalized_resource_with_subresources(
                &config.bucket,
                "",
                &[("continuation-token", Some(token))],
            ),
            _ => canonicalized_resource(&config.bucket, ""),
        };
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "GET",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let mut url = self.inner.base.clone();
        url.set_path("/");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("list-type", "2");
            query.append_pair("max-keys", "1000");
            query.append_pair("prefix", prefix);
            if let Some(token) = continuation_token {
                query.append_pair("continuation-token", token);
            }
        }
        let response = self
            .inner
            .http
            .request(Method::GET, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("GET", &error))?;
        let status = response.status();
        if !status.is_success() {
            let body = read_limited_body(
                response,
                self.inner.config.max_error_body_bytes,
                "LIST error body",
            )
            .await?;
            return Err(status_error(
                "LIST",
                "/",
                status,
                &String::from_utf8_lossy(&body),
            ));
        }
        let bytes = read_limited_body(response, self.read_limit(), "LIST body").await?;
        parse_list_result(&bytes)
    }

    /// 内存读取上限：对象上限与缓冲上限的较小值。
    fn read_limit(&self) -> usize {
        self.inner
            .config
            .max_object_bytes
            .min(self.inner.config.max_buffer_bytes)
    }

    // ── Multipart ──────────────────────────────────────────────────────────

    /// 初始化分片上传，返回 `upload_id`（含重试）。
    pub async fn initiate_multipart(&self, key: &str) -> OssResult<String> {
        self.initiate_multipart_with_deadline(key, self.inner.config.operation_deadline)
            .await
    }

    async fn initiate_multipart_with_deadline(
        &self,
        key: &str,
        deadline: Duration,
    ) -> OssResult<String> {
        let key = key.to_string();
        let this = self.clone();
        // 响应若在服务端成功后丢失，重试会制造不可关联的 orphan。
        let retry = RetryConfig::fixed(1, 0);
        with_retry_deadline(&retry, "initiate_multipart", deadline, move || {
            let this = this.clone();
            let key = key.clone();
            async move { this.initiate_multipart_once(&key).await }
        })
        .await
    }

    async fn initiate_multipart_once(&self, key: &str) -> OssResult<String> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let resource =
            canonicalized_resource_with_subresources(&config.bucket, &key, &[("uploads", None)]);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "POST",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let mut url = object_url(&self.inner.base, &key)?;
        url.set_query(Some("uploads"));

        let response = self
            .inner
            .http
            .request(Method::POST, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("InitiateMultipart", &error))?;

        let status = response.status();
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "InitiateMultipart XML",
        )
        .await?;
        let body = String::from_utf8(body.to_vec()).map_err(|error| {
            OssError::Serialization(format!("InitiateMultipart XML 非 UTF-8: {error}"))
        })?;
        if !status.is_success() {
            return Err(status_error("InitiateMultipart", &key, status, &body));
        }
        parse_upload_id(&body)
    }

    /// 上传单个分片，返回 ETag（含重试）。
    pub async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        data: Bytes,
    ) -> OssResult<String> {
        self.upload_part_with_deadline(
            key,
            upload_id,
            part_number,
            data,
            self.inner.config.operation_deadline,
        )
        .await
    }

    async fn upload_part_with_deadline(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        data: Bytes,
        deadline: Duration,
    ) -> OssResult<String> {
        validate_part_number(part_number)?;
        validate_upload_id(upload_id)?;
        self.validate_object_size(data.len())?;
        if data.is_empty() || data.len() > MAX_MULTIPART_PART_BYTES {
            return Err(OssError::Config(format!(
                "multipart 分片大小必须在 1..={MAX_MULTIPART_PART_BYTES} 范围内"
            )));
        }
        let key = key.to_string();
        let upload_id = upload_id.to_string();
        let this = self.clone();
        let retry = self.inner.retry;
        with_retry_deadline(&retry, "upload_part", deadline, move || {
            let this = this.clone();
            let key = key.clone();
            let upload_id = upload_id.clone();
            let data = data.clone();
            async move {
                this.upload_part_once(&key, &upload_id, part_number, data)
                    .await
            }
        })
        .await
    }

    async fn upload_part_once(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        data: Bytes,
    ) -> OssResult<String> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let part_number_text = part_number.to_string();
        let content_type = "application/octet-stream";
        let resource = canonicalized_resource_with_subresources(
            &config.bucket,
            &key,
            &[
                ("partNumber", Some(part_number_text.as_str())),
                ("uploadId", Some(upload_id)),
            ],
        );
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "PUT",
            content_type,
            &resource,
            config.sse_enabled,
        )?;

        let mut url = object_url(&self.inner.base, &key)?;
        url.query_pairs_mut()
            .append_pair("partNumber", &part_number_text)
            .append_pair("uploadId", upload_id);

        let response = self
            .inner
            .http
            .request(Method::PUT, url)
            .headers(headers)
            .body(data)
            .send()
            .await
            .map_err(|error| map_network("UploadPart", &error))?;

        let status = response.status();
        if !status.is_success() {
            let body = read_limited_body(
                response,
                self.inner.config.max_error_body_bytes,
                "UploadPart",
            )
            .await?;
            return Err(status_error(
                "UploadPart",
                &key,
                status,
                &String::from_utf8_lossy(&body),
            ));
        }
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| OssError::Backend("UploadPart 响应缺 ETag".into()))?;
        validate_etag(&etag)?;
        Ok(etag)
    }

    /// 完成分片上传（含重试）。
    ///
    /// `parts`：`(part_number, etag)`，将按 `part_number` 排序写入 Complete XML。
    pub async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(u32, String)>,
    ) -> OssResult<()> {
        self.complete_multipart_with_deadline(
            key,
            upload_id,
            parts,
            self.inner.config.operation_deadline,
        )
        .await
    }

    async fn complete_multipart_with_deadline(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(u32, String)>,
        deadline: Duration,
    ) -> OssResult<()> {
        validate_upload_id(upload_id)?;
        validate_complete_parts(&parts)?;
        let key = key.to_string();
        let upload_id = upload_id.to_string();
        let this = self.clone();
        // 响应不确定时自动重放会掩盖“对象已完成但响应丢失”的状态。
        let retry = RetryConfig::fixed(1, 0);
        with_retry_deadline(&retry, "complete_multipart", deadline, move || {
            let this = this.clone();
            let key = key.clone();
            let upload_id = upload_id.clone();
            let parts = parts.clone();
            async move { this.complete_multipart_once(&key, &upload_id, parts).await }
        })
        .await
    }

    async fn complete_multipart_once(
        &self,
        key: &str,
        upload_id: &str,
        mut parts: Vec<(u32, String)>,
    ) -> OssResult<()> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        parts.sort_by_key(|(number, _)| *number);
        let body = build_complete_xml(&parts)?;
        let config = &self.inner.config;
        let content_type = "application/xml";
        let resource = canonicalized_resource_with_subresources(
            &config.bucket,
            &key,
            &[("uploadId", Some(upload_id))],
        );
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "POST",
            content_type,
            &resource,
            config.sse_enabled,
        )?;

        let mut url = object_url(&self.inner.base, &key)?;
        url.query_pairs_mut().append_pair("uploadId", upload_id);

        let response = self
            .inner
            .http
            .request(Method::POST, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|error| map_network("CompleteMultipart", &error))?;

        map_status(
            "CompleteMultipart",
            key.as_str(),
            response.status(),
            response,
            self.inner.config.max_error_body_bytes,
        )
        .await
    }

    /// 中止分片上传（含重试；幂等）。
    ///
    /// 成功后会从 orphan 审计队列移除对应记录。
    pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> OssResult<()> {
        let result = self
            .abort_multipart_with_deadline(key, upload_id, self.inner.config.operation_deadline)
            .await;
        if result.is_ok() {
            self.remove_orphan_audit(key, upload_id);
        }
        result
    }

    async fn abort_multipart_with_deadline(
        &self,
        key: &str,
        upload_id: &str,
        deadline: Duration,
    ) -> OssResult<()> {
        validate_upload_id(upload_id)?;
        let key = key.to_string();
        let upload_id = upload_id.to_string();
        let this = self.clone();
        let retry = self.inner.retry;
        with_retry_deadline(&retry, "abort_multipart", deadline, move || {
            let this = this.clone();
            let key = key.clone();
            let upload_id = upload_id.clone();
            async move { this.abort_multipart_once(&key, &upload_id).await }
        })
        .await
    }

    async fn abort_multipart_once(&self, key: &str, upload_id: &str) -> OssResult<()> {
        let _permit = self.acquire().await?;
        let key = normalize_key(key)?;
        let config = &self.inner.config;
        let resource = canonicalized_resource_with_subresources(
            &config.bucket,
            &key,
            &[("uploadId", Some(upload_id))],
        );
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "DELETE",
            "",
            &resource,
            config.sse_enabled,
        )?;

        let mut url = object_url(&self.inner.base, &key)?;
        url.query_pairs_mut().append_pair("uploadId", upload_id);

        let response = self
            .inner
            .http
            .request(Method::DELETE, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("AbortMultipart", &error))?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND
            || status == StatusCode::NO_CONTENT
            || status.is_success()
        {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "AbortMultipart",
        )
        .await?;
        Err(status_error(
            "AbortMultipart",
            &key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    /// 高层：按 `part_size` 切分并完成 multipart 上传。
    ///
    /// - 数据为空 → [`OssError::Config`]
    /// - 单片（`data.len() <= part_size`）仍走 multipart 路径
    /// - 任一分片失败时尝试 `abort_multipart`
    /// - abort 失败会返回带 `orphan_risk=true` 的 [`OssError::Backend`]，
    ///   禁止静默丢失孤儿风险
    ///
    /// 整个状态机共享一个 operation deadline。调用方 drop future 时同步写入有界
    /// orphan 审计注册表，可通过 [`Self::multipart_orphan_audits`] 取得 key/UploadId
    /// 后显式补偿。注册表不替代服务端 lifecycle。
    pub async fn put_object_multipart(
        &self,
        key: &str,
        data: Bytes,
        part_size: usize,
    ) -> OssResult<()> {
        let started = Instant::now();
        let total_deadline = self.inner.config.operation_deadline;
        self.validate_object_size(data.len())?;
        validate_multipart_plan(data.len(), part_size)?;
        if part_size > self.inner.config.max_buffer_bytes {
            return Err(OssError::Config(format!(
                "multipart part_size {part_size} 超过缓冲上限 {}",
                self.inner.config.max_buffer_bytes
            )));
        }
        let chunks = split_parts(&data, part_size);

        let initiate_deadline = remaining_deadline(started, total_deadline, "multipart initiate")?;
        let upload_id = match self
            .initiate_multipart_with_deadline(key, initiate_deadline)
            .await
        {
            Ok(id) => id,
            Err(error) => {
                // initiate 失败时 upload_id 未知，仍登记 key 侧审计供人工排查
                if matches!(error, OssError::Connection(_) | OssError::Timeout(_)) {
                    push_orphan_audit_inner(
                        &self.inner,
                        MultipartOrphanAudit {
                            key: key.to_owned(),
                            upload_id: "unknown".to_owned(),
                        },
                    );
                }
                return Err(mark_unknown_initiate_orphan_risk(error));
            }
        };
        let mut audit_guard = MultipartAuditGuard::new(self, key, &upload_id);
        let mut completed: Vec<(u32, String)> = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let part_number = u32::try_from(index + 1)
                .map_err(|_| OssError::Config("multipart part_number 溢出".into()))?;
            // 拷贝 chunk 为 Bytes（分片重试需要所有权）
            let part_data = Bytes::copy_from_slice(chunk);
            let remaining = match remaining_deadline(started, total_deadline, "multipart upload") {
                Ok(value) => value,
                Err(error) => {
                    return Err(self
                        .cleanup_multipart_failure(
                            key,
                            &upload_id,
                            error,
                            started,
                            total_deadline,
                            &mut audit_guard,
                        )
                        .await);
                }
            };
            match self
                .upload_part_with_deadline(key, &upload_id, part_number, part_data, remaining)
                .await
            {
                Ok(etag) => completed.push((part_number, etag)),
                Err(error) => {
                    return Err(self
                        .cleanup_multipart_failure(
                            key,
                            &upload_id,
                            error,
                            started,
                            total_deadline,
                            &mut audit_guard,
                        )
                        .await);
                }
            }
        }
        let remaining = match remaining_deadline(started, total_deadline, "multipart complete") {
            Ok(value) => value,
            Err(error) => {
                return Err(self
                    .cleanup_multipart_failure(
                        key,
                        &upload_id,
                        error,
                        started,
                        total_deadline,
                        &mut audit_guard,
                    )
                    .await);
            }
        };
        if let Err(error) = self
            .complete_multipart_with_deadline(key, &upload_id, completed, remaining)
            .await
        {
            return Err(self
                .cleanup_multipart_failure(
                    key,
                    &upload_id,
                    error,
                    started,
                    total_deadline,
                    &mut audit_guard,
                )
                .await);
        }
        audit_guard.disarm();
        Ok(())
    }

    async fn cleanup_multipart_failure(
        &self,
        key: &str,
        upload_id: &str,
        primary: OssError,
        started: Instant,
        total_deadline: Duration,
        audit_guard: &mut MultipartAuditGuard,
    ) -> OssError {
        let Ok(remaining) = remaining_deadline(started, total_deadline, "multipart abort") else {
            // 总 deadline 已耗尽：无法再 abort → 显式登记孤儿审计（不单靠 Drop，
            // 避免 await 边界抖动）
            self.register_orphan_audit(key, upload_id, audit_guard);
            return mark_known_orphan_risk(primary, upload_id);
        };
        let abort = self
            .abort_multipart_with_deadline(key, upload_id, remaining)
            .await;
        if abort.is_ok() {
            audit_guard.disarm();
            return primary;
        }
        // abort 失败：会话仍可能残留在服务端
        self.register_orphan_audit(key, upload_id, audit_guard);
        merge_abort_result(primary, abort, upload_id)
    }

    /// 显式写入 orphan 审计并 `disarm` guard，避免 Drop 重复登记。
    fn register_orphan_audit(
        &self,
        key: &str,
        upload_id: &str,
        audit_guard: &mut MultipartAuditGuard,
    ) {
        audit_guard.disarm();
        push_orphan_audit_inner(
            &self.inner,
            MultipartOrphanAudit {
                key: key.to_owned(),
                upload_id: upload_id.to_owned(),
            },
        );
    }

    fn remove_orphan_audit(&self, key: &str, upload_id: &str) {
        let mut audits = match self.inner.orphan_audits.lock() {
            Ok(audits) => audits,
            Err(poisoned) => poisoned.into_inner(),
        };
        audits.retain(|audit| audit.key != key || audit.upload_id != upload_id);
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

#[cfg(test)]
mod tests {
    use super::*;

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
