//! [`OssPool`]：带并发许可、统计与**可刷新凭据**的 OSS 连接池。
//!
//! 与 [`crate::OssClient`] 的差别：
//! - 每次请求都向 [`CredentialProvider`] 取一次凭据，支持 STS/自建凭据服务轮换；
//! - 内置计数（成功/失败/超时/取消），可经 [`OssPool::stats`] 直接对接指标；
//! - 提供流式上传/下载（[`OssPool::put_stream`] / [`OssPool::get_stream`]）。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use reqwest::{Client, Method, StatusCode, Url};
use tokio::sync::Semaphore;
use tokio::time;

use crate::client::{
    build_complete_xml, map_network, normalize_key, object_meta_from_headers, object_url,
    parse_upload_id, read_limited_body, signed_headers, status_error, validate_upload_id,
    virtual_host_base, MAX_MULTIPART_PARTS, MAX_MULTIPART_PART_BYTES, MIN_MULTIPART_PART_BYTES,
};
use crate::config::OssConfig;
use crate::credential::{CredentialProvider, OssCredentials, StaticCredentialProvider};
use crate::error::{OssError, OssResult};
use crate::retry::{self, default_retry_config, RetryConfig};
use crate::sign;
use crate::types::{ByteStream, DownloadOptions, ObjectMeta, UploadOptions};

/// `put_stream` 未显式指定 `part_size` 时的默认分片大小（5 MiB）。
const DEFAULT_STREAM_PART_BYTES: usize = 5 * 1024 * 1024;

/// 连接池统计快照。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OssPoolStats {
    /// 池是否已关闭。
    pub closed: bool,
    /// 当前借出的并发许可数。
    pub in_flight: usize,
    /// 并发许可上限。
    pub max_in_flight: usize,
    /// 成功上传次数。
    pub puts_ok: u64,
    /// 失败上传次数。
    pub puts_err: u64,
    /// 成功下载次数。
    pub gets_ok: u64,
    /// 失败下载次数。
    pub gets_err: u64,
    /// 成功删除次数。
    pub deletes_ok: u64,
    /// 失败删除次数。
    pub deletes_err: u64,
    /// 获取并发许可超时次数。
    pub timeouts: u64,
    /// 因池关闭被拒绝的次数。
    pub cancelled: u64,
}

pub use crate::types::OssHealth;
struct PoolInner {
    http: Client,
    config: OssConfig,
    base: Url,
    closed: AtomicBool,
    permits: Arc<Semaphore>,
    retry: RetryConfig,
    credential_provider: Arc<dyn CredentialProvider>,
    puts_ok: AtomicU64,
    puts_err: AtomicU64,
    gets_ok: AtomicU64,
    gets_err: AtomicU64,
    deletes_ok: AtomicU64,
    deletes_err: AtomicU64,
    timeouts: AtomicU64,
    cancelled: AtomicU64,
}

/// 可克隆的 OSS 连接池。
///
/// ```
/// use ossx::{OssConfig, OssPool};
///
/// # async fn demo() -> Result<(), ossx::OssError> {
/// let config = OssConfig::builder()
///     .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
///     .bucket("demo-bucket")
///     .access_key_id("LTAI5tExample")
///     .access_key_secret("secret")
///     .build()?;
/// let pool = OssPool::connect(config).await?;
/// assert_eq!(pool.stats().max_in_flight, 64);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct OssPool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for OssPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OssPool")
            .field("config", &self.inner.config)
            .field(
                "credential_provider",
                &self.inner.credential_provider.provider_name(),
            )
            .field("stats", &self.stats())
            .finish()
    }
}

impl OssPool {
    /// 同步构造：只做配置校验与连接池预热，不发起网络请求。
    pub fn new(config: OssConfig) -> OssResult<Self> {
        Self::new_with_retry(config, default_retry_config(), None)
    }

    /// 按配置建立连接池（异步入口，语义同 [`OssPool::new`]）。
    pub async fn connect(config: OssConfig) -> OssResult<Self> {
        Self::new(config)
    }

    /// 同步构造并使用自定义重试配置。
    pub fn new_with_retry(
        config: OssConfig,
        retry: RetryConfig,
        credential_provider: Option<Arc<dyn CredentialProvider>>,
    ) -> OssResult<Self> {
        config.validate()?;
        retry.validate()?;
        let provider = match credential_provider {
            Some(provider) => provider,
            None => Arc::new(StaticCredentialProvider::new(
                config.access_key_id.clone(),
                config.access_key_secret(),
                config.security_token().map(str::to_owned),
            )),
        };
        let base = virtual_host_base(&config.endpoint, &config.bucket)?;
        let max_in_flight = config.max_in_flight;
        let http = Client::builder()
            .timeout(config.request_timeout)
            .pool_max_idle_per_host(max_in_flight)
            .user_agent(concat!("ossx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| OssError::Connection(format!("oss http client 构建失败: {error}")))?;
        Ok(Self {
            inner: Arc::new(PoolInner {
                http,
                config,
                base,
                closed: AtomicBool::new(false),
                permits: Arc::new(Semaphore::new(max_in_flight)),
                retry,
                credential_provider: provider,
                puts_ok: AtomicU64::new(0),
                puts_err: AtomicU64::new(0),
                gets_ok: AtomicU64::new(0),
                gets_err: AtomicU64::new(0),
                deletes_ok: AtomicU64::new(0),
                deletes_err: AtomicU64::new(0),
                timeouts: AtomicU64::new(0),
                cancelled: AtomicU64::new(0),
            }),
        })
    }

    /// 异步构造并使用自定义重试配置与凭据提供者。
    pub async fn connect_with_retry(config: OssConfig, retry: RetryConfig) -> OssResult<Self> {
        Self::new_with_retry(config, retry, None)
    }

    /// 异步构造并注入自定义凭据提供者（用于 STS / 自建凭据服务）。
    pub async fn connect_with_provider(
        config: OssConfig,
        retry: RetryConfig,
        credential_provider: Arc<dyn CredentialProvider>,
    ) -> OssResult<Self> {
        Self::new_with_retry(config, retry, Some(credential_provider))
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

    /// 凭据提供者名称（不含凭据）。
    #[must_use]
    pub fn provider_name(&self) -> &'static str {
        self.inner.credential_provider.provider_name()
    }

    /// 统计快照。
    #[must_use]
    pub fn stats(&self) -> OssPoolStats {
        let inner = &self.inner;
        OssPoolStats {
            closed: inner.closed.load(Ordering::SeqCst),
            in_flight: inner
                .config
                .max_in_flight
                .saturating_sub(inner.permits.available_permits()),
            max_in_flight: inner.config.max_in_flight,
            puts_ok: inner.puts_ok.load(Ordering::Relaxed),
            puts_err: inner.puts_err.load(Ordering::Relaxed),
            gets_ok: inner.gets_ok.load(Ordering::Relaxed),
            gets_err: inner.gets_err.load(Ordering::Relaxed),
            deletes_ok: inner.deletes_ok.load(Ordering::Relaxed),
            deletes_err: inner.deletes_err.load(Ordering::Relaxed),
            timeouts: inner.timeouts.load(Ordering::Relaxed),
            cancelled: inner.cancelled.load(Ordering::Relaxed),
        }
    }

    /// 关闭连接池（幂等）；关闭后所有数据面操作立即失败。
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.permits.close();
    }

    /// 健康检查：HEAD bucket 成功返回 `Ok(())`。
    pub async fn ping(&self) -> OssResult<()> {
        self.ensure_open()?;
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource(&self.inner.config.bucket, "");
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "HEAD",
            "",
            &resource,
            self.inner.config.sse_enabled,
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
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "HEAD bucket",
        )
        .await?;
        Err(status_error(
            "HEAD bucket",
            "/",
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    /// 健康检查（按 `operation_deadline` 限时）：返回结构化结果。
    pub async fn health_check(&self) -> OssResult<OssHealth> {
        self.health(self.inner.config.operation_deadline).await
    }

    /// 健康检查（显式 deadline）。
    ///
    /// 远端不可达/无权限返回 `ready = false` 的结构化结果；
    /// 只有本地生命周期拒绝（池已关闭）才返回 `Err`。
    pub async fn health(&self, deadline: Duration) -> OssResult<OssHealth> {
        let started = std::time::Instant::now();
        let outcome = time::timeout(deadline, self.ping()).await;
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match outcome {
            Ok(Ok(())) => Ok(OssHealth {
                ready: true,
                bucket_accessible: true,
                latency_ms,
                detail: format!(
                    "{} bucket={}",
                    self.inner.config.endpoint, self.inner.config.bucket
                ),
            }),
            Ok(Err(error)) if matches!(error, OssError::Unsupported(_)) => Err(error),
            Ok(Err(error)) => Ok(OssHealth::unreachable(latency_ms, error.to_string())),
            Err(_) => Ok(OssHealth::unreachable(
                latency_ms,
                format!("探活超过 deadline {}ms", deadline.as_millis()),
            )),
        }
    }

    /// 上传对象（整体驻留内存，含重试）。
    #[tracing::instrument(skip(self, key, data))]
    pub async fn put_object(&self, key: impl Into<String>, data: Bytes) -> OssResult<()> {
        let key = normalize_key(&key.into())?;
        self.validate_size(data.len())?;
        let result = retry::with_retry_deadline(
            &self.inner.retry,
            "put_object",
            self.inner.config.operation_deadline,
            || async {
                let _permit = self.acquire().await?;
                self.put_once(&key, &data, None, false).await
            },
        )
        .await;
        self.record(&self.inner.puts_ok, &self.inner.puts_err, result.is_ok());
        result
    }

    /// 下载对象（整体驻留内存，含重试）。
    #[tracing::instrument(skip(self, key))]
    pub async fn get_object(&self, key: impl Into<String>) -> OssResult<Bytes> {
        let key = normalize_key(&key.into())?;
        let result = retry::with_retry_deadline(
            &self.inner.retry,
            "get_object",
            self.inner.config.operation_deadline,
            || async {
                let _permit = self.acquire().await?;
                self.get_once(&key).await
            },
        )
        .await;
        self.record(&self.inner.gets_ok, &self.inner.gets_err, result.is_ok());
        result
    }

    /// 删除对象（幂等，含重试）。
    #[tracing::instrument(skip(self, key))]
    pub async fn delete_object(&self, key: impl Into<String>) -> OssResult<()> {
        let key = normalize_key(&key.into())?;
        let result = retry::with_retry_deadline(
            &self.inner.retry,
            "delete_object",
            self.inner.config.operation_deadline,
            || async {
                let _permit = self.acquire().await?;
                self.delete_once(&key).await
            },
        )
        .await;
        self.record(
            &self.inner.deletes_ok,
            &self.inner.deletes_err,
            result.is_ok(),
        );
        result
    }

    /// 取对象元数据（HEAD，含重试）。
    #[tracing::instrument(skip(self, key))]
    pub async fn head(&self, key: impl Into<String>) -> OssResult<ObjectMeta> {
        let key = normalize_key(&key.into())?;
        retry::with_retry_deadline(
            &self.inner.retry,
            "head",
            self.inner.config.operation_deadline,
            || async {
                let _permit = self.acquire().await?;
                self.head_once(&key).await
            },
        )
        .await
    }

    /// 流式上传：按 `opts.part_size` 切分，单片走单次 PUT，多片走 multipart。
    ///
    /// - `part_size == 0` 时使用 5 MiB 默认值；
    /// - `opts.metadata` 当前不支持（自定义 `x-oss-meta-*` 头需要参与 V1 签名），
    ///   传入非空值会返回 [`OssError::Unsupported`]，不会静默忽略；
    /// - 分片失败会尝试 `AbortMultipartUpload`。
    #[tracing::instrument(skip(self, key, stream))]
    pub async fn put_stream(
        &self,
        key: impl Into<String>,
        stream: ByteStream,
        opts: UploadOptions,
    ) -> OssResult<ObjectMeta> {
        let key = normalize_key(&key.into())?;
        if opts
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.is_empty())
        {
            return Err(OssError::Unsupported(
                "put_stream 暂不支持自定义 metadata（x-oss-meta-* 需参与 V1 签名）".into(),
            ));
        }
        let part_size = if opts.part_size > 0 {
            opts.part_size
        } else {
            DEFAULT_STREAM_PART_BYTES
        };
        if !(MIN_MULTIPART_PART_BYTES..=MAX_MULTIPART_PART_BYTES).contains(&part_size) {
            return Err(OssError::Config(format!(
                "put_stream part_size 必须在 {MIN_MULTIPART_PART_BYTES}..={MAX_MULTIPART_PART_BYTES} 范围内"
            )));
        }
        let parts = self.collect_parts(stream, part_size).await?;
        let total: usize = parts.iter().map(Bytes::len).sum();
        if total > self.inner.config.max_object_bytes {
            return Err(OssError::Config(format!(
                "stream 对象大小 {total} 超过上限 {}",
                self.inner.config.max_object_bytes
            )));
        }
        let content_type = opts
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");
        if parts.len() == 1 {
            let _permit = self.acquire().await?;
            self.put_once(&key, &parts[0], Some(content_type), opts.sse_enabled)
                .await?;
            return Ok(ObjectMeta::with_size(total as u64));
        }
        let upload_id = {
            let _permit = self.acquire().await?;
            self.init_mp_once(&key, opts.sse_enabled).await?
        };
        let mut uploaded: Vec<(u32, String)> = Vec::with_capacity(parts.len());
        for (index, part) in parts.into_iter().enumerate() {
            let part_number = u32::try_from(index + 1)
                .map_err(|_| OssError::Config("multipart part_number 溢出".into()))?;
            let this = self.clone();
            let part_key = key.clone();
            let part_upload_id = upload_id.clone();
            let sse = opts.sse_enabled;
            let retry = self.inner.retry;
            let deadline = self.inner.config.operation_deadline;
            let outcome = retry::with_retry_deadline(&retry, "upload_part", deadline, || {
                let this = this.clone();
                let part_key = part_key.clone();
                let part_upload_id = part_upload_id.clone();
                let data = part.clone();
                async move {
                    let _permit = this.acquire().await?;
                    this.upload_part_once(&part_key, &part_upload_id, part_number, &data, sse)
                        .await
                }
            })
            .await;
            match outcome {
                Ok(etag) => uploaded.push((part_number, etag)),
                Err(error) => {
                    // abort 是补偿动作：失败也不掩盖原始错误
                    let _permit = self.acquire().await.ok();
                    let _ = self.abort_mp_once(&key, &upload_id).await;
                    return Err(error);
                }
            }
        }
        let _permit = self.acquire().await?;
        self.complete_mp_once(&key, &upload_id, &uploaded).await?;
        Ok(ObjectMeta::with_size(total as u64))
    }

    /// 流式下载：返回元数据与惰性字节流。
    ///
    /// 流会在累计字节数超过 `max_object_bytes` 时以 [`OssError::Config`] 终止，
    /// 避免无界下游把内存吃满。
    #[tracing::instrument(skip(self, key))]
    pub async fn get_stream(
        &self,
        key: impl Into<String>,
        opts: DownloadOptions,
    ) -> OssResult<(ObjectMeta, ByteStream)> {
        let key = normalize_key(&key.into())?;
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource(&self.inner.config.bucket, &key);
        let mut headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "GET",
            "",
            &resource,
            self.inner.config.sse_enabled,
        )?;
        if let Some(range) = &opts.range {
            headers.insert("Range", crate::client::header_value(range)?);
        }
        if let Some(if_match) = &opts.if_match {
            headers.insert("If-Match", crate::client::header_value(if_match)?);
        }
        if let Some(if_none_match) = &opts.if_none_match {
            headers.insert("If-None-Match", crate::client::header_value(if_none_match)?);
        }
        let url = object_url(&self.inner.base, &key)?;
        let _permit = self.acquire().await?;
        let response = self
            .inner
            .http
            .request(Method::GET, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("GET stream", &error))?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok((ObjectMeta::with_size(0), empty_stream()));
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = read_limited_body(
                response,
                self.inner.config.max_error_body_bytes,
                "GET error body",
            )
            .await?;
            return Err(status_error(
                "GET stream",
                &key,
                status,
                &String::from_utf8_lossy(&body),
            ));
        }
        let meta = object_meta_from_headers(response.headers());
        let budget = Some(self.inner.config.max_object_bytes);
        let stream: ByteStream = Box::pin(futures_util::stream::unfold(
            (response, budget),
            |(mut response, budget)| async move {
                let remaining = budget?;
                match response.chunk().await {
                    Ok(Some(chunk)) => match remaining.checked_sub(chunk.len()) {
                        Some(left) => Some((Ok(chunk), (response, Some(left)))),
                        None => Some((
                            Err(OssError::Config(
                                "get_stream 累计字节数超过 max_object_bytes".into(),
                            )),
                            (response, None),
                        )),
                    },
                    Ok(None) => None,
                    Err(error) => Some((
                        Err(map_network("GET stream", &error)),
                        (response, Some(remaining)),
                    )),
                }
            },
        ));
        Ok((meta, stream))
    }

    // ── 内部 ─────────────────────────────────────────────────────────────

    fn ensure_open(&self) -> OssResult<()> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(OssError::Unsupported("oss pool 已关闭".into()));
        }
        Ok(())
    }

    async fn acquire(&self) -> OssResult<tokio::sync::OwnedSemaphorePermit> {
        if self.inner.closed.load(Ordering::SeqCst) {
            self.inner.cancelled.fetch_add(1, Ordering::Relaxed);
            return Err(OssError::Unsupported("oss pool 已关闭".into()));
        }
        match time::timeout(
            self.inner.config.acquire_timeout,
            self.inner.permits.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => {
                if self.inner.closed.load(Ordering::SeqCst) {
                    self.inner.cancelled.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return Err(OssError::Unsupported("oss pool 已关闭".into()));
                }
                Ok(permit)
            }
            Ok(Err(_)) => Err(OssError::Unsupported("oss pool 信号量已关闭".into())),
            Err(_) => {
                self.inner.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(OssError::Timeout(format!(
                    "oss 获取 in-flight 许可超时（max={}）",
                    self.inner.config.max_in_flight
                )))
            }
        }
    }

    async fn credentials(&self) -> OssResult<OssCredentials> {
        self.ensure_open()?;
        self.inner.credential_provider.get_credentials().await
    }

    fn validate_size(&self, size: usize) -> OssResult<()> {
        if size > self.inner.config.max_object_bytes {
            return Err(OssError::Config(format!(
                "oss 对象大小 {size} 超过上限 {}",
                self.inner.config.max_object_bytes
            )));
        }
        if size > self.inner.config.max_buffer_bytes {
            return Err(OssError::Config(format!(
                "oss 缓冲大小 {size} 超过上限 {}，请改用 put_stream",
                self.inner.config.max_buffer_bytes
            )));
        }
        Ok(())
    }

    fn record(&self, ok: &AtomicU64, err: &AtomicU64, succeeded: bool) {
        if succeeded {
            ok.fetch_add(1, Ordering::Relaxed);
        } else {
            err.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 空字节流（`304 Not Modified` 等无实体场景）。
fn empty_stream() -> ByteStream {
    Box::pin(futures_util::stream::empty::<OssResult<Bytes>>())
}

mod ops;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OssConfig {
        OssConfig::builder()
            .endpoint("https://oss.example.com")
            .bucket("test-bucket")
            .access_key_id("test-id")
            .access_key_secret("test-secret")
            .build()
            .expect("config")
    }

    fn test_pool() -> OssPool {
        OssPool::new(test_config()).expect("pool")
    }

    #[test]
    fn virtual_host_and_object_url_are_shared() {
        assert_eq!(
            virtual_host_base("https://oss.example.com", "b")
                .expect("base")
                .host_str(),
            Some("b.oss.example.com")
        );
        let base = virtual_host_base("https://oss.example.com", "b").expect("base");
        let url = object_url(&base, "path/to/object.txt").expect("object url");
        assert_eq!(url.path(), "/path/to/object.txt");
    }

    #[test]
    fn stats_defaults_and_provider_name() {
        let stats = test_pool().stats();
        assert!(!stats.closed);
        assert_eq!(stats.max_in_flight, 64);
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.puts_ok, 0);
        assert_eq!(stats.puts_ok, stats.puts_err);
        assert_eq!(test_pool().provider_name(), "static");
        assert!(format!("{:?}", test_pool()).contains("static"));
    }

    #[tokio::test]
    async fn close_rejects_and_is_idempotent() {
        let pool = test_pool();
        pool.close();
        pool.close();
        assert!(pool.stats().closed);
        let error = pool
            .put_object("k", Bytes::from_static(b"v"))
            .await
            .expect_err("closed pool");
        assert!(matches!(error, OssError::Unsupported(_)));
        assert!(pool.get_object("k").await.is_err());
        assert!(pool.delete_object("k").await.is_err());
        assert!(pool.head("k").await.is_err());
        assert_eq!(
            pool.stats().cancelled,
            4,
            "acquire 在池关闭时计入 cancelled"
        );
        assert_eq!(pool.stats().puts_err, 1);
    }

    #[test]
    fn invalid_keys_and_sizes_fail_closed() {
        let pool = test_pool();
        assert!(normalize_key("").is_err());
        assert!(normalize_key("../escape").is_err());
        assert!(pool
            .validate_size(pool.config().max_object_bytes + 1)
            .is_err());
        assert!(pool
            .validate_size(pool.config().max_buffer_bytes + 1)
            .is_err());
        assert!(pool.validate_size(1).is_ok());
    }

    #[tokio::test]
    async fn put_stream_rejects_unsupported_metadata_and_part_size() {
        let pool = test_pool();
        let options = UploadOptions {
            metadata: Some(vec![("k".into(), "v".into())]),
            ..UploadOptions::default()
        };
        let error = pool
            .put_stream(
                "k",
                crate::types::byte_stream_from_bytes(Bytes::from_static(b"x")),
                options,
            )
            .await
            .expect_err("metadata 必须 fail-closed");
        assert!(matches!(error, OssError::Unsupported(_)));

        let options = UploadOptions {
            part_size: 1,
            ..UploadOptions::default()
        };
        let error = pool
            .put_stream(
                "k",
                crate::types::byte_stream_from_bytes(Bytes::from_static(b"x")),
                options,
            )
            .await
            .expect_err("非法分片大小必须被拒绝");
        assert!(matches!(error, OssError::Config(_)));
    }

    #[tokio::test]
    async fn custom_credential_provider_is_used() {
        struct CountingProvider {
            calls: Arc<AtomicU64>,
        }

        impl CredentialProvider for CountingProvider {
            fn get_credentials(
                &self,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = OssResult<OssCredentials>> + Send + '_>,
            > {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(OssCredentials {
                        access_key_id: "custom-id".into(),
                        access_key_secret: "custom-secret".into(),
                        security_token: Some("sts".into()),
                    })
                })
            }

            fn provider_name(&self) -> &'static str {
                "counting"
            }
        }

        let calls = Arc::new(AtomicU64::new(0));
        let pool = OssPool::new_with_retry(
            test_config(),
            default_retry_config(),
            Some(Arc::new(CountingProvider {
                calls: Arc::clone(&calls),
            })),
        )
        .expect("pool");
        assert_eq!(pool.provider_name(), "counting");
        let credentials = pool.credentials().await.expect("credentials");
        assert_eq!(credentials.access_key_id, "custom-id");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn acquire_is_bounded_by_concurrency_and_timeout() {
        let config = OssConfig::builder()
            .endpoint("https://oss.example.com")
            .bucket("test-bucket")
            .access_key_id("id")
            .access_key_secret("secret")
            .max_in_flight(1)
            .acquire_timeout(Duration::from_millis(200))
            .build()
            .expect("config");
        let pool = OssPool::new(config).expect("pool");
        let permit = pool.acquire().await.expect("first permit");
        let error = pool
            .acquire()
            .await
            .expect_err("second permit must time out");
        assert!(matches!(error, OssError::Timeout(_)));
        assert_eq!(pool.stats().timeouts, 1);
        assert_eq!(pool.stats().in_flight, 1);
        drop(permit);
        let _permit = pool.acquire().await.expect("permit released");
        assert_eq!(pool.stats().in_flight, 1);
    }

    #[tokio::test]
    async fn collect_parts_splits_stream_by_part_size() {
        let pool = test_pool();
        let stream =
            crate::types::byte_stream_from_bytes(Bytes::from(vec![
                b'x';
                MIN_MULTIPART_PART_BYTES * 2 + 1
            ]));
        let parts = pool
            .collect_parts(stream, MIN_MULTIPART_PART_BYTES)
            .await
            .expect("parts");
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), MIN_MULTIPART_PART_BYTES);
        assert_eq!(parts[1].len(), MIN_MULTIPART_PART_BYTES);
        assert_eq!(parts[2].len(), 1);
    }

    #[tokio::test]
    async fn health_check_reports_unreachable_endpoint() {
        let config = OssConfig::builder()
            .endpoint("http://localhost:1")
            .bucket("test-bucket")
            .access_key_id("id")
            .access_key_secret("secret")
            .request_timeout(Duration::from_millis(300))
            .operation_deadline(Duration::from_millis(500))
            .build()
            .expect("config");
        let pool = OssPool::new(config).expect("pool");
        let health = pool
            .health(Duration::from_millis(500))
            .await
            .expect("结构化结果");
        assert!(!health.ready);
        assert!(!health.bucket_accessible);
        assert!(!health.detail.is_empty());
        assert!(pool.ping().await.is_err(), "不可达 endpoint 必须返回 Err");
    }
}
