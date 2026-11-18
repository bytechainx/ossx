//! [`OssPool`]：带并发许可、统计与**可刷新凭据**的 OSS 连接池。
//!
//! 与 [`crate::OssClient`] 的差别：
//! - 每次请求都向 [`CredentialProvider`] 取一次凭据，支持 STS/自建凭据服务轮换；
//! - 内置计数（成功/失败/超时/取消），可经 [`OssPool::stats`] 直接对接指标；
//! - 提供流式上传/下载（[`OssPool::put_stream`] / [`OssPool::get_stream`]）。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use reqwest::{Client, Method, StatusCode, Url};
use tokio::sync::Semaphore;
use tokio::time;

use crate::client::{
    build_complete_xml, map_network, normalize_key, object_meta_from_headers, object_url,
    parse_upload_id, put_output_from_headers, read_limited_body, signed_headers,
    signed_headers_with, status_error, validate_upload_id, MultipartOrphanAudit,
    MAX_MULTIPART_PARTS, MAX_MULTIPART_PART_BYTES, MIN_MULTIPART_PART_BYTES, ORPHAN_AUDIT_CAPACITY,
};
use crate::config::OssConfig;
use crate::credential::{CredentialProvider, OssCredentials};
use crate::error::{OssError, OssResult};
use crate::retry::{self, RetryConfig};
use crate::sign;
use crate::types::{ByteStream, DownloadOptions, ObjectMeta, PutObjectOutput, UploadOptions};

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
    /// 流式 multipart 补偿失败后登记的孤儿分片审计（有界，超限计 overflow）。
    orphan_audits: Mutex<VecDeque<MultipartOrphanAudit>>,
    orphan_audit_overflow: AtomicU64,
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
    /// 上传对象（整体驻留内存，含重试）。丢弃 `ETag` 与版本回执，
    /// 需要回执时用 [`OssPool::put_object_with`]。
    #[tracing::instrument(skip(self, key, data))]
    pub async fn put_object(&self, key: impl Into<String>, data: Bytes) -> OssResult<()> {
        self.put_object_with(key, data, &UploadOptions::default())
            .await
            .map(|_| ())
    }

    /// 上传对象（整体驻留内存，含重试），应用 [`UploadOptions`] 并返回回执。
    ///
    /// `options.metadata` 与 `options.part_size` 在单次 `PUT` 路径上不生效；
    /// `forbid_overwrite` 同名存在时映射为后端错误（HTTP 409）。
    #[tracing::instrument(skip(self, key, data, options))]
    pub async fn put_object_with(
        &self,
        key: impl Into<String>,
        data: Bytes,
        options: &UploadOptions,
    ) -> OssResult<PutObjectOutput> {
        let key = normalize_key(&key.into())?;
        self.validate_size(data.len())?;
        let sse = self.inner.config.sse_enabled || options.sse_enabled;
        let content_type = options.content_type.as_deref();
        let forbid_overwrite = options.forbid_overwrite;
        let result = retry::with_retry_deadline(
            &self.inner.retry,
            "put_object",
            self.inner.config.operation_deadline,
            || async {
                let _permit = self.acquire().await?;
                self.put_once(&key, &data, content_type, sse, forbid_overwrite)
                    .await
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

    /// 流式上传：分片填满即传，内存中不聚合全量分片。
    ///
    /// - `part_size == 0` 时使用 5 MiB 默认值；单片走单次 PUT，多片走 multipart；
    /// - 内存占用上界为一个 `part_size` 缓冲加单个 stream chunk，与对象总大小无关，
    ///   因此 TB 级对象不依赖 `max_buffer_bytes`；对象总大小仍受 `max_object_bytes` 约束，
    ///   超限时若已发起 multipart 会先 `AbortMultipartUpload` 补偿再返回错误；
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
        let content_type = opts
            .content_type
            .as_deref()
            .unwrap_or("application/octet-stream");
        let max_object_bytes = self.inner.config.max_object_bytes as u64;
        let request_timeout = self.inner.config.request_timeout;

        let mut stream = stream;
        let mut pending = BytesMut::with_capacity(part_size);
        let mut upload_id: Option<String> = None;
        let mut guard: Option<StreamAbortGuard> = None;
        let mut uploaded: Vec<(u32, String)> = Vec::new();
        let mut total: u64 = 0;

        // 任一失败路径直接返回错误；已发起的 multipart 由 `StreamAbortGuard`
        // 在 Drop 时统一补偿（spawn 异步 abort，失败写 orphan 审计）。
        macro_rules! fail {
            ($error:expr) => {
                return Err($error)
            };
        }

        loop {
            // 先把 pending 填到 part_size，或读到流结束。
            let eof = loop {
                if pending.len() >= part_size {
                    break false;
                }
                match time::timeout(request_timeout, stream.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        total = total.saturating_add(chunk.len() as u64);
                        if total > max_object_bytes {
                            fail!(OssError::Config(format!(
                                "stream 对象大小超过上限 {max_object_bytes}"
                            )));
                        }
                        pending.extend_from_slice(&chunk);
                    }
                    Ok(Some(Err(error))) => fail!(error),
                    Ok(None) => break true,
                    Err(_) => {
                        fail!(OssError::Timeout(format!(
                            "oss put_stream 读取分片超过 request_timeout {}ms",
                            request_timeout.as_millis()
                        )));
                    }
                }
            };
            if pending.is_empty() {
                debug_assert!(eof, "pending 为空时只能来自流结束");
                break;
            }
            let part = if eof {
                pending.split_to(pending.len()).freeze()
            } else {
                pending.split_to(part_size).freeze()
            };
            let part_number = match u32::try_from(uploaded.len() + 1) {
                Ok(number) if number <= MAX_MULTIPART_PARTS as u32 => number,
                _ => fail!(OssError::Config(format!(
                    "multipart 分片数超过上限 {MAX_MULTIPART_PARTS}"
                ))),
            };

            // 只有「首个分片即最后一个分片」时走单次 PUT，避免无谓的 multipart 往返。
            if upload_id.is_none() && eof {
                let _permit = self.acquire().await?;
                self.put_once(&key, &part, Some(content_type), opts.sse_enabled, false)
                    .await?;
                return Ok(ObjectMeta::with_size(total));
            }
            if upload_id.is_none() {
                let _permit = self.acquire().await?;
                let id = self.init_mp_once(&key, opts.sse_enabled).await?;
                guard = Some(StreamAbortGuard::new(self, &key, &id));
                upload_id = Some(id);
            }
            let mp_id = upload_id
                .clone()
                .ok_or_else(|| OssError::Backend("multipart upload_id 缺失".into()))?;

            let this = self.clone();
            let part_key = key.clone();
            let sse = opts.sse_enabled;
            let retry = self.inner.retry;
            let deadline = self.inner.config.operation_deadline;
            let outcome = retry::with_retry_deadline(&retry, "upload_part", deadline, || {
                let this = this.clone();
                let part_key = part_key.clone();
                let part_upload_id = mp_id.clone();
                let data = part.clone();
                async move {
                    let _permit = this.acquire().await?;
                    this.upload_part_once(&part_key, &part_upload_id, part_number, data, sse)
                        .await
                }
            })
            .await;
            match outcome {
                Ok(etag) => uploaded.push((part_number, etag)),
                Err(error) => fail!(error),
            }
            if eof {
                break;
            }
        }

        // 走到这里仍无 upload_id ⟺ 流为空：按空对象单次 PUT 处理。
        let Some(mp_id) = upload_id else {
            let _permit = self.acquire().await?;
            self.put_once(&key, &[], Some(content_type), opts.sse_enabled, false)
                .await?;
            return Ok(ObjectMeta::with_size(0));
        };
        let _permit = self.acquire().await?;
        // complete 失败时 `?` 直接返回，guard Drop 负责 abort 补偿。
        self.complete_mp_once(&key, &mp_id, &uploaded).await?;
        if let Some(g) = guard.as_mut() {
            g.disarm();
        }
        Ok(ObjectMeta::with_size(total))
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

/// `put_stream` 的 multipart 补偿守卫。
///
/// multipart 已发起但尚未 complete 时，任何退出路径——错误返回、future 取消、
/// panic 展开——都会在 `Drop` 中 spawn 异步 abort；abort 失败（或当前无线程
/// runtime 可用）时把 `(key, upload_id)` 写入有界 orphan 审计，进程退出窗口
/// 由 bucket lifecycle `AbortIncompleteMultipartUpload` 兜底。
struct StreamAbortGuard {
    pool: OssPool,
    key: String,
    upload_id: String,
    armed: bool,
}

impl StreamAbortGuard {
    fn new(pool: &OssPool, key: &str, upload_id: &str) -> Self {
        Self {
            pool: pool.clone(),
            key: key.to_owned(),
            upload_id: upload_id.to_owned(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StreamAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let pool = self.pool.clone();
        let key = self.key.clone();
        let upload_id = self.upload_id.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(abort_err) = pool.abort_stream_upload(&key, &upload_id).await {
                        pool.push_orphan_audit(&key, &upload_id);
                        tracing::error!(
                            key = %key,
                            upload_id = %upload_id,
                            error = %abort_err,
                            "put_stream abort 失败，OSS 可能残留未完成的分片上传（会产生存储费用）"
                        );
                    }
                });
            }
            Err(_) => {
                pool.push_orphan_audit(&key, &upload_id);
                tracing::error!(
                    key = %key,
                    upload_id = %upload_id,
                    "put_stream 补偿时无 runtime 可用，已登记 orphan 审计"
                );
            }
        }
    }
}

impl OssPool {
    /// 流式路径的 abort 补偿：取并发许可后执行 DELETE ?uploadId。
    async fn abort_stream_upload(&self, key: &str, upload_id: &str) -> OssResult<()> {
        let _permit = self.acquire().await?;
        self.abort_mp_once(key, upload_id).await
    }

    /// 写入有界 orphan 审计；容量满时丢弃并累计 overflow。
    fn push_orphan_audit(&self, key: &str, upload_id: &str) {
        let audit = MultipartOrphanAudit::new(key.to_owned(), upload_id.to_owned());
        let mut audits = match self.inner.orphan_audits.lock() {
            Ok(audits) => audits,
            Err(poisoned) => poisoned.into_inner(),
        };
        if audits.len() < ORPHAN_AUDIT_CAPACITY {
            audits.push_back(audit);
        } else {
            self.inner
                .orphan_audit_overflow
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

mod health;
mod lifecycle;
mod ops;

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn http_pool_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("本机监听");
        let address = listener.local_addr().expect("本机地址");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("接受连接");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 4096, "请求头必须有界");
                request.push(stream.read_u8().await.expect("读取请求"));
            }
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /other-key\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.expect("返回重定向");
        });
        let pool = test_pool();
        let response = pool
            .inner
            .http
            .get(format!("http://{address}/original-key"))
            .send()
            .await
            .expect("收到原始响应");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(response.url().path(), "/original-key");
        server.await.expect("服务完成");
    }

    // 仅测试用到的项写在测试模块内（避免非测试构建 unused import）。
    use std::time::Duration;

    use crate::client::virtual_host_base;
    use crate::retry::default_retry_config;

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
