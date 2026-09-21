//! [`OssClient`] 的生命周期、探活与并发许可。

use super::*;

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

    pub(super) fn ensure_open(&self) -> OssResult<()> {
        if self.is_closed() {
            return Err(OssError::Unsupported("oss client 已关闭".into()));
        }
        Ok(())
    }

    pub(super) async fn acquire(&self) -> OssResult<OwnedSemaphorePermit> {
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

    pub(super) fn validate_object_size(&self, size: usize) -> OssResult<()> {
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
}
