//! `OssPool` 的构造、建连、只读观测与关闭。
//!
//! 自 `src/pool.rs` 下沉而来：`new` / `connect` / `new_with_retry` / `connect_with_retry` /
//! `connect_with_provider` / `from_env` / `config` / `retry_config` / `provider_name` /
//! `stats` / `close`。`OssPool` / `PoolInner` 的定义仍在门面 `src/pool.rs`；本模块是它的
//! 子模块，故可直接读写二者的私有字段。方法全部为 `pub`，**无需任何可见性调整**。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use reqwest::Client;
use tokio::sync::Semaphore;

use crate::client::virtual_host_base;
use crate::config::OssConfig;
use crate::credential::{CredentialProvider, StaticCredentialProvider};
use crate::error::{OssError, OssResult};
use crate::retry::{default_retry_config, RetryConfig};

use super::{OssPool, OssPoolStats, PoolInner};

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
}
