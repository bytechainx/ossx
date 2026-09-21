//! OSS 重试策略：指数退避 + 抖动 + 单操作 deadline。
//!
//! 本模块在 crate 内独立实现，不依赖任何外部重试框架；重试判定完全依赖
//! [`OssError::is_retryable`]（见 [`is_oss_retryable`]），因此**不存在**
//! 「错误文案与重试判定耦合」的隐性契约。
//!
//! - [`with_retry`]：按 [`RetryConfig`] 重试，永久错误立即返回；
//! - [`with_retry_deadline`]：在单一 deadline 内完成整段重试，超时返回
//!   [`OssError::Timeout`]，避免每次尝试各自耗尽请求超时后继续放大；
//! - [`with_retry_default`]：等价于 [`with_retry`] 的便捷入口。

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{OssError, OssResult};

/// 重试次数硬上界，防止错误配置制造无界放大。
pub const MAX_RETRY_ATTEMPTS: u32 = 10;

/// 指数退避默认基数（毫秒）。
const DEFAULT_BASE_DELAY_MS: u64 = 100;
/// 指数退避默认单次上限（毫秒）。
const DEFAULT_MAX_DELAY_MS: u64 = 2_000;
/// 默认抖动比例（±25%）。
const DEFAULT_JITTER_RATIO: f64 = 0.25;

/// 重试配置。
///
/// `max_attempts` 含首次尝试：`3` 表示最多 3 次请求（1 次首发 + 2 次重试）。
/// 第 `n` 次重试的退避为 `min(base_delay_ms * 2^(n-1), max_delay_ms)`，
/// 再叠加 `±jitter_ratio` 的随机抖动，避免多实例同步重试造成惊群。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RetryConfig {
    /// 最大尝试次数（含首次），必须落在 `1..=MAX_RETRY_ATTEMPTS`。
    pub max_attempts: u32,
    /// 首次退避基数（毫秒）。
    pub base_delay_ms: u64,
    /// 单次退避上限（毫秒）。
    pub max_delay_ms: u64,
    /// 抖动比例（`0.0..=1.0`）；`0.0` 表示无抖动，便于确定性测试。
    pub jitter_ratio: f64,
}

impl RetryConfig {
    /// 固定间隔重试（无抖动）。
    #[must_use]
    pub const fn fixed(max_attempts: u32, delay_ms: u64) -> Self {
        Self {
            max_attempts,
            base_delay_ms: delay_ms,
            max_delay_ms: delay_ms,
            jitter_ratio: 0.0,
        }
    }

    /// 指数退避重试（含抖动）。
    #[must_use]
    pub const fn exponential(
        max_attempts: u32,
        base_delay_ms: u64,
        max_delay_ms: u64,
        jitter_ratio: f64,
    ) -> Self {
        Self {
            max_attempts,
            base_delay_ms,
            max_delay_ms,
            jitter_ratio,
        }
    }

    /// 校验配置；越界返回 [`OssError::Config`]。
    pub fn validate(&self) -> OssResult<()> {
        if self.max_attempts == 0 || self.max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(OssError::Config(format!(
                "oss retry max_attempts 必须在 1..={MAX_RETRY_ATTEMPTS} 范围内"
            )));
        }
        if self.max_delay_ms < self.base_delay_ms {
            return Err(OssError::Config(
                "oss retry max_delay_ms 不得小于 base_delay_ms".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.jitter_ratio) {
            return Err(OssError::Config(
                "oss retry jitter_ratio 必须在 0.0..=1.0 范围内".into(),
            ));
        }
        Ok(())
    }

    /// 第 `retry_index` 次（1 起）重试前的退避时长。
    #[must_use]
    pub fn delay_for(&self, retry_index: u32) -> Duration {
        if self.base_delay_ms == 0 || self.max_delay_ms == 0 {
            return Duration::ZERO;
        }
        let shift = retry_index.saturating_sub(1).min(32);
        let base = self
            .base_delay_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_delay_ms);
        if self.jitter_ratio <= 0.0 {
            return Duration::from_millis(base);
        }
        // 抖动因子 ∈ [1 - r, 1 + r]；下界保证退避不被抖动抹成零。
        let factor = 1.0 - self.jitter_ratio + 2.0 * self.jitter_ratio * random_unit();
        let millis = (base as f64 * factor).max(1.0);
        Duration::from_millis(millis as u64)
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        default_retry_config()
    }
}

/// 默认重试配置：3 次尝试、指数退避 100ms 起、±25% 抖动。
#[must_use]
pub fn default_retry_config() -> RetryConfig {
    RetryConfig::exponential(
        3,
        DEFAULT_BASE_DELAY_MS,
        DEFAULT_MAX_DELAY_MS,
        DEFAULT_JITTER_RATIO,
    )
}

/// 判断 OSS 错误是否值得重试。
///
/// 直接转发 [`OssError::is_retryable`]：仅 [`OssError::Connection`]（网络抖动、
/// 连接中断、远端 5xx）可重试，鉴权/权限降级与所有永久错误立即返回。
#[must_use]
pub fn is_oss_retryable(error: &OssError) -> bool {
    error.is_retryable()
}

/// 异步重试包装。
///
/// - 可重试错误 → 按配置退避后重试，直到 `max_attempts` 用尽；
/// - 永久错误 → 立即返回，不消耗重试预算；
/// - `config` 非法 → 直接返回 [`OssError::Config`]。
pub async fn with_retry<F, Fut, T>(config: &RetryConfig, op: &str, mut operation: F) -> OssResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = OssResult<T>>,
{
    config.validate()?;
    let mut attempt: u32 = 1;
    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if !is_oss_retryable(&error) || attempt >= config.max_attempts {
                    return Err(error);
                }
                let delay = config.delay_for(attempt);
                tracing::debug!(
                    op = op,
                    attempt = attempt,
                    delay_ms = delay.as_millis() as u64,
                    error = %error,
                    "oss 操作失败，按退避策略重试",
                );
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                attempt += 1;
            }
        }
    }
}

/// [`with_retry`] 的便捷入口（无外部 instrumentation 依赖）。
pub async fn with_retry_default<F, Fut, T>(
    config: &RetryConfig,
    op: &str,
    operation: F,
) -> OssResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = OssResult<T>>,
{
    with_retry(config, op, operation).await
}

/// 在单一 deadline 内执行完整重试过程。
///
/// deadline 到期会丢弃当前尝试 future 并返回 [`OssError::Timeout`]，
/// 从而避免每次尝试各自耗尽请求超时后继续放大。
pub async fn with_retry_deadline<F, Fut, T>(
    config: &RetryConfig,
    op: &str,
    deadline: Duration,
    operation: F,
) -> OssResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = OssResult<T>>,
{
    if deadline.is_zero() {
        return Err(OssError::Config("oss retry deadline 必须大于零".into()));
    }
    match tokio::time::timeout(deadline, with_retry_default(config, op, operation)).await {
        Ok(result) => result,
        Err(_) => Err(OssError::Timeout(format!(
            "oss {op} 超过总 deadline {}ms",
            deadline.as_millis()
        ))),
    }
}

/// 无依赖伪随机数的 `[0, 1)` 取值（xorshift64）。
///
/// 仅用于退避抖动，不需要密码学强度；种子来自墙钟纳秒 + 进程内计数器，
/// 保证同一调度周期内的并发抖动也不会完全同步。
fn random_unit() -> f64 {
    const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
    const FALLBACK_SEED: u64 = 0x2545_F491_4F6C_DD1D;
    static STATE: AtomicU64 = AtomicU64::new(0);
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut state = STATE.load(Ordering::Relaxed);
    if state == 0 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or(FALLBACK_SEED);
        state = nanos ^ COUNTER.fetch_add(GOLDEN_GAMMA, Ordering::Relaxed);
        if state == 0 {
            state = FALLBACK_SEED;
        }
    }
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    STATE.store(state, Ordering::Relaxed);
    (state >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn retryability_matches_error_classification() {
        assert!(is_oss_retryable(&OssError::Connection(
            "oss GET network: reset".into()
        )));
        assert!(is_oss_retryable(&OssError::Connection(
            "oss GET server status=503".into()
        )));
        assert!(!is_oss_retryable(&OssError::Connection(
            "oss GET auth/forbidden status=403".into()
        )));
        assert!(!is_oss_retryable(&OssError::Connection(
            "HTTP unauthorized".into()
        )));
        assert!(!is_oss_retryable(&OssError::Connection(
            "403 Forbidden".into()
        )));
        assert!(!is_oss_retryable(&OssError::Config("bad key".into())));
        assert!(!is_oss_retryable(&OssError::Backend("not found".into())));
        assert!(!is_oss_retryable(&OssError::Serialization("xml".into())));
        assert!(!is_oss_retryable(&OssError::Timeout("slow".into())));
        assert!(!is_oss_retryable(&OssError::Unsupported("closed".into())));
        assert!(!is_oss_retryable(&OssError::Io(std::io::Error::other(
            "disk"
        ))));
    }

    #[test]
    fn config_bounds_are_enforced() {
        assert!(RetryConfig::fixed(1, 0).validate().is_ok());
        assert!(RetryConfig::fixed(MAX_RETRY_ATTEMPTS, 0).validate().is_ok());
        assert!(RetryConfig::fixed(0, 0).validate().is_err());
        assert!(RetryConfig::fixed(MAX_RETRY_ATTEMPTS + 1, 0)
            .validate()
            .is_err());
        assert!(RetryConfig::exponential(3, 200, 100, 0.0)
            .validate()
            .is_err());
        assert!(RetryConfig::exponential(3, 100, 200, 1.5)
            .validate()
            .is_err());
        let _ = default_retry_config();
        assert_eq!(RetryConfig::default(), default_retry_config());
    }

    #[test]
    fn exponential_backoff_is_capped_and_monotonic() {
        let config = RetryConfig::exponential(6, 100, 400, 0.0);
        assert_eq!(config.delay_for(1), Duration::from_millis(100));
        assert_eq!(config.delay_for(2), Duration::from_millis(200));
        assert_eq!(config.delay_for(3), Duration::from_millis(400));
        // 超出上限后封顶，不会无限放大
        assert_eq!(config.delay_for(4), Duration::from_millis(400));
        assert_eq!(config.delay_for(u32::MAX), Duration::from_millis(400));
        assert_eq!(RetryConfig::fixed(3, 0).delay_for(9), Duration::ZERO);
    }

    #[test]
    fn jitter_stays_inside_configured_window() {
        let config = RetryConfig::exponential(3, 1_000, 1_000, 0.25);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let millis = config.delay_for(1).as_millis() as u64;
            assert!((750..=1_250).contains(&millis), "抖动越界: {millis}");
            seen.insert(millis);
        }
        assert!(seen.len() > 1, "抖动必须产生随机性");
    }

    #[tokio::test]
    async fn retries_transient_then_succeeds() {
        let attempts = AtomicU32::new(0);
        let output = with_retry_default(&RetryConfig::fixed(5, 0), "put", || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if attempt < 3 {
                    Err(OssError::Connection(format!("blip-{attempt}")))
                } else {
                    Ok(42u32)
                }
            }
        })
        .await
        .expect("重试后应成功");
        assert_eq!(output, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retries_remote_5xx_classified_error() {
        let attempts = AtomicU32::new(0);
        let output = with_retry_default(&RetryConfig::fixed(3, 0), "get", || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if attempt < 2 {
                    Err(OssError::Connection("oss GET server status=500".into()))
                } else {
                    Ok("ok".to_string())
                }
            }
        })
        .await
        .expect("5xx 应可重试");
        assert_eq!(output, "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn permanent_errors_do_not_retry() {
        let attempts = AtomicU32::new(0);
        let error = with_retry_default(&RetryConfig::fixed(5, 0), "bad", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(OssError::Config("object key 非法".into())) }
        })
        .await
        .expect_err("永久错误必须失败");
        assert!(matches!(error, OssError::Config(_)));
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "永久错误不得消耗重试预算"
        );
    }

    #[tokio::test]
    async fn auth_failure_does_not_retry() {
        let attempts = AtomicU32::new(0);
        let error = with_retry_default(&RetryConfig::fixed(5, 0), "get", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<(), _>(OssError::Connection(
                    "oss GET auth/forbidden status=403".into(),
                ))
            }
        })
        .await
        .expect_err("403 必须失败");
        assert!(matches!(error, OssError::Connection(_)));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exhausts_configured_budget() {
        let attempts = AtomicU32::new(0);
        let error = with_retry_default(&RetryConfig::fixed(3, 0), "always", || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(OssError::Connection("still bad".into())) }
        })
        .await
        .expect_err("必须耗尽预算");
        assert!(is_oss_retryable(&error));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn deadline_bounds_the_whole_operation() {
        let attempts = AtomicU32::new(0);
        let error = with_retry_deadline(
            &RetryConfig::fixed(5, 0),
            "slow",
            Duration::from_millis(20),
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    Err::<(), _>(OssError::Connection("slow".into()))
                }
            },
        )
        .await
        .expect_err("deadline 必须终止整段重试");
        assert!(matches!(error, OssError::Timeout(_)), "{error:?}");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zero_deadline_and_invalid_config_fail_closed() {
        let error =
            with_retry_deadline(&RetryConfig::fixed(1, 0), "op", Duration::ZERO, || async {
                Ok::<_, OssError>(())
            })
            .await
            .expect_err("零 deadline 必须被拒绝");
        assert!(matches!(error, OssError::Config(_)));

        let error = with_retry_default(
            &RetryConfig::fixed(MAX_RETRY_ATTEMPTS + 1, 0),
            "op",
            || async { Ok::<_, OssError>(()) },
        )
        .await
        .expect_err("超界尝试次数必须 fail-closed");
        assert!(matches!(error, OssError::Config(_)));
    }

    #[test]
    fn random_unit_is_in_unit_interval() {
        for _ in 0..1_000 {
            let value = random_unit();
            assert!((0.0..1.0).contains(&value), "{value}");
        }
    }
}
