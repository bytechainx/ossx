//! `OssPool` 的探活：`ping` / `health_check` / `health`。
//!
//! 自 `src/pool.rs` 下沉而来。`OssPool` 的定义仍在门面 `src/pool.rs`；本模块是它的子模块，
//! 故可直接调用门面的私有辅助（`ensure_open` / `credentials` / `record`）与 `pool/ops.rs`
//! 的 `pub(super)` 入口。方法全部为 `pub`，**无需任何可见性调整**。

use std::time::Duration;

use reqwest::Method;
use tokio::time;

use crate::client::{map_network, read_limited_body, signed_headers, status_error};
use crate::error::{OssError, OssResult};
use crate::sign;
use crate::types::OssHealth;

use super::OssPool;

impl OssPool {
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
}
