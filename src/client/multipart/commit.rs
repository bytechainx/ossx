//! 分片上传的收口面：`complete_multipart*` 与 `abort_multipart*`。
//!
//! 从门面 `client/multipart.rs` 下沉（`MR-STRUCT-007` 腾余量）。
//!
//! 两处需要放宽可见性：
//!
//! - 两个 `*_with_deadline` 被门面的 `put_object_multipart` / `cleanup_multipart_failure`
//!   调用 → 提为 `pub(super)`；
//! - 门面的私有辅助 `remove_orphan_audit` 被本模块的 `abort_multipart_with_deadline` 调用，
//!   而**兄弟模块看不到彼此的私有项** → 在门面提为 `pub(super)`。
//!
//! 两个 `*_once` 只在本模块内被同组的 `*_with_deadline` 调用，保持私有。
//! 符号经 `use super::super::*` 取自 `client` 模块。

use super::super::*;

impl OssClient {
    // ── 收口：完成与中止 ──────────────────────────────────────────────────
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

    pub(super) async fn complete_multipart_with_deadline(
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

    pub(super) async fn abort_multipart_with_deadline(
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
}
