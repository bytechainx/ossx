//! 分片上传的会话面：`initiate_multipart*` 与 `upload_part*`。
//!
//! 从门面 `client/multipart.rs` 下沉（`MR-STRUCT-007` 腾余量）。两个 `*_with_deadline`
//! 被门面的 `put_object_multipart` 直接调用，而**父模块看不到子模块的私有项**，故提为
//! `pub(super)`；两个 `*_once` 只在本模块内被同组的 `*_with_deadline` 调用，保持私有。
//! 符号经 `use super::super::*` 取自 `client` 模块。

use super::super::*;

impl OssClient {
    // ── 会话：初始化与上传分片 ─────────────────────────────────────────────
    // ── Multipart ──────────────────────────────────────────────────────────

    /// 初始化分片上传，返回 `upload_id`（含重试）。
    pub async fn initiate_multipart(&self, key: &str) -> OssResult<String> {
        self.initiate_multipart_with_deadline(key, self.inner.config.operation_deadline)
            .await
    }

    pub(super) async fn initiate_multipart_with_deadline(
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

    pub(super) async fn upload_part_with_deadline(
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
}
