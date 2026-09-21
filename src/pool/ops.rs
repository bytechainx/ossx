//! 低层单次请求实现：流分片聚合与各操作的 HTTP 往返 + 错误映射。
//!
//! 迁至子模块后仍可访问 `pool` 的私有 `PoolInner` 与内部方法；
//! 被父模块调用的入口放宽为 `pub(super)`。

use super::*;

impl OssPool {
    /// 读取流并按 `part_size` 聚合为内存分片。
    pub(super) async fn collect_parts(
        &self,
        mut stream: ByteStream,
        part_size: usize,
    ) -> OssResult<Vec<Bytes>> {
        let mut parts: Vec<Bytes> = Vec::new();
        let mut current = BytesMut::with_capacity(part_size);
        loop {
            match time::timeout(self.inner.config.request_timeout, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    current.extend_from_slice(&chunk);
                    while current.len() >= part_size {
                        parts.push(current.split_to(part_size).freeze());
                        if parts.len() > MAX_MULTIPART_PARTS {
                            return Err(OssError::Config(format!(
                                "multipart 分片数超过上限 {MAX_MULTIPART_PARTS}"
                            )));
                        }
                    }
                }
                Ok(Some(Err(error))) => return Err(error),
                Ok(None) => {
                    if !current.is_empty() {
                        parts.push(current.freeze());
                    }
                    return Ok(parts);
                }
                Err(_) => {
                    return Err(OssError::Timeout(format!(
                        "oss put_stream 读取分片超过 request_timeout {}ms",
                        self.inner.config.request_timeout.as_millis()
                    )));
                }
            }
        }
    }

    pub(super) async fn put_once(
        &self,
        key: &str,
        data: &[u8],
        content_type: Option<&str>,
        sse: bool,
    ) -> OssResult<()> {
        let credentials = self.credentials().await?;
        let content_type = content_type.unwrap_or("application/octet-stream");
        let resource = sign::canonicalized_resource(&self.inner.config.bucket, key);
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "PUT",
            content_type,
            &resource,
            sse,
        )?;
        let url = object_url(&self.inner.base, key)?;
        let response = self
            .inner
            .http
            .request(Method::PUT, url)
            .headers(headers)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|error| map_network("PUT", &error))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "PUT error body",
        )
        .await?;
        Err(status_error(
            "PUT",
            key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    pub(super) async fn get_once(&self, key: &str) -> OssResult<Bytes> {
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource(&self.inner.config.bucket, key);
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "GET",
            "",
            &resource,
            self.inner.config.sse_enabled,
        )?;
        let url = object_url(&self.inner.base, key)?;
        let response = self
            .inner
            .http
            .request(Method::GET, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("GET", &error))?;
        let status = response.status();
        if status.is_success() {
            let max_object_bytes =
                u64::try_from(self.inner.config.max_object_bytes).unwrap_or(u64::MAX);
            if response
                .content_length()
                .is_some_and(|length| length > max_object_bytes)
            {
                return Err(OssError::Config("对象过大，请改用 get_stream".into()));
            }
            return read_limited_body(response, self.inner.config.max_buffer_bytes, "GET body")
                .await;
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "GET error body",
        )
        .await?;
        Err(status_error(
            "GET",
            key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    pub(super) async fn delete_once(&self, key: &str) -> OssResult<()> {
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource(&self.inner.config.bucket, key);
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "DELETE",
            "",
            &resource,
            self.inner.config.sse_enabled,
        )?;
        let url = object_url(&self.inner.base, key)?;
        let response = self
            .inner
            .http
            .request(Method::DELETE, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("DELETE", &error))?;
        let status = response.status();
        if status.is_success()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_FOUND
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
            key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    pub(super) async fn head_once(&self, key: &str) -> OssResult<ObjectMeta> {
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource(&self.inner.config.bucket, key);
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "HEAD",
            "",
            &resource,
            self.inner.config.sse_enabled,
        )?;
        let url = object_url(&self.inner.base, key)?;
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
            key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    pub(super) async fn init_mp_once(&self, key: &str, sse: bool) -> OssResult<String> {
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource_with_subresources(
            &self.inner.config.bucket,
            key,
            &[("uploads", None)],
        );
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "POST",
            "",
            &resource,
            sse,
        )?;
        let mut url = object_url(&self.inner.base, key)?;
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
            return Err(status_error("InitiateMultipart", key, status, &body));
        }
        parse_upload_id(&body)
    }

    pub(super) async fn upload_part_once(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        data: &[u8],
        sse: bool,
    ) -> OssResult<String> {
        validate_upload_id(upload_id)?;
        let credentials = self.credentials().await?;
        let part_number_text = part_number.to_string();
        let content_type = "application/octet-stream";
        let resource = sign::canonicalized_resource_with_subresources(
            &self.inner.config.bucket,
            key,
            &[
                ("partNumber", Some(part_number_text.as_str())),
                ("uploadId", Some(upload_id)),
            ],
        );
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "PUT",
            content_type,
            &resource,
            sse,
        )?;
        let mut url = object_url(&self.inner.base, key)?;
        url.query_pairs_mut()
            .append_pair("partNumber", &part_number_text)
            .append_pair("uploadId", upload_id);
        let response = self
            .inner
            .http
            .request(Method::PUT, url)
            .headers(headers)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|error| map_network("UploadPart", &error))?;
        let status = response.status();
        if !status.is_success() {
            let body = read_limited_body(
                response,
                self.inner.config.max_error_body_bytes,
                "UploadPart error body",
            )
            .await?;
            return Err(status_error(
                "UploadPart",
                key,
                status,
                &String::from_utf8_lossy(&body),
            ));
        }
        response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| OssError::Backend("UploadPart 响应缺 ETag".into()))
    }

    pub(super) async fn complete_mp_once(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> OssResult<()> {
        validate_upload_id(upload_id)?;
        let mut sorted = parts.to_vec();
        sorted.sort_by_key(|(number, _)| *number);
        let body = build_complete_xml(&sorted)?;
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource_with_subresources(
            &self.inner.config.bucket,
            key,
            &[("uploadId", Some(upload_id))],
        );
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "POST",
            "application/xml",
            &resource,
            self.inner.config.sse_enabled,
        )?;
        let mut url = object_url(&self.inner.base, key)?;
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
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "CompleteMultipart error body",
        )
        .await?;
        Err(status_error(
            "CompleteMultipart",
            key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    pub(super) async fn abort_mp_once(&self, key: &str, upload_id: &str) -> OssResult<()> {
        validate_upload_id(upload_id)?;
        let credentials = self.credentials().await?;
        let resource = sign::canonicalized_resource_with_subresources(
            &self.inner.config.bucket,
            key,
            &[("uploadId", Some(upload_id))],
        );
        let headers = signed_headers(
            &credentials.access_key_id,
            &credentials.access_key_secret,
            credentials.security_token.as_deref(),
            "DELETE",
            "",
            &resource,
            self.inner.config.sse_enabled,
        )?;
        let mut url = object_url(&self.inner.base, key)?;
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
        if status.is_success()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_FOUND
        {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            self.inner.config.max_error_body_bytes,
            "AbortMultipart error body",
        )
        .await?;
        Err(status_error(
            "AbortMultipart",
            key,
            status,
            &String::from_utf8_lossy(&body),
        ))
    }
}
