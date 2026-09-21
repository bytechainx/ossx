//! [`OssClient`] 的对象读写（含单次请求实现）。

use super::*;

impl OssClient {
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
}
