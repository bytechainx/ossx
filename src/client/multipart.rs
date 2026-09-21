//! [`OssClient`] 的分片上传：初始化 / 上传分片 / 完成 / 中止与孤儿审计。

use super::*;

impl OssClient {
    // ── Multipart ──────────────────────────────────────────────────────────

    /// 初始化分片上传，返回 `upload_id`（含重试）。
    pub async fn initiate_multipart(&self, key: &str) -> OssResult<String> {
        self.initiate_multipart_with_deadline(key, self.inner.config.operation_deadline)
            .await
    }

    async fn initiate_multipart_with_deadline(
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

    async fn upload_part_with_deadline(
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

    async fn complete_multipart_with_deadline(
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

    async fn abort_multipart_with_deadline(
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

    /// 高层：按 `part_size` 切分并完成 multipart 上传。
    ///
    /// - 数据为空 → [`OssError::Config`]
    /// - 单片（`data.len() <= part_size`）仍走 multipart 路径
    /// - 任一分片失败时尝试 `abort_multipart`
    /// - abort 失败会返回带 `orphan_risk=true` 的 [`OssError::Backend`]，
    ///   禁止静默丢失孤儿风险
    ///
    /// 整个状态机共享一个 operation deadline。调用方 drop future 时同步写入有界
    /// orphan 审计注册表，可通过 [`Self::multipart_orphan_audits`] 取得 key/UploadId
    /// 后显式补偿。注册表不替代服务端 lifecycle。
    pub async fn put_object_multipart(
        &self,
        key: &str,
        data: Bytes,
        part_size: usize,
    ) -> OssResult<()> {
        let started = Instant::now();
        let total_deadline = self.inner.config.operation_deadline;
        self.validate_object_size(data.len())?;
        validate_multipart_plan(data.len(), part_size)?;
        if part_size > self.inner.config.max_buffer_bytes {
            return Err(OssError::Config(format!(
                "multipart part_size {part_size} 超过缓冲上限 {}",
                self.inner.config.max_buffer_bytes
            )));
        }
        let chunks = split_parts(&data, part_size);

        let initiate_deadline = remaining_deadline(started, total_deadline, "multipart initiate")?;
        let upload_id = match self
            .initiate_multipart_with_deadline(key, initiate_deadline)
            .await
        {
            Ok(id) => id,
            Err(error) => {
                // initiate 失败时 upload_id 未知，仍登记 key 侧审计供人工排查
                if matches!(error, OssError::Connection(_) | OssError::Timeout(_)) {
                    push_orphan_audit_inner(
                        &self.inner,
                        MultipartOrphanAudit {
                            key: key.to_owned(),
                            upload_id: "unknown".to_owned(),
                        },
                    );
                }
                return Err(mark_unknown_initiate_orphan_risk(error));
            }
        };
        let mut audit_guard = MultipartAuditGuard::new(self, key, &upload_id);
        let mut completed: Vec<(u32, String)> = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let part_number = u32::try_from(index + 1)
                .map_err(|_| OssError::Config("multipart part_number 溢出".into()))?;
            // 拷贝 chunk 为 Bytes（分片重试需要所有权）
            let part_data = Bytes::copy_from_slice(chunk);
            let remaining = match remaining_deadline(started, total_deadline, "multipart upload") {
                Ok(value) => value,
                Err(error) => {
                    return Err(self
                        .cleanup_multipart_failure(
                            key,
                            &upload_id,
                            error,
                            started,
                            total_deadline,
                            &mut audit_guard,
                        )
                        .await);
                }
            };
            match self
                .upload_part_with_deadline(key, &upload_id, part_number, part_data, remaining)
                .await
            {
                Ok(etag) => completed.push((part_number, etag)),
                Err(error) => {
                    return Err(self
                        .cleanup_multipart_failure(
                            key,
                            &upload_id,
                            error,
                            started,
                            total_deadline,
                            &mut audit_guard,
                        )
                        .await);
                }
            }
        }
        let remaining = match remaining_deadline(started, total_deadline, "multipart complete") {
            Ok(value) => value,
            Err(error) => {
                return Err(self
                    .cleanup_multipart_failure(
                        key,
                        &upload_id,
                        error,
                        started,
                        total_deadline,
                        &mut audit_guard,
                    )
                    .await);
            }
        };
        if let Err(error) = self
            .complete_multipart_with_deadline(key, &upload_id, completed, remaining)
            .await
        {
            return Err(self
                .cleanup_multipart_failure(
                    key,
                    &upload_id,
                    error,
                    started,
                    total_deadline,
                    &mut audit_guard,
                )
                .await);
        }
        audit_guard.disarm();
        Ok(())
    }

    async fn cleanup_multipart_failure(
        &self,
        key: &str,
        upload_id: &str,
        primary: OssError,
        started: Instant,
        total_deadline: Duration,
        audit_guard: &mut MultipartAuditGuard,
    ) -> OssError {
        let Ok(remaining) = remaining_deadline(started, total_deadline, "multipart abort") else {
            // 总 deadline 已耗尽：无法再 abort → 显式登记孤儿审计（不单靠 Drop，
            // 避免 await 边界抖动）
            self.register_orphan_audit(key, upload_id, audit_guard);
            return mark_known_orphan_risk(primary, upload_id);
        };
        let abort = self
            .abort_multipart_with_deadline(key, upload_id, remaining)
            .await;
        if abort.is_ok() {
            audit_guard.disarm();
            return primary;
        }
        // abort 失败：会话仍可能残留在服务端
        self.register_orphan_audit(key, upload_id, audit_guard);
        merge_abort_result(primary, abort, upload_id)
    }

    /// 显式写入 orphan 审计并 `disarm` guard，避免 Drop 重复登记。
    fn register_orphan_audit(
        &self,
        key: &str,
        upload_id: &str,
        audit_guard: &mut MultipartAuditGuard,
    ) {
        audit_guard.disarm();
        push_orphan_audit_inner(
            &self.inner,
            MultipartOrphanAudit {
                key: key.to_owned(),
                upload_id: upload_id.to_owned(),
            },
        );
    }

    fn remove_orphan_audit(&self, key: &str, upload_id: &str) {
        let mut audits = match self.inner.orphan_audits.lock() {
            Ok(audits) => audits,
            Err(poisoned) => poisoned.into_inner(),
        };
        audits.retain(|audit| audit.key != key || audit.upload_id != upload_id);
    }
}
