//! [`OssClient`] 的分片上传：初始化 / 上传分片 / 完成 / 中止与孤儿审计。
//!
//! `impl OssClient` 跨三个文件（合法，Rust 允许同一类型的多个 impl 块）：
//! - 门面即本文件：`put_object_multipart` 批量编排与孤儿审计注册表；
//! - `session.rs`：`initiate_multipart*` / `upload_part*`；
//! - `commit.rs`：`complete_multipart*` / `abort_multipart*`。

use super::*;

mod commit;
mod session;

impl OssClient {
    // ── 批量编排与孤儿审计 ────────────────────────────────────────────────
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
        let completed = self
            .upload_all_parts(
                key,
                &upload_id,
                &chunks,
                started,
                total_deadline,
                &mut audit_guard,
            )
            .await?;
        self.finish_multipart(
            key,
            &upload_id,
            completed,
            started,
            total_deadline,
            &mut audit_guard,
        )
        .await?;
        audit_guard.disarm();
        Ok(())
    }

    /// 逐个上传分片；任一分片失败（含预算耗尽）时按 abort 语义收口，返回收口后的错误。
    ///
    /// 返回值是 `(part_number, etag)` 列表，交给 [`OssClient::finish_multipart`] 提交。
    async fn upload_all_parts(
        &self,
        key: &str,
        upload_id: &str,
        chunks: &[&[u8]],
        started: Instant,
        total_deadline: Duration,
        audit_guard: &mut MultipartAuditGuard,
    ) -> OssResult<Vec<(u32, String)>> {
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
                            upload_id,
                            error,
                            started,
                            total_deadline,
                            audit_guard,
                        )
                        .await);
                }
            };
            match self
                .upload_part_with_deadline(key, upload_id, part_number, part_data, remaining)
                .await
            {
                Ok(etag) => completed.push((part_number, etag)),
                Err(error) => {
                    return Err(self
                        .cleanup_multipart_failure(
                            key,
                            upload_id,
                            error,
                            started,
                            total_deadline,
                            audit_guard,
                        )
                        .await);
                }
            }
        }
        Ok(completed)
    }

    /// 提交已完成的分片列表；预算不足或提交失败时按 abort 语义收口。
    async fn finish_multipart(
        &self,
        key: &str,
        upload_id: &str,
        completed: Vec<(u32, String)>,
        started: Instant,
        total_deadline: Duration,
        audit_guard: &mut MultipartAuditGuard,
    ) -> OssResult<()> {
        let remaining = match remaining_deadline(started, total_deadline, "multipart complete") {
            Ok(value) => value,
            Err(error) => {
                return Err(self
                    .cleanup_multipart_failure(
                        key,
                        upload_id,
                        error,
                        started,
                        total_deadline,
                        audit_guard,
                    )
                    .await);
            }
        };
        if let Err(error) = self
            .complete_multipart_with_deadline(key, upload_id, completed, remaining)
            .await
        {
            return Err(self
                .cleanup_multipart_failure(
                    key,
                    upload_id,
                    error,
                    started,
                    total_deadline,
                    audit_guard,
                )
                .await);
        }
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

    pub(super) fn remove_orphan_audit(&self, key: &str, upload_id: &str) {
        let mut audits = match self.inner.orphan_audits.lock() {
            Ok(audits) => audits,
            Err(poisoned) => poisoned.into_inner(),
        };
        audits.retain(|audit| audit.key != key || audit.upload_id != upload_id);
    }
}
