//! 对象 key、元数据、上传/下载选项与字节流抽象。

use std::pin::Pin;

use bytes::Bytes;
use futures_core::Stream;

use crate::error::{OssError, OssResult};
use crate::MAX_OBJECT_KEY_BYTES;

/// 经校验的对象 key。
///
/// 构造时拒绝空 key、以 `/` 开头、包含 `..`、包含控制字符以及超过
/// 1023 字节的 key。所有拒绝都返回 [`OssError::Config`]，调用方可在发起任何
/// 网络请求前 fail-fast。
///
/// 与源实现相比有**一处行为收紧**：源实现把前导 `/` 静默归一化掉，
/// 本 crate 直接拒绝，避免「调用方以为写的是 `/a`，实际写的是 `a`」这类隐性歧义。
///
/// ```
/// use ossx::ObjectKey;
///
/// # fn main() -> Result<(), ossx::OssError> {
/// assert_eq!(ObjectKey::new("a/b.txt")?.as_str(), "a/b.txt");
/// assert!(ObjectKey::new("/leading").is_err());
/// assert!(ObjectKey::new("../escape").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// 校验并构造对象 key。
    pub fn new(key: impl Into<String>) -> OssResult<Self> {
        let trimmed = key.into();
        let trimmed = trimmed.trim();
        if trimmed.is_empty() {
            return Err(OssError::Config("object key 不得为空".into()));
        }
        if trimmed.starts_with('/') {
            return Err(OssError::Config("object key 不得以 '/' 开头".into()));
        }
        if trimmed.contains("..") {
            return Err(OssError::Config("object key 不得包含 '..'".into()));
        }
        if trimmed.len() > MAX_OBJECT_KEY_BYTES {
            return Err(OssError::Config(format!(
                "object key 超过 {MAX_OBJECT_KEY_BYTES} 字节上限"
            )));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(OssError::Config("object key 不得包含控制字符".into()));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// 归一化后的 key 字面量。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ObjectKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 对象元数据（HEAD / 下载响应头解析结果）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectMeta {
    /// 对象字节数。
    pub size: u64,
    /// ETag（去引号后的裸值）。
    pub etag: Option<String>,
    /// 版本 id（bucket 开启版本控制时存在）。
    pub version_id: Option<String>,
    /// CRC64-ECMA 校验和。
    pub checksum: Option<String>,
    /// Content-Type。
    pub content_type: Option<String>,
}

impl ObjectMeta {
    /// 仅按大小构造元数据，其余字段为 `None`。
    #[must_use]
    pub fn with_size(size: u64) -> Self {
        Self {
            size,
            etag: None,
            version_id: None,
            checksum: None,
            content_type: None,
        }
    }
}

/// 字节流：crate 内所有流式数据面的统一形态。
///
/// 元素为 [`bytes::Bytes`]，错误类型为 [`OssError`]；`Send` 使其可跨任务移动。
pub type ByteStream = Pin<Box<dyn Stream<Item = OssResult<Bytes>> + Send>>;

/// 由内存字节构造单元素 [`ByteStream`]。
#[must_use]
pub fn byte_stream_from_bytes(data: Bytes) -> ByteStream {
    Box::pin(futures_util::stream::once(async move { Ok(data) }))
}

/// 上传选项。
#[derive(Clone, Debug, Default)]
pub struct UploadOptions {
    /// Content-Type；`None` 时由调用方或服务端决定。
    pub content_type: Option<String>,
    /// 自定义元数据（`x-oss-meta-*`）。
    pub metadata: Option<Vec<(String, String)>>,
    /// 分片大小（字节）；`0` 表示使用实现默认值。
    pub part_size: usize,
    /// 是否启用 SSE-S3 服务端加密。
    pub sse_enabled: bool,
}

/// 下载选项。
#[derive(Clone, Debug, Default)]
pub struct DownloadOptions {
    /// HTTP `Range` 头，例如 `bytes=0-1023`。
    pub range: Option<String>,
    /// HTTP `If-Match` 头。
    pub if_match: Option<String>,
    /// HTTP `If-None-Match` 头。
    pub if_none_match: Option<String>,
    /// 指定版本 id。
    pub version_id: Option<String>,
}

impl DownloadOptions {
    /// 按 `Range` 构造下载选项。
    #[must_use]
    pub fn with_range(range: impl Into<String>) -> Self {
        Self {
            range: Some(range.into()),
            ..Self::default()
        }
    }
}

/// 健康检查结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OssHealth {
    /// 是否可用（bucket 可访问）。
    pub ready: bool,
    /// bucket 是否可访问。
    pub bucket_accessible: bool,
    /// 探活耗时（毫秒）。
    pub latency_ms: u64,
    /// 人类可读细节（不含凭据）。
    pub detail: String,
}

impl OssHealth {
    pub(super) fn unreachable(latency_ms: u64, detail: impl Into<String>) -> Self {
        Self {
            ready: false,
            bucket_accessible: false,
            latency_ms,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_key_accepts_and_rejects() {
        assert_eq!(ObjectKey::new("a/b").expect("ok").as_str(), "a/b");
        assert_eq!(ObjectKey::new("  a/b  ").expect("ok").as_str(), "a/b");
        assert_eq!(ObjectKey::new("a/b").expect("ok").to_string(), "a/b");
        assert_eq!(ObjectKey::new("a/b").expect("ok").as_ref(), "a/b");

        assert!(ObjectKey::new("/leading").is_err());
        assert!(ObjectKey::new("").is_err());
        assert!(ObjectKey::new("   ").is_err());
        assert!(ObjectKey::new("../x").is_err());
        assert!(ObjectKey::new("a/../b").is_err());
        assert!(ObjectKey::new("a\0b").is_err());
        assert!(ObjectKey::new("a\nb").is_err());
        assert!(ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES + 1)).is_err());
        assert!(ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES)).is_ok());
    }

    #[test]
    fn object_key_error_is_config_class() {
        let error = ObjectKey::new("/bad").expect_err("rejected");
        assert!(matches!(error, OssError::Config(_)));
        assert!(!error.is_retryable());
    }

    #[test]
    fn object_meta_and_options_builders() {
        let meta = ObjectMeta::with_size(42);
        assert_eq!(meta.size, 42);
        assert!(meta.etag.is_none());
        assert_eq!(ObjectMeta::default().size, 0);

        let upload = UploadOptions {
            content_type: Some("text/plain".into()),
            metadata: Some(vec![("k".into(), "v".into())]),
            part_size: 1024,
            sse_enabled: true,
        };
        assert!(upload.sse_enabled);
        assert_eq!(upload.part_size, 1024);

        let download = DownloadOptions::with_range("bytes=0-9");
        assert_eq!(download.range.as_deref(), Some("bytes=0-9"));
        assert!(download.if_match.is_none());
    }

    #[tokio::test]
    async fn byte_stream_from_bytes_yields_single_item() {
        use futures_util::StreamExt;
        let mut stream = byte_stream_from_bytes(Bytes::from_static(b"payload"));
        assert_eq!(
            stream.next().await.expect("item").expect("ok"),
            Bytes::from_static(b"payload")
        );
        assert!(stream.next().await.is_none());
    }
}
