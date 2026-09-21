//! crate 统一错误类型与重试判定。
//!
//! ## 分类映射
//!
//! 本 crate 把「本地校验失败」「传输层可重试失败」「远端协议错误」严格分开，
//! 因为重试策略只依赖分类，不依赖错误文案：
//!
//! | 错误来源 | 变体 | [`OssError::is_retryable`] |
//! | --- | --- | --- |
//! | 配置/参数/硬上限校验失败 | [`OssError::Config`] | `false` |
//! | 网络抖动、连接中断、远端 5xx | [`OssError::Connection`] | `true`（鉴权降级除外） |
//! | 远端 4xx / 404 / 403 / 未完成分片风险 | [`OssError::Backend`] | `false` |
//! | XML / TOML 解析失败 | [`OssError::Serialization`] | `false` |
//! | 本地文件系统 I/O | [`OssError::Io`] | `false` |
//! | 单请求或单操作超时 | [`OssError::Timeout`] | `false` |
//! | 客户端已关闭等本地生命周期拒绝 | [`OssError::Unsupported`] | `false` |
//!
//! 错误消息**绝不回显 `AccessKeySecret`**；所有文案来自本 crate 的固定模板与
//! 远端响应片段（响应片段不含签名密钥）。

/// `ossx` 错误类型。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OssError {
    /// 配置或本地输入非法（含硬上限校验失败）。
    #[error("配置无效: {0}")]
    Config(String),
    /// 连接建立或维护失败（网络抖动、连接中断、远端 5xx 瞬时不可用）。
    #[error("连接失败: {0}")]
    Connection(String),
    /// 远端返回业务/协议错误（4xx、404、403 以及未完成分片的孤儿风险）。
    #[error("远端返回错误: {0}")]
    Backend(String),
    /// 序列化或解析失败（XML / TOML）。
    #[error("序列化失败: {0}")]
    Serialization(String),
    /// 本地网络或文件系统 I/O 失败。
    #[error("I/O 失败: {0}")]
    Io(#[from] std::io::Error),
    /// 操作超时（单请求或含重试的整段 deadline）。
    #[error("操作超时: {0}")]
    Timeout(String),
    /// 当前能力不支持，或客户端已关闭等本地生命周期拒绝。
    #[error("不支持的操作: {0}")]
    Unsupported(String),
}

impl OssError {
    /// 是否属于可安全重试的瞬时错误。
    ///
    /// 仅 [`OssError::Connection`] 可重试，且鉴权/权限失败是例外：
    /// 401/403 重放多少次都不会成功，必须立即返回，避免把凭证问题放大成风控事件。
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Connection(message) => !is_auth_failure(message),
            Self::Config(_)
            | Self::Backend(_)
            | Self::Serialization(_)
            | Self::Io(_)
            | Self::Timeout(_)
            | Self::Unsupported(_) => false,
        }
    }
}

/// 判定文案是否属于鉴权/权限降级（不区分大小写）。
///
/// 与 [`crate::is_oss_retryable`] 共用；401/403 在 `status_error` 中已归入
/// [`OssError::Backend`]（本不可重试），此处的文案判定是第二道防线：
/// 即使未来有人把鉴权失败归入 [`OssError::Connection`]，也不会被重试。
#[must_use]
pub(crate) fn is_auth_failure(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("auth/forbidden")
        || lowered.contains("unauthorized")
        || lowered.contains("forbidden")
}

/// crate 专用 `Result` 别名。
pub type OssResult<T> = Result<T, OssError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(OssError::Connection("oss GET network: connection reset".into()).is_retryable());
        assert!(OssError::Connection("oss PUT server status=500".into()).is_retryable());
        // 鉴权降级不重试（即使被归入 Connection）
        assert!(!OssError::Connection("oss GET auth/forbidden status=403".into()).is_retryable());
        assert!(!OssError::Connection("HTTP unauthorized".into()).is_retryable());
        assert!(!OssError::Connection("403 Forbidden".into()).is_retryable());
        assert!(!OssError::Config("bad".into()).is_retryable());
        assert!(!OssError::Backend("HTTP 404".into()).is_retryable());
        assert!(!OssError::Serialization("xml".into()).is_retryable());
        assert!(!OssError::Timeout("slow".into()).is_retryable());
        assert!(!OssError::Unsupported("closed".into()).is_retryable());
        assert!(!OssError::Io(std::io::Error::other("disk")).is_retryable());
    }

    #[test]
    fn display_prefixes_are_stable() {
        assert_eq!(OssError::Config("x".into()).to_string(), "配置无效: x");
        assert_eq!(OssError::Connection("x".into()).to_string(), "连接失败: x");
        assert_eq!(OssError::Backend("x".into()).to_string(), "远端返回错误: x");
        assert_eq!(
            OssError::Serialization("x".into()).to_string(),
            "序列化失败: x"
        );
        assert_eq!(OssError::Timeout("x".into()).to_string(), "操作超时: x");
        assert_eq!(
            OssError::Unsupported("x".into()).to_string(),
            "不支持的操作: x"
        );
        assert_eq!(
            OssError::Io(std::io::Error::other("x")).to_string(),
            "I/O 失败: x"
        );
    }

    #[test]
    fn io_error_converts_via_from() {
        let error: OssError = std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into();
        assert!(matches!(error, OssError::Io(_)));
    }
}
