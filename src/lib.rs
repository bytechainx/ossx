//! # ossx — 阿里云 OSS 适配器
//!
//! `ossx` 是面向生产使用的阿里云对象存储（OSS）客户端：`reqwest` + OSS Signature V1，
//! 覆盖对象读写、流式传输、分片上传、预签名 URL、凭据轮换与连接池统计。
//! 它不依赖任何内部框架，配置、错误、重试与并发治理全部在本 crate 内自洽实现。
//!
//! ## 最小可运行示例
//!
//! ```no_run
//! use bytes::Bytes;
//! use ossx::{OssClient, OssConfig, PresignOptions};
//!
//! # async fn run() -> Result<(), ossx::OssError> {
//! // 1. 配置：也可用 OssConfig::from_env()（FOUNDATIONX_OSSX_*）或 OssConfig::from_toml()
//! let config = OssConfig::builder()
//!     .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
//!     .bucket("demo-bucket")
//!     .access_key_id("LTAI5tExample")
//!     .access_key_secret("your-access-key-secret")
//!     .build()?;
//!
//! // 2. 构造客户端（不发起网络请求）
//! let client = OssClient::connect(config).await?;
//!
//! // 3. 上传 / 下载 / 删除
//! client.put_object("dir/object.txt", Bytes::from_static(b"hello ossx")).await?;
//! let body = client.get_object("dir/object.txt").await?;
//! assert_eq!(body, Bytes::from_static(b"hello ossx"));
//! client.delete_object("dir/object.txt").await?;
//!
//! // 4. 预签名 URL（GET，1 小时有效）
//! let url = client.presign_url("dir/object.txt", &PresignOptions::default())?;
//! println!("{url}");
//!
//! // 5. 探活
//! client.ping().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## 公开 API 一览
//!
//! | 主题 | 类型 / 函数 |
//! | --- | --- |
//! | 错误 | [`OssError`]（`is_retryable`）、[`OssResult`] |
//! | 配置 | [`OssConfig`]、[`OssConfigBuilder`]、`ENV_*`、`HARD_MAX_*` |
//! | 客户端 | [`OssClient`]（`put_object` / `get_object` / `head_object` / `delete_object` / `list_objects` / multipart / `ping` / `health_check`） |
//! | 连接池 | [`OssPool`]、[`OssHealth`]、[`OssPoolStats`] |
//! | 签名 | [`sign_v1`]、[`authorization_header`]、[`canonicalized_resource`]、[`canonicalized_resource_with_subresources`]、[`split_parts`] |
//! | 预签名 | [`presign_url`]、[`PresignOptions`] |
//! | 凭据 | [`CredentialProvider`]、[`OssCredentials`]、[`StaticCredentialProvider`] |
//! | 数据形态 | [`ObjectKey`]、[`ObjectMeta`]、[`UploadOptions`]、[`DownloadOptions`]、[`ByteStream`]、[`byte_stream_from_bytes`] |
//! | 重试 | [`RetryConfig`]、[`default_retry_config`]、[`is_oss_retryable`]、[`with_retry`]、[`with_retry_deadline`] |
//!
//! ## 安全约定
//!
//! - `AccessKeySecret` 只出现在签名计算中，`Debug` 输出与错误消息均不回显；
//! - 远程 endpoint 强制 HTTPS，HTTP 仅允许 loopback 开发端点；
//! - 所有资源上界（对象大小、缓冲、并发、错误体）在构建期校验并 clamp 到 `HARD_MAX_*`；
//! - 重试只发生在可安全重放的瞬时错误上，鉴权/权限失败立即返回。

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unreachable_pub)]

mod client;
mod config;
mod credential;
mod error;
mod pool;
mod presign;
mod retry;
mod sign;
mod types;

pub use client::{
    MultipartOrphanAudit, OssClient, MAX_MULTIPART_PARTS, MAX_MULTIPART_PART_BYTES,
    MAX_OBJECT_KEY_BYTES, MIN_MULTIPART_PART_BYTES, ORPHAN_AUDIT_CAPACITY,
};
pub use config::{
    OssConfig, OssConfigBuilder, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET, ENV_ACQUIRE_TIMEOUT_MS,
    ENV_BUCKET, ENV_ENDPOINT, ENV_MAX_BUFFER_BYTES, ENV_MAX_ERROR_BODY_BYTES, ENV_MAX_IN_FLIGHT,
    ENV_MAX_OBJECT_BYTES, ENV_OPERATION_DEADLINE_MS, ENV_REGION, ENV_REQUEST_TIMEOUT_MS,
    HARD_MAX_BUFFER_BYTES, HARD_MAX_ERROR_BODY_BYTES, HARD_MAX_IN_FLIGHT, HARD_MAX_OBJECT_BYTES,
};
pub use credential::{CredentialProvider, OssCredentials, StaticCredentialProvider};
pub use error::{OssError, OssResult};
pub use pool::{OssHealth, OssPool, OssPoolStats};
pub use presign::{presign_url, PresignOptions};
pub use retry::{
    default_retry_config, is_oss_retryable, with_retry, with_retry_deadline, with_retry_default,
    RetryConfig, MAX_RETRY_ATTEMPTS,
};
pub use sign::{
    authorization_header, canonicalized_resource, canonicalized_resource_with_subresources,
    sign_v1, split_parts,
};
pub use types::{
    byte_stream_from_bytes, ByteStream, DownloadOptions, ObjectKey, ObjectMeta, UploadOptions,
};

#[cfg(test)]
mod public_api_surface {
    use super::*;

    /// crate-root 导出被逐一点名，防止重构时无声破坏公共 API。
    #[test]
    fn exports_are_named_and_usable() {
        assert_eq!(ENV_ENDPOINT, "FOUNDATIONX_OSSX_ENDPOINT");
        assert_eq!(ENV_ACCESS_KEY_SECRET, "FOUNDATIONX_OSSX_ACCESS_KEY_SECRET");
        assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);

        let config: OssConfig = OssConfig::builder()
            .endpoint("https://oss.example.com")
            .bucket("b")
            .access_key_id("id")
            .access_key_secret("sec")
            .build()
            .expect("config");
        let builder: OssConfigBuilder = OssConfig::builder();
        let _ = builder;

        let resource = canonicalized_resource("b", "/k");
        let signature = sign_v1("sec", "GET", "", "", "date", "", &resource);
        assert!(authorization_header("id", &signature).starts_with("OSS id:"));
        assert!(
            canonicalized_resource_with_subresources("b", "k", &[("uploads", None)])
                .ends_with("?uploads")
        );
        assert_eq!(split_parts(b"abc", 2).len(), 2);

        let options = PresignOptions::default();
        assert!(presign_url("https://oss.example.com", "b", "k", "id", "sec", &options).is_ok());

        let retry: RetryConfig = default_retry_config();
        assert!(retry.validate().is_ok());
        assert!(is_oss_retryable(&OssError::Connection("network".into())));
        assert!(!is_oss_retryable(&OssError::Config("bad".into())));

        let credentials = OssCredentials {
            access_key_id: "id".into(),
            access_key_secret: "sec".into(),
            security_token: None,
        };
        assert_eq!(credentials.access_key_id, "id");
        let provider: std::sync::Arc<dyn CredentialProvider> =
            std::sync::Arc::new(StaticCredentialProvider::new("id", "sec", None));
        assert_eq!(provider.provider_name(), "static");

        let key = ObjectKey::new("a/b").expect("key");
        assert_eq!(key.as_str(), "a/b");
        let meta = ObjectMeta::with_size(1);
        assert_eq!(meta.size, 1);
        let _ = UploadOptions::default();
        let _ = DownloadOptions::default();
        let _: ByteStream = byte_stream_from_bytes(bytes::Bytes::from_static(b"x"));

        let _ = config.bucket.len();
        let _ = OssPoolStats::default();
        let _ = MAX_MULTIPART_PART_BYTES;
        let _ = MIN_MULTIPART_PART_BYTES;
        let _ = MAX_MULTIPART_PARTS;
        let _ = MAX_OBJECT_KEY_BYTES;
        let _ = ORPHAN_AUDIT_CAPACITY;
        let _ = MAX_RETRY_ATTEMPTS;
    }

    /// 公开类型必须可跨线程共享（`tokio::spawn` / `rayon` / 静态缓存的前置条件）。
    ///
    /// [`ByteStream`] 只要求 `Send`：字节流是被单个任务顺序消费的资源，
    /// 让它 `Sync` 只会无谓收紧实现方的约束。
    #[test]
    fn public_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}
        fn assert_clone<T: Clone>() {}

        assert_send_sync::<OssClient>();
        assert_send_sync::<OssPool>();
        assert_send_sync::<OssConfig>();
        assert_send_sync::<OssConfigBuilder>();
        assert_send_sync::<OssError>();
        assert_send_sync::<OssResult<()>>();
        assert_send_sync::<MultipartOrphanAudit>();
        assert_send_sync::<OssHealth>();
        assert_send_sync::<OssPoolStats>();
        assert_send_sync::<PresignOptions>();
        assert_send_sync::<RetryConfig>();
        assert_send_sync::<ObjectKey>();
        assert_send_sync::<ObjectMeta>();
        assert_send_sync::<UploadOptions>();
        assert_send_sync::<DownloadOptions>();
        assert_send::<ByteStream>();
        assert_send_sync::<OssCredentials>();
        assert_send_sync::<StaticCredentialProvider>();
        assert_send_sync::<std::sync::Arc<dyn CredentialProvider>>();

        assert_clone::<OssClient>();
        assert_clone::<OssPool>();
        assert_clone::<OssConfig>();
        assert_clone::<OssHealth>();
        assert_clone::<OssPoolStats>();
        assert_clone::<MultipartOrphanAudit>();
        assert_clone::<PresignOptions>();
        assert_clone::<RetryConfig>();
    }

    /// 公开错误类型不暴露凭据（回归断言）。
    #[test]
    fn error_never_echoes_secret() {
        let error = OssError::Connection("oss GET network: connection reset".into());
        assert!(!error.to_string().contains("access_key_secret"));
        let config_debug = format!(
            "{:?}",
            OssConfig::builder()
                .endpoint("https://oss.example.com")
                .bucket("b")
                .access_key_id("LTAI5tSecretId")
                .access_key_secret("leaked-secret-value")
                .build()
                .expect("config")
        );
        assert!(!config_debug.contains("leaked-secret-value"));
    }
}
