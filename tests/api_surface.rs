#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! 公共 API 表面回归：导出项存在、可用，且公开类型满足 `Send + Sync`。

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ossx::{
    authorization_header, byte_stream_from_bytes, canonicalized_resource,
    canonicalized_resource_with_subresources, default_retry_config, is_oss_retryable, presign_url,
    sign_v1, split_parts, with_retry, with_retry_deadline, with_retry_default, ByteStream,
    CredentialProvider, DownloadOptions, MultipartOrphanAudit, ObjectKey, ObjectMeta, OssClient,
    OssConfig, OssConfigBuilder, OssCredentials, OssError, OssHealth, OssPool, OssPoolStats,
    OssResult, PresignOptions, RetryConfig, StaticCredentialProvider, UploadOptions,
    ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET, ENV_ACQUIRE_TIMEOUT_MS, ENV_BUCKET, ENV_ENDPOINT,
    ENV_MAX_BUFFER_BYTES, ENV_MAX_ERROR_BODY_BYTES, ENV_MAX_IN_FLIGHT, ENV_MAX_OBJECT_BYTES,
    ENV_OPERATION_DEADLINE_MS, ENV_REGION, ENV_REQUEST_TIMEOUT_MS, HARD_MAX_BUFFER_BYTES,
    HARD_MAX_ERROR_BODY_BYTES, HARD_MAX_IN_FLIGHT, HARD_MAX_OBJECT_BYTES, MAX_MULTIPART_PARTS,
    MAX_MULTIPART_PART_BYTES, MAX_OBJECT_KEY_BYTES, MAX_RETRY_ATTEMPTS, MIN_MULTIPART_PART_BYTES,
    ORPHAN_AUDIT_CAPACITY,
};

#[test]
fn constants_are_stable() {
    assert_eq!(ENV_ENDPOINT, "FOUNDATIONX_OSSX_ENDPOINT");
    assert_eq!(ENV_BUCKET, "FOUNDATIONX_OSSX_BUCKET");
    assert_eq!(ENV_ACCESS_KEY_ID, "FOUNDATIONX_OSSX_ACCESS_KEY_ID");
    assert_eq!(ENV_ACCESS_KEY_SECRET, "FOUNDATIONX_OSSX_ACCESS_KEY_SECRET");
    assert_eq!(ENV_REGION, "FOUNDATIONX_OSSX_REGION");
    assert_eq!(
        ENV_REQUEST_TIMEOUT_MS,
        "FOUNDATIONX_OSSX_REQUEST_TIMEOUT_MS"
    );
    assert_eq!(
        ENV_OPERATION_DEADLINE_MS,
        "FOUNDATIONX_OSSX_OPERATION_DEADLINE_MS"
    );
    assert_eq!(
        ENV_ACQUIRE_TIMEOUT_MS,
        "FOUNDATIONX_OSSX_ACQUIRE_TIMEOUT_MS"
    );
    assert_eq!(ENV_MAX_IN_FLIGHT, "FOUNDATIONX_OSSX_MAX_IN_FLIGHT");
    assert_eq!(ENV_MAX_OBJECT_BYTES, "FOUNDATIONX_OSSX_MAX_OBJECT_BYTES");
    assert_eq!(ENV_MAX_BUFFER_BYTES, "FOUNDATIONX_OSSX_MAX_BUFFER_BYTES");
    assert_eq!(
        ENV_MAX_ERROR_BODY_BYTES,
        "FOUNDATIONX_OSSX_MAX_ERROR_BODY_BYTES"
    );

    assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);
    assert_eq!(HARD_MAX_OBJECT_BYTES, 5 * 1024 * 1024 * 1024);
    assert_eq!(HARD_MAX_BUFFER_BYTES, 512 * 1024 * 1024);
    assert_eq!(HARD_MAX_ERROR_BODY_BYTES, 1024 * 1024);

    assert_eq!(MIN_MULTIPART_PART_BYTES, 100 * 1024);
    assert_eq!(MAX_MULTIPART_PART_BYTES, 512 * 1024 * 1024);
    assert_eq!(MAX_MULTIPART_PARTS, 10_000);
    assert_eq!(MAX_OBJECT_KEY_BYTES, 1_023);
    assert_eq!(ORPHAN_AUDIT_CAPACITY, 1_024);
    assert_eq!(MAX_RETRY_ATTEMPTS, 10);
}

#[test]
fn send_sync_and_clone_bounds() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    fn assert_clone<T: Clone>() {}
    fn assert_debug<T: std::fmt::Debug>() {}

    assert_send_sync::<OssClient>();
    assert_send_sync::<OssPool>();
    assert_send_sync::<OssConfig>();
    assert_send_sync::<OssConfigBuilder>();
    assert_send_sync::<OssError>();
    assert_send_sync::<OssResult<()>>();
    assert_send_sync::<OssHealth>();
    assert_send_sync::<OssPoolStats>();
    assert_send_sync::<MultipartOrphanAudit>();
    assert_send_sync::<PresignOptions>();
    assert_send_sync::<RetryConfig>();
    assert_send_sync::<ObjectKey>();
    assert_send_sync::<ObjectMeta>();
    assert_send_sync::<UploadOptions>();
    assert_send_sync::<DownloadOptions>();
    assert_send_sync::<OssCredentials>();
    assert_send_sync::<StaticCredentialProvider>();
    assert_send_sync::<Arc<dyn CredentialProvider>>();
    // 字节流只需 Send：它由单个任务顺序消费
    assert_send::<ByteStream>();

    assert_clone::<OssClient>();
    assert_clone::<OssPool>();
    assert_clone::<OssConfig>();
    assert_clone::<OssConfigBuilder>();
    assert_clone::<MultipartOrphanAudit>();
    assert_clone::<OssHealth>();
    assert_clone::<OssPoolStats>();
    assert_clone::<RetryConfig>();
    assert_clone::<ObjectKey>();
    assert_clone::<ObjectMeta>();
    assert_clone::<PresignOptions>();
    assert_clone::<OssCredentials>();

    assert_debug::<OssClient>();
    assert_debug::<OssPool>();
    assert_debug::<OssConfig>();
    assert_debug::<OssError>();
    assert_debug::<MultipartOrphanAudit>();
    assert_debug::<OssHealth>();
    assert_debug::<OssPoolStats>();
    assert_debug::<ObjectKey>();
    assert_debug::<ObjectMeta>();
}

#[test]
fn public_api_is_usable_end_to_end_without_network() {
    let config: OssConfig = OssConfig::builder()
        .endpoint("https://oss.example.com")
        .bucket("example-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("secret")
        .region("cn-hangzhou")
        .request_timeout(Duration::from_secs(5))
        .operation_deadline(Duration::from_secs(10))
        .acquire_timeout(Duration::from_secs(1))
        .max_in_flight(4)
        .max_object_bytes(1024 * 1024)
        .max_buffer_bytes(1024 * 1024)
        .max_error_body_bytes(4096)
        .sse_enabled(false)
        .build()
        .expect("config");
    config.validate().expect("validate");

    // OssClient / OssPool 均可同步构造且可克隆
    let client = OssClient::new(config.clone()).expect("client");
    let cloned = client.clone();
    assert_eq!(cloned.config().bucket, "example-bucket");
    assert_eq!(client.retry_config(), default_retry_config());
    assert!(client.multipart_orphan_audits().is_empty());
    assert_eq!(client.orphan_audit_overflow_count(), 0);
    assert!(!client.is_closed());

    let pool = OssPool::new(config).expect("pool");
    assert_eq!(pool.stats().max_in_flight, 4);
    assert_eq!(pool.provider_name(), "static");
    assert_eq!(pool.retry_config(), default_retry_config());

    // 预签名无需网络
    let url = client
        .presign_url("dir/object.txt", &PresignOptions::default())
        .expect("presign");
    assert!(url.starts_with("https://example-bucket.oss.example.com/dir/object.txt?"));
    assert!(presign_url(
        "https://oss.example.com",
        "example-bucket",
        "k",
        "id",
        "sec",
        &PresignOptions::default(),
    )
    .is_ok());

    // 纯函数与类型
    let signature = sign_v1("secret", "GET", "", "", "date", "", "/example-bucket/k");
    assert!(!signature.is_empty());
    assert_eq!(
        authorization_header("id", &signature),
        format!("OSS id:{signature}")
    );
    assert_eq!(canonicalized_resource("b", "k"), "/b/k");
    assert!(
        canonicalized_resource_with_subresources("b", "k", &[("uploads", None)])
            .ends_with("?uploads")
    );
    assert_eq!(split_parts(b"abcd", 2).len(), 2);
    assert_eq!(ObjectKey::new("a/b").expect("key").as_str(), "a/b");
    assert_eq!(ObjectMeta::with_size(7).size, 7);
    let stream: ByteStream = byte_stream_from_bytes(Bytes::from_static(b"x"));
    drop(stream);
}

#[tokio::test]
async fn retry_helpers_are_usable() {
    let config = RetryConfig::fixed(2, 0);
    let value = with_retry(&config, "op", || async { Ok::<_, OssError>(1u8) })
        .await
        .expect("ok");
    assert_eq!(value, 1);
    let value = with_retry_default(&config, "op", || async { Ok::<_, OssError>(2u8) })
        .await
        .expect("ok");
    assert_eq!(value, 2);
    let value = with_retry_deadline(&config, "op", Duration::from_secs(1), || async {
        Ok::<_, OssError>(3u8)
    })
    .await
    .expect("ok");
    assert_eq!(value, 3);

    assert!(is_oss_retryable(&OssError::Connection("network".into())));
    assert!(!is_oss_retryable(&OssError::Config("bad".into())));
    assert!(default_retry_config().validate().is_ok());
}

#[test]
fn debug_and_errors_never_expose_secret() {
    let config = OssConfig::builder()
        .endpoint("https://oss.example.com")
        .bucket("b")
        .access_key_id("LTAI5tVeryLongAccessKeyId")
        .access_key_secret("super-secret-value")
        .security_token("sts-token-value")
        .build()
        .expect("config");
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("super-secret-value"));
    assert!(!debug.contains("LTAI5tVeryLongAccessKeyId"));
    assert!(!debug.contains("sts-token-value"));

    let client_debug = format!("{:?}", OssClient::new(config).expect("client"));
    assert!(!client_debug.contains("super-secret-value"));

    let credentials = OssCredentials {
        access_key_id: "AKID".into(),
        access_key_secret: "super-secret-value".into(),
        security_token: None,
    };
    assert!(!format!("{credentials:?}").contains("super-secret-value"));

    // 错误消息同样不得回显凭据
    let error = OssError::Backend("oss GET auth/forbidden status=403 Forbidden".into());
    let display = error.to_string();
    assert!(!display.contains("super-secret-value"));
    assert!(!error.is_retryable());
}
