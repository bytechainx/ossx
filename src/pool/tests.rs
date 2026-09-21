//! `pool` 模块单元测试。

use super::*;

fn test_config() -> OssConfig {
    OssConfig::builder()
        .endpoint("https://oss.example.com")
        .bucket("test-bucket")
        .access_key_id("test-id")
        .access_key_secret("test-secret")
        .build()
        .expect("config")
}

fn test_pool() -> OssPool {
    OssPool::new(test_config()).expect("pool")
}

#[test]
fn virtual_host_and_object_url_are_shared() {
    assert_eq!(
        virtual_host_base("https://oss.example.com", "b")
            .expect("base")
            .host_str(),
        Some("b.oss.example.com")
    );
    let base = virtual_host_base("https://oss.example.com", "b").expect("base");
    let url = object_url(&base, "path/to/object.txt").expect("object url");
    assert_eq!(url.path(), "/path/to/object.txt");
}

#[test]
fn stats_defaults_and_provider_name() {
    let stats = test_pool().stats();
    assert!(!stats.closed);
    assert_eq!(stats.max_in_flight, 64);
    assert_eq!(stats.in_flight, 0);
    assert_eq!(stats.puts_ok, 0);
    assert_eq!(stats.puts_ok, stats.puts_err);
    assert_eq!(test_pool().provider_name(), "static");
    assert!(format!("{:?}", test_pool()).contains("static"));
}

#[tokio::test]
async fn close_rejects_and_is_idempotent() {
    let pool = test_pool();
    pool.close();
    pool.close();
    assert!(pool.stats().closed);
    let error = pool
        .put_object("k", Bytes::from_static(b"v"))
        .await
        .expect_err("closed pool");
    assert!(matches!(error, OssError::Unsupported(_)));
    assert!(pool.get_object("k").await.is_err());
    assert!(pool.delete_object("k").await.is_err());
    assert!(pool.head("k").await.is_err());
    assert_eq!(
        pool.stats().cancelled,
        4,
        "acquire 在池关闭时计入 cancelled"
    );
    assert_eq!(pool.stats().puts_err, 1);
}

#[test]
fn invalid_keys_and_sizes_fail_closed() {
    let pool = test_pool();
    assert!(normalize_key("").is_err());
    assert!(normalize_key("../escape").is_err());
    assert!(pool
        .validate_size(pool.config().max_object_bytes + 1)
        .is_err());
    assert!(pool
        .validate_size(pool.config().max_buffer_bytes + 1)
        .is_err());
    assert!(pool.validate_size(1).is_ok());
}

#[tokio::test]
async fn put_stream_rejects_unsupported_metadata_and_part_size() {
    let pool = test_pool();
    let options = UploadOptions {
        metadata: Some(vec![("k".into(), "v".into())]),
        ..UploadOptions::default()
    };
    let error = pool
        .put_stream(
            "k",
            crate::types::byte_stream_from_bytes(Bytes::from_static(b"x")),
            options,
        )
        .await
        .expect_err("metadata 必须 fail-closed");
    assert!(matches!(error, OssError::Unsupported(_)));

    let options = UploadOptions {
        part_size: 1,
        ..UploadOptions::default()
    };
    let error = pool
        .put_stream(
            "k",
            crate::types::byte_stream_from_bytes(Bytes::from_static(b"x")),
            options,
        )
        .await
        .expect_err("非法分片大小必须被拒绝");
    assert!(matches!(error, OssError::Config(_)));
}

#[tokio::test]
async fn custom_credential_provider_is_used() {
    struct CountingProvider {
        calls: Arc<AtomicU64>,
    }

    impl CredentialProvider for CountingProvider {
        fn get_credentials(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = OssResult<OssCredentials>> + Send + '_>,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(OssCredentials {
                    access_key_id: "custom-id".into(),
                    access_key_secret: "custom-secret".into(),
                    security_token: Some("sts".into()),
                })
            })
        }

        fn provider_name(&self) -> &'static str {
            "counting"
        }
    }

    let calls = Arc::new(AtomicU64::new(0));
    let pool = OssPool::new_with_retry(
        test_config(),
        default_retry_config(),
        Some(Arc::new(CountingProvider {
            calls: Arc::clone(&calls),
        })),
    )
    .expect("pool");
    assert_eq!(pool.provider_name(), "counting");
    let credentials = pool.credentials().await.expect("credentials");
    assert_eq!(credentials.access_key_id, "custom-id");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn acquire_is_bounded_by_concurrency_and_timeout() {
    let config = OssConfig::builder()
        .endpoint("https://oss.example.com")
        .bucket("test-bucket")
        .access_key_id("id")
        .access_key_secret("secret")
        .max_in_flight(1)
        .acquire_timeout(Duration::from_millis(200))
        .build()
        .expect("config");
    let pool = OssPool::new(config).expect("pool");
    let permit = pool.acquire().await.expect("first permit");
    let error = pool
        .acquire()
        .await
        .expect_err("second permit must time out");
    assert!(matches!(error, OssError::Timeout(_)));
    assert_eq!(pool.stats().timeouts, 1);
    assert_eq!(pool.stats().in_flight, 1);
    drop(permit);
    let _permit = pool.acquire().await.expect("permit released");
    assert_eq!(pool.stats().in_flight, 1);
}

#[tokio::test]
async fn collect_parts_splits_stream_by_part_size() {
    let pool = test_pool();
    let stream =
        crate::types::byte_stream_from_bytes(Bytes::from(vec![
            b'x';
            MIN_MULTIPART_PART_BYTES * 2 + 1
        ]));
    let parts = pool
        .collect_parts(stream, MIN_MULTIPART_PART_BYTES)
        .await
        .expect("parts");
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].len(), MIN_MULTIPART_PART_BYTES);
    assert_eq!(parts[1].len(), MIN_MULTIPART_PART_BYTES);
    assert_eq!(parts[2].len(), 1);
}

#[tokio::test]
async fn health_check_reports_unreachable_endpoint() {
    let config = OssConfig::builder()
        .endpoint("http://localhost:1")
        .bucket("test-bucket")
        .access_key_id("id")
        .access_key_secret("secret")
        .request_timeout(Duration::from_millis(300))
        .operation_deadline(Duration::from_millis(500))
        .build()
        .expect("config");
    let pool = OssPool::new(config).expect("pool");
    let health = pool
        .health(Duration::from_millis(500))
        .await
        .expect("结构化结果");
    assert!(!health.ready);
    assert!(!health.bucket_accessible);
    assert!(!health.detail.is_empty());
    assert!(pool.ping().await.is_err(), "不可达 endpoint 必须返回 Err");
}
