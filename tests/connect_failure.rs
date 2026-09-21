//! 失败路径：不可达 endpoint 下 `ping` / 数据面操作必须返回 `Err`，且健康检查
//! 必须以结构化结果表达「不可用」，绝不静默成功。
//!
//! 使用 `localhost:1`（必然拒绝连接）作为不可达 endpoint，
//! 不依赖任何真实 OSS 服务。

use std::time::Duration;

use bytes::Bytes;
use ossx::{OssClient, OssConfig, OssError, OssPool};

fn unreachable_config() -> OssConfig {
    OssConfig::builder()
        .endpoint("http://localhost:1")
        .bucket("unreachable-bucket")
        .access_key_id("id")
        .access_key_secret("secret")
        .request_timeout(Duration::from_millis(400))
        .operation_deadline(Duration::from_secs(1))
        .build()
        .expect("配置")
}

#[tokio::test]
async fn ping_on_unreachable_endpoint_returns_error() {
    let client = OssClient::new(unreachable_config()).expect("client");
    let error = client
        .ping()
        .await
        .expect_err("不可达 endpoint 必须返回 Err");
    assert!(
        matches!(error, OssError::Connection(_) | OssError::Timeout(_)),
        "期望连接/超时分类，实际 {error:?}"
    );
}

#[tokio::test]
async fn health_check_reports_not_ready_without_error() {
    let client = OssClient::new(unreachable_config()).expect("client");
    let health = client.health_check().await.expect("探活结论应是结构化结果");
    assert!(!health.ready);
    assert!(!health.bucket_accessible);
    assert!(!health.detail.is_empty());
}

#[tokio::test]
async fn data_plane_operations_fail_on_unreachable_endpoint() {
    let client = OssClient::new(unreachable_config()).expect("client");
    assert!(client
        .put_object("key", Bytes::from_static(b"v"))
        .await
        .is_err());
    assert!(client.get_object("key").await.is_err());
    assert!(client.head_object("key").await.is_err());
    assert!(client.list_objects("").await.is_err());
    assert!(client.delete_object("key").await.is_err());
    assert!(client.initiate_multipart("key").await.is_err());
}

#[tokio::test]
async fn closed_client_rejects_before_any_network_call() {
    let client = OssClient::new(unreachable_config()).expect("client");
    client.close();
    let error = client.ping().await.expect_err("关闭后必须拒绝");
    assert!(matches!(error, OssError::Unsupported(_)));
    assert!(!error.is_retryable(), "本地生命周期拒绝不可重试");
}

#[tokio::test]
async fn pool_failure_paths_are_structured() {
    let pool = OssPool::new(unreachable_config()).expect("pool");
    assert!(pool.ping().await.is_err());
    let health = pool.health_check().await.expect("探活结论应是结构化结果");
    assert!(!health.ready);
    assert!(!health.detail.is_empty());
    let timed = pool
        .health(Duration::from_millis(200))
        .await
        .expect("结构化结果");
    assert!(!timed.ready);

    assert!(pool.get_object("key").await.is_err());
    let stats = pool.stats();
    assert!(stats.gets_err >= 1, "失败必须计入统计");
    assert_eq!(stats.gets_ok, 0);

    pool.close();
    assert!(pool.stats().closed);
    assert!(pool.ping().await.is_err());
}

#[tokio::test]
async fn invalid_key_is_rejected_before_network() {
    let client = OssClient::new(unreachable_config()).expect("client");
    let error = client
        .put_object("../escape", Bytes::from_static(b"v"))
        .await
        .expect_err("非法 key");
    assert!(matches!(error, OssError::Config(_)));
    assert!(!error.is_retryable());
}
