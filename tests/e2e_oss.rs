#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! E2E（ossx）：离线走公开面 fail-closed 串；真连走 `#[ignore]` 对象往返。
//!
//! 与 `live_oss.rs`（拆条冒烟）不同：本文件是分层里的 **E2E** 路径。
//! 离线断言配置 → 校验 → 构造 → 不可达数据面 / 关闭。
//! 完整 `cargo +nightly public-api` 清单核对是独立命令
//! `node scripts/verify-e2e-coverage.mjs ossx`，不在本页写条数。
//!
//! 凭据只从 `FOUNDATIONX_OSSX_*` 读取，不硬编码。

use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind};
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use ossx::{
    authorization_header, byte_stream_from_bytes, canonicalized_resource,
    canonicalized_resource_with_subresources, default_retry_config, is_oss_retryable, presign_url,
    sign_v1, split_parts, with_retry, with_retry_deadline, with_retry_default, CredentialProvider,
    DownloadOptions, ObjectKey, ObjectMeta, OssClient, OssConfig, OssError, OssPool,
    OssPoolStats, PresignOptions, RetryConfig, StaticCredentialProvider, UploadOptions,
    ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET, ENV_ACQUIRE_TIMEOUT_MS, ENV_BUCKET, ENV_ENDPOINT,
    ENV_MAX_BUFFER_BYTES, ENV_MAX_ERROR_BODY_BYTES, ENV_MAX_IN_FLIGHT, ENV_MAX_OBJECT_BYTES,
    ENV_OPERATION_DEADLINE_MS, ENV_REGION, ENV_REQUEST_TIMEOUT_MS, HARD_MAX_BUFFER_BYTES,
    HARD_MAX_ERROR_BODY_BYTES, HARD_MAX_IN_FLIGHT, HARD_MAX_OBJECT_BYTES, MAX_MULTIPART_PARTS,
    MAX_MULTIPART_PART_BYTES, MAX_OBJECT_KEY_BYTES, MAX_RETRY_ATTEMPTS, MIN_MULTIPART_PART_BYTES,
    ORPHAN_AUDIT_CAPACITY,
};

const E2E_MANIFEST: &[(&str, &str)] = &[
    ("const", "ENV_ACCESS_KEY_ID"),
    ("const", "ENV_ACCESS_KEY_SECRET"),
    ("const", "ENV_ACQUIRE_TIMEOUT_MS"),
    ("const", "ENV_BUCKET"),
    ("const", "ENV_ENDPOINT"),
    ("const", "ENV_MAX_BUFFER_BYTES"),
    ("const", "ENV_MAX_ERROR_BODY_BYTES"),
    ("const", "ENV_MAX_IN_FLIGHT"),
    ("const", "ENV_MAX_OBJECT_BYTES"),
    ("const", "ENV_OPERATION_DEADLINE_MS"),
    ("const", "ENV_REGION"),
    ("const", "ENV_REQUEST_TIMEOUT_MS"),
    ("const", "HARD_MAX_BUFFER_BYTES"),
    ("const", "HARD_MAX_ERROR_BODY_BYTES"),
    ("const", "HARD_MAX_IN_FLIGHT"),
    ("const", "HARD_MAX_OBJECT_BYTES"),
    ("const", "MAX_MULTIPART_PARTS"),
    ("const", "MAX_MULTIPART_PART_BYTES"),
    ("const", "MAX_OBJECT_KEY_BYTES"),
    ("const", "MAX_RETRY_ATTEMPTS"),
    ("const", "MIN_MULTIPART_PART_BYTES"),
    ("const", "ORPHAN_AUDIT_CAPACITY"),
    ("type", "OssError"),
    ("variant", "OssError::Backend"),
    ("variant", "OssError::Config"),
    ("variant", "OssError::Connection"),
    ("variant", "OssError::Io"),
    ("variant", "OssError::Serialization"),
    ("variant", "OssError::Timeout"),
    ("variant", "OssError::Unsupported"),
    ("fn", "OssError::is_retryable"),
    ("type", "OssConfig"),
    ("fn", "OssConfig::builder"),
    ("fn", "OssConfig::from_env"),
    ("fn", "OssConfig::from_toml"),
    ("fn", "OssConfig::from_toml_file"),
    ("fn", "OssConfig::validate"),
    ("fn", "OssConfigBuilder::access_key_id"),
    ("fn", "OssConfigBuilder::access_key_secret"),
    ("fn", "OssConfigBuilder::bucket"),
    ("fn", "OssConfigBuilder::build"),
    ("fn", "OssConfigBuilder::endpoint"),
    ("type", "OssClient"),
    ("fn", "OssClient::new"),
    ("fn", "OssClient::connect"),
    ("fn", "OssClient::ping"),
    ("fn", "OssClient::health_check"),
    ("fn", "OssClient::put_object"),
    ("fn", "OssClient::get_object"),
    ("fn", "OssClient::delete_object"),
    ("fn", "OssClient::close"),
    ("fn", "OssClient::is_closed"),
    ("type", "OssPool"),
    ("fn", "OssPool::new"),
    ("fn", "OssPool::connect"),
    ("fn", "OssPool::ping"),
    ("fn", "OssPool::stats"),
    ("fn", "OssPool::close"),
    ("fn", "sign_v1"),
    ("fn", "authorization_header"),
    ("fn", "canonicalized_resource"),
    ("fn", "canonicalized_resource_with_subresources"),
    ("fn", "split_parts"),
    ("fn", "presign_url"),
    ("fn", "ObjectKey::new"),
];

mod cover {
    use super::*;
    use std::sync::Mutex;

    static LOG: Mutex<Option<BTreeSet<(&'static str, &'static str)>>> = Mutex::new(None);

    fn log() -> std::sync::MutexGuard<'static, Option<BTreeSet<(&'static str, &'static str)>>> {
        LOG.lock().expect("覆盖登记表锁")
    }

    pub fn reset() {
        *log() = Some(BTreeSet::new());
    }

    pub fn hit(kind: &'static str, id: &'static str) {
        assert!(
            E2E_MANIFEST
                .iter()
                .any(|(k, i)| *k == kind && *i == id),
            "登记了清单外的公开条目：{kind} {id}"
        );
        log()
            .as_mut()
            .expect("先 reset")
            .insert((kind, id));
    }

    pub fn executed() -> BTreeSet<(&'static str, &'static str)> {
        log().as_ref().expect("先 reset").clone()
    }
}

fn hit(kind: &'static str, id: &'static str) {
    cover::hit(kind, id);
}

fn assert_manifest_wellformed() {
    let mut seen = BTreeSet::new();
    for (kind, id) in E2E_MANIFEST {
        assert!(
            matches!(*kind, "fn" | "type" | "field" | "const" | "variant"),
            "未知类别 {kind}"
        );
        assert!(seen.insert((kind, id)), "清单重复：{kind} {id}");
    }
}

fn assert_coverage_complete() {
    let declared: BTreeSet<_> = E2E_MANIFEST.iter().copied().collect();
    let executed = cover::executed();
    let missing: Vec<_> = declared.difference(&executed).collect();
    let ghost: Vec<_> = executed.difference(&declared).collect();
    assert!(missing.is_empty(), "声明未执行：{missing:?}");
    assert!(ghost.is_empty(), "执行未声明：{ghost:?}");
}

fn unreachable_config() -> OssConfig {
    hit("fn", "OssConfig::builder");
    hit("fn", "OssConfigBuilder::endpoint");
    hit("fn", "OssConfigBuilder::bucket");
    hit("fn", "OssConfigBuilder::access_key_id");
    hit("fn", "OssConfigBuilder::access_key_secret");
    hit("fn", "OssConfigBuilder::build");
    OssConfig::builder()
        .endpoint("http://localhost:1")
        .bucket("e2e-bucket")
        .access_key_id("id")
        .access_key_secret("secret")
        .request_timeout(Duration::from_millis(250))
        .operation_deadline(Duration::from_secs(1))
        .acquire_timeout(Duration::from_millis(250))
        .build()
        .expect("loopback HTTP 配置")
}

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn clear_oss_env() {
    for key in [
        ENV_ENDPOINT,
        ENV_BUCKET,
        ENV_ACCESS_KEY_ID,
        ENV_ACCESS_KEY_SECRET,
        ENV_REGION,
        ENV_REQUEST_TIMEOUT_MS,
        ENV_OPERATION_DEADLINE_MS,
        ENV_ACQUIRE_TIMEOUT_MS,
        ENV_MAX_IN_FLIGHT,
        ENV_MAX_OBJECT_BYTES,
        ENV_MAX_BUFFER_BYTES,
        ENV_MAX_ERROR_BODY_BYTES,
    ] {
        std::env::remove_var(key);
    }
}

/// 离线 E2E：不连真实 OSS。
#[tokio::test]
async fn e2e_oss_offline_fail_closed() {
    cover::reset();
    assert_manifest_wellformed();

    for (name, value) in [
        (ENV_ENDPOINT, "FOUNDATIONX_OSSX_ENDPOINT"),
        (ENV_BUCKET, "FOUNDATIONX_OSSX_BUCKET"),
        (ENV_ACCESS_KEY_ID, "FOUNDATIONX_OSSX_ACCESS_KEY_ID"),
        (ENV_ACCESS_KEY_SECRET, "FOUNDATIONX_OSSX_ACCESS_KEY_SECRET"),
        (ENV_REGION, "FOUNDATIONX_OSSX_REGION"),
        (ENV_REQUEST_TIMEOUT_MS, "FOUNDATIONX_OSSX_REQUEST_TIMEOUT_MS"),
        (
            ENV_OPERATION_DEADLINE_MS,
            "FOUNDATIONX_OSSX_OPERATION_DEADLINE_MS",
        ),
        (ENV_ACQUIRE_TIMEOUT_MS, "FOUNDATIONX_OSSX_ACQUIRE_TIMEOUT_MS"),
        (ENV_MAX_IN_FLIGHT, "FOUNDATIONX_OSSX_MAX_IN_FLIGHT"),
        (ENV_MAX_OBJECT_BYTES, "FOUNDATIONX_OSSX_MAX_OBJECT_BYTES"),
        (ENV_MAX_BUFFER_BYTES, "FOUNDATIONX_OSSX_MAX_BUFFER_BYTES"),
        (
            ENV_MAX_ERROR_BODY_BYTES,
            "FOUNDATIONX_OSSX_MAX_ERROR_BODY_BYTES",
        ),
    ] {
        assert_eq!(name, value);
        let id = name.trim_start_matches("FOUNDATIONX_OSSX_");
        let const_id = match id {
            "ACCESS_KEY_ID" => "ENV_ACCESS_KEY_ID",
            "ACCESS_KEY_SECRET" => "ENV_ACCESS_KEY_SECRET",
            "ACQUIRE_TIMEOUT_MS" => "ENV_ACQUIRE_TIMEOUT_MS",
            "BUCKET" => "ENV_BUCKET",
            "ENDPOINT" => "ENV_ENDPOINT",
            "MAX_BUFFER_BYTES" => "ENV_MAX_BUFFER_BYTES",
            "MAX_ERROR_BODY_BYTES" => "ENV_MAX_ERROR_BODY_BYTES",
            "MAX_IN_FLIGHT" => "ENV_MAX_IN_FLIGHT",
            "MAX_OBJECT_BYTES" => "ENV_MAX_OBJECT_BYTES",
            "OPERATION_DEADLINE_MS" => "ENV_OPERATION_DEADLINE_MS",
            "REGION" => "ENV_REGION",
            "REQUEST_TIMEOUT_MS" => "ENV_REQUEST_TIMEOUT_MS",
            other => panic!("未映射常量 {other}"),
        };
        hit("const", const_id);
    }
    assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);
    hit("const", "HARD_MAX_IN_FLIGHT");
    hit("const", "HARD_MAX_OBJECT_BYTES");
    hit("const", "HARD_MAX_BUFFER_BYTES");
    hit("const", "HARD_MAX_ERROR_BODY_BYTES");
    hit("const", "MAX_MULTIPART_PARTS");
    hit("const", "MAX_MULTIPART_PART_BYTES");
    hit("const", "MAX_OBJECT_KEY_BYTES");
    hit("const", "MAX_RETRY_ATTEMPTS");
    hit("const", "MIN_MULTIPART_PART_BYTES");
    hit("const", "ORPHAN_AUDIT_CAPACITY");
    let _ = (
        HARD_MAX_OBJECT_BYTES,
        HARD_MAX_BUFFER_BYTES,
        HARD_MAX_ERROR_BODY_BYTES,
        MAX_MULTIPART_PARTS,
        MAX_MULTIPART_PART_BYTES,
        MAX_OBJECT_KEY_BYTES,
        MAX_RETRY_ATTEMPTS,
        MIN_MULTIPART_PART_BYTES,
        ORPHAN_AUDIT_CAPACITY,
    );

    hit("type", "OssError");
    let config_err = OssError::Config("bad".into());
    hit("variant", "OssError::Config");
    assert!(!config_err.is_retryable());
    hit("fn", "OssError::is_retryable");
    assert!(!OssError::Backend("403".into()).is_retryable());
    hit("variant", "OssError::Backend");
    assert!(OssError::Connection("reset".into()).is_retryable());
    hit("variant", "OssError::Connection");
    assert!(!OssError::Serialization("xml".into()).is_retryable());
    hit("variant", "OssError::Serialization");
    assert!(!OssError::Timeout("deadline".into()).is_retryable());
    hit("variant", "OssError::Timeout");
    assert!(!OssError::Unsupported("closed".into()).is_retryable());
    hit("variant", "OssError::Unsupported");
    let io = OssError::from(IoError::new(ErrorKind::NotFound, "missing"));
    hit("variant", "OssError::Io");
    assert!(!io.is_retryable());

    hit("type", "OssConfig");
    let config = unreachable_config();
    config.validate().expect("已 build 的配置可再 validate");
    hit("fn", "OssConfig::validate");

    let toml = r#"
schema_version = 1

[oss]
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"
bucket = "toml-bucket"
region = "cn-hangzhou"
max_in_flight = 2
request_timeout_ms = 2000
operation_deadline_ms = 4000
"#;
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_oss_env();
    std::env::set_var(ENV_ACCESS_KEY_ID, "toml-id");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "toml-secret");
    let from_toml = OssConfig::from_toml(toml).expect("合法 TOML");
    hit("fn", "OssConfig::from_toml");
    assert_eq!(from_toml.bucket, "toml-bucket");
    let missing = std::env::temp_dir().join("ossx-e2e-does-not-exist.toml");
    assert!(OssConfig::from_toml_file(&missing).is_err());
    hit("fn", "OssConfig::from_toml_file");
    clear_oss_env();
    assert!(OssConfig::from_env().is_err());
    hit("fn", "OssConfig::from_env");
    drop(_guard);

    hit("type", "OssClient");
    let client = OssClient::new(config.clone()).expect("new 不联网");
    hit("fn", "OssClient::new");
    let connected = OssClient::connect(config.clone()).await.expect("connect 不打桶");
    hit("fn", "OssClient::connect");
    assert!(client.ping().await.is_err());
    hit("fn", "OssClient::ping");
    let health = connected.health_check().await.expect("结构化健康");
    hit("fn", "OssClient::health_check");
    assert!(!health.ready);
    assert!(connected
        .put_object("e2e/key.txt", Bytes::from_static(b"x"))
        .await
        .is_err());
    hit("fn", "OssClient::put_object");
    assert!(connected.get_object("e2e/key.txt").await.is_err());
    hit("fn", "OssClient::get_object");
    assert!(connected.delete_object("e2e/key.txt").await.is_err());
    hit("fn", "OssClient::delete_object");
    connected.close();
    hit("fn", "OssClient::close");
    assert!(connected.is_closed());
    hit("fn", "OssClient::is_closed");

    hit("type", "OssPool");
    let pool = OssPool::new(config.clone()).expect("pool new");
    hit("fn", "OssPool::new");
    let pool2 = OssPool::connect(config).await.expect("pool connect");
    hit("fn", "OssPool::connect");
    assert!(pool.ping().await.is_err());
    hit("fn", "OssPool::ping");
    let _ = pool.stats();
    hit("fn", "OssPool::stats");
    let _ = OssPoolStats::default();
    pool2.close();
    hit("fn", "OssPool::close");

    let resource = canonicalized_resource("b", "/k");
    hit("fn", "canonicalized_resource");
    let sig = sign_v1("sec", "GET", "", "", "date", "", &resource);
    hit("fn", "sign_v1");
    assert!(authorization_header("id", &sig).starts_with("OSS id:"));
    hit("fn", "authorization_header");
    assert!(canonicalized_resource_with_subresources("b", "k", &[("uploads", None)])
        .contains("uploads"));
    hit("fn", "canonicalized_resource_with_subresources");
    assert_eq!(split_parts(b"abc", 2).len(), 2);
    hit("fn", "split_parts");
    let opts = PresignOptions::default();
    assert!(presign_url("https://oss.example.com", "b", "k", "id", "sec", &opts).is_ok());
    hit("fn", "presign_url");
    assert!(ObjectKey::new("a/b").is_ok());
    hit("fn", "ObjectKey::new");

    let _ = (
        DownloadOptions::default(),
        UploadOptions::default(),
        ObjectMeta::with_size(1),
        byte_stream_from_bytes(Bytes::from_static(b"x")),
        default_retry_config(),
        RetryConfig::fixed(2, 10),
        is_oss_retryable(&OssError::Connection("n".into())),
        StaticCredentialProvider::new("id", "sec", None).provider_name(),
    );
    let retry = default_retry_config();
    let _ = with_retry_default(&retry, "e2e", || async { Ok::<_, OssError>(()) }).await;
    let _ = with_retry(&retry, "e2e", || async { Ok::<_, OssError>(()) }).await;
    let _ = with_retry_deadline(&retry, "e2e", Duration::from_secs(1), || async {
        Ok::<_, OssError>(())
    })
    .await;

    assert_coverage_complete();
}

/// 真连：默认不跑。凭据只认环境变量。
#[tokio::test]
#[ignore = "需要真实 OSS 与 FOUNDATIONX_OSSX_*"]
async fn e2e_oss_live_object_roundtrip() {
    let config = OssConfig::from_env().expect("FOUNDATIONX_OSSX_*");
    let client = OssClient::connect(config).await.expect("connect");
    client.ping().await.expect("ping");
    let key = format!(
        "e2e/ossx/{}/probe.txt",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    client
        .put_object(&key, Bytes::from_static(b"e2e-oss"))
        .await
        .expect("put");
    let body = client.get_object(&key).await.expect("get");
    assert_eq!(body.as_ref(), b"e2e-oss");
    client.delete_object(&key).await.expect("delete");
    client.close();
}
