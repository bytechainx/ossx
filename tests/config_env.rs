#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! 配置校验、环境变量装载、硬上限与 secret 脱敏。

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ossx::{
    OssConfig, OssError, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET, ENV_ACQUIRE_TIMEOUT_MS,
    ENV_BUCKET, ENV_ENDPOINT, ENV_MAX_BUFFER_BYTES, ENV_MAX_ERROR_BODY_BYTES, ENV_MAX_IN_FLIGHT,
    ENV_MAX_OBJECT_BYTES, ENV_OPERATION_DEADLINE_MS, ENV_REGION, ENV_REQUEST_TIMEOUT_MS,
    HARD_MAX_ERROR_BODY_BYTES, HARD_MAX_IN_FLIGHT, HARD_MAX_OBJECT_BYTES,
};

/// 环境变量是进程级共享状态：本文件的 env 用例必须串行。
static ENV_LOCK: Mutex<()> = Mutex::new(());

const MANAGED_KEYS: [&str; 12] = [
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
];

fn lock_env() -> MutexGuard<'static, ()> {
    match ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn clear_env() {
    for key in MANAGED_KEYS {
        std::env::remove_var(key);
    }
}

fn base_builder() -> ossx::OssConfigBuilder {
    OssConfig::builder()
        .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
        .bucket("demo-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("secret")
}

#[test]
fn builder_accepts_and_validates_configuration() {
    let config = base_builder()
        .region("cn-hangzhou")
        .request_timeout(Duration::from_secs(3))
        .operation_deadline(Duration::from_secs(5))
        .acquire_timeout(Duration::from_secs(1))
        .max_in_flight(2)
        .max_object_bytes(2048)
        .max_buffer_bytes(4096)
        .max_error_body_bytes(512)
        .security_token("sts")
        .sse_enabled(true)
        .build()
        .expect("build");
    config.validate().expect("validate");
    assert_eq!(config.bucket, "demo-bucket");
    assert_eq!(config.region, "cn-hangzhou");
    assert_eq!(config.request_timeout, Duration::from_secs(3));
    assert_eq!(config.operation_deadline, Duration::from_secs(5));
    assert_eq!(config.acquire_timeout, Duration::from_secs(1));
    assert_eq!(config.max_in_flight, 2);
    assert_eq!(config.max_object_bytes, 2048);
    assert_eq!(config.max_buffer_bytes, 4096);
    assert_eq!(config.max_error_body_bytes, 512);
    assert!(config.sse_enabled);
    assert_eq!(config.endpoint, "https://oss-cn-hangzhou.aliyuncs.com");
}

#[test]
fn default_config_is_unvalidated_and_region_defaults() {
    let config = OssConfig::default();
    assert_eq!(config.region, "ap-northeast-1");
    assert_eq!(config.max_in_flight, 64);
    assert!(config.validate().is_err(), "默认配置缺必填项");
    assert_eq!(
        base_builder().build().expect("build").region,
        "ap-northeast-1"
    );
}

#[test]
fn validation_rejects_bad_inputs() {
    // endpoint 空
    let error = OssConfig::builder()
        .endpoint("")
        .bucket("b")
        .access_key_id("id")
        .access_key_secret("sec")
        .build()
        .expect_err("empty endpoint");
    assert!(matches!(error, OssError::Config(_)));

    // 远程明文 HTTP
    let error = base_builder()
        .endpoint("http://oss.example.com")
        .build()
        .expect_err("remote http");
    assert!(error.to_string().contains("HTTPS"));

    // loopback HTTP 允许（本地开发）
    let loopback = base_builder()
        .endpoint("http://localhost:9000")
        .build()
        .expect("loopback http");
    assert_eq!(loopback.endpoint, "http://localhost:9000");
    base_builder()
        .endpoint("http://127.0.0.1:9000")
        .build()
        .expect("loopback ip");

    // endpoint 带 userinfo / path / query
    for endpoint in [
        "https://user:pass@oss.example.com",
        "https://oss.example.com/path",
        "https://oss.example.com/?x=1",
    ] {
        let error = base_builder()
            .endpoint(endpoint)
            .build()
            .expect_err("endpoint extras");
        assert!(error.to_string().contains("endpoint"), "{endpoint}");
    }

    // bucket 命名
    for bucket in ["Bad_Bucket", "-bucket", "bucket-", "bUcket"] {
        let error = base_builder().bucket(bucket).build().expect_err("bucket");
        assert!(error.to_string().contains("bucket"), "{bucket}");
    }

    // deadline < timeout
    let error = base_builder()
        .request_timeout(Duration::from_secs(10))
        .operation_deadline(Duration::from_secs(1))
        .build()
        .expect_err("deadline < timeout");
    assert!(error.to_string().contains("operation_deadline"));

    // 零超时
    let error = base_builder()
        .acquire_timeout(Duration::ZERO)
        .build()
        .expect_err("zero acquire timeout");
    assert!(error.to_string().contains("timeout"));

    // 空凭据
    assert!(base_builder().access_key_secret(" ").build().is_err());
    assert!(base_builder().access_key_id(" ").build().is_err());

    // 对象上限 > 缓冲上限
    let error = base_builder()
        .max_object_bytes(4096)
        .max_buffer_bytes(1024)
        .build()
        .expect_err("object > buffer");
    assert!(error.to_string().contains("max_object_bytes"));
}

#[test]
fn hard_upper_bounds_fail_closed() {
    let error = base_builder()
        .max_in_flight(0)
        .build()
        .expect_err("zero in-flight");
    assert!(error.to_string().contains("max_in_flight"));

    let error = base_builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT + 1)
        .build()
        .expect_err("in-flight above hard max");
    assert!(error.to_string().contains("max_in_flight"));

    let error = base_builder()
        .max_error_body_bytes(HARD_MAX_ERROR_BODY_BYTES + 1)
        .build()
        .expect_err("error body above hard max");
    assert!(error.to_string().contains("max_error_body_bytes"));

    let error = base_builder()
        .max_object_bytes(HARD_MAX_OBJECT_BYTES + 1)
        .build()
        .expect_err("object above hard max");
    assert!(error.to_string().contains("max_object_bytes"));

    // 恰好等于硬上界仍然合法
    base_builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT)
        .max_error_body_bytes(HARD_MAX_ERROR_BODY_BYTES)
        .build()
        .expect("exactly at hard max");
}

#[test]
fn from_env_loads_every_supported_variable() {
    let _guard = lock_env();
    clear_env();
    std::env::set_var(ENV_ENDPOINT, "https://oss-cn-hangzhou.aliyuncs.com");
    std::env::set_var(ENV_BUCKET, "env-bucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "env-id");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "env-secret");
    std::env::set_var(ENV_REGION, "cn-hangzhou");
    std::env::set_var(ENV_REQUEST_TIMEOUT_MS, "1500");
    std::env::set_var(ENV_OPERATION_DEADLINE_MS, "3000");
    std::env::set_var(ENV_ACQUIRE_TIMEOUT_MS, "700");
    std::env::set_var(ENV_MAX_IN_FLIGHT, "8");
    std::env::set_var(ENV_MAX_OBJECT_BYTES, "4096");
    std::env::set_var(ENV_MAX_BUFFER_BYTES, "8192");
    std::env::set_var(ENV_MAX_ERROR_BODY_BYTES, "1024");

    let config = OssConfig::from_env().expect("from_env");
    assert_eq!(config.endpoint, "https://oss-cn-hangzhou.aliyuncs.com");
    assert_eq!(config.bucket, "env-bucket");
    assert_eq!(config.access_key_id, "env-id");
    assert_eq!(config.region, "cn-hangzhou");
    assert_eq!(config.request_timeout, Duration::from_millis(1500));
    assert_eq!(config.operation_deadline, Duration::from_millis(3000));
    assert_eq!(config.acquire_timeout, Duration::from_millis(700));
    assert_eq!(config.max_in_flight, 8);
    assert_eq!(config.max_object_bytes, 4096);
    assert_eq!(config.max_buffer_bytes, 8192);
    assert_eq!(config.max_error_body_bytes, 1024);

    // 客户端与连接池都能直接从环境变量构造
    let client = ossx::OssClient::from_env().expect("client from env");
    assert_eq!(client.config().bucket, "env-bucket");
    let pool = ossx::OssPool::from_env().expect("pool from env");
    assert_eq!(pool.config().bucket, "env-bucket");

    // region 未设置时回落到默认值
    std::env::remove_var(ENV_REGION);
    assert_eq!(
        OssConfig::from_env().expect("from_env").region,
        "ap-northeast-1"
    );

    clear_env();
}

#[test]
fn from_env_fails_closed_on_missing_or_invalid_values() {
    let _guard = lock_env();
    clear_env();

    let error = OssConfig::from_env().expect_err("missing endpoint");
    assert!(matches!(error, OssError::Config(_)));
    assert!(error.to_string().contains(ENV_ENDPOINT), "{error}");

    std::env::set_var(ENV_ENDPOINT, "https://oss-cn-hangzhou.aliyuncs.com");
    std::env::set_var(ENV_BUCKET, "env-bucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "env-id");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "env-secret");

    // 非数字
    std::env::set_var(ENV_MAX_IN_FLIGHT, "not-a-number");
    let error = OssConfig::from_env().expect_err("non numeric");
    assert!(error.to_string().contains(ENV_MAX_IN_FLIGHT));

    // 超过硬上界
    std::env::set_var(ENV_MAX_IN_FLIGHT, (HARD_MAX_IN_FLIGHT + 1).to_string());
    let error = OssConfig::from_env().expect_err("above hard max");
    assert!(error.to_string().contains("max_in_flight"));

    // 零值
    std::env::set_var(ENV_MAX_IN_FLIGHT, "0");
    assert!(OssConfig::from_env().is_err(), "零值并发必须 fail-closed");

    // TOML 基线 + 环境变量凭据：env 覆盖 TOML 调参
    std::env::remove_var(ENV_MAX_IN_FLIGHT);
    std::env::set_var(ENV_MAX_IN_FLIGHT, "3");
    let toml = r#"
schema_version = 1

[oss]
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"
bucket = "toml-bucket"
region = "cn-shanghai"
max_in_flight = 9
request_timeout_ms = 2000
operation_deadline_ms = 4000
"#;
    let config = OssConfig::from_toml(toml).expect("toml + env");
    assert_eq!(config.bucket, "toml-bucket");
    assert_eq!(config.access_key_id, "env-id");
    assert_eq!(config.max_in_flight, 3, "环境变量必须覆盖 TOML");
    assert_eq!(config.request_timeout, Duration::from_millis(2000));

    clear_env();
}

#[test]
fn toml_rejects_secret_fields_and_unknown_keys() {
    let _guard = lock_env();
    clear_env();

    let with_key_id = r#"
schema_version = 1

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
access_key_id = "LTAI..."
"#;
    let error = OssConfig::from_toml(with_key_id).expect_err("access_key_id 禁止");
    assert!(matches!(error, OssError::Config(_)));
    assert!(error.to_string().contains("access_key_id"));

    let root_level = r#"
schema_version = 1
access_key_secret = "secret"

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
"#;
    let error = OssConfig::from_toml(root_level).expect_err("根级 secret 禁止");
    assert!(error.to_string().contains("access_key_secret"));

    let unknown = r#"
schema_version = 1
unexpected = true

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
"#;
    assert!(OssConfig::from_toml(unknown).is_err(), "未知字段必须拒绝");

    let bad_schema = r#"
schema_version = 2

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
"#;
    let error = OssConfig::from_toml(bad_schema).expect_err("schema version");
    assert!(error.to_string().contains("schema_version"));

    let malformed = OssConfig::from_toml("this is not = = toml").expect_err("malformed");
    assert!(matches!(malformed, OssError::Serialization(_)));
    assert!(!malformed.is_retryable());

    // 文件不存在 → I/O 分类
    let missing = std::env::temp_dir().join("ossx-does-not-exist.toml");
    let error = OssConfig::from_toml_file(&missing).expect_err("missing file");
    assert!(matches!(error, OssError::Io(_)));

    clear_env();
}

#[test]
fn config_and_credentials_redact_secrets() {
    let config = base_builder()
        .access_key_id("LTAI5tVeryLongAccessKeyId")
        .access_key_secret("super-secret-value")
        .security_token("sts-token-value")
        .build()
        .expect("config");
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("super-secret-value"), "secret 绝不能泄露");
    assert!(
        !debug.contains("LTAI5tVeryLongAccessKeyId"),
        "access key id 必须脱敏"
    );
    assert!(!debug.contains("sts-token-value"), "STS token 绝不能泄露");
}
