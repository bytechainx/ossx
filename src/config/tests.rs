//! `config` 模块单元测试。

use super::*;

fn full_builder() -> OssConfigBuilder {
    OssConfig::builder()
        .endpoint("https://oss.example.com")
        .bucket("example-bucket")
        .access_key_id("LTAI5tABCDEFGH")
        .access_key_secret("super-secret-value")
}

#[test]
fn debug_redacts_secret_and_access_key_id() {
    let config = full_builder().build().expect("cfg");
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("super-secret-value"));
    assert!(!debug.contains("LTAI5tABCDEFGH"));
    assert!(debug.contains("LTA***GH"));
}

#[test]
fn debug_omits_security_token() {
    let config = full_builder()
        .security_token("sts-token-value")
        .build()
        .expect("cfg");
    let debug = format!("{config:?}");
    assert!(!debug.contains("sts-token-value"));
    assert!(!debug.contains("security_token"));
}

#[test]
fn builder_requires_fields_and_limits() {
    let error = OssConfig::builder().build().expect_err("endpoint required");
    assert!(error.to_string().contains("endpoint"));

    let error = full_builder()
        .max_in_flight(0)
        .build()
        .expect_err("zero in-flight");
    assert!(error.to_string().contains("max_in_flight"));

    let error = full_builder()
        .max_error_body_bytes(HARD_MAX_ERROR_BODY_BYTES + 1)
        .build()
        .expect_err("above hard max");
    assert!(error.to_string().contains("max_error_body_bytes"));

    let error = full_builder()
        .max_object_bytes(HARD_MAX_OBJECT_BYTES + 1)
        .build()
        .expect_err("above object hard max");
    assert!(error.to_string().contains("max_object_bytes"));
}

#[test]
fn validate_rejects_bad_endpoint_bucket_and_timeouts() {
    let error = full_builder()
        .endpoint("http://oss.example.com")
        .build()
        .expect_err("remote http");
    assert!(error.to_string().contains("HTTPS"));

    full_builder()
        .endpoint("http://127.0.0.1:9000")
        .build()
        .expect("loopback 开发端点可使用 HTTP");

    let error = full_builder()
        .endpoint("https://oss.example.com/path?x=1")
        .build()
        .expect_err("endpoint extras");
    assert!(error.to_string().contains("endpoint"));

    let error = full_builder()
        .bucket("Bad_Bucket")
        .build()
        .expect_err("bucket");
    assert!(error.to_string().contains("bucket"));

    let error = full_builder()
        .request_timeout(Duration::from_secs(10))
        .operation_deadline(Duration::from_secs(1))
        .build()
        .expect_err("deadline < timeout");
    assert!(error.to_string().contains("operation_deadline"));

    let error = full_builder()
        .access_key_secret("   ")
        .build()
        .expect_err("empty secret");
    assert!(error.to_string().contains("access_key_secret"));

    let error = full_builder()
        .max_object_bytes(4096)
        .max_buffer_bytes(1024)
        .build()
        .expect_err("object > buffer");
    assert!(error.to_string().contains("max_object_bytes"));
}

#[test]
fn default_is_tunable_but_unvalidated() {
    let config = OssConfig::default();
    assert_eq!(config.region, DEFAULT_REGION);
    assert_eq!(config.max_in_flight, DEFAULT_MAX_IN_FLIGHT);
    assert_eq!(config.request_timeout, DEFAULT_REQUEST_TIMEOUT);
    assert!(!config.sse_enabled);
    assert!(config.security_token().is_none());
    assert!(config.access_key_secret().is_empty());
    assert!(config.validate().is_err(), "默认配置缺必填项，必须校验失败");
}

#[test]
fn toml_parses_non_secret_fields_and_rejects_secrets() {
    let toml = r#"
schema_version = 1

[oss]
endpoint = "https://oss-ap-northeast-1.aliyuncs.com"
bucket = "demo-bucket"
region = "ap-northeast-1"
request_timeout_ms = 5000
max_in_flight = 8
sse_enabled = true
"#;
    let file = OssConfig::parse_toml(toml).expect("toml parse");
    assert_eq!(file.oss.endpoint, "https://oss-ap-northeast-1.aliyuncs.com");
    assert_eq!(file.oss.request_timeout_ms, Some(5000));
    assert_eq!(file.oss.max_in_flight, Some(8));
    assert_eq!(file.oss.sse_enabled, Some(true));

    let with_key = r#"
schema_version = 1

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
access_key_id = "LTAI..."
"#;
    let error = OssConfig::from_toml(with_key).expect_err("access_key_id forbidden");
    assert!(matches!(error, OssError::Config(_)));
    assert!(error.to_string().contains("access_key_id"));

    let with_secret = r#"
schema_version = 1

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
access_key_secret = "secret"
"#;
    let error = OssConfig::from_toml(with_secret).expect_err("access_key_secret forbidden");
    assert!(error.to_string().contains("access_key_secret"));

    let unknown = r#"
schema_version = 1
unexpected = true

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
"#;
    assert!(OssConfig::from_toml(unknown).is_err(), "未知字段必须被拒绝");

    let bad_schema = r#"
schema_version = 99

[oss]
endpoint = "https://oss.example.com"
bucket = "b"
"#;
    let error = OssConfig::from_toml(bad_schema).expect_err("schema");
    assert!(error.to_string().contains("schema_version"));

    // 非法 TOML 文本 → 解析类错误，不可重试
    let error = OssConfig::from_toml("this is not = = toml").expect_err("malformed toml");
    assert!(matches!(error, OssError::Serialization(_)), "{error:?}");
    assert!(!error.is_retryable());
}

#[test]
fn toml_without_env_credentials_fails_closed() {
    let toml = r#"
schema_version = 1

[oss]
endpoint = "https://oss-ap-northeast-1.aliyuncs.com"
bucket = "demo-bucket"
"#;
    // 测试进程未注入凭据时必失败；已注入时后续步骤仍应成功。
    match OssConfig::from_toml(toml) {
        Ok(config) => assert!(!config.access_key_id.is_empty()),
        Err(error) => {
            assert!(error.to_string().contains(ENV_ACCESS_KEY_ID), "{error}");
        }
    }
}

#[test]
fn missing_toml_file_is_io_error() {
    let missing = std::env::temp_dir().join(format!("ossx-missing-{}.toml", std::process::id()));
    let error = OssConfig::from_toml_file(&missing).expect_err("missing file");
    assert!(matches!(error, OssError::Io(_)), "{error:?}");
    assert!(error.to_string().contains("不可读"));
}

#[test]
fn redact_mid_bounds() {
    assert_eq!(redact_mid(""), "***");
    assert_eq!(redact_mid("abcdef"), "***");
    let long = redact_mid("abcdefghij");
    assert!(long.starts_with("abc"));
    assert!(long.ends_with("ij"));
    assert!(long.contains("***"));
}

#[test]
fn env_constants_are_stable() {
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
}

#[test]
fn deserialize_fills_missing_fields_from_default() {
    let config: OssConfig =
        toml::from_str("endpoint = \"https://oss.example.com\"").expect("deserialize");
    assert_eq!(config.endpoint, "https://oss.example.com");
    assert_eq!(config.region, DEFAULT_REGION);
    assert_eq!(config.max_in_flight, DEFAULT_MAX_IN_FLIGHT);
    assert!(config.bucket.is_empty());
}
