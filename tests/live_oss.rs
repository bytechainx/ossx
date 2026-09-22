#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! live 真连云（ossx）：对真实阿里云 OSS（生产桶）做公开接口的端到端验证。
//!
//! 全部用例 `#[ignore]`，默认不跑（CI 行为不变）。显式运行：
//!
//! ```bash
//! set -a; source /home/zone/workspace/sre/secrets/env/ossx.env; set +a
//! CARGO_TARGET_DIR=/home/workspace/bytechainx/.cargo/target \
//!   cargo test --test live_oss -- --ignored --test-threads=1
//! ```
//!
//! ## 2026-09-23 环境状态注记（外部阻塞，非代码缺陷）
//!
//! - 实测：阿里云账号被封禁，所有数据面请求返回 `403 UserDisable`
//!   （`EC 0003-00000801`，`HostId=xhyper.oss-ap-northeast-1.aliyuncs.com`）；
//!   未签名 HEAD 桶同样 403（team-lead 已独立复核）→ 非凭据错配、非沙箱/网络问题。
//!   凭据恢复前**无需重试**，重试只会得到同一结果。
//! - 影响：下方矩阵中 8 个需要云端数据面的用例**无法真跑**；PUT / LIST / multipart
//!   initiate 均在创建对象前被 403 拒绝，故桶内零残留。
//!   `live_oss_pure_surface_config_and_credentials` 与 `live_oss_close_fail_closed`
//!   两个不依赖数据面的用例已真跑通过。
//! - 已绿：`cargo fmt --check` / `cargo clippy --all-targets -- -D warnings` /
//!   `cargo test`（默认非 ignore 全部通过）。**不得把这 8 个失败判为代码缺陷。**
//! - 收口方式：恢复凭据后按本节上方那条命令重跑一次即可，无需改动用例。
//!
//! ## 真桶红线（生产桶）
//!
//! - 对象键一律落在唯一前缀 `bytechainx-e2e/<pid>-<nanos>/` 之下；
//! - DELETE 只作用于**预先拼好**的自建键名，绝不用 list 结果外推删除；
//! - list 断言一律限定在该前缀内，不触碰桶根与他人前缀；
//! - multipart 用例结束要么 complete 后 delete、要么 abort，不留悬挂分片；
//! - 每个用例先拼好全部键名再执行主体；主体以 `Result` 返回（不中途 panic），
//!   失败路径同样先走统一清理、再断言前缀归零、最后判失败。
//!
//! ## 公开接口覆盖矩阵（用例名 → 覆盖项）
//!
//! | 用例 | 覆盖 |
//! | --- | --- |
//! | live_oss_pure_surface_config_and_credentials | 全部 `ENV_*` / `HARD_MAX_*` / multipart 常量、`OssConfig`（from_env/from_toml/from_toml_file/builder/validate/Default/Debug 脱敏）、`OssConfigBuilder` 全部 setter、`OssCredentials`/`StaticCredentialProvider`/`CredentialProvider`、`ObjectKey`/`ObjectMeta`/`UploadOptions`/`DownloadOptions`/`ByteStream`/`byte_stream_from_bytes`、`sign_v1`/`authorization_header`/`canonicalized_resource(_with_subresources)`/`split_parts`、`presign_url` 自由函数/`PresignOptions`、`RetryConfig` 全方法/`with_retry*`/`is_oss_retryable`/`MAX_RETRY_ATTEMPTS`、`OssError` 全变体/`is_retryable`/`From<io::Error>`、`OssPoolStats::default` |
//! | live_oss_client_construct_ping_health | `OssClient::{new, connect, new_with_retry, connect_with_retry, from_env, config, retry_config, is_closed, multipart_orphan_audits, orphan_audit_overflow_count, ping, health_check}` |
//! | live_oss_pool_construct_ping_health_stats | `OssPool::{new, connect, new_with_retry, connect_with_retry, connect_with_provider, from_env, config, retry_config, provider_name, stats, ping, health_check, health}`（`connect_with_provider` 走自定义凭据提供者的真实探活） |
//! | live_oss_object_crud_roundtrip | `OssClient::{put_object, head_object, get_object, list_objects, delete_object}`（含 404 映射 Backend、删除幂等） |
//! | live_oss_concurrent_puts | 并发许可下的多任务 `put_object`/`get_object` 往返 |
//! | live_oss_presigned_url_roundtrip | `OssClient::presign_url`（GET 免签直读 / 缺失对象 4xx / PUT 免签直写回读） |
//! | live_oss_multipart_high_level | `OssClient::put_object_multipart`（3 分片完整编排 + 孤儿审计恒空） |
//! | live_oss_multipart_low_level_complete_and_abort | `OssClient::{initiate_multipart, upload_part, complete_multipart, abort_multipart}`（abort 后 complete 必失败、abort 幂等） |
//! | live_oss_pool_data_plane_and_stats | `OssPool::{put_object, get_object, head, delete_object, put_stream(单/多分片), get_stream(全量/Range/If-None-Match 304/缺失), stats}` |
//! | live_oss_close_fail_closed | `OssClient::{close, is_closed}` 与 `OssPool::{close, stats}` 关闭后数据面 fail-closed 与 cancelled 计数 |
//!
//! ### 唯一不能 E2E 的项：`MultipartOrphanAudit::{key, upload_id}`
//!
//! 该类型无公开构造器、字段私有，集成测试无法构造非空实例；live 成功/失败路径下注册表
//! 恒空，故本文件只断言「注册表为空」，**不覆盖这两个访问器**。现有覆盖位置与缺口
//! （2026-09-23 逐仓 grep 实测）：
//!
//! | 位置 | 覆盖内容 |
//! | --- | --- |
//! | `src/lib.rs` `public_api_surface::{exports_are_named_and_usable, public_types_are_send_and_sync}` | 类型导出与 `Send + Sync` / `Clone` 边界 |
//! | `tests/api_surface.rs` | `Send + Sync` / `Clone` / `Debug` 边界 |
//! | `src/client.rs` `orphan_registry_capacity_and_overflow_are_bounded` | 注册表非空路径：只断言 `multipart_orphan_audits().len()` 与溢出计数，**未调用访问器** |
//!
//! **缺口**：`key()` / `upload_id()` 全仓零调用，属**既有覆盖缺口**（需在 crate 内单测补齐；
//! 本特性不改 `src/`），非本次交付引入。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use ossx::{
    authorization_header, byte_stream_from_bytes, canonicalized_resource,
    canonicalized_resource_with_subresources, default_retry_config, is_oss_retryable, presign_url,
    sign_v1, split_parts, with_retry, with_retry_deadline, with_retry_default, ByteStream,
    CredentialProvider, DownloadOptions, ObjectKey, ObjectMeta, OssClient, OssConfig,
    OssCredentials, OssError, OssPool, OssPoolStats, OssResult, PresignOptions, RetryConfig,
    StaticCredentialProvider, UploadOptions, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET,
    ENV_ACQUIRE_TIMEOUT_MS, ENV_BUCKET, ENV_ENDPOINT, ENV_MAX_BUFFER_BYTES,
    ENV_MAX_ERROR_BODY_BYTES, ENV_MAX_IN_FLIGHT, ENV_MAX_OBJECT_BYTES, ENV_OPERATION_DEADLINE_MS,
    ENV_REGION, ENV_REQUEST_TIMEOUT_MS, HARD_MAX_BUFFER_BYTES, HARD_MAX_ERROR_BODY_BYTES,
    HARD_MAX_IN_FLIGHT, HARD_MAX_OBJECT_BYTES, MAX_MULTIPART_PARTS, MAX_MULTIPART_PART_BYTES,
    MAX_OBJECT_KEY_BYTES, MAX_RETRY_ATTEMPTS, MIN_MULTIPART_PART_BYTES, ORPHAN_AUDIT_CAPACITY,
};

/// 断言宏：条件不满足时以错误消息结束当前用例主体（仍会执行统一清理）。
macro_rules! require {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            return Err(format!($($arg)*));
        }
    };
}

/// 本用例唯一前缀：`bytechainx-e2e/<pid>-<nanos>/`。
fn unique_prefix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时间应晚于 UNIX_EPOCH")
        .as_nanos();
    format!("bytechainx-e2e/{}-{}/", std::process::id(), nanos)
}

/// `OssResult` → `Result<_, String>`：让用例主体可以 `?`，失败仍能走到统一清理。
fn m<T>(result: OssResult<T>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

/// 从 endpoint 提取 host（去 scheme 与尾斜杠），用于预签名 URL 形态断言。
fn endpoint_host(endpoint: &str) -> String {
    endpoint
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .to_string()
}

/// 读取字节流到内存（`get_stream` 断言用）。
async fn collect_stream(stream: &mut ByteStream) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    while let Some(chunk) = stream.next().await {
        buffer.extend_from_slice(&chunk.map_err(|error| error.to_string())?);
    }
    Ok(buffer)
}

/// 统一清理：只删**预先登记**的自建键（幂等），随后核查前缀下是否仍有残留。
async fn cleanup(client: &OssClient, keys: &[String], prefix: &str) -> Result<Vec<String>, String> {
    for key in keys {
        let _ = client.delete_object(key).await;
    }
    m(client.list_objects(prefix).await)
}

/// 纯函数面 + 配置装载 + 凭据模型的 live 前置断言（不动桶内对象，无需清理）。
#[tokio::test]
#[ignore = "需要 FOUNDATIONX_OSSX_* 环境变量（from_env / from_toml 合并断言）"]
async fn live_oss_pure_surface_config_and_credentials() {
    // ── 常量 ──────────────────────────────────────────────────────────────
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

    // ── OssConfig::from_env（真实环境变量）与 Debug 脱敏 ──────────────────
    let config = OssConfig::from_env().expect("from_env 必须装载真实凭据");
    config.validate().expect("真实配置必须通过校验");
    let env_endpoint = std::env::var(ENV_ENDPOINT).expect("endpoint 环境变量");
    let env_bucket = std::env::var(ENV_BUCKET).expect("bucket 环境变量");
    let env_key_id = std::env::var(ENV_ACCESS_KEY_ID).expect("ak id 环境变量");
    let env_secret = std::env::var(ENV_ACCESS_KEY_SECRET).expect("ak secret 环境变量");
    assert_eq!(config.endpoint, env_endpoint);
    assert_eq!(config.bucket, env_bucket);
    assert_eq!(config.access_key_id, env_key_id);
    assert_eq!(config.region, std::env::var(ENV_REGION).unwrap_or_default());
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"), "Debug 必须脱敏: {debug}");
    assert!(
        !debug.contains(&env_secret),
        "Debug 绝不能回显 AccessKeySecret"
    );

    // ── Builder 全 setter 链 ─────────────────────────────────────────────
    let built = OssConfig::builder()
        .endpoint(env_endpoint.clone())
        .bucket(env_bucket.clone())
        .access_key_id(env_key_id.clone())
        .access_key_secret(env_secret.clone())
        .region("ap-northeast-1")
        .request_timeout(Duration::from_secs(15))
        .operation_deadline(Duration::from_secs(60))
        .acquire_timeout(Duration::from_secs(2))
        .max_in_flight(8)
        .max_object_bytes(1024 * 1024)
        .max_buffer_bytes(2 * 1024 * 1024)
        .max_error_body_bytes(4096)
        .security_token("sts-token-live-only-for-builder-assert".to_string())
        .sse_enabled(false)
        .build()
        .expect("builder 必须产出合法配置");
    built.validate().expect("builder 产物必须通过校验");
    assert_eq!(built.max_in_flight, 8);
    assert_eq!(built.request_timeout, Duration::from_secs(15));
    assert_eq!(built.operation_deadline, Duration::from_secs(60));
    assert_eq!(built.acquire_timeout, Duration::from_secs(2));
    assert_eq!(built.max_object_bytes, 1024 * 1024);
    assert_eq!(built.max_buffer_bytes, 2 * 1024 * 1024);
    assert_eq!(built.max_error_body_bytes, 4096);
    assert!(!built.sse_enabled);
    let built_debug = format!("{built:?}");
    assert!(
        !built_debug.contains("sts-token-live-only-for-builder-assert"),
        "Debug 绝不能回显 security_token: {built_debug}"
    );

    // 拒绝路径（构建期 fail-closed）
    assert!(
        OssConfig::builder()
            .endpoint("http://oss.example.com")
            .bucket("b")
            .access_key_id("id")
            .access_key_secret("s")
            .build()
            .is_err(),
        "远程 HTTP endpoint 必须被拒绝"
    );
    assert!(
        OssConfig::builder()
            .endpoint("https://oss.example.com")
            .bucket("b")
            .access_key_id("id")
            .access_key_secret("s")
            .request_timeout(Duration::from_secs(10))
            .operation_deadline(Duration::from_secs(1))
            .build()
            .is_err(),
        "deadline < timeout 必须被拒绝"
    );
    let default = OssConfig::default();
    assert_eq!(default.region, "ap-northeast-1");
    assert!(!default.sse_enabled);
    assert!(default.validate().is_err(), "默认配置缺必填项必须校验失败");

    // ── from_toml / from_toml_file（凭据仍来自环境变量） ─────────────────
    let toml_text = format!(
        "schema_version = 1\n\n[oss]\nendpoint = \"{env_endpoint}\"\nbucket = \"{env_bucket}\"\nregion = \"ap-northeast-1\"\nmax_in_flight = 8\n"
    );
    let merged = OssConfig::from_toml(&toml_text).expect("from_toml 必须合并环境凭据");
    assert_eq!(merged.bucket, env_bucket);
    assert_eq!(merged.access_key_id, env_key_id, "凭据必须来自环境变量");
    assert_eq!(merged.max_in_flight, 8);

    let path = std::env::temp_dir().join(format!(
        "ossx-live-toml-{}-{}.toml",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("时钟")
            .as_nanos()
    ));
    std::fs::write(&path, &toml_text).expect("临时 TOML 必须可写");
    let from_file = OssConfig::from_toml_file(&path).expect("from_toml_file 必须装载");
    assert_eq!(from_file.bucket, env_bucket);
    std::fs::remove_file(&path).expect("临时文件必须清理");

    let with_secret = format!(
        "schema_version = 1\n\n[oss]\nendpoint = \"{env_endpoint}\"\nbucket = \"{env_bucket}\"\naccess_key_secret = \"leak\"\n"
    );
    let error = OssConfig::from_toml(&with_secret).expect_err("TOML 携带 secret 必须 fail-closed");
    assert!(error.to_string().contains("access_key_secret"));
    assert!(
        OssConfig::from_toml(
            "schema_version = 99\n\n[oss]\nendpoint = \"https://e.com\"\nbucket = \"b\"\n"
        )
        .is_err(),
        "不支持的 schema_version 必须被拒绝"
    );
    assert!(
        OssConfig::from_toml("not = = toml").is_err(),
        "非法 TOML 必须报错"
    );

    // ── 凭据模型 ──────────────────────────────────────────────────────────
    let provider = StaticCredentialProvider::new("live-id", "live-secret-value", None);
    let credentials = provider.get_credentials().await.expect("凭据必须可取");
    assert_eq!(credentials.access_key_id, "live-id");
    assert_eq!(credentials.access_key_secret, "live-secret-value");
    assert!(credentials.security_token.is_none());
    assert_eq!(provider.provider_name(), "static");
    let provider_ref: Arc<dyn CredentialProvider> = Arc::new(provider);
    assert_eq!(provider_ref.provider_name(), "static");
    let credentials_debug = format!(
        "{:?}",
        OssCredentials {
            access_key_id: "id".into(),
            access_key_secret: "super-secret-value".into(),
            security_token: Some("sts-token-value".into()),
        }
    );
    assert!(!credentials_debug.contains("super-secret-value"));
    assert!(!credentials_debug.contains("sts-token-value"));

    // ── 数据形态 ──────────────────────────────────────────────────────────
    let key = ObjectKey::new("  a/b.txt  ").expect("key 必须可构造");
    assert_eq!(key.as_str(), "a/b.txt");
    assert_eq!(key.to_string(), "a/b.txt");
    assert_eq!(key.as_ref(), "a/b.txt");
    assert!(ObjectKey::new("/leading").is_err());
    assert!(ObjectKey::new("../escape").is_err());
    assert!(ObjectKey::new("").is_err());
    assert!(ObjectKey::new("a\nb").is_err());
    assert_eq!(ObjectMeta::with_size(42).size, 42);
    assert_eq!(ObjectMeta::default().size, 0);
    let upload = UploadOptions {
        content_type: Some("text/plain".into()),
        metadata: Some(Vec::new()),
        part_size: 1024,
        sse_enabled: true,
    };
    assert_eq!(upload.part_size, 1024);
    assert!(upload.sse_enabled);
    let download = DownloadOptions::with_range("bytes=0-9");
    assert_eq!(download.range.as_deref(), Some("bytes=0-9"));
    assert!(download.if_match.is_none());
    let mut stream = byte_stream_from_bytes(Bytes::from_static(b"payload"));
    assert_eq!(
        stream.next().await.expect("单元素流").expect("ok"),
        Bytes::from_static(b"payload")
    );
    assert!(stream.next().await.is_none());

    // ── 签名纯函数（固定向量） ───────────────────────────────────────────
    let signature = sign_v1(
        "secret",
        "PUT",
        "",
        "application/octet-stream",
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "",
        "/bucket/key",
    );
    assert_eq!(signature, "i2eNP/BLD/pc/CxWss90UYPvKI4=");
    assert_eq!(
        authorization_header("AKID", &signature),
        format!("OSS AKID:{signature}")
    );
    assert_eq!(canonicalized_resource("b", "a/b"), "/b/a/b");
    assert_eq!(canonicalized_resource("b", ""), "/b/");
    assert_eq!(
        canonicalized_resource_with_subresources(
            "bucket",
            "obj/key",
            &[("uploadId", Some("UID")), ("partNumber", Some("2"))]
        ),
        "/bucket/obj/key?partNumber=2&uploadId=UID"
    );
    assert_eq!(
        canonicalized_resource_with_subresources("b", "k", &[("uploads", None)]),
        "/b/k?uploads"
    );
    let parts = split_parts(b"abcdefghij", 3);
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[3], b"j");
    assert!(split_parts(b"", 4).is_empty());
    assert_eq!(split_parts(b"ab", 5).len(), 1);

    // ── 预签名自由函数（真实 endpoint/bucket 形态） ──────────────────────
    let presigned = presign_url(
        &config.endpoint,
        &config.bucket,
        "a/b.txt",
        "id",
        "secret-value",
        &PresignOptions::default(),
    )
    .expect("presign 必须成功");
    assert!(
        presigned.starts_with(&format!(
            "https://{}.{}/a/b.txt?",
            config.bucket,
            endpoint_host(&config.endpoint)
        )),
        "虚拟主机形态: {presigned}"
    );
    assert!(presigned.contains("OSSAccessKeyId=id"));
    assert!(presigned.contains("&Expires="));
    assert!(presigned.contains("&Signature="));
    assert!(
        presign_url(
            "http://e.com",
            "b",
            "k",
            "i",
            "s",
            &PresignOptions::default()
        )
        .is_err(),
        "HTTP endpoint 的预签名必须被拒绝"
    );
    let default_options = PresignOptions::default();
    assert_eq!(default_options.method, "GET");
    assert_eq!(default_options.expires, Duration::from_secs(3600));
    assert!(default_options.content_type.is_none());

    // ── 重试配置与包装 ────────────────────────────────────────────────────
    let fixed = RetryConfig::fixed(3, 10);
    fixed.validate().expect("fixed 配置必须合法");
    assert_eq!(fixed.delay_for(1), Duration::from_millis(10));
    assert_eq!(fixed.delay_for(2), Duration::from_millis(10), "max 封顶");
    let exponential = RetryConfig::exponential(3, 100, 200, 0.0);
    assert_eq!(exponential.delay_for(1), Duration::from_millis(100));
    assert_eq!(exponential.delay_for(2), Duration::from_millis(200));
    assert_eq!(exponential.delay_for(9), Duration::from_millis(200));
    assert_eq!(RetryConfig::default(), default_retry_config());
    assert!(RetryConfig::fixed(0, 1).validate().is_err());
    assert!(RetryConfig::exponential(3, 200, 100, 0.0)
        .validate()
        .is_err());
    assert!(RetryConfig::exponential(3, 1, 10, 1.5).validate().is_err());

    let value = with_retry(&fixed, "live-op", || async { Ok::<_, OssError>(7_u8) })
        .await
        .expect("Ok 路径");
    assert_eq!(value, 7);
    let value = with_retry_default(&fixed, "live-op", || async { Ok::<_, OssError>(8_u8) })
        .await
        .expect("Ok 路径");
    assert_eq!(value, 8);
    let value = with_retry_deadline(&fixed, "live-op", Duration::from_secs(5), || async {
        Ok::<_, OssError>(9_u8)
    })
    .await
    .expect("Ok 路径");
    assert_eq!(value, 9);

    let attempts = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&attempts);
    let error = with_retry(&fixed, "live-retry", move || {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(OssError::Connection("live 重试耗尽".into()))
        }
    })
    .await
    .expect_err("可重试错误必须重试耗尽后报错");
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "3 次尝试后必须耗尽");
    assert!(error.is_retryable());

    let permanent_attempts = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&permanent_attempts);
    let _ = with_retry(&fixed, "live-permanent", move || {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(OssError::Backend("live 永久错误".into()))
        }
    })
    .await
    .expect_err("永久错误必须报错");
    assert_eq!(
        permanent_attempts.load(Ordering::SeqCst),
        1,
        "永久错误必须立即返回、不消耗重试预算"
    );

    // ── 错误面与统计默认值 ────────────────────────────────────────────────
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
    assert!(OssError::Connection("net".into()).is_retryable());
    assert!(!OssError::Connection("auth/forbidden".into()).is_retryable());
    assert!(!OssError::Connection("HTTP unauthorized".into()).is_retryable());
    assert!(!OssError::Config("x".into()).is_retryable());
    assert!(!OssError::Backend("x".into()).is_retryable());
    assert!(!OssError::Serialization("x".into()).is_retryable());
    assert!(!OssError::Timeout("x".into()).is_retryable());
    assert!(!OssError::Unsupported("x".into()).is_retryable());
    assert!(!OssError::Io(std::io::Error::other("disk")).is_retryable());
    assert!(is_oss_retryable(&OssError::Connection("net".into())));
    assert!(!is_oss_retryable(&OssError::Config("x".into())));
    let io_error: OssError = std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into();
    assert!(matches!(io_error, OssError::Io(_)));
    let stats = OssPoolStats::default();
    assert!(!stats.closed);
    assert_eq!(stats.in_flight, 0);
    assert_eq!(stats.puts_ok, 0);
    assert_eq!(stats.gets_err, 0);
    assert_eq!(stats.timeouts, 0);
    assert_eq!(stats.cancelled, 0);
}

/// `OssClient` 五个构造入口（均不发网络请求）+ ping / health_check 真实探活。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_client_construct_ping_health() {
    let config = OssConfig::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let retry = RetryConfig::fixed(2, 0);

    let client = OssClient::connect(config.clone()).await.expect("connect");
    let via_new = OssClient::new(config.clone()).expect("new");
    let via_env = OssClient::from_env().expect("from_env");
    let with_retry_client =
        OssClient::new_with_retry(config.clone(), retry).expect("new_with_retry");
    let via_connect_retry = OssClient::connect_with_retry(config.clone(), retry)
        .await
        .expect("connect_with_retry");

    assert!(!client.is_closed());
    assert_eq!(client.config().bucket, config.bucket);
    assert_eq!(client.config().endpoint, config.endpoint);
    assert_eq!(client.retry_config(), default_retry_config());
    assert_eq!(with_retry_client.retry_config(), retry);
    assert_eq!(via_new.config().bucket, config.bucket);
    assert_eq!(via_env.config().bucket, config.bucket);
    assert_eq!(via_connect_retry.retry_config(), retry);
    assert!(client.multipart_orphan_audits().is_empty());
    assert_eq!(client.orphan_audit_overflow_count(), 0);
    // clone 共享内部状态
    assert_eq!(client.clone().config().bucket, config.bucket);

    // 真实探活：HEAD bucket
    client.ping().await.expect("ping 必须成功");
    let health = client.health_check().await.expect("health_check 恒为 Ok");
    assert!(health.ready, "真实桶必须 ready: {}", health.detail);
    assert!(health.bucket_accessible);
    assert!(
        health.latency_ms < 10_000,
        "探活延迟应远小于超时: {}",
        health.latency_ms
    );
    assert!(
        health.detail.contains(&config.bucket),
        "detail 应含 bucket: {}",
        health.detail
    );
}

/// `OssPool` 全部构造入口（含自定义凭据提供者路径）+ ping / health_check / health。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_pool_construct_ping_health_stats() {
    let config = OssConfig::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let retry = RetryConfig::fixed(2, 0);
    let secret = std::env::var(ENV_ACCESS_KEY_SECRET).expect("ak secret 环境变量");

    let pool = OssPool::connect(config.clone()).await.expect("connect");
    let via_new = OssPool::new(config.clone()).expect("new");
    let via_env = OssPool::from_env().expect("from_env");
    let via_new_with_retry =
        OssPool::new_with_retry(config.clone(), retry, None).expect("new_with_retry");
    let via_connect_retry = OssPool::connect_with_retry(config.clone(), retry)
        .await
        .expect("connect_with_retry");
    let provider = Arc::new(StaticCredentialProvider::new(
        config.access_key_id.clone(),
        secret,
        None,
    ));
    let via_provider = OssPool::connect_with_provider(config.clone(), retry, provider)
        .await
        .expect("connect_with_provider");

    assert_eq!(pool.provider_name(), "static");
    assert_eq!(via_provider.provider_name(), "static");
    assert_eq!(pool.config().bucket, config.bucket);
    assert_eq!(pool.retry_config(), default_retry_config());
    assert_eq!(via_new_with_retry.retry_config(), retry);
    assert_eq!(via_new.config().bucket, config.bucket);
    assert_eq!(via_env.config().bucket, config.bucket);
    assert_eq!(via_connect_retry.retry_config(), retry);

    let stats = pool.stats();
    assert!(!stats.closed);
    assert_eq!(stats.in_flight, 0);
    assert_eq!(stats.max_in_flight, 64);
    assert_eq!(stats.puts_ok, 0);
    assert_eq!(stats.gets_ok, 0);
    assert_eq!(stats.deletes_ok, 0);

    // 探活：ping / health_check / health(显式 deadline)
    pool.ping().await.expect("pool ping 必须成功");
    let health = pool.health_check().await.expect("health_check 恒为 Ok");
    assert!(
        health.ready && health.bucket_accessible,
        "detail: {}",
        health.detail
    );
    assert!(health.latency_ms < 10_000);
    let health = pool
        .health(Duration::from_secs(10))
        .await
        .expect("health 恒为 Ok");
    assert!(health.ready, "health.detail: {}", health.detail);
    // 自定义凭据提供者路径也真实探活（每次请求向 provider 取凭据）
    via_provider
        .ping()
        .await
        .expect("自定义凭据提供者路径 ping 必须成功");
}

/// 对象 CRUD 往返：put / head / get / list（限定前缀）/ 404 映射 / delete 幂等。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_object_crud_roundtrip() {
    let client = OssClient::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let prefix = unique_prefix();
    let key_text = format!("{prefix}crud/hello.txt");
    let key_bin = format!("{prefix}crud/nested/deep/bin.dat");
    let keys = vec![key_text.clone(), key_bin.clone()];
    let payload_text = Bytes::from_static(b"ossx live roundtrip: hello production bucket.");
    let payload_bin = Bytes::from((0..=255_u8).cycle().take(4096).collect::<Vec<_>>());

    let outcome: Result<(), String> = async {
        m(client.put_object(&key_text, payload_text.clone()).await)?;
        m(client.put_object(&key_bin, payload_bin.clone()).await)?;

        let meta = m(client.head_object(&key_text).await)?;
        require!(
            meta.size == payload_text.len() as u64,
            "HEAD size 应为 {}: {meta:?}",
            payload_text.len()
        );
        require!(meta.etag.is_some(), "HEAD 必须返回 ETag: {meta:?}");

        let fetched = m(client.get_object(&key_text).await)?;
        require!(fetched == payload_text, "文本对象往返必须逐字节一致");
        let fetched = m(client.get_object(&key_bin).await)?;
        require!(fetched == payload_bin, "二进制对象往返必须逐字节一致");

        let listed = m(client.list_objects(&prefix).await)?;
        let mut sorted = listed.clone();
        sorted.sort();
        let mut expected = vec![key_text.clone(), key_bin.clone()];
        expected.sort();
        require!(
            sorted == expected,
            "list 应恰好包含两个自建对象: {sorted:?}"
        );

        // 不存在对象：GET / HEAD 均映射 Backend
        let missing = format!("{prefix}crud/missing.txt");
        let error = client
            .get_object(&missing)
            .await
            .expect_err("缺失对象 GET 必须失败");
        require!(
            matches!(error, OssError::Backend(_)),
            "GET 404 应映射 Backend: {error}"
        );
        let error = client
            .head_object(&missing)
            .await
            .expect_err("缺失对象 HEAD 必须失败");
        require!(
            matches!(error, OssError::Backend(_)),
            "HEAD 404 应映射 Backend: {error}"
        );

        // 删除 + 幂等
        m(client.delete_object(&key_text).await)?;
        require!(
            client.get_object(&key_text).await.is_err(),
            "删除后 GET 必须失败"
        );
        m(client.delete_object(&key_text).await)?;
        m(client.delete_object(&key_bin).await)?;
        Ok(())
    }
    .await;

    let remaining = cleanup(&client, &keys, &prefix)
        .await
        .expect("清理后核查 list 必须可用");
    assert!(
        remaining.is_empty(),
        "前缀 {prefix} 清理后仍有残留: {remaining:?}"
    );
    outcome.expect("live 用例主体必须成功");
}

/// 并发许可下的多任务 put/get 往返。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_concurrent_puts() {
    let client = OssClient::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let prefix = unique_prefix();
    let keys: Vec<String> = (0..4)
        .map(|index| format!("{prefix}concurrent/obj-{index}.bin"))
        .collect();
    let payloads: Vec<Bytes> = keys
        .iter()
        .enumerate()
        .map(|(index, _)| Bytes::from(vec![(index as u8) + 1; 1024 * (index + 1)]))
        .collect();

    let outcome: Result<(), String> = async {
        let mut tasks = Vec::new();
        for (key, payload) in keys.iter().zip(payloads.iter()) {
            let client = client.clone();
            let key = key.clone();
            let payload = payload.clone();
            tasks.push(tokio::spawn(async move {
                client.put_object(&key, payload.clone()).await?;
                let fetched = client.get_object(&key).await?;
                if fetched != payload {
                    return Err(OssError::Backend(format!("并发往返载荷不一致: {key}")));
                }
                Ok(())
            }));
        }
        for task in tasks {
            task.await
                .map_err(|error| format!("并发任务 panic: {error}"))?
                .map_err(|error| format!("并发往返失败: {error}"))?;
        }
        let listed = m(client.list_objects(&prefix).await)?;
        require!(listed.len() == 4, "应列出 4 个并发对象: {listed:?}");
        Ok(())
    }
    .await;

    let remaining = cleanup(&client, &keys, &prefix)
        .await
        .expect("清理后核查 list 必须可用");
    assert!(
        remaining.is_empty(),
        "前缀 {prefix} 清理后仍有残留: {remaining:?}"
    );
    outcome.expect("live 用例主体必须成功");
}

/// 预签名 URL：GET 免签直读 / 缺失对象 4xx / PUT 免签直写后回读校验。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_presigned_url_roundtrip() {
    let client = OssClient::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let prefix = unique_prefix();
    let key_get = format!("{prefix}presign/get.txt");
    let key_put = format!("{prefix}presign/put.txt");
    let missing = format!("{prefix}presign/missing.txt");
    let keys = vec![key_get.clone(), key_put.clone()];
    let payload = Bytes::from_static(b"presigned-url-live-payload");

    m(client.put_object(&key_get, payload.clone()).await).expect("预置对象必须上传成功");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("直连 HTTP 客户端必须可构造");

    let outcome: Result<(), String> = async {
        // GET 预签名：免签直连可读
        let url = m(client.presign_url(&key_get, &PresignOptions::default()))?;
        require!(
            url.starts_with(&format!(
                "https://{}.{}/",
                client.config().bucket,
                endpoint_host(&client.config().endpoint)
            )),
            "虚拟主机形态: {url}"
        );
        require!(
            url.contains("OSSAccessKeyId=")
                && url.contains("&Expires=")
                && url.contains("&Signature="),
            "预签名 URL 必须携带三要素: {url}"
        );
        let response = http
            .get(&url)
            .send()
            .await
            .map_err(|error| format!("预签名 GET 失败: {error}"))?;
        require!(
            response.status().is_success(),
            "预签名 GET 应成功: {}",
            response.status()
        );
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("读取预签名 GET 响应失败: {error}"))?;
        require!(body == payload, "预签名 GET 载荷必须逐字节一致");

        // 缺失对象的预签名 GET → 4xx
        let url_missing = m(client.presign_url(&missing, &PresignOptions::default()))?;
        let response = http
            .get(&url_missing)
            .send()
            .await
            .map_err(|error| format!("预签名 GET(缺失) 失败: {error}"))?;
        require!(
            !response.status().is_success(),
            "缺失对象的预签名 GET 不应成功: {}",
            response.status()
        );

        // PUT 预签名：免签直连可写（Content-Type 参与签名，必须一致）
        let options = PresignOptions {
            method: "PUT".into(),
            expires: Duration::from_secs(600),
            content_type: Some("application/octet-stream".into()),
        };
        let url_put = m(client.presign_url(&key_put, &options))?;
        let response = http
            .put(&url_put)
            .header("Content-Type", "application/octet-stream")
            .body(payload.clone())
            .send()
            .await
            .map_err(|error| format!("预签名 PUT 失败: {error}"))?;
        require!(
            response.status().is_success(),
            "预签名 PUT 应成功: {}",
            response.status()
        );
        let fetched = m(client.get_object(&key_put).await)?;
        require!(fetched == payload, "预签名 PUT 写入的载荷必须可回读且一致");
        Ok(())
    }
    .await;

    let remaining = cleanup(&client, &keys, &prefix)
        .await
        .expect("清理后核查 list 必须可用");
    assert!(
        remaining.is_empty(),
        "前缀 {prefix} 清理后仍有残留: {remaining:?}"
    );
    outcome.expect("live 用例主体必须成功");
}

/// 高层 multipart：`put_object_multipart` 3 分片完整编排 + 回读 + 孤儿审计恒空。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_multipart_high_level() {
    let client = OssClient::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let prefix = unique_prefix();
    let key = format!("{prefix}mp-high/object.bin");
    let keys = vec![key.clone()];
    let part_size = MIN_MULTIPART_PART_BYTES;
    let data = Bytes::from(
        (0..part_size * 2 + 4096)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );

    let outcome: Result<(), String> = async {
        m(client
            .put_object_multipart(&key, data.clone(), part_size)
            .await)?;

        let meta = m(client.head_object(&key).await)?;
        require!(
            meta.size == data.len() as u64,
            "multipart 对象 size 应为 {}: {meta:?}",
            data.len()
        );
        let fetched = m(client.get_object(&key).await)?;
        require!(fetched == data, "multipart 写入对象必须逐字节一致");
        require!(
            client.multipart_orphan_audits().is_empty(),
            "成功路径不得留下孤儿审计"
        );
        require!(
            client.orphan_audit_overflow_count() == 0,
            "成功路径不得有溢出计数"
        );
        m(client.delete_object(&key).await)?;
        Ok(())
    }
    .await;

    let remaining = cleanup(&client, &keys, &prefix)
        .await
        .expect("清理后核查 list 必须可用");
    assert!(
        remaining.is_empty(),
        "前缀 {prefix} 清理后仍有残留: {remaining:?}"
    );
    outcome.expect("live 用例主体必须成功");
}

/// 低层 multipart：手工编排 initiate/upload/complete；abort 后 complete 必失败、abort 幂等。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_multipart_low_level_complete_and_abort() {
    let client = OssClient::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let prefix = unique_prefix();
    let key_complete = format!("{prefix}mp-low/complete.bin");
    let key_abort = format!("{prefix}mp-low/abort.bin");
    let keys = vec![key_complete.clone(), key_abort.clone()];
    let part1 = Bytes::from(
        (0..MIN_MULTIPART_PART_BYTES)
            .map(|index| (index % 249) as u8)
            .collect::<Vec<_>>(),
    );
    let part2 = Bytes::from_static(b"ossx-live-multipart-tail");

    let outcome: Result<(), String> = async {
        // 手工编排：initiate → 2 分片 → complete → 回读
        let upload_id = m(client.initiate_multipart(&key_complete).await)?;
        require!(!upload_id.is_empty(), "upload_id 不得为空");
        let etag1 = m(client
            .upload_part(&key_complete, &upload_id, 1, part1.clone())
            .await)?;
        require!(!etag1.is_empty(), "分片 1 必须返回 ETag");
        let etag2 = m(client
            .upload_part(&key_complete, &upload_id, 2, part2.clone())
            .await)?;
        m(client
            .complete_multipart(&key_complete, &upload_id, vec![(1, etag1), (2, etag2)])
            .await)?;
        let mut expected = Vec::with_capacity(part1.len() + part2.len());
        expected.extend_from_slice(&part1);
        expected.extend_from_slice(&part2);
        let fetched = m(client.get_object(&key_complete).await)?;
        require!(
            fetched.as_ref() == expected.as_slice(),
            "手工 complete 的对象必须逐字节一致"
        );
        let meta = m(client.head_object(&key_complete).await)?;
        require!(
            meta.size == expected.len() as u64,
            "对象 size 应为 {}: {meta:?}",
            expected.len()
        );

        // abort：initiate → 1 分片 → abort → complete 必失败且对象不存在；abort 幂等
        let upload_id = m(client.initiate_multipart(&key_abort).await)?;
        let etag = m(client
            .upload_part(&key_abort, &upload_id, 1, part1.clone())
            .await)?;
        m(client.abort_multipart(&key_abort, &upload_id).await)?;
        let error = client
            .complete_multipart(&key_abort, &upload_id, vec![(1, etag)])
            .await
            .expect_err("abort 后 complete 必须失败");
        require!(
            matches!(error, OssError::Backend(_)),
            "abort 后 complete 应映射 Backend: {error}"
        );
        require!(
            client.head_object(&key_abort).await.is_err(),
            "abort 后对象必须不存在"
        );
        m(client.abort_multipart(&key_abort, &upload_id).await)?;
        require!(
            client.multipart_orphan_audits().is_empty(),
            "显式 abort 收口的路径不得留下孤儿审计"
        );
        m(client.delete_object(&key_complete).await)?;
        Ok(())
    }
    .await;

    let remaining = cleanup(&client, &keys, &prefix)
        .await
        .expect("清理后核查 list 必须可用");
    assert!(
        remaining.is_empty(),
        "前缀 {prefix} 清理后仍有残留: {remaining:?}"
    );
    outcome.expect("live 用例主体必须成功");
}

/// `OssPool` 数据面：put/get/head/delete + 计数；put_stream 单/多分片；
/// get_stream 全量 / Range / If-None-Match 304 / 缺失对象。
#[tokio::test]
#[ignore = "需要真实阿里云 OSS 与 FOUNDATIONX_OSSX_* 环境变量"]
async fn live_oss_pool_data_plane_and_stats() {
    let pool = OssPool::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let verifier = OssClient::from_env().expect("核查用客户端必须可构造");
    let prefix = unique_prefix();
    let key_obj = format!("{prefix}pool/obj.bin");
    let key_single = format!("{prefix}pool/stream-single.bin");
    let key_multi = format!("{prefix}pool/stream-multi.bin");
    let keys = vec![key_obj.clone(), key_single.clone(), key_multi.clone()];
    let payload = Bytes::from_static(b"ossx pool live payload");
    let single_data = Bytes::from((0..4096_u32).map(|index| index as u8).collect::<Vec<_>>());
    let multi_data: Vec<u8> = (0..MIN_MULTIPART_PART_BYTES * 2 + 512)
        .map(|index| (index % 253) as u8)
        .collect();

    let outcome: Result<(), String> = async {
        // put/get/head + 计数
        m(pool.put_object(&key_obj, payload.clone()).await)?;
        let fetched = m(pool.get_object(&key_obj).await)?;
        require!(fetched == payload, "pool 文本往返必须一致");
        let meta = m(pool.head(&key_obj).await)?;
        require!(
            meta.size == payload.len() as u64,
            "pool HEAD size 不符: {meta:?}"
        );

        // 流式上传：单分片（part_size=0 → 默认 5 MiB → 单片 PUT）
        let meta = m(pool
            .put_stream(
                &key_single,
                byte_stream_from_bytes(single_data.clone()),
                UploadOptions::default(),
            )
            .await)?;
        require!(
            meta.size == single_data.len() as u64,
            "单分片 put_stream size 不符: {meta:?}"
        );
        let (meta, mut stream) = m(pool
            .get_stream(&key_single, DownloadOptions::default())
            .await)?;
        require!(
            meta.size == single_data.len() as u64,
            "get_stream meta size 不符: {meta:?}"
        );
        let collected = collect_stream(&mut stream).await?;
        require!(
            collected.as_slice() == single_data.as_ref(),
            "单分片流式往返必须逐字节一致"
        );

        // 流式上传：多分片（100 KiB × 2 + 512 → 3 片，走 multipart）
        let options = UploadOptions {
            part_size: MIN_MULTIPART_PART_BYTES,
            ..UploadOptions::default()
        };
        m(pool
            .put_stream(
                &key_multi,
                byte_stream_from_bytes(Bytes::from(multi_data.clone())),
                options,
            )
            .await)?;
        let (meta, mut stream) = m(pool
            .get_stream(&key_multi, DownloadOptions::default())
            .await)?;
        require!(
            meta.size == multi_data.len() as u64,
            "多分片 meta size 不符: {meta:?}"
        );
        let collected = collect_stream(&mut stream).await?;
        require!(collected == multi_data, "多分片流式往返必须逐字节一致");

        // Range 条件下载：只回前 100 字节
        let (meta, mut stream) = m(pool
            .get_stream(&key_multi, DownloadOptions::with_range("bytes=0-99"))
            .await)?;
        require!(
            meta.size == 100,
            "Range 响应的 meta size 应为 100: {meta:?}"
        );
        let collected = collect_stream(&mut stream).await?;
        require!(
            collected.len() == 100 && collected == multi_data[..100],
            "Range 读回应为前 100 字节，实际 {} 字节",
            collected.len()
        );

        // If-None-Match 命中 → 304 Not Modified → 元数据 size=0 且流为空
        let meta = m(pool.head(&key_multi).await)?;
        let etag = meta.etag.clone().unwrap_or_default();
        let options = DownloadOptions {
            if_none_match: Some(format!("\"{etag}\"")),
            ..DownloadOptions::default()
        };
        let (meta, mut stream) = m(pool.get_stream(&key_multi, options).await)?;
        require!(meta.size == 0, "304 响应的 meta size 应为 0: {meta:?}");
        let collected = collect_stream(&mut stream).await?;
        require!(collected.is_empty(), "304 响应的流必须为空");

        // 缺失对象：get_stream / get_object 均 Err
        require!(
            pool.get_stream(
                format!("{prefix}pool/missing.bin"),
                DownloadOptions::default()
            )
            .await
            .is_err(),
            "缺失对象 get_stream 必须失败"
        );
        require!(
            pool.get_object(format!("{prefix}pool/missing2.bin"))
                .await
                .is_err(),
            "缺失对象 get_object 必须失败"
        );

        // 计数：put_object / get_object 各 1 次；stream 与条件下载不计数
        let stats = pool.stats();
        require!(
            stats.puts_ok == 1 && stats.gets_ok == 1 && stats.deletes_ok == 0,
            "计数不符: {stats:?}"
        );
        require!(
            stats.puts_err == 0
                && stats.gets_err == 0
                && stats.deletes_err == 0
                && stats.timeouts == 0
                && stats.cancelled == 0,
            "成功路径不应有错误计数: {stats:?}"
        );
        require!(
            !stats.closed && stats.in_flight == 0,
            "收尾统计不符: {stats:?}"
        );

        // delete + 计数
        m(pool.delete_object(&key_obj).await)?;
        let stats = pool.stats();
        require!(stats.deletes_ok == 1, "删除成功必须计数: {stats:?}");
        Ok(())
    }
    .await;

    let remaining = cleanup(&verifier, &keys, &prefix)
        .await
        .expect("清理后核查 list 必须可用");
    assert!(
        remaining.is_empty(),
        "前缀 {prefix} 清理后仍有残留: {remaining:?}"
    );
    outcome.expect("live 用例主体必须成功");
}

/// 关闭语义：`OssClient::close` / `OssPool::close` 后数据面 fail-closed 与 cancelled 计数。
#[tokio::test]
#[ignore = "需要 FOUNDATIONX_OSSX_* 环境变量（仅配置装载，不发网络请求）"]
async fn live_oss_close_fail_closed() {
    let config = OssConfig::from_env().expect("FOUNDATIONX_OSSX_* 必须已注入");
    let prefix = unique_prefix();
    let key = format!("{prefix}closed/never-created.txt");

    let client = OssClient::new(config.clone()).expect("client 必须可构造");
    assert!(!client.is_closed());
    client.close();
    client.close();
    assert!(client.is_closed(), "close 幂等且必须置位");
    let error = client
        .put_object(&key, Bytes::from_static(b"x"))
        .await
        .expect_err("关闭后 put 必须失败");
    assert!(
        matches!(error, OssError::Unsupported(_)),
        "应 Unsupported: {error}"
    );
    let error = client.ping().await.expect_err("关闭后 ping 必须失败");
    assert!(
        matches!(error, OssError::Unsupported(_)),
        "应 Unsupported: {error}"
    );
    assert!(
        client.health_check().await.is_err(),
        "关闭后 health_check 必须返回 Err"
    );

    let pool = OssPool::new(config).expect("pool 必须可构造");
    pool.close();
    pool.close();
    assert!(pool.stats().closed, "pool close 幂等且必须置位");
    let error = pool
        .put_object(&key, Bytes::from_static(b"x"))
        .await
        .expect_err("关闭池后 put 必须失败");
    assert!(
        matches!(error, OssError::Unsupported(_)),
        "应 Unsupported: {error}"
    );
    assert!(
        pool.get_object(&key).await.is_err(),
        "关闭池后 get 必须失败"
    );
    assert!(
        pool.delete_object(&key).await.is_err(),
        "关闭池后 delete 必须失败"
    );
    assert!(pool.head(&key).await.is_err(), "关闭池后 head 必须失败");
    let stats = pool.stats();
    assert_eq!(
        stats.cancelled, 4,
        "四次数据面尝试都应计入 cancelled: {stats:?}"
    );
    assert_eq!(stats.puts_err, 1, "put 失败必须计数: {stats:?}");
    assert_eq!(stats.gets_err, 1, "get 失败必须计数: {stats:?}");
    assert_eq!(stats.deletes_err, 1, "delete 失败必须计数: {stats:?}");
}
