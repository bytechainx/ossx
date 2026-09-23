#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! TDD 行为契约（特性 002）。
//!
//! 下表逐条登记 `specs/features/002-*/contracts/public-api-contract.md` 中 ossx 的全部入口。
//! 公开 API 已存在，先写断言只能得到假断言，因此每条入口都在 `/tmp` 的变异副本上
//! 观测过红、再在本树观测绿；变异描述与复现命令见 PR 描述。
//!
//! 数据面入口用**本地一次性 TCP 服务**（loopback HTTP）驱动，完全离线、
//! 不依赖真实 OSS，也不使用 `#[ignore]`。
//!
//! // TDD-PROBE: OssConfig::from_env | 变异：必填环境变量缺失时回落到默认值 | 红=from_env_fails_closed_on_missing_credentials | 绿=from_env_fails_closed_on_missing_credentials
//! // TDD-PROBE: OssConfig::from_toml | 变异：TOML 中的 access_key_secret 被接受 | 红=from_toml_rejects_credentials | 绿=from_toml_rejects_credentials
//! // TDD-PROBE: OssConfig::validate | 变异：远程明文 HTTP endpoint 被放行 | 红=validate_forces_https_and_hard_caps | 绿=validate_forces_https_and_hard_caps
//! // TDD-PROBE: OssClient::new | 变异：非法配置也能构造客户端 | 红=client_new_is_sync_and_fail_fast | 绿=client_new_is_sync_and_fail_fast
//! // TDD-PROBE: OssClient::ping | 变异：200 响应被当作探活失败 | 红=ping_reports_reachability | 绿=ping_reports_reachability
//! // TDD-PROBE: OssClient::put_object | 变异：超限对象放行上传 | 红=put_object_round_trip_and_size_guard | 绿=put_object_round_trip_and_size_guard
//! // TDD-PROBE: OssClient::get_object | 变异：404 被当作成功返回空体 | 红=get_object_reads_body_and_surfaces_404 | 绿=get_object_reads_body_and_surfaces_404
//! // TDD-PROBE: OssClient::delete_object | 变异：404 不再视为幂等成功 | 红=delete_object_is_idempotent | 绿=delete_object_is_idempotent
//! // TDD-PROBE: sign_v1 | 变异：签名串少一个换行分隔符 | 红=sign_v1_matches_known_vector | 绿=sign_v1_matches_known_vector
//! // TDD-PROBE: OssError::is_retryable | 变异：鉴权失败降级也被判可重试 | 红=error_is_retryable_by_classification | 绿=error_is_retryable_by_classification

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use ossx::{
    authorization_header, canonicalized_resource, is_oss_retryable, sign_v1, split_parts,
    OssClient, OssConfig, OssError, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET,
    ENV_ACQUIRE_TIMEOUT_MS, ENV_BUCKET, ENV_ENDPOINT, ENV_MAX_BUFFER_BYTES,
    ENV_MAX_ERROR_BODY_BYTES, ENV_MAX_IN_FLIGHT, ENV_MAX_OBJECT_BYTES, ENV_OPERATION_DEADLINE_MS,
    ENV_REGION, ENV_REQUEST_TIMEOUT_MS, HARD_MAX_BUFFER_BYTES, HARD_MAX_IN_FLIGHT,
    HARD_MAX_OBJECT_BYTES,
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

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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

/// 起一个本地一次性 HTTP 服务，最多处理 `connections` 个请求，返回 `http://localhost:<port>`。
///
/// 客户端使用 OSS 虚拟主机风格（`{bucket}.{host}`），IP endpoint 会被拒绝，
/// 因此 endpoint 的 host 必须是一个**可解析名**（这里是 `localhost`）——
/// **绑定的地址家族必须跟随解析结果，不能硬编码**：
/// 2026-09-22 实测本机 `getent hosts localhost` 给出 `::1`，而 `getaddrinfo`
/// （`std::net::ToSocketAddrs` 走的也是它）只给出 `127.0.0.1`，两套工具不一致；
/// 旧实现硬编码绑 `[::1]`，等于把可用性押在客户端栈的隐式回退上。
///
/// 现实现：解析 `localhost` → 绑第一个地址 → 在其余地址上补绑**同一端口**（失败不致命），
/// 并把「解析列表 / 实际绑定地址」写进 panic 消息，使失败可直接指向根因。
/// 服务线程随句柄被丢弃而分离；进程退出时自然结束，不阻塞用例。
fn serve(status_line: &'static str, body: &'static str, connections: usize) -> String {
    let resolved: Vec<SocketAddr> = ("localhost", 0)
        .to_socket_addrs()
        .expect("localhost 必须可解析（本地联调前提）")
        .collect();
    assert!(
        !resolved.is_empty(),
        "localhost 必须解析出至少一个地址（本地联调前提）"
    );

    let first = resolved[0];
    let listener = TcpListener::bind(first)
        .unwrap_or_else(|error| panic!("绑定 {first} 失败（解析列表：{resolved:?}）：{error}"));
    let port = listener.local_addr().expect("读取本地地址").port();

    // 其余解析地址上补绑同一端口：覆盖「客户端解析顺序与 bind 尝试顺序不一致」的情形。
    // 失败不致命（端口可能已被占用，或该家族不可用），仅用于提高稳定性。
    let mut listeners = vec![listener];
    for addr in resolved.iter().skip(1) {
        let mut with_port = *addr;
        with_port.set_port(port);
        if let Ok(extra) = TcpListener::bind(with_port) {
            listeners.push(extra);
        }
    }

    for listener in listeners {
        let _server = std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
    }

    format!("http://localhost:{port}")
}

/// loopback HTTP 是唯一允许的明文端点（本地开发；IP endpoint 不支持虚拟主机风格）。
fn loopback_client(endpoint: &str) -> OssClient {
    let config = base_builder()
        .endpoint(endpoint)
        .request_timeout(Duration::from_millis(400))
        .operation_deadline(Duration::from_secs(1))
        .build()
        .expect("loopback 配置必须有效");
    OssClient::new(config).expect("客户端构造必须成功")
}

/// `OssConfig::from_env`：必填项缺失即 fail-closed，且错误消息点名缺失变量。
#[test]
fn from_env_fails_closed_on_missing_credentials() {
    let _guard = env_guard();
    clear_env();

    let error = OssConfig::from_env().expect_err("缺 endpoint 必须失败");
    assert!(matches!(error, OssError::Config(_)));
    assert!(error.to_string().contains(ENV_ENDPOINT), "{error}");

    std::env::set_var(ENV_ENDPOINT, "https://oss-cn-hangzhou.aliyuncs.com");
    std::env::set_var(ENV_BUCKET, "env-bucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "env-id");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "env-secret");
    let config = OssConfig::from_env().expect("四项必填齐备即成功");
    assert_eq!(config.bucket, "env-bucket");
    assert_eq!(config.region, "ap-northeast-1", "region 未设置时取默认值");

    // 非数字与越界都必须报错，而不是静默取默认值。
    std::env::set_var(ENV_MAX_IN_FLIGHT, "not-a-number");
    assert!(OssConfig::from_env().is_err());
    std::env::set_var(ENV_MAX_IN_FLIGHT, (HARD_MAX_IN_FLIGHT + 1).to_string());
    let error = OssConfig::from_env().expect_err("超过硬上界必须失败");
    assert!(error.to_string().contains("max_in_flight"), "{error}");

    clear_env();
}

/// `OssConfig::from_toml`：凭据字段一律拒绝；非凭据字段可解析，凭据仍从环境变量合并。
#[test]
fn from_toml_rejects_credentials() {
    let _guard = env_guard();
    clear_env();

    let with_key_id = r#"
schema_version = 1

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
access_key_id = "LTAI..."
"#;
    let error = OssConfig::from_toml(with_key_id).expect_err("access_key_id 必须拒绝");
    assert!(error.to_string().contains("access_key_id"), "{error}");

    let root_level = r#"
schema_version = 1
access_key_secret = "secret"

[oss]
endpoint = "https://oss.example.com"
bucket = "demo-bucket"
"#;
    let error = OssConfig::from_toml(root_level).expect_err("根级 secret 必须拒绝");
    assert!(error.to_string().contains("access_key_secret"), "{error}");

    let malformed = OssConfig::from_toml("this is not = = toml").expect_err("语法错误");
    assert!(matches!(malformed, OssError::Serialization(_)));

    // 合法 TOML + 环境变量凭据：可构造，且 TOML 提供调参基线。
    std::env::set_var(ENV_ACCESS_KEY_ID, "env-id");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "env-secret");
    let valid = r#"
schema_version = 1

[oss]
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"
bucket = "toml-bucket"
request_timeout_ms = 2000
operation_deadline_ms = 4000
"#;
    let config = OssConfig::from_toml(valid).expect("toml + env");
    assert_eq!(config.bucket, "toml-bucket");
    assert_eq!(config.access_key_id, "env-id");
    assert_eq!(config.request_timeout, Duration::from_millis(2000));

    clear_env();
}

/// `OssConfig::validate`：远程强制 HTTPS、loopback 例外、资源上界落在 `1..=HARD_MAX_*`。
#[test]
fn validate_forces_https_and_hard_caps() {
    // 远程明文 HTTP 必须拒绝；loopback HTTP 允许。
    assert!(base_builder()
        .endpoint("http://oss.example.com")
        .build()
        .unwrap_err()
        .to_string()
        .contains("HTTPS"));
    base_builder()
        .endpoint("http://localhost:9000")
        .build()
        .expect("loopback http 允许");
    base_builder()
        .endpoint("http://127.0.0.1:9000")
        .build()
        .expect("loopback ip 允许");

    // endpoint 不允许 userinfo / path / query。
    for endpoint in [
        "https://user:pass@oss.example.com",
        "https://oss.example.com/path",
        "https://oss.example.com/?x=1",
    ] {
        assert!(
            base_builder().endpoint(endpoint).build().is_err(),
            "{endpoint} 必须被拒绝"
        );
    }

    // 必填项非空。
    assert!(base_builder().bucket("").build().is_err());
    assert!(base_builder().access_key_secret(" ").build().is_err());

    // 超时/deadline 为正，且 deadline >= request_timeout。
    assert!(base_builder()
        .acquire_timeout(Duration::ZERO)
        .build()
        .is_err());
    assert!(base_builder()
        .request_timeout(Duration::from_secs(10))
        .operation_deadline(Duration::from_secs(1))
        .build()
        .is_err());

    // 硬上界：越界拒绝、恰好等于硬上界放行。
    assert!(base_builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT + 1)
        .build()
        .is_err());
    assert!(base_builder()
        .max_object_bytes(HARD_MAX_OBJECT_BYTES + 1)
        .build()
        .is_err());
    assert!(base_builder()
        .max_buffer_bytes(HARD_MAX_BUFFER_BYTES + 1)
        .build()
        .is_err());
    base_builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT)
        .build()
        .expect("恰好等于硬上界合法");

    // object 上限不得超过 buffer 上限。
    assert!(base_builder()
        .max_object_bytes(4096)
        .max_buffer_bytes(1024)
        .build()
        .is_err());

    // validate() 与 build() 结论一致。
    let ok = base_builder().build().unwrap();
    ok.validate().expect("已构造的配置必须通过 validate");
    OssConfig::default()
        .validate()
        .expect_err("默认配置缺必填项");
}

/// `OssClient::new`：同步构造、不联网、非法配置 fail-fast。
#[test]
fn client_new_is_sync_and_fail_fast() {
    // 不可达端点也能同步构造（构造阶段不发网络请求）。
    let client = OssClient::new(
        base_builder()
            .endpoint("http://localhost:1")
            .build()
            .unwrap(),
    )
    .expect("构造不联网，必须成功");
    assert_eq!(client.config().bucket, "demo-bucket");
    assert!(!client.is_closed());

    // 非法配置（缺 endpoint）必须构造失败。
    assert!(OssClient::new(OssConfig::default()).is_err());
    let bad = OssConfig::builder()
        .endpoint("http://remote.example.com")
        .bucket("b")
        .access_key_id("id")
        .access_key_secret("sec")
        .build()
        .unwrap_err();
    assert!(matches!(bad, OssError::Config(_)));
}

/// `OssClient::ping`：按状态码判定可达性——200/403 可达，网络失败/5xx 不可达。
#[tokio::test]
async fn ping_reports_reachability() {
    let endpoint = serve("HTTP/1.1 200 OK", "", 4);
    let client = loopback_client(&endpoint);
    client.ping().await.expect("200 必须探活成功");
    let health = client.health_check().await.expect("健康检查是结构化结果");
    assert!(health.ready && health.bucket_accessible);

    // 不可达端点。
    let unreachable = loopback_client("http://localhost:1");
    let error = unreachable.ping().await.expect_err("不可达必须失败");
    assert!(
        matches!(error, OssError::Connection(_) | OssError::Timeout(_)),
        "{error:?}"
    );

    // 已关闭的客户端在本地即拒绝，且不可重试。
    let closed = loopback_client("http://localhost:1");
    closed.close();
    let error = closed.ping().await.expect_err("关闭后必须拒绝");
    assert!(matches!(error, OssError::Unsupported(_)));
    assert!(!error.is_retryable(), "本地生命周期拒绝不可重试");
}

/// `OssClient::put_object`：200 视为成功；超限对象与非法 key 在发请求前即拒绝。
#[tokio::test]
async fn put_object_round_trip_and_size_guard() {
    let endpoint = serve("HTTP/1.1 200 OK", "", 4);
    let client = loopback_client(&endpoint);
    client
        .put_object("dir/object.txt", Bytes::from_static(b"hello ossx"))
        .await
        .expect("200 必须视为上传成功");

    // 超过 max_object_bytes：本地前置校验，Config 分类且不可重试。
    let small = OssClient::new(
        base_builder()
            .endpoint("http://localhost:1")
            .max_object_bytes(4)
            .max_buffer_bytes(8)
            .build()
            .unwrap(),
    )
    .unwrap();
    let error = small
        .put_object("k", Bytes::from_static(b"12345"))
        .await
        .expect_err("超限必须拒绝");
    assert!(matches!(error, OssError::Config(_)), "{error:?}");
    assert!(!error.is_retryable());

    // 非法 key（含 `..`）在发请求前拒绝。
    let error = client
        .put_object("../escape", Bytes::from_static(b"v"))
        .await
        .expect_err("非法 key 必须拒绝");
    assert!(matches!(error, OssError::Config(_)), "{error:?}");
}

/// `OssClient::get_object`：读取响应体；404 归类为远端错误且不可重试。
#[tokio::test]
async fn get_object_reads_body_and_surfaces_404() {
    let endpoint = serve("HTTP/1.1 200 OK", "hello ossx", 4);
    let client = loopback_client(&endpoint);
    let body = client
        .get_object("dir/object.txt")
        .await
        .expect("200 必须成功");
    assert_eq!(&body[..], b"hello ossx");

    let missing = serve("HTTP/1.1 404 Not Found", "", 2);
    let client = loopback_client(&missing);
    let error = client.get_object("absent").await.expect_err("404 必须失败");
    assert!(matches!(error, OssError::Backend(_)), "{error:?}");
    assert!(!error.is_retryable(), "404 是永久故障");
}

/// `OssClient::delete_object`：204/200/404 都视为删除成功（幂等）；5xx 可重试。
#[tokio::test]
async fn delete_object_is_idempotent() {
    let endpoint = serve("HTTP/1.1 204 No Content", "", 4);
    let client = loopback_client(&endpoint);
    client
        .delete_object("dir/gone.txt")
        .await
        .expect("204 成功");

    let missing = serve("HTTP/1.1 404 Not Found", "", 2);
    let client = loopback_client(&missing);
    client
        .delete_object("already-gone.txt")
        .await
        .expect("404 表示对象已不存在，删除幂等");

    // 5xx：可重试（默认重试配置最多 3 次尝试，服务端预留更多连接）。
    let flaky = serve("HTTP/1.1 500 Internal Server Error", "", 8);
    let client = loopback_client(&flaky);
    let error = client.delete_object("k").await.expect_err("500 必须失败");
    assert!(error.is_retryable(), "5xx 是瞬时故障：{error:?}");
}

/// `sign_v1`：OSS Signature V1（HMAC-SHA1）已知向量与纯函数形态。
#[test]
fn sign_v1_matches_known_vector() {
    // docs/API.md 与 rustdoc 示例中锁定的向量。
    assert_eq!(
        sign_v1(
            "secret",
            "PUT",
            "",
            "application/octet-stream",
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "",
            "/bucket/key",
        ),
        "i2eNP/BLD/pc/CxWss90UYPvKI4="
    );

    // 任一字段变化都必须改变签名（无字段被吞掉）。
    let base = sign_v1("s", "GET", "", "", "d", "", "/b/k");
    assert_ne!(base, sign_v1("s", "PUT", "", "", "d", "", "/b/k"));
    assert_ne!(base, sign_v1("s2", "GET", "", "", "d", "", "/b/k"));
    assert_ne!(base, sign_v1("s", "GET", "", "", "d", "", "/b/k2"));
    assert_ne!(base, sign_v1("s", "GET", "", "", "d2", "", "/b/k"));

    // 拼装与资源规范化（纯函数，无需客户端）。
    assert_eq!(authorization_header("id", &base), format!("OSS id:{base}"));
    assert_eq!(canonicalized_resource("b", ""), "/b/");
    assert_eq!(canonicalized_resource("b", "/k"), "/b/k");
    assert_eq!(split_parts(b"abcdef", 2).len(), 3);
}

/// `OssError::is_retryable`：只有「连接类且非鉴权降级」可重试。
#[test]
fn error_is_retryable_by_classification() {
    assert!(is_oss_retryable(&OssError::Connection(
        "oss GET network: connection reset".into()
    )));
    assert!(OssError::Connection("oss PUT server status=500".into()).is_retryable());

    // 鉴权/权限降级是第二道防线：即使被归入 Connection 也不得重试。
    for message in [
        "oss GET auth/forbidden status=403",
        "HTTP unauthorized",
        "403 Forbidden",
    ] {
        let error = OssError::Connection(message.into());
        assert!(!error.is_retryable(), "{message} 不得重试");
        assert!(!is_oss_retryable(&error));
    }

    assert!(!OssError::Config("bad".into()).is_retryable());
    assert!(!OssError::Backend("HTTP 404".into()).is_retryable());
    assert!(!OssError::Serialization("xml".into()).is_retryable());
    assert!(!OssError::Timeout("slow".into()).is_retryable());
    assert!(!OssError::Unsupported("closed".into()).is_retryable());
    assert!(!OssError::Io(std::io::Error::other("disk")).is_retryable());
}
