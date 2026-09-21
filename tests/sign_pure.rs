//! 纯函数行为回归：签名向量、CanonicalizedResource、分片、key 校验、重试判定。
//!
//! 签名摘要是协议正确性的关键：本文件用固定 `secret` / `date` 断言 HMAC-SHA1
//! 摘要（期望值由独立实现按 OSS V1 规范计算），并在真实 loopback HTTP 上核对
//! `Authorization` 头，确保「签名输入」与「实际发出的请求」不脱节。

use std::time::Duration;

use bytes::Bytes;
use ossx::{
    authorization_header, canonicalized_resource, canonicalized_resource_with_subresources,
    is_oss_retryable, sign_v1, split_parts, with_retry, with_retry_default, ObjectKey, OssClient,
    OssConfig, OssError, RetryConfig, MAX_MULTIPART_PARTS, MAX_OBJECT_KEY_BYTES,
    MIN_MULTIPART_PART_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 固定向量 1：PUT 对象（无 x-oss-* 头）。
const PUT_OBJECT_SIGNATURE: &str = "i2eNP/BLD/pc/CxWss90UYPvKI4=";
/// 固定向量 2：InitiateMultipartUpload（子资源 `?uploads`）。
const INITIATE_SIGNATURE: &str = "PgucxVrEkprTdj6PxjXZ/V41Xr8=";
/// 固定向量 3：bucket 根请求（CanonicalizedResource 带尾斜杠）。
const BUCKET_ROOT_SIGNATURE: &str = "xDz9ReVLbYqefA9P8wEftXm7gZM=";
/// 固定向量 4：预签名形态（`Date` 位为 Expires 秒）。
const PRESIGN_SIGNATURE: &str = "C/Z+oEWx2wstp6ES//XafsrRoxo=";
/// 固定向量 5：含 CanonicalizedOSSHeaders 的完整 StringToSign。
const OSS_HEADERS_SIGNATURE: &str = "h7XSe5eonIvTvNHn3ZEP/0y7Rrk=";

#[test]
fn sign_v1_matches_fixed_vectors() {
    assert_eq!(
        sign_v1(
            "secret",
            "PUT",
            "",
            "application/octet-stream",
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "",
            "/bucket/key"
        ),
        PUT_OBJECT_SIGNATURE
    );
    assert_eq!(
        sign_v1("sec", "POST", "", "", "date", "", "/bucket/k?uploads"),
        INITIATE_SIGNATURE
    );
    assert_eq!(
        sign_v1(
            "sec",
            "GET",
            "",
            "",
            "Fri, 01 Jan 2100 00:00:00 GMT",
            "",
            "/bucket/"
        ),
        BUCKET_ROOT_SIGNATURE
    );
    assert_eq!(
        sign_v1("sk", "GET", "", "", "1893456000", "", "/bucket/key"),
        PRESIGN_SIGNATURE
    );
    assert_eq!(
        sign_v1(
            "sk-test",
            "PUT",
            "d41d8cd98f00b204e9800998ecf8427e",
            "text/plain",
            "Mon, 21 Sep 2026 00:00:00 GMT",
            "x-oss-meta-a:1\n",
            "/demo-bucket/dir/obj?partNumber=2&uploadId=UID"
        ),
        OSS_HEADERS_SIGNATURE
    );
}

#[test]
fn sign_v1_is_deterministic_and_sensitivity_checked() {
    let baseline = sign_v1("secret", "GET", "", "", "date", "", "/bucket/key");
    // 同一输入必须稳定
    assert_eq!(
        baseline,
        sign_v1("secret", "GET", "", "", "date", "", "/bucket/key")
    );
    // 任一签名输入变化都必须改变摘要
    assert_ne!(
        baseline,
        sign_v1("secret!", "GET", "", "", "date", "", "/bucket/key")
    );
    assert_ne!(
        baseline,
        sign_v1("secret", "PUT", "", "", "date", "", "/bucket/key")
    );
    assert_ne!(
        baseline,
        sign_v1("secret", "GET", "", "", "date!", "", "/bucket/key")
    );
    assert_ne!(
        baseline,
        sign_v1("secret", "GET", "", "", "date", "", "/bucket/KEY")
    );
    assert_ne!(
        baseline,
        sign_v1("secret", "GET", "md5", "", "date", "", "/bucket/key")
    );
    assert_ne!(
        baseline,
        sign_v1("secret", "GET", "", "text/plain", "date", "", "/bucket/key")
    );
    assert_ne!(
        baseline,
        sign_v1(
            "secret",
            "GET",
            "",
            "",
            "date",
            "x-oss-a:1\n",
            "/bucket/key"
        )
    );

    // Authorization 头格式固定
    assert_eq!(
        authorization_header("AKID", &baseline),
        format!("OSS AKID:{baseline}")
    );
}

#[test]
fn canonicalized_resource_normalizes_and_sorts_subresources() {
    assert_eq!(canonicalized_resource("b", "a/b"), "/b/a/b");
    assert_eq!(canonicalized_resource("b", "/a"), "/b/a");
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
    assert_eq!(
        canonicalized_resource_with_subresources("b", "k", &[("uploads", Some(""))]),
        "/b/k?uploads"
    );
    assert_eq!(
        canonicalized_resource_with_subresources("b", "k", &[("uploadId", Some("u1"))]),
        "/b/k?uploadId=u1"
    );
    assert_eq!(
        canonicalized_resource_with_subresources("b", "", &[("continuation-token", Some("tok"))]),
        "/b/?continuation-token=tok"
    );
    // 空子资源集合退化为无 query 形态
    assert_eq!(
        canonicalized_resource_with_subresources("b", "k", &[]),
        "/b/k"
    );
}

#[test]
fn split_parts_covers_boundaries() {
    let data = b"abcdefghij";
    let parts = split_parts(data, 3);
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], b"abc");
    assert_eq!(parts[1], b"def");
    assert_eq!(parts[2], b"ghi");
    assert_eq!(parts[3], b"j");

    assert!(split_parts(b"", 4).is_empty());
    assert_eq!(split_parts(data, 0), vec![&data[..]]);
    assert_eq!(split_parts(data, 10), vec![&data[..]]);
    assert_eq!(split_parts(data, usize::MAX), vec![&data[..]]);

    // multipart 计划：末片可小于最小值，但非末片必须达到最小值
    let big = vec![0u8; MIN_MULTIPART_PART_BYTES * 2 + 1];
    let parts = split_parts(&big, MIN_MULTIPART_PART_BYTES);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2].len(), 1);
    // 分片数上界由 MAX_MULTIPART_PARTS 约束（校验在 client 内部完成）
    assert_eq!(MAX_MULTIPART_PARTS, 10_000);
}

#[test]
fn object_key_rejects_unsafe_inputs() {
    assert_eq!(
        ObjectKey::new("dir/object.txt").expect("ok").as_str(),
        "dir/object.txt"
    );
    assert_eq!(
        ObjectKey::new("  dir/object.txt  ").expect("trim").as_str(),
        "dir/object.txt"
    );

    // 前导斜杠、`..`、超长、空、控制字符全部拒绝
    for key in [
        "/leading",
        "..",
        "../escape",
        "a/../b",
        "",
        "   ",
        "a\0b",
        "a\nb",
    ] {
        let error = ObjectKey::new(key).expect_err("必须拒绝");
        assert!(matches!(error, OssError::Config(_)), "{key}");
        assert!(!error.is_retryable());
    }
    assert!(ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES)).is_ok());
    let error = ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES + 1)).expect_err("过长");
    assert!(error.to_string().contains("上限"), "{error}");
}

#[test]
fn retry_predicate_matches_error_classification() {
    assert!(is_oss_retryable(&OssError::Connection(
        "oss GET network: reset".into()
    )));
    assert!(is_oss_retryable(&OssError::Connection(
        "oss GET server status=503".into()
    )));
    // 鉴权降级永不重试
    assert!(!is_oss_retryable(&OssError::Connection(
        "oss GET auth/forbidden status=403".into()
    )));
    assert!(!is_oss_retryable(&OssError::Connection(
        "HTTP 401 unauthorized".into()
    )));
    assert!(!is_oss_retryable(&OssError::Connection(
        "403 Forbidden".into()
    )));
    // 永久错误与本地拒绝
    assert!(!is_oss_retryable(&OssError::Config("bad key".into())));
    assert!(!is_oss_retryable(&OssError::Backend("HTTP 404".into())));
    assert!(!is_oss_retryable(&OssError::Serialization("xml".into())));
    assert!(!is_oss_retryable(&OssError::Timeout("slow".into())));
    assert!(!is_oss_retryable(&OssError::Unsupported("closed".into())));
    assert!(!is_oss_retryable(&OssError::Io(std::io::Error::other(
        "disk"
    ))));
}

#[tokio::test]
async fn retry_config_bounds_and_backoff() {
    assert!(RetryConfig::fixed(3, 0).validate().is_ok());
    assert!(RetryConfig::fixed(0, 0).validate().is_err());
    assert!(RetryConfig::fixed(11, 0).validate().is_err());

    let exponential = RetryConfig::exponential(6, 100, 400, 0.0);
    assert_eq!(exponential.delay_for(1), Duration::from_millis(100));
    assert_eq!(exponential.delay_for(2), Duration::from_millis(200));
    assert_eq!(exponential.delay_for(3), Duration::from_millis(400));
    assert_eq!(
        exponential.delay_for(9),
        Duration::from_millis(400),
        "退避必须封顶"
    );

    // 永久错误不消耗重试预算
    let mut attempts = 0u32;
    let error = with_retry_default(&RetryConfig::fixed(5, 0), "op", || {
        attempts += 1;
        async { Err::<(), _>(OssError::Config("permanent".into())) }
    })
    .await
    .expect_err("必须失败");
    assert!(matches!(error, OssError::Config(_)));
    assert_eq!(attempts, 1);

    // 可重试错误耗尽预算
    let mut attempts = 0u32;
    let error = with_retry(&RetryConfig::fixed(3, 0), "op", || {
        attempts += 1;
        async { Err::<(), _>(OssError::Connection("blip".into())) }
    })
    .await
    .expect_err("必须耗尽");
    assert!(is_oss_retryable(&error));
    assert_eq!(attempts, 3);
}

/// 读取一个完整 HTTP 请求（含 body），返回原始文本。
async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut expected_length = None;
    loop {
        let read = stream.read(&mut chunk).await.expect("读取请求");
        assert!(read > 0, "连接在请求完成前关闭");
        received.extend_from_slice(&chunk[..read]);
        if expected_length.is_none() {
            if let Some(header_end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&received[..header_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                expected_length = Some(header_end + 4 + content_length);
            }
        }
        if expected_length.is_some_and(|total| received.len() >= total) {
            return String::from_utf8_lossy(&received).to_string();
        }
    }
}

fn header_value(request_head: &str, name: &str) -> Option<String> {
    request_head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

#[tokio::test]
async fn put_object_signs_the_real_http_request() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 loopback");
    let address = listener.local_addr().expect("本地地址");
    let config = OssConfig::builder()
        .endpoint(format!("http://localhost:{}", address.port()))
        .bucket("bucket")
        .access_key_id("AKID")
        .access_key_secret("secret")
        .build()
        .expect("配置");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = read_http_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .expect("写响应");
        request
    });

    let client = OssClient::new(config).expect("客户端");
    client
        .put_object("dir/object.txt", Bytes::from_static(b"payload"))
        .await
        .expect("PUT");
    let request = server.await.expect("server task");

    let head = request
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(head.starts_with("PUT /dir/object.txt HTTP/1.1"), "{head}");

    let date = header_value(&head, "date").expect("Date 头");
    let expected = sign_v1(
        "secret",
        "PUT",
        "",
        "application/octet-stream",
        &date,
        "",
        "/bucket/dir/object.txt",
    );
    let expected_authorization = format!("OSS AKID:{expected}");
    assert_eq!(
        header_value(&head, "authorization").as_deref(),
        Some(expected_authorization.as_str())
    );

    assert_eq!(
        header_value(&head, "content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert!(
        header_value(&head, "host").is_some_and(|host| host.starts_with("bucket.localhost")),
        "{head}"
    );
}
