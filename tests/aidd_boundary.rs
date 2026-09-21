#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! AIDD 对抗 / 边界用例（特性 002）。
//!
//! 候选由 AI 生成，逐条人工复核后仅保留「结论=保留」项；丢弃项登记于 PR 描述。
//! 全部离线（不依赖真实 OSS，也不使用 `#[ignore]`）。
//!
//! // AIDD: secret 经 Debug/错误/预签名 URL 三条路径不外泄 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 凭据脱敏 | 结论=保留
//! // AIDD: 远程明文 HTTP endpoint | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 强制 HTTPS | 结论=保留
//! // AIDD: ObjectKey 路径穿越与超长 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 对象键校验 | 结论=保留
//! // AIDD: 超限对象大小 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 资源上界 | 结论=保留
//! // AIDD: 鉴权降级文案多形态 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 4xx 不重试 | 结论=保留
//! // AIDD: 不可达端点与已关闭客户端 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 超时/生命周期 | 结论=保留
//! // AIDD: 签名向量与资源归一 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 单一签名入口 | 结论=保留
//! // AIDD: 分片切分边界 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 split_parts 唯一 | 结论=保留

use std::time::Duration;

use bytes::Bytes;
use ossx::{
    canonicalized_resource, presign_url, sign_v1, split_parts, ObjectKey, OssClient, OssConfig,
    OssError, PresignOptions, MAX_OBJECT_KEY_BYTES,
};

fn builder() -> ossx::OssConfigBuilder {
    OssConfig::builder()
        .bucket("demo-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("super-secret-value")
}

/// 对抗：secret 只进签名计算——Debug、错误消息、预签名 URL 三条出口都不得回显。
#[test]
fn secret_never_leaks_from_any_surface() {
    let config = builder()
        .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
        .security_token("sts-token-value")
        .build()
        .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains("super-secret-value"), "{debug}");
    assert!(!debug.contains("sts-token-value"), "{debug}");

    let client = OssClient::new(config).expect("客户端");
    let url = client
        .presign_url("dir/object.txt", &PresignOptions::default())
        .expect("预签名");
    assert!(!url.contains("super-secret-value"), "{url}");
    assert!(url.contains("Signature="), "{url}");

    // 错误消息不携带 secret 字段名之外的任何凭据内容。
    for error in [
        OssError::Connection("oss GET network: connection reset".into()),
        OssError::Backend("HTTP 403".into()),
        OssError::Config("bad".into()),
    ] {
        let rendered = error.to_string();
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
    }
}

/// 对抗：远程明文 HTTP 必须 fail-closed；loopback HTTP 是唯一例外。
/// 预签名 URL 更严格——一律要求 `https://`。
#[test]
fn plain_http_is_rejected_outside_loopback() {
    for endpoint in ["http://oss.example.com", "http://10.0.0.1:9000"] {
        assert!(
            builder().endpoint(endpoint).build().is_err(),
            "{endpoint} 必须拒绝"
        );
    }
    for endpoint in ["http://localhost:9000", "http://127.0.0.1:9000"] {
        builder()
            .endpoint(endpoint)
            .build()
            .unwrap_or_else(|error| panic!("{endpoint} 应允许：{error}"));
    }

    let error = presign_url(
        "http://localhost:9000",
        "demo-bucket",
        "k",
        "id",
        "sec",
        &PresignOptions::default(),
    )
    .expect_err("预签名不接受明文 HTTP");
    assert!(matches!(error, OssError::Config(_)));
    assert!(error.to_string().contains("https"), "{error}");
}

/// 对抗：对象键是唯一入口，路径穿越 / 超长 / 控制字符 / 前导斜杠全部拒绝。
#[test]
fn object_key_rejects_traversal_and_oversized_input() {
    let too_long = "k".repeat(MAX_OBJECT_KEY_BYTES + 1);
    for bad in [
        "",
        "   ",
        "/leading",
        "..",
        "a/../../etc/passwd",
        "line\nbreak",
        "ansi\u{1b}[31m",
        too_long.as_str(),
    ] {
        assert!(ObjectKey::new(bad).is_err(), "非法 key {bad:?} 必须拒绝");
    }
    // 合法键：保留原样（含非 ASCII 与空白以外的字符）。
    let ok = ObjectKey::new("dir/子目录/object v1.txt").expect("合法键");
    assert_eq!(ok.as_str(), "dir/子目录/object v1.txt");
}

/// 对抗：对象大小超过配置上限时在发请求前拒绝，且归类为不可重试的本地配置错误。
#[tokio::test]
async fn oversized_object_is_rejected_before_network() {
    let client = OssClient::new(
        builder()
            .endpoint("http://localhost:1") // 必然不可达；请求若发出则错误类型会是 Connection/Timeout
            .max_object_bytes(8)
            .max_buffer_bytes(16)
            .build()
            .unwrap(),
    )
    .unwrap();

    let error = client
        .put_object("k", Bytes::from(vec![0_u8; 9]))
        .await
        .expect_err("超限必须拒绝");
    assert!(matches!(error, OssError::Config(_)), "{error:?}");
    assert!(!error.is_retryable(), "本地校验错误不可重试");

    // 恰好等于上限：允许（会走到网络层，因此以网络失败告终，但不是 Config）。
    let error = client
        .put_object("k", Bytes::from(vec![0_u8; 8]))
        .await
        .expect_err("端点不可达");
    assert!(!matches!(error, OssError::Config(_)), "{error:?}");
}

/// 对抗：鉴权/权限文案有多种形态，大小写不同也必须判为不可重试。
#[test]
fn auth_failure_never_retries() {
    for message in [
        "oss GET auth/forbidden status=403",
        "HTTP unauthorized",
        "403 Forbidden",
        "FORBIDDEN",
        "Auth/Forbidden",
    ] {
        let error = OssError::Connection(message.into());
        assert!(!error.is_retryable(), "{message} 不得重试");
    }
    // 非鉴权的连接类错误仍可重试。
    assert!(OssError::Connection("oss PUT server status=503".into()).is_retryable());
}

/// 对抗：不可达端点是「可重试的瞬时故障」，已关闭客户端是「本地生命周期拒绝」——
/// 两者分类必须区分，不能合并成同一个错误。
#[tokio::test]
async fn unreachable_and_closed_client_are_distinct() {
    let unreachable = OssClient::new(builder().endpoint("http://localhost:1").build().unwrap())
        .expect("构造不联网");
    let error = unreachable.ping().await.expect_err("不可达必须失败");
    assert!(
        matches!(error, OssError::Connection(_) | OssError::Timeout(_)),
        "{error:?}"
    );
    assert!(error.is_retryable(), "网络故障可重试");

    let closed = OssClient::new(builder().endpoint("http://localhost:1").build().unwrap())
        .expect("构造不联网");
    closed.close();
    assert!(closed.is_closed());
    let error = closed.ping().await.expect_err("关闭后必须拒绝");
    assert!(matches!(error, OssError::Unsupported(_)), "{error:?}");
    assert!(!error.is_retryable(), "本地拒绝不可重试");
    assert!(closed.get_object("k").await.is_err());
    assert!(closed.delete_object("k").await.is_err());
    let health = closed.health_check().await;
    assert!(health.is_err(), "生命周期拒绝必须 Err 而不是「不可用」结论");
}

/// 对抗：签名向量（HMAC-SHA1）与资源规范化——空 key、前导斜杠、子资源排序。
#[test]
fn sign_v1_vector_and_resource_normalization() {
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

    // 空 key 归一到 bucket 根；前导 `/` 被归一掉，不会产生 `//`。
    assert_eq!(canonicalized_resource("b", ""), "/b/");
    assert_eq!(canonicalized_resource("b", "/k"), "/b/k");
    assert_eq!(canonicalized_resource("b", "//k"), "/b/k");

    // 方法参与签名：GET 与 PUT 的同资源签名必须不同。
    let resource = canonicalized_resource("b", "k");
    assert_ne!(
        sign_v1("s", "GET", "", "", "d", "", &resource),
        sign_v1("s", "PUT", "", "", "d", "", &resource)
    );
}

/// 对抗：分片切分的空输入 / 零分片 / 超大分片边界，且不产生空片。
#[test]
fn split_parts_boundaries() {
    assert!(split_parts(b"", 4).is_empty(), "空数据不得产生分片");
    assert_eq!(split_parts(b"abc", 0).len(), 1, "part_size=0 按整段单片");
    assert_eq!(split_parts(b"abc", 3).len(), 1);
    assert_eq!(split_parts(b"abc", 4).len(), 1, "分片大于数据时单片");
    assert_eq!(split_parts(b"abcdef", 2).len(), 3);
    assert_eq!(
        split_parts(b"abcdef", 4)
            .iter()
            .map(|part| part.len())
            .collect::<Vec<_>>(),
        vec![4, 2]
    );

    // 预签名默认有效期是 1 小时，且方法参与签名。
    let options = PresignOptions::default();
    assert_eq!(options.method, "GET");
    assert_eq!(options.expires, Duration::from_secs(3600));
    let put = PresignOptions {
        method: "PUT".into(),
        ..PresignOptions::default()
    };
    let get_url = presign_url("https://oss.example.com", "b", "k", "id", "sec", &options).unwrap();
    let put_url = presign_url("https://oss.example.com", "b", "k", "id", "sec", &put).unwrap();
    assert_ne!(get_url, put_url, "方法不同则签名必须不同");
}
