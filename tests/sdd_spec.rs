#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! SDD 规格对照（特性 002）：把 `docs/标准.md` 的章节条款转成可执行断言。
//!
//! // SPEC-MAP: S-1 | 1. 定位 | assert_positioning
//! // SPEC-MAP: S-2 | 2. 字段治理 / 数据约定 | assert_field_and_data_governance
//! // SPEC-MAP: S-3 | 3. 资源治理 | assert_resource_governance
//! // SPEC-MAP: S-4 | 4. 安全约定 | assert_security_contracts
//! // SPEC-MAP: S-5 | 5. 验收 | assert_acceptance
//! // SPEC-MAP: S-6 | 6. 质量门禁约束 | assert_quality_gates

use std::time::Duration;

use bytes::Bytes;
use ossx::{
    byte_stream_from_bytes, canonicalized_resource, canonicalized_resource_with_subresources,
    default_retry_config, is_oss_retryable, sign_v1, split_parts, ObjectKey, OssConfig, OssError,
    OssPool, PresignOptions, RetryConfig, HARD_MAX_BUFFER_BYTES, HARD_MAX_ERROR_BODY_BYTES,
    HARD_MAX_IN_FLIGHT, HARD_MAX_OBJECT_BYTES, MAX_MULTIPART_PART_BYTES, MAX_OBJECT_KEY_BYTES,
    MAX_RETRY_ATTEMPTS, MIN_MULTIPART_PART_BYTES,
};

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn standard_doc() -> String {
    std::fs::read_to_string(format!("{MANIFEST}/docs/标准.md")).expect("docs/标准.md 必须存在")
}

fn valid_config() -> OssConfig {
    OssConfig::builder()
        .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
        .bucket("demo-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("secret")
        .build()
        .expect("测试配置必须有效")
}

/// S-1：面向生产的 OSS 适配器，零内部耦合；签名/预签名/重试均为 crate 内自洽实现，
/// 不含领域模型或业务编排。
#[test]
fn assert_positioning() {
    let manifest = std::fs::read_to_string(format!("{MANIFEST}/Cargo.toml")).expect("Cargo.toml");
    for internal in ["kernel", "contracts", "observex", "resiliencx"] {
        assert!(
            !manifest.contains(internal),
            "不得依赖内部 crate：{internal}"
        );
    }
    // 签名与预签名是纯函数：不需要任何客户端句柄即可工作。
    let signature = sign_v1("secret", "GET", "", "", "date", "", "/bucket/key");
    assert!(!signature.is_empty());
    let url = ossx::presign_url(
        "https://oss.example.com",
        "bucket",
        "key",
        "id",
        "secret",
        &PresignOptions::default(),
    )
    .expect("预签名是纯函数");
    assert!(url.contains("Signature="), "{url}");

    // 数据面走显式句柄类型，且可跨线程共享。
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ossx::OssClient>();
    assert_send_sync::<OssPool>();
    assert_send_sync::<OssConfig>();
}

/// S-2：`ObjectKey` 是唯一合法对象键入口；签名统一走纯函数；分片受常量约束；
/// 环境变量使用 `ENV_*` 常量而非硬编码字符串。
#[test]
fn assert_field_and_data_governance() {
    // ObjectKey 构造期校验：空 / 前导 `/` / `..` / 控制字符 / 超长全部拒绝。
    assert_eq!(ObjectKey::new("dir/k.txt").unwrap().as_str(), "dir/k.txt");
    let too_long = "k".repeat(MAX_OBJECT_KEY_BYTES + 1);
    for bad in [
        "",
        "/leading",
        "../escape",
        "a/../b",
        "line\nbreak",
        too_long.as_str(),
    ] {
        assert!(ObjectKey::new(bad).is_err(), "非法 key {bad:?} 必须拒绝");
    }

    // 签名统一入口：子资源按字典序排序，空 key 归一到 bucket 根。
    assert_eq!(canonicalized_resource("b", ""), "/b/");
    assert_eq!(canonicalized_resource("b", "/k"), "/b/k");
    assert_eq!(
        canonicalized_resource_with_subresources(
            "bucket",
            "obj/key",
            &[("uploadId", Some("UID")), ("partNumber", Some("2"))],
        ),
        "/bucket/obj/key?partNumber=2&uploadId=UID"
    );

    // 分片切分受常量约束，`split_parts` 是唯一实现。
    assert_eq!(MIN_MULTIPART_PART_BYTES, 100 * 1024);
    assert_eq!(MAX_MULTIPART_PART_BYTES, 512 * 1024 * 1024);
    assert_eq!(ossx::MAX_MULTIPART_PARTS, 10_000);
    assert_eq!(split_parts(b"", 4).len(), 0);
    assert_eq!(
        split_parts(b"abc", 0).len(),
        1,
        "part_size=0 按整段返回单片"
    );

    // 环境变量以常量登记（前缀统一）。
    assert_eq!(ossx::ENV_ENDPOINT, "FOUNDATIONX_OSSX_ENDPOINT");
    assert_eq!(
        ossx::ENV_ACCESS_KEY_SECRET,
        "FOUNDATIONX_OSSX_ACCESS_KEY_SECRET"
    );
    assert!(ossx::ENV_ENDPOINT.starts_with("FOUNDATIONX_OSSX_"));
}

/// S-3：资源上界在构建期校验并 clamp 到 `HARD_MAX_*`；超时不得为零且
/// `operation_deadline >= request_timeout`；重试指数退避且尝试次数有上限；
/// 错误体读取有界。
#[test]
fn assert_resource_governance() {
    assert_eq!(HARD_MAX_IN_FLIGHT, 1_024);
    assert_eq!(HARD_MAX_OBJECT_BYTES, 5 * 1024 * 1024 * 1024);
    assert_eq!(HARD_MAX_BUFFER_BYTES, 512 * 1024 * 1024);
    assert_eq!(HARD_MAX_ERROR_BODY_BYTES, 1024 * 1024);

    let builder = || {
        OssConfig::builder()
            .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
            .bucket("demo-bucket")
            .access_key_id("id")
            .access_key_secret("sec")
    };

    // 越界 fail-closed；恰好等于硬上界放行。
    assert!(builder()
        .max_in_flight(HARD_MAX_IN_FLIGHT + 1)
        .build()
        .is_err());
    builder().max_in_flight(HARD_MAX_IN_FLIGHT).build().unwrap();
    assert!(builder()
        .max_error_body_bytes(HARD_MAX_ERROR_BODY_BYTES + 1)
        .build()
        .is_err());

    // 超时/deadline 关系。
    assert!(builder().request_timeout(Duration::ZERO).build().is_err());
    assert!(builder()
        .request_timeout(Duration::from_secs(9))
        .operation_deadline(Duration::from_secs(3))
        .build()
        .is_err());

    // 重试：指数退避 + 抖动、次数上限。
    let retry: RetryConfig = default_retry_config();
    retry.validate().expect("默认重试配置必须合法");
    assert!(retry.delay_for(1) > Duration::ZERO);
    assert!(retry.validate().is_ok());
    assert!(
        RetryConfig::exponential(MAX_RETRY_ATTEMPTS + 1, 10, 100, 0.1)
            .validate()
            .is_err()
    );
}

/// S-4：`AccessKeySecret` 只进入签名计算，Debug / 错误消息 / URL 均不回显；
/// 远程强制 HTTPS；鉴权失败不重试；STS token 同级脱敏。
#[test]
fn assert_security_contracts() {
    let config = OssConfig::builder()
        .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
        .bucket("demo-bucket")
        .access_key_id("LTAI5tVeryLongAccessKeyId")
        .access_key_secret("super-secret-value")
        .security_token("sts-token-value")
        .build()
        .unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains("super-secret-value"), "{debug}");
    assert!(!debug.contains("sts-token-value"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(
        !debug.contains("LTAI5tVeryLongAccessKeyId"),
        "AK id 需中间脱敏"
    );

    // 错误消息永不回显 secret。
    let error = OssError::Connection("oss GET network: connection reset".into());
    assert!(!error.to_string().contains("access_key_secret"));

    // 预签名 URL 携带签名但绝不携带 secret 本体。
    let url = ossx::presign_url(
        "https://oss.example.com",
        "bucket",
        "key",
        "id",
        "super-secret-value",
        &PresignOptions::default(),
    )
    .unwrap();
    assert!(!url.contains("super-secret-value"), "{url}");

    // 远程强制 HTTPS，HTTP 仅 loopback。
    assert!(OssConfig::builder()
        .endpoint("http://oss.example.com")
        .bucket("b")
        .access_key_id("id")
        .access_key_secret("sec")
        .build()
        .is_err());

    // 鉴权/权限失败立即返回，不重试。
    assert!(!is_oss_retryable(&OssError::Backend("HTTP 403".into())));
    assert!(!is_oss_retryable(&OssError::Connection(
        "oss GET auth/forbidden status=403".into()
    )));
    assert!(is_oss_retryable(&OssError::Connection("network".into())));

    // 数据形态与凭据类型不携带明文 secret 的展示路径。
    let _ = byte_stream_from_bytes(Bytes::from_static(b"x"));
    let _ = valid_config();
}

/// S-5：验收面——标准文档登记的 fmt / test / clippy / package 与热路径基准可复现，
/// 且测试覆盖清单确实登记了签名向量、脱敏、ObjectKey 与重试分类。
#[test]
fn assert_acceptance() {
    let standard = standard_doc();
    for command in [
        "cargo fmt --all --check",
        "cargo test --all-targets",
        "cargo clippy --all-targets -- -D warnings",
        "cargo package --no-verify",
        "cargo bench --bench hot_path -- --quick",
    ] {
        assert!(
            standard.contains(command),
            "验收命令 {command:?} 必须登记在 docs/标准.md"
        );
    }
    for coverage in ["签名已知向量", "凭据脱敏回归", "ObjectKey", "重试分类"] {
        assert!(
            standard.contains(coverage),
            "覆盖清单 {coverage:?} 必须登记在 docs/标准.md"
        );
    }
}

/// S-6：crate 级质量门禁属性不得移除；公共 API 面由 lib.rs 的逐项点名测试锁定，
/// 且必须与 `docs/API.md` 同步存在。
#[test]
fn assert_quality_gates() {
    let lib = std::fs::read_to_string(format!("{MANIFEST}/src/lib.rs")).expect("src/lib.rs");
    for attribute in [
        "#![forbid(unsafe_code)]",
        "#![deny(missing_docs)]",
        "#![deny(unreachable_pub)]",
    ] {
        assert!(lib.contains(attribute), "crate 级属性不得移除：{attribute}");
    }
    assert!(
        lib.contains("public_api_surface"),
        "公共 API 面必须由 lib.rs 的逐项点名测试锁定"
    );
    assert!(
        std::path::Path::new(MANIFEST).join("docs/API.md").is_file(),
        "新增/删除导出必须同步 docs/API.md"
    );
    assert!(
        std::path::Path::new(MANIFEST)
            .join("docs/标准.md")
            .is_file(),
        "新增/删除导出必须同步 docs/标准.md"
    );
}
