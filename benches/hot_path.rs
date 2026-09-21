#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! ossx 热路径：`OssConfig` 构建校验 + Signature V1 签名纯函数。
//!
//! 纯本地路径，不发起任何网络请求、不依赖阿里云 OSS 服务。
use std::hint::black_box;
use std::time::Instant;

use ossx::{authorization_header, canonicalized_resource, sign_v1, OssConfig};

fn iters() -> u32 {
    if std::env::args().any(|a| a == "--quick") {
        1_000
    } else {
        50_000
    }
}

fn main() {
    let n = iters();

    // 预热：配置构建 + 校验。
    for _ in 0..n.min(1_000) {
        let config = OssConfig::builder()
            .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
            .bucket("bench-bucket")
            .access_key_id("bench-key-id")
            .access_key_secret("bench-key-secret")
            .build()
            .unwrap();
        config.validate().unwrap();
        black_box(&config);
    }
    // 预热：Signature V1 签名。
    for _ in 0..n.min(1_000) {
        let resource = canonicalized_resource("bench-bucket", "dir/object.txt");
        let signature = sign_v1(
            "bench-key-secret",
            "GET",
            "",
            "",
            "Mon, 21 Sep 2026 00:00:00 GMT",
            "",
            &resource,
        );
        black_box(authorization_header("bench-key-id", &signature));
    }

    let start = Instant::now();
    for i in 0..n {
        let config = OssConfig::builder()
            .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
            .bucket("bench-bucket")
            .access_key_id("bench-key-id")
            .access_key_secret("bench-key-secret")
            .build()
            .unwrap();
        config.validate().unwrap();
        let resource = canonicalized_resource("bench-bucket", "dir/object.txt");
        let signature = sign_v1(
            "bench-key-secret",
            "GET",
            "",
            "",
            "Mon, 21 Sep 2026 00:00:00 GMT",
            "",
            &resource,
        );
        let header = authorization_header("bench-key-id", &signature);
        black_box((i, &config, &header));
    }
    let elapsed = start.elapsed();
    println!(
        "bench_ossx_hot_path: iters={n} total={elapsed:?} per_iter={:?}",
        elapsed / n
    );
}
