#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! `put_object_multipart` 的端到端行为契约（本地脚本化 HTTP 桩，离线、不依赖真实 OSS）。
//!
//! 起因（2026-09-22）：该入口此前**零测试覆盖** —— 把 `put_object_multipart` 的
//! 「分片循环」与「提交」抽成 `upload_all_parts` / `finish_multipart` 两个私有方法时，
//! `cargo test` 全绿**不构成**对该重构的验证。故补上两条用例，断言**请求序列**与**返回值**：
//!
//! - `happy_path_uploads_then_completes`：POST `?uploads` → PUT `?partNumber=1` → POST `?uploadId=…`，
//!   且成功路径**不留下孤儿审计**；
//! - `part_failure_aborts_and_reports_without_orphan`：分片 400 → DELETE `?uploadId=…`（abort），
//!   且 abort 成功时**不登记孤儿**（guard 已 disarm）。
//!
//! **验收方式**（两棵树各跑一次 + 变异探测，2026-09-22 实测）：
//!
//! 1. 桩用 `std::net` + 独立线程（本 crate 的 tokio 未开 `net` / `io-util` feature）；
//!    **必须有界等待** —— 脚本未被耗尽时按 deadline 退出，否则变异场景会**挂住**而不是变红；
//! 2. 桩绑定 `localhost` 的**全部**解析地址（本机 `getent hosts localhost` 给 `::1`、
//!    `getaddrinfo` 给 `127.0.0.1`，两套工具不一致 —— 与 `tdd_contracts.rs` 同源处理）；
//! 3. 变异「让分片循环一次都不执行」（`chunks.iter().enumerate().take(0)`）：
//!    **两条用例同时 RED**（请求数 3 → 2），证明用例不是空转。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::time::Duration;

use bytes::Bytes;
use ossx::{OssClient, OssConfig};

/// 按脚本应答的本地 HTTP 桩；返回 endpoint 与「收到的请求行」句柄。
///
/// 复用 `tests/tdd_contracts.rs` 的解析/补绑逻辑（本机 `localhost` 解析可能给出 `::1`）。
/// **有界等待**：脚本未被耗尽时按 deadline 退出，否则变异场景会**挂住**而不是变红。
fn serve_raw(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let resolved: Vec<SocketAddr> = ("localhost", 0)
        .to_socket_addrs()
        .expect("localhost 必须可解析")
        .collect();
    assert!(!resolved.is_empty(), "localhost 必须解析出地址");
    let first = resolved[0];
    let listener = TcpListener::bind(first).unwrap_or_else(|e| panic!("绑定 {first} 失败: {e}"));
    let port = listener.local_addr().expect("addr").port();
    let mut listeners = vec![listener];
    for addr in resolved.iter().skip(1) {
        let mut with_port = *addr;
        with_port.set_port(port);
        if let Ok(extra) = TcpListener::bind(with_port) {
            listeners.push(extra);
        }
    }
    for listener in &listeners {
        let _ = listener.set_nonblocking(true);
    }

    let expected = responses.len();
    let handle = std::thread::spawn(move || {
        let mut lines: Vec<String> = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        'outer: while lines.len() < expected && std::time::Instant::now() < deadline {
            let mut progressed = false;
            for listener in &listeners {
                if lines.len() >= expected {
                    break 'outer;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        progressed = true;
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let mut buf = [0_u8; 8192];
                        let read = stream.read(&mut buf).unwrap_or(0);
                        let text = String::from_utf8_lossy(&buf[..read]).to_string();
                        lines.push(text.lines().next().unwrap_or_default().to_owned());
                        let _ = stream.write_all(responses[lines.len() - 1].as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        lines
    });
    (format!("http://localhost:{port}"), handle)
}

fn ok_with(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn client_for(endpoint: &str) -> OssClient {
    let config = OssConfig::builder()
        .endpoint(endpoint)
        .bucket("demo-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("secret")
        .request_timeout(Duration::from_millis(400))
        .operation_deadline(Duration::from_secs(2))
        .build()
        .expect("loopback 配置必须有效");
    OssClient::new(config).expect("客户端构造必须成功")
}

const INITIATE_XML: &str =
    "<InitiateMultipartUploadResult><UploadId>upl-1</UploadId></InitiateMultipartUploadResult>";

#[tokio::test]
async fn happy_path_uploads_then_completes() {
    let responses = vec![
        ok_with(INITIATE_XML),
        "HTTP/1.1 200 OK\r\nETag: \"etag-1\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_owned(),
        ok_with(""),
    ];
    let (endpoint, handle) = serve_raw(responses);
    let client = client_for(&endpoint);

    client
        .put_object_multipart("k", Bytes::from_static(b"x"), 1)
        .await
        .expect("happy path 必须成功");

    let lines = handle.join().expect("桩线程");
    assert_eq!(lines.len(), 3, "应恰好 3 次请求，实为 {lines:?}");
    assert!(
        lines[0].starts_with("POST ") && lines[0].contains("uploads"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("PUT ") && lines[1].contains("partNumber=1"),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("POST ") && lines[2].contains("uploadId=upl-1"),
        "{}",
        lines[2]
    );
    assert!(
        client.multipart_orphan_audits().is_empty(),
        "成功路径不得留下孤儿审计"
    );
}

#[tokio::test]
async fn part_failure_aborts_and_reports_without_orphan() {
    let responses = vec![
        ok_with(INITIATE_XML),
        // 400 属不可重试类，避免桩脚本被重试消耗
        "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned(),
        "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned(),
    ];
    let (endpoint, handle) = serve_raw(responses);
    let client = client_for(&endpoint);

    let error = client
        .put_object_multipart("k", Bytes::from_static(b"x"), 1)
        .await
        .expect_err("分片失败必须报错");

    let lines = handle.join().expect("桩线程");
    assert_eq!(
        lines.len(),
        3,
        "应恰好 3 次请求（含 abort），实为 {lines:?}"
    );
    assert!(
        lines[2].starts_with("DELETE ") && lines[2].contains("uploadId=upl-1"),
        "第 3 次应为 abort：{}",
        lines[2]
    );
    assert!(
        client.multipart_orphan_audits().is_empty(),
        "abort 成功则不得登记孤儿（guard 已 disarm）：{error}"
    );
}
