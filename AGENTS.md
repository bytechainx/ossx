# ossx Agent 指南

> 本文件为 AI Agent 在本仓库工作时的入口指南。

## 项目定位

阿里云 OSS 适配器：`reqwest` + OSS Signature V1，覆盖对象读写、流式传输、分片上传、预签名 URL、凭据轮换与连接池统计。

## 技术栈

- Rust edition 2021, rust-version 1.85
- 关键依赖: `reqwest`（rustls-tls）、`tokio`、`hmac`/`sha1`（Signature V1）、`quick-xml`、`bytes`、`serde`、`thiserror`、`tracing`、`chrono`、`base64`、`toml`、`url`
- 零内部耦合，不依赖 kernel/contracts 等私有 crate

## 代码结构

```text
src/
├── lib.rs        # 入口：模块声明 + 受控 re-export + 公开 API 面测试
├── client.rs     # OssClient 数据面：对象读写 / multipart / ping / health_check
├── config.rs     # OssConfig 配置结构体 + builder + env/toml 加载 + 校验
├── credential.rs # CredentialProvider / StaticCredentialProvider 凭据轮换
├── error.rs      # OssError / OssResult
├── pool.rs       # OssPool 连接池 + OssPoolStats / OssHealth
├── presign.rs    # presign_url / PresignOptions 预签名 URL
├── retry.rs      # RetryConfig / with_retry 重试策略
├── sign.rs       # sign_v1 / authorization_header / canonicalized_resource 签名原语
└── types.rs      # ObjectKey / ObjectMeta / UploadOptions / DownloadOptions / ByteStream
```

## 开发约定

- 注释与文档使用简体中文；标识符保持英文
- 错误：`OssError` thiserror 枚举 + `#[non_exhaustive]` + `OssResult<T>` 别名
- 配置：结构体 + `builder()`/`from_env()`（前缀 `FOUNDATIONX_OSSX_`）/`from_toml()` + `validate()` + fail-fast
- 凭据只能从 env 或 builder 注入，`Debug` 输出与错误消息不回显 `AccessKeySecret`
- 禁止裸 `unwrap()`（库代码）
- async tokio，禁止阻塞 I/O；`#![forbid(unsafe_code)]`
- 远程 endpoint 强制 HTTPS，HTTP 仅允许 loopback 开发端点
- 资源上界（对象大小、缓冲、并发、错误体）构建期校验并 clamp 到 `HARD_MAX_*`

## 门禁（P0）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

热路径基准（离线，无需 OSS 服务）：

```bash
cargo bench --bench hot_path -- --quick
```

## 相关文档

- 组织 Rust 规范：`~/org-config/rulesets/rust/RULES.md`
- API 文档：`docs/API.md`
- 标准与验收：`docs/标准.md`
- 术语与领域语言：`CONTEXT.md`
- 贡献指南：`CONTRIBUTING.md`
- 变更记录：`CHANGELOG.md`
- 基准测试：`benches/hot_path.rs`
