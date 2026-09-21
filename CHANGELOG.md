# Changelog — ossx

本文件记录 `ossx` 的用户可见变更，遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [Semantic Versioning](https://semver.org/)。

本仓库代码自 `xhyper.rs` 的 `crates/platform/drivers/oss` 抽取而来（抽取时点为 `0.4.21`）。
该工程内的版本线不在本文件中延续，本仓库从 `0.1.0` 重新起算。

## [Unreleased]

### 新增

- 三类测试（特性 002）：`tests/tdd_contracts.rs`（逐公开入口的行为契约与变异探测红绿，
  数据面入口由本地一次性 TCP 服务驱动）、`tests/sdd_spec.rs`（与 `docs/标准.md` 章节 1:1
  的规格断言）、`tests/aidd_boundary.rs`（凭据脱敏 / 明文 HTTP / 对象键 / 资源上界 /
  鉴权降级等对抗用例）；均为离线用例，不依赖真实 OSS，也不引入 `#[ignore]`。

## [0.1.0] - 2026-09-21

### 新增

- `OssClient` 数据面：`put_object` / `get_object` / `head_object` / `delete_object`（幂等）/
  `list_objects`（V2 + 翻页）/ `ping` / `health_check`。
- 分片上传：`initiate` / `upload_part` / `complete` / `abort` 与高层 `put_object_multipart`；
  未完成 upload 进入**有界** orphan 审计队列（`MultipartOrphanAudit`）。
- 流式传输：`put_stream` / `get_stream`（`ByteStream`），下载流按 `max_object_bytes` 硬性截断。
- 预签名 URL：`presign_url` / `PresignOptions`（方法 + 过期时间，以 `Expires` 位签名）。
- 签名原语：`sign_v1` / `authorization_header` / `canonicalized_resource` /
  `canonicalized_resource_with_subresources` / `split_parts`（OSS Signature V1，HMAC-SHA1）。
- 凭据轮换：`CredentialProvider` trait 与 `OssCredentials` / `StaticCredentialProvider`，
  每次请求取一次凭据，支持 STS `security_token`。
- 重试：`RetryConfig` / `default_retry_config` / `is_oss_retryable` / `with_retry` /
  `with_retry_deadline` / `with_retry_default`，指数退避 + 抖动 + 整操作 deadline。
- 治理面：并发信号量、单请求超时、整操作 deadline、资源硬上限（`HARD_MAX_*`）、
  `OssConfig` / `OssConfigBuilder` / `from_env` / `from_toml` / `validate` 与 `ENV_*` 常量。
- `OssPool` / `OssHealth` / `OssPoolStats`：池化句柄、健康状态与统计。
- 数据形态：`ObjectKey`（构造期校验）/ `ObjectMeta` / `UploadOptions` / `DownloadOptions` /
  `ByteStream` / `byte_stream_from_bytes`；错误类型 `OssError` / `OssResult`。

### 变更

- 移除对主工程内部 crate（`kernel` / `contracts` / `resiliencx` 等）的依赖：错误模型下沉为
  crate 内 `src/error.rs` 的 `OssError`（`#[non_exhaustive]` + `is_retryable`），
  重试策略在 crate 内 `src/retry.rs` 自洽实现，不再依赖外部弹性框架。
- 签名路径消除 panic 分支：HMAC 密钥先按 RFC 2104 规整为定长分组，再走不可失败的
  `Mac::new`，因此 `sign_v1` 不再含 `expect` 分支（摘要逐字节不变，有向量测试锁定）。
- 凭据注入收敛为环境变量或 builder 两条路径，TOML 明确拒绝 `access_key_id` /
  `access_key_secret`（fail-closed）。

### 说明

- 只做 OSS 访问原语：对象 CRUD、流式下载、multipart 上传、预签名 URL、健康检查；
  不含领域模型或业务编排。
- 本 crate 实现阿里云 OSS 的 **Signature V1**，与 S3 的 SigV4 是不同协议栈，两者不可互换。
- `connect` / `new` 只做校验与构造，不发网络请求；连通性用 `ping` / `health_check` 显式验证。
- `ByteStream` 只要求 `Send`（单任务顺序消费），不承诺 `Sync`；预签名 URL 依赖本机时钟。
- 本 crate **不发布到 crates.io**，仅以 GitHub 源码 / git 依赖形式复用。
