# Changelog — ossx

本文件记录 `ossx` 的用户可见变更，遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [Semantic Versioning](https://semver.org/)。

本仓库代码自 `xhyper.rs` 的 `crates/platform/drivers/oss` 抽取而来（抽取时点为 `0.4.21`）。
该工程内的版本线不在本文件中延续，本仓库从 `0.1.0` 重新起算。

## [Unreleased]

## [0.1.2] - 2026-09-22

### 变更

- **内部结构改写（公开 API 与可观察契约均不变）**：按 `docs/module-rules.md` §5.5 的手法，把
  `src/pool.rs` 的两块职责下沉为子模块 —— 构造 / 建连 / 只读观测 / 关闭 →
  `src/pool/lifecycle.rs`、探活三方法（`ping` / `health_check` / `health`）→ `src/pool/health.rs`。
  门面 `src/pool.rs` 保留模块文档、`DEFAULT_STREAM_PART_BYTES`、`OssPoolStats`、
  `PoolInner` / `OssPool` 定义与 `Debug`、数据面六方法（`put_object` / `get_object` /
  `delete_object` / `head` / `put_stream` / `get_stream`）、内部辅助
  （`ensure_open` / `acquire` / `credentials` / `validate_size` / `record`）、`empty_stream`
  与**原有内联测试**。搬走的 14 个方法**全部是 `pub`**，故**无需任何可见性调整**。
  `src/pool.rs` 生产段 **638 → 445** 行。
  动机：`module-rules` 是元仓库必需检查，且它审计各仓**默认分支**，故当 `pool.rs` 生产段距
  `MR-STRUCT-007` 的 800 行 ERROR 阈值只剩 162 行时，任一仓的任意改动都可能卡住元仓库的全部 PR。
  属**纯搬移**（行多重集比对确认零代码行丢失），全部 145 项测试与 doctest 结果不变。

## [0.1.1] - 2026-09-22

### 修正

- 测试（本地一次性 HTTP 桩服务）：绑定地址改为**跟随 `localhost` 的解析结果**
  （并在其余解析地址上补绑同一端口），不再硬编码 `[::1]`；失败信息同时给出解析列表与
  实际绑定地址。该桩的 endpoint 必须是可解析名（虚拟主机风格不支持 IP 字面量），
  硬编码地址家族会在解析结果与该家族不一致时出现 `Connection refused`。

### 新增

- 三类测试（特性 002）：`tests/tdd_contracts.rs`（逐公开入口的行为契约与变异探测红绿，
  数据面入口由本地一次性 TCP 服务驱动）、`tests/sdd_spec.rs`（与 `docs/标准.md` 章节 1:1
  的规格断言）、`tests/aidd_boundary.rs`（凭据脱敏 / 明文 HTTP / 对象键 / 资源上界 /
  鉴权降级等对抗用例）；均为离线用例，不依赖真实 OSS，也不引入 `#[ignore]`。

### 变更

- **内部结构改写（公开 API 与可观察契约均不变）**：按 `docs/module-rules.md` §5.5 的手法，把
  `src/client.rs` 与 `src/config.rs` 两处超长门面下沉为子模块 ——
  客户端：端点与对象 key 辅助 → `src/client/endpoint.rs`、请求头组装/签名/有界响应读取/
  错误映射 → `src/client/http.rs`、XML 解析与 multipart 字段校验 → `src/client/xml.rs`；
  配置：链式构建器 → `src/config/builder.rs`、环境变量读取与覆盖 → `src/config/envvars.rs`、
  TOML 形态与凭据键拒绝 → `src/config/tomlfile.rs`。两个门面只保留模块文档、类型定义、
  与 multipart 生命周期/孤儿风险相关的辅助，以及**原有内联测试**。
  `OssConfigBuilder` 经门面 `pub use` 导出，公开路径不变；`pub(crate)` 辅助经门面
  `pub(crate) use` 转出，故 `src/pool.rs` 的显式导入列表与 `src/client/*.rs` 的
  `use super::*` **一行未改**。**可见性调整仅限 crate 内部**（`pub(super)`）。
  `src/client.rs` 生产段 **668 → 327**、`src/config.rs` 生产段 **679 → 364**。
  动机：`module-rules` 是元仓库必需检查，且它审计各仓**默认分支**，故当两处距
  `MR-STRUCT-007` 的 800 行 ERROR 阈值只剩 132 / 121 行时，任一仓的任意改动都可能卡住
  元仓库的全部 PR。属**纯搬移**（行多重集比对确认零代码行丢失），全部 145 项测试与
  doctest 结果不变。
  两处模块名刻意避开同名遮蔽：`endpoint.rs`（不叫 `url.rs`，避免遮蔽 `url` crate）、
  `envvars.rs` / `tomlfile.rs`（不叫 `env.rs` / `toml.rs`，避免遮蔽 `std::env` 与 `toml` crate）。

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
