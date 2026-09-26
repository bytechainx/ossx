# Changelog — ossx

本文件记录 `ossx` 的用户可见变更，遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [Semantic Versioning](https://semver.org/)。

本仓库代码自 `xhyper.rs` 的 `crates/platform/drivers/oss` 抽取而来（抽取时点为 `0.4.21`）。
该工程内的版本线不在本文件中延续，本仓库从 `0.1.0` 重新起算。

## [Unreleased]

### 修正

- `put_object_multipart` 分片失败后 abort 自身的错误不再被静默丢弃：改为
  `tracing::error!` 记录（含 `key` / `upload_id` / 错误详情），确保运维侧可
  感知 OSS 残留未完成分片的风险。原始分片错误仍按原路径传播，不因 abort 失败而改变。

### 新增

- `tests/e2e_oss.rs`：离线 fail-closed E2E 与 `#[ignore]` 真连往返（不替代 `live_oss`）。

- `tests/multipart_flow.rs`：`part_failure_when_abort_also_fails_still_returns_original_error`
  —— abort 自己也失败时，验证返回的是原始分片错误（不被 abort 错误掩盖）。

## [0.1.4] - 2026-09-22

### 新增

- `tests/multipart_flow.rs`：`put_object_multipart` 的**端到端行为契约**（本地脚本化 HTTP 桩，
  离线、不依赖真实 OSS），断言**请求序列**与返回值 —— 成功路径
  `POST ?uploads` → `PUT ?partNumber=1` → `POST ?uploadId=…` 且不留下孤儿审计；
  分片 400 时 `DELETE ?uploadId=…`（abort）且 abort 成功不登记孤儿。
  补这条的背景：该入口此前**零测试覆盖**，「全绿」不构成对本次结构改写的验证。
  验收方式：两棵树各跑一次（结果一致）+ 变异探测（让分片循环一次都不执行 ⇒ 两条用例同时红）。

### 变更

- **内部结构改写（公开 API 与可观察契约均不变）**：把 `put_object_multipart` 的**函数体**
  从 106 行降到 55 行，以满足 `MR-ORG-004`（**启发式**函数体行数 > 100 提示，见
  `docs/module-rules.md` §6.7）。抽出的两个私有方法：
  - `upload_all_parts`（分片循环，返回 `(part_number, etag)` 列表）；
  - `finish_multipart`（提交 `CompleteMultipartUpload` 并按 abort 语义收口）。

  编排函数保留参数校验、分片切分、initiate 与孤儿审计 guard 的建立 / `disarm`。
  **搬走的代码块逐字保留**：`upload_all_parts` 与 `finish_multipart` 的循环体 / 提交体与
  原函数中的对应块**行数相同（40 ↔ 40、30 ↔ 30）**，差异仅为参数形态变化引出的机械替换
  （`&upload_id` → `upload_id`、`&mut audit_guard` → `audit_guard`，共 8 处）——
  即**零逻辑改动**。错误处理次序与 `?` 的传播点全部保持原样（含 `part_number` 溢出**不**走
  cleanup 这一点）。
  版本按 `docs/versioning.md` §5「内部改写 → PATCH」升 `0.1.3 → 0.1.4`。

## [0.1.3] - 2026-09-22

### 变更

- **内部结构改写（公开 API 与可观察契约均不变）**：按 `docs/module-rules.md` §5.5 的手法，把
  `src/client/multipart.rs` 的两个方法组下沉为子模块 —— 分片上传的会话面
  （`initiate_multipart*` / `upload_part*`）→ `src/client/multipart/session.rs`（200 行）；
  收口面（`complete_multipart*` / `abort_multipart*`）→ `src/client/multipart/commit.rs`
  （187 行）。门面 `src/client/multipart.rs` 保留模块文档、`put_object_multipart` 批量编排、
  `cleanup_multipart_failure` 与孤儿审计注册表（`register_orphan_audit` /
  `remove_orphan_audit`）。
  `impl OssClient` 现跨三个文件（Rust 允许同一类型的多个 impl 块），五个公开入口
  （`initiate_multipart` / `upload_part` / `complete_multipart` / `abort_multipart` /
  `put_object_multipart`）**签名与路径一字未改**。
  五处可见性放宽（均为 `pub(super)`，均因「父/兄弟模块互相看不到私有项」）：
  门面调用的四个 `*_with_deadline`，以及被 `commit.rs` 调用的门面私有辅助
  `remove_orphan_audit`；同组的四个 `*_once` 只在本模块内被调用，**保持私有**。
  `src/client/multipart.rs` 生产段 **548 → 190** 行（该文件本就没有内联测试段，
  故生产段等于总行数）。
  动机：`module-rules` 是元仓库必需检查，且它审计各仓**默认分支**，故当 `multipart.rs` 距
  `MR-STRUCT-007` 的 800 行 ERROR 阈值只剩 252 行时，任一仓的任意改动都可能卡住元仓库的全部 PR。
  属**纯搬移**（行多重集比对确认零代码行丢失：仅旧的行恰为提级的 5 条签名），
  145 项测试与 doctest 结果不变。
  另：该文件的 `MR-ORG-004`（函数长度启发式）仍提示 `put_object_multipart` 为 106 行 > 100；
  它是**启发式**提示、非必须整改项，且消除它需要改动该状态机的函数体（不是纯搬移），
  故本次不动。

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
