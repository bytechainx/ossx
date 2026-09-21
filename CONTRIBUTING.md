# CONTRIBUTING.md — 贡献指南（ossx）

本文件面向贡献者，汇总本地门禁与提交约定。
AI Agent 的工作约定另见 [`AGENTS.md`](./AGENTS.md)；术语与领域语言见 [`CONTEXT.md`](./CONTEXT.md)。

## 开发流程

- 本仓库是**独立的单 crate 仓库**，不依赖 `xhyper.rs` 主工程及其内部 crate（`kernel` /
  `contracts` / `resiliencx` 等），全部依赖来自 crates.io 公开包。
- substantial 变更走 feature branch → PR → review → merge，**禁止直接 push `main`**。
- `main` 已启用分支保护：要求 PR + 必需检查 `fmt / clippy / test`，
  `required_approving_review_count = 0`（单人也能合并），禁止强推与删除。
- 合并方式固定为 **create a merge commit**。注意仓库设置是
  `merge_commit_title = MERGE_MESSAGE` + `merge_commit_message = PR_TITLE`，因此
  `gh pr merge` 必须显式传 `--subject` 与 `--body`，否则会产出通用
  `Merge pull request #N from …` 标题。
- 提交信息遵循 Conventional Commits（`feat:` / `fix:` / `docs:` / `ci:` / `chore:` /
  `refactor:`），描述用简体中文。

## 本地门禁（P0 三件套）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

元数据完整性门禁（**不发布 crates.io**，此命令只校验打包元数据）：

```bash
cargo package --no-verify --allow-dirty
```

热路径基准（离线，无需 OSS 服务，可选）：

```bash
cargo bench --bench hot_path -- --quick
```

## 复用口径（不发布 crates.io）

- 本 crate **不发布到 crates.io**，仅以 GitHub 源码 / git 依赖形式复用。
- 文档与元数据中不得出现「可独立发布」「可直接 `cargo publish`」等表述，
  也不得放置 crates.io / docs.rs 徽章与外链。
- `Cargo.toml` 的 `documentation` 指向 `https://github.com/bytechainx/ossx#readme`。
- 消费方引入方式（README「安装」小节为准）：

  ```toml
  [dependencies]
  ossx = { git = "https://github.com/bytechainx/ossx" }
  ```

## 开发约定

- 注释、文档、错误消息使用**简体中文**；标识符保持英文。
- 错误类型：`thiserror` 枚举 + `#[non_exhaustive]` + `pub type OssResult<T>` 别名。
- 不在库代码里裸 `unwrap()`（`[lints.clippy]` 已 `deny` `unwrap_used` / `expect_used` /
  `panic`）。库内单测经 `src/lib.rs` 的 `#![cfg_attr(test, allow(...))]` 豁免，集成测试目标
  （`tests/*.rs`、`benches/hot_path.rs`）经 `#![allow(...)]` 豁免。
- 所有 `pub` 项必须有中文 `///` 文档（`missing_docs` 已 `deny`）。
- 集成测试**必须离线运行**，不触碰真实网络。
- MSRV 为 `1.85`，edition 2021；升级下界必须同步 `rust-version` 与 CI。
- `ObjectKey` 是唯一合法的对象键入口：构造时校验长度与字符，数据面方法只接受 `ObjectKey`，
  禁止把裸 `String` 直接拼进 URL。
- 签名统一走 `sign_v1` / `authorization_header` / `canonicalized_resource*` 纯函数；
  新增请求路径必须复用同一入口，禁止手工构造 `Authorization` 头。
- 资源上界（对象大小、缓冲、并发、错误体）在构建期校验并 clamp 到 `HARD_MAX_*`；
  新增可变上界须同时更新常量与校验。
- 远程 endpoint 强制 HTTPS，HTTP 仅允许 loopback 开发端点；凭据只能经环境变量或 builder
  注入，TOML 拒绝 `access_key_id` / `access_key_secret`。
- 公共 API 面由 `src/lib.rs` 的 `public_api_surface` 测试逐一点名，新增/删除导出必须同步
  该测试与 `docs/API.md`。

## 提交前自检清单

- [ ] `cargo fmt --all -- --check` 通过
- [ ] `cargo clippy --all-targets -- -D warnings` 通过
- [ ] `cargo test --all-targets` 通过
- [ ] `cargo package --no-verify --allow-dirty` 通过
- [ ] 新增 `pub` 项都有中文 `///` 文档
- [ ] 文档中无「可独立发布」/ crates.io / docs.rs 表述
- [ ] 新增请求路径复用 `sign_v1` / `authorization_header`，未手工构造 `Authorization` 头
