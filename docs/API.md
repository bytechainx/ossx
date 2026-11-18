# ossx 公开 API

**版本 / 角色**：`ossx 0.1.0` · 阿里云 OSS 适配器（Signature V1，对象读写 / 流式传输 / 分片上传 / 预签名 URL）

## 公开消费面

| 主题 | 类型 / 函数 | 说明 |
| --- | --- | --- |
| 错误 | `OssError`（`is_retryable`）、`OssResult` | thiserror 枚举；区分瞬时与永久故障 |
| 配置 | `OssConfig`、`OssConfigBuilder`、`ENV_*`、`HARD_MAX_*` | `builder()` / `from_env()`（前缀 `FOUNDATIONX_OSSX_`）/ `from_toml()` / `validate()` |
| 客户端 | `OssClient` | `put_object` / `get_object` / `head_object` / `delete_object` / `list_objects` / multipart / `put_bucket_lifecycle` / `get_bucket_lifecycle` / `delete_bucket_lifecycle` / `ping` / `health_check` |
| 连接池 | `OssPool`、`OssHealth`、`OssPoolStats` | 池化句柄、健康状态与统计 |
| 签名 | `sign_v1`、`authorization_header`、`canonicalized_resource`、`canonicalized_resource_with_subresources`、`split_parts` | OSS Signature V1 纯函数原语 |
| 预签名 | `presign_url`、`presign_url_with_token`、`PresignOptions` | query-string 方式签名的临时 URL；`*_with_token` 携带 STS `security-token` |
| 凭据 | `CredentialProvider`、`OssCredentials`、`StaticCredentialProvider`、`StsCredentialProvider`、`StsConfig`、`sts_config_from_env` | 凭据轮换抽象（含 STS `security_token`）与 STS `AssumeRole` 自动刷新提供者 |
| 生命周期 | `LifecycleRule`、`LifecycleStatus` | bucket 生命周期规则（对象过期 / 未完成分片自动中止） |
| 数据形态 | `ObjectKey`、`ObjectMeta`、`UploadOptions`、`DownloadOptions`、`ByteStream`、`byte_stream_from_bytes` | 已校验对象键、元数据、读写选项与下载流 |
| 重试 | `RetryConfig`、`default_retry_config`、`is_oss_retryable`、`with_retry`、`with_retry_deadline` | 指数退避 + 抖动，可加总 deadline |
| Multipart 常量 | `MAX_MULTIPART_PARTS`、`MAX_MULTIPART_PART_BYTES`、`MIN_MULTIPART_PART_BYTES`、`MAX_OBJECT_KEY_BYTES`、`ORPHAN_AUDIT_CAPACITY`、`MultipartOrphanAudit` | 分片上界与孤儿分片审计 |

## 最小用法

```rust,no_run
use bytes::Bytes;
use ossx::{OssClient, OssConfig, PresignOptions};

# async fn run() -> Result<(), ossx::OssError> {
let config = OssConfig::builder()
    .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
    .bucket("demo-bucket")
    .access_key_id("LTAI5tExample")
    .access_key_secret("your-access-key-secret")
    .build()?;

let client = OssClient::connect(config).await?; // 不发起网络请求

client.put_object("dir/object.txt", Bytes::from_static(b"hello ossx")).await?;
let body = client.get_object("dir/object.txt").await?;
client.delete_object("dir/object.txt").await?;

let url = client.presign_url("dir/object.txt", &PresignOptions::default())?;
client.ping().await?;
# Ok(())
# }
```

## 安全约定

- `AccessKeySecret` 只出现在签名计算中，`Debug` 输出与错误消息均不回显（有回归测试锁定）；
- 远程 endpoint 强制 HTTPS，HTTP 仅允许 loopback 开发端点；
- 所有资源上界（对象大小、缓冲、并发、错误体）在构建期校验并 clamp 到 `HARD_MAX_*`；
- 重试只发生在可安全重放的瞬时错误上，鉴权/权限失败立即返回。

## 能力边界

- 只做 OSS 访问原语：对象 CRUD、流式上传/下载（`OssPool::put_stream` / `get_stream`，分片填满即传、不聚合全量分片，内存占用与对象总大小无关）、multipart 上传、预签名 URL（含 STS token）、bucket 生命周期规则、STS `AssumeRole` 凭据自动刷新、健康检查；不含领域模型或业务编排。
- `connect` 只做校验与构造，不发网络请求；连通性用 `ping` 显式验证。
- `ByteStream` 只要求 `Send`（单任务顺序消费），不承诺 `Sync`。
- 预签名 URL 依赖本机时钟；有效期与过期语义以 OSS 服务端为准。
- 对象总大小上界 `max_object_bytes`（硬上界 48.8 TB）与单次内存缓冲上界 `max_buffer_bytes` 相互独立；TB 级对象走流式路径，不要求 `max_object_bytes <= max_buffer_bytes`。
