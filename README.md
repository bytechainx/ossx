# ossx

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

阿里云 OSS（对象存储）异步适配器。基于 `reqwest` + **OSS Signature V1**，覆盖对象读写、
流式传输、分片上传、预签名 URL、可刷新凭据与连接池统计；零内部框架依赖。

## 特性

- **数据面**：`put_object` / `get_object` / `head_object` / `delete_object`（幂等）/ `list_objects`（V2 + 翻页）
- **分片上传**：`initiate` / `upload_part` / `complete` / `abort`，以及高层 `put_object_multipart`；
  未完成分片会进入**有界** orphan 审计队列，供受控补偿
- **流式**：`OssPool::put_stream` / `get_stream`，下载流按 `max_object_bytes` 硬性截断
- **预签名 URL**：`PresignOptions` 支持方法与过期时间
- **凭据**：`CredentialProvider` 每次请求取一次凭据，天然支持 STS / 自建凭据服务轮换
- **治理**：并发信号量、单请求超时、整操作 deadline、指数退避 + 抖动重试、资源硬上限
- **安全**：`Debug` 与错误消息均不回显 `AccessKeySecret`；远程 endpoint 强制 HTTPS
- **零内部耦合**：不依赖 `kernel` / `resiliencx` 等内部框架，全部走 crates.io 公开依赖

## 安装

本 crate **不发布到 crates.io**，通过 git 依赖引入：

```toml
[dependencies]
ossx = { git = "https://github.com/bytechainx/ossx" }
```

## 最小可运行示例

```rust,no_run
use bytes::Bytes;
use ossx::{OssClient, OssConfig, PresignOptions};

#[tokio::main]
async fn main() -> Result<(), ossx::OssError> {
    // 1. 配置（也可用 OssConfig::from_env() / OssConfig::from_toml()）
    let config = OssConfig::builder()
        .endpoint("https://oss-cn-hangzhou.aliyuncs.com")
        .bucket("demo-bucket")
        .access_key_id("LTAI5tExample")
        .access_key_secret("your-access-key-secret")
        .build()?;

    // 2. 构造客户端（只做本地校验，不发起网络请求）
    let client = OssClient::connect(config).await?;

    // 3. 上传 → 下载 → 元数据
    client.put_object("dir/object.txt", Bytes::from_static(b"hello ossx")).await?;
    let body = client.get_object("dir/object.txt").await?;
    assert_eq!(body, Bytes::from_static(b"hello ossx"));
    let meta = client.head_object("dir/object.txt").await?;
    println!("size = {}", meta.size);

    // 4. 预签名 URL（GET，1 小时有效；PUT 请设置 PresignOptions.method）
    let url = client.presign_url("dir/object.txt", &PresignOptions::default())?;
    println!("presigned: {url}");

    // 5. 探活
    client.ping().await?;

    // 6. 清理
    client.delete_object("dir/object.txt").await?;
    Ok(())
}
```

大对象（超过内存缓冲上限）请走分片：

```rust,no_run
use bytes::Bytes;
use ossx::OssClient;

async fn upload_large(client: &OssClient) -> Result<(), ossx::OssError> {
    // 按 5 MiB 分片；末片允许小于 100 KiB 的最小分片阈值
    client
        .put_object_multipart("dir/big.bin", Bytes::from(vec![0u8; 20 * 1024 * 1024]), 5 * 1024 * 1024)
        .await
}
```

## 环境变量

`OssConfig::from_env()` / `OssClient::from_env()` / `OssPool::from_env()` 读取 `FOUNDATIONX_OSSX_*`：

| 环境变量 | 对应字段 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `FOUNDATIONX_OSSX_ENDPOINT` | `endpoint` | — | 必填，`https://oss-<region>.aliyuncs.com`（HTTP 仅允许 loopback） |
| `FOUNDATIONX_OSSX_BUCKET` | `bucket` | — | 必填，小写字母/数字/连字符，首尾为字母或数字，≤63 字节 |
| `FOUNDATIONX_OSSX_ACCESS_KEY_ID` | `access_key_id` | — | 必填 |
| `FOUNDATIONX_OSSX_ACCESS_KEY_SECRET` | `access_key_secret` | — | 必填，禁止写入代码或日志 |
| `FOUNDATIONX_OSSX_REGION` | `region` | `ap-northeast-1` | 元数据；V1 签名不强制使用 |
| `FOUNDATIONX_OSSX_REQUEST_TIMEOUT_MS` | `request_timeout` | `30000` | 单请求超时 |
| `FOUNDATIONX_OSSX_OPERATION_DEADLINE_MS` | `operation_deadline` | `90000` | 含重试的整操作 deadline，不得小于 `request_timeout` |
| `FOUNDATIONX_OSSX_ACQUIRE_TIMEOUT_MS` | `acquire_timeout` | `5000` | 等待并发许可的超时 |
| `FOUNDATIONX_OSSX_MAX_IN_FLIGHT` | `max_in_flight` | `64` | 并发上限，硬上界 `HARD_MAX_IN_FLIGHT = 1024` |
| `FOUNDATIONX_OSSX_MAX_OBJECT_BYTES` | `max_object_bytes` | 512 MiB | 对象上限，硬上界 5 GiB，且不得大于 `max_buffer_bytes` |
| `FOUNDATIONX_OSSX_MAX_BUFFER_BYTES` | `max_buffer_bytes` | 512 MiB | 单次内存缓冲上限，硬上界 512 MiB |
| `FOUNDATIONX_OSSX_MAX_ERROR_BODY_BYTES` | `max_error_body_bytes` | 64 KiB | 错误响应体读取上限，硬上界 1 MiB |

TOML 装载（`OssConfig::from_toml` / `from_toml_file`）只接受**非 secret** 字段，
凭据仍由环境变量提供；TOML 中出现 `access_key_id` / `access_key_secret` 会直接 fail-closed：

> **endpoint 必须是域名。** OSS 只支持虚拟主机风格访问（`https://{bucket}.{host}/{key}`），
> 因此 `http://127.0.0.1:9000` 这类 IP 端点会被拒绝并给出可操作提示；本地联调请使用
> `*.localhost`（多数系统解析到回环地址）。

```toml
schema_version = 1

[oss]
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"
bucket = "demo-bucket"
region = "cn-hangzhou"
request_timeout_ms = 5000
max_in_flight = 32
sse_enabled = true
```

## 签名说明（Signature V1）

请求头形如 `Authorization: OSS <AccessKeyId>:<Signature>`，`Signature` 为：

```text
StringToSign =
    VERB + "\n"
  + Content-MD5 + "\n"
  + Content-Type + "\n"
  + Date + "\n"
  + CanonicalizedOSSHeaders      # 所有 x-oss-* 头，小写名、字典序、每行以 \n 结尾
  + CanonicalizedResource        # /{bucket}/{key}[?subresource[=value]&...]，子资源字典序

Signature = Base64(HMAC-SHA1(AccessKeySecret, StringToSign))
```

要点：

- **逐字节兼容**：`sign_v1` / `canonicalized_resource` / `canonicalized_resource_with_subresources` /
  `split_parts` 保持与源实现完全一致，并有固定 secret + date 的向量测试锁定摘要；
- **`x-oss-*` 头参与签名**：SSE-S3（`x-oss-server-side-encryption`）与 STS
  （`x-oss-security-token`）都写入 `CanonicalizedOSSHeaders`，漏签会被服务端判为
  `SignatureDoesNotMatch`；
- **子资源**：multipart 的 `uploads` / `partNumber` / `uploadId` 与 ListObjects V2 翻页的
  `continuation-token` 必须参与签名（其余 query 如 `prefix`、`max-keys` 不参与）；
- **预签名 URL**：以 `Expires`（epoch 秒）替代 `Date` 位签名，query 携带
  `OSSAccessKeyId` / `Expires` / `Signature`（`+`、`/` 已转义为 `%2B`、`%2F`）。

## 重试与错误分类

`OssError` 把「本地校验失败」「传输层可重试失败」「远端协议错误」分开，重试只依赖分类：

| 分类 | 典型来源 | `is_retryable()` |
| --- | --- | --- |
| `Config` | 配置/参数/硬上限校验失败、非法 key | 否 |
| `Connection` | 网络抖动、连接中断、远端 5xx | 是（401/403 例外） |
| `Backend` | 远端 4xx、404/403、未完成分片孤儿风险 | 否 |
| `Serialization` | XML / TOML 解析失败 | 否 |
| `Io` | 本地文件系统错误 | 否 |
| `Timeout` | 单请求或整操作 deadline 到期 | 否 |
| `Unsupported` | 客户端/连接池已关闭等本地生命周期拒绝 | 否 |

退避策略为指数增长 + 抖动（默认 3 次尝试、100 ms 起、±25%，单次上限 2 s），
可用 `RetryConfig::exponential` 调整；整段操作受 `operation_deadline` 限制，
到期返回 `Timeout` 而不是继续放大重试。

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
