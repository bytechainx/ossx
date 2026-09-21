# ossx 上下文

本文件定义 `ossx` 与其使用方共享的核心词汇。它只记录领域含义与能力边界，
不记录具体实现、API 签名、存储或部署决定。

## 角色与边界

**适配器**：把阿里云 OSS 的 REST 协议收敛成稳定 Rust API 的库；只提供对象访问原语，
不含领域模型、业务编排或跨来源同步。
_Avoid_: S3 客户端（本仓库实现 OSS Signature V1，与 S3 的 SigV4 是不同协议栈，不可互换）

**对象键（ObjectKey）**：构造时即校验长度与字符合法性的对象标识；它是数据面方法唯一接受的
键类型。
_Avoid_: 路径字符串（裸 `String` 不承担校验，直接拼 URL 会绕过 fail-closed 关卡）

**虚拟主机风格寻址**：请求地址形如 `https://{bucket}.{host}/{key}`，bucket 进 hostname、
key 进 path；因此 endpoint 必须是域名，IP 端点会被拒绝。
_Avoid_: 路径风格（把 bucket 放在 path 里是另一种寻址方式，OSS 不支持）

**连接池（OssPool）**：对 `OssClient` 的池化视图，附健康与统计；它不引入第二套请求实现。
_Avoid_: 连接复用（复用是手段；这里的边界是「多一层池化视图」，不是新建连接管理栈）

## 签名与凭据

**Signature V1**：`Authorization: OSS <AccessKeyId>:<Signature>`，签名值为
`Base64(HMAC-SHA1(secret, StringToSign))`。
_Avoid_: 签名算法（要点是「哪一套协议」而非「用什么哈希」）

**CanonicalizedResource**：`/{bucket}/{key}` 加上参与签名的子资源（如 `uploads` /
`partNumber` / `continuation-token`）；只有规范列出的子资源参与，其余 query 不参与。
_Avoid_: 请求路径（CanonicalizedResource 含子资源且不含未列入的 query，与 URL 路径不等价）

**CanonicalizedOSSHeaders**：所有 `x-oss-*` 头按小写名、字典序拼成的签名片段；SSE 与 STS
令牌头都必须在此，漏签会被服务端判为 `SignatureDoesNotMatch`。
_Avoid_: 自定义头（只有 `x-oss-*` 前缀的头进入该片段，普通头不参与）

**预签名 URL**：把签名搬到 query（`OSSAccessKeyId` / `Expires` / `Signature`）的临时 URL，
`Expires` 取代 `Date` 参与签名。
_Avoid_: 临时凭据（URL 里没有 secret，泄漏的是限定方法与期限的访问权，不是凭据本身）

**凭据提供者（CredentialProvider）**：每次请求取一次凭据的抽象，用于承接 STS 或自建凭据服务
轮换；换成动态实现不需要重建客户端。
_Avoid_: 凭据缓存（提供者不承诺缓存语义，缓存策略由实现方决定）

## 资源与生命周期

**分片上传（multipart）**：把大对象切成受 `MIN_MULTIPART_PART_BYTES` /
`MAX_MULTIPART_PART_BYTES` / `MAX_MULTIPART_PARTS` 约束的分片顺序上传再合并的路径。
_Avoid_: 分块传输（multipart 是有状态的 init/upload/complete 协议，不是 HTTP 传输层分块）

**孤儿分片审计（MultipartOrphanAudit）**：记录 abort 前中断的 upload 的有界队列，容量
`ORPHAN_AUDIT_CAPACITY`，超限丢弃最旧记录。
_Avoid_: 垃圾回收（审计只提供可观测线索，回收由调用方决定）

**字节流（ByteStream）**：下载返回的字节流，只要求 `Send`、不承诺 `Sync`；它被单个任务
顺序消费，总长受 `max_object_bytes` 硬性截断。
_Avoid_: 缓冲区（流不承诺随机访问或可重放，不能当内存 buffer 用）

**整操作 deadline**：横跨重试的总时间上限（`operation_deadline`），到期返回 `Timeout` 而
不再放大重试。
_Avoid_: 请求超时（单请求超时只约束一次尝试，不能表达整段重试的预算）

## 错误与可靠性

**可重试错误**：可安全重放而不改变结果的瞬时失败（连接中断、远端 5xx 等）；经
`OssError::is_retryable()` 判定。
_Avoid_: 服务端错误（4xx/5xx 不是判据，`401` / `403` 明确不可重试）

**指数退避 + 抖动**：第 n 次重试退避为 `min(base * 2^(n-1), max_delay_ms)` 叠加
`±jitter_ratio`，避免多实例同步重试造成惊群；尝试次数受 `MAX_RETRY_ATTEMPTS` 硬上界约束。
_Avoid_: 固定间隔（固定间隔在多实例下会形成同步脉冲，抖动是刻意引入的）

**秘密脱敏**：`AccessKeySecret` 与 STS `security_token` 只进入签名计算，`Debug`、错误消息与
URL 一律不回显。
_Avoid_: 日志脱敏（脱敏覆盖所有对外可见面，不只是日志）
