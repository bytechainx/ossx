//! 阿里云 OSS REST 签名 V1（`Authorization: OSS AccessKeyId:Signature`）。
//!
//! 本模块是协议正确性关键路径：函数语义与源实现**逐字节一致**，
//! 单元测试以固定 secret / date 断言 HMAC-SHA1 摘要（见 `tests/sign_pure.rs`）。

use base64::Engine;
use hmac::digest::Key;
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

type HmacSha1 = Hmac<Sha1>;

/// SHA-1 的分组大小（字节），也是 HMAC 密钥规整后的目标长度。
const SHA1_BLOCK_BYTES: usize = 64;

/// 按 RFC 2104 §2 把 HMAC 密钥规整为恰好一个分组。
///
/// - 密钥长于分组：先取 `SHA-1(key)`，再左补零；
/// - 否则：直接左补零。
///
/// 显式做这一步是为了让后续构造走**不可失败**的 [`Mac::new`]（取定长密钥），从而
/// 在签名路径上彻底消除 `Result` 与 `panic` 两种分支——早先的实现在理论上不可达的
/// 失败路径上直接 `expect`，虽然不会触发，但那是一条真实存在的 panic 分支。
///
/// 该规则与 `hmac` crate 内部的 `get_der_key` 一致，并由差分测试
/// `hmac_sha1_matches_hmac_crate_across_key_lengths` 逐字节验证。
fn derive_key_block(key: &[u8]) -> [u8; SHA1_BLOCK_BYTES] {
    let mut block = [0_u8; SHA1_BLOCK_BYTES];
    if key.len() > SHA1_BLOCK_BYTES {
        // SHA-1 输出恒为 20 字节，短于 64 字节分组，故此切片不会越界。
        let digest = Sha1::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    block
}

/// HMAC-SHA1 摘要（20 字节）。
fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let key_block: Key<HmacSha1> = derive_key_block(key).into();
    let mut mac = <HmacSha1 as Mac>::new(&key_block);
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// 构造 StringToSign 并 HMAC-SHA1 + Base64。
///
/// ```text
/// StringToSign =
///   VERB + "\n"
///   + Content-MD5 + "\n"
///   + Content-Type + "\n"
///   + Date + "\n"
///   + CanonicalizedOSSHeaders
///   + CanonicalizedResource
/// ```
///
/// `canonicalized_oss_headers` 为空时该行为空串；非空时每行以 `\n` 结尾，
/// 因此调用方拼接时不需要额外补分隔符。
///
/// ```
/// use ossx::sign_v1;
///
/// let signature = sign_v1(
///     "secret",
///     "PUT",
///     "",
///     "application/octet-stream",
///     "Thu, 01 Jan 1970 00:00:00 GMT",
///     "",
///     "/bucket/key",
/// );
/// assert_eq!(signature, "i2eNP/BLD/pc/CxWss90UYPvKI4=");
/// ```
#[must_use]
pub fn sign_v1(
    secret: &str,
    verb: &str,
    content_md5: &str,
    content_type: &str,
    date: &str,
    canonicalized_oss_headers: &str,
    canonicalized_resource: &str,
) -> String {
    let string_to_sign = format!(
        "{verb}\n{content_md5}\n{content_type}\n{date}\n{canonicalized_oss_headers}{canonicalized_resource}"
    );
    let digest = hmac_sha1(secret.as_bytes(), string_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// `Authorization: OSS <AccessKeyId>:<Signature>`。
#[must_use]
pub fn authorization_header(access_key_id: &str, signature: &str) -> String {
    format!("OSS {access_key_id}:{signature}")
}

/// CanonicalizedResource：`/{bucket}/{object_key}`（object 可为空）。
///
/// object key 不应以 `/` 开头；实现按源语义**归一化**掉前导 `/`，
/// 空 key 得到 `/{bucket}/`（bucket 根请求的签名形态）。
#[must_use]
pub fn canonicalized_resource(bucket: &str, object_key: &str) -> String {
    if object_key.is_empty() {
        format!("/{bucket}/")
    } else {
        // 对象 key 不应以 / 开头
        let key = object_key.trim_start_matches('/');
        format!("/{bucket}/{key}")
    }
}

/// 带 OSS 子资源的 CanonicalizedResource。
///
/// 子资源按字典序排序后以 `?k` / `?k=v` 拼接，符合阿里云 OSS V1 规则。
/// 典型 multipart 场景：
/// - initiate：`[("uploads", None)]` → `?uploads`
/// - upload_part：`[("partNumber", Some("1")), ("uploadId", Some(id))]`
/// - complete/abort：`[("uploadId", Some(id))]`
/// - list 翻页：`[("continuation-token", Some(token))]`（该子资源参与签名）
///
/// # Examples
///
/// ```
/// use ossx::canonicalized_resource_with_subresources;
///
/// let resource = canonicalized_resource_with_subresources(
///     "bucket",
///     "obj/key",
///     &[("uploadId", Some("UID")), ("partNumber", Some("2"))],
/// );
/// assert_eq!(resource, "/bucket/obj/key?partNumber=2&uploadId=UID");
/// ```
#[must_use]
pub fn canonicalized_resource_with_subresources(
    bucket: &str,
    object_key: &str,
    subresources: &[(&str, Option<&str>)],
) -> String {
    let base = canonicalized_resource(bucket, object_key);
    if subresources.is_empty() {
        return base;
    }
    let mut pairs: Vec<String> = subresources
        .iter()
        .map(|(k, v)| match v {
            Some(val) if !val.is_empty() => format!("{k}={val}"),
            _ => (*k).to_string(),
        })
        .collect();
    pairs.sort();
    format!("{base}?{}", pairs.join("&"))
}

/// 分片切分：按 `part_size` 将数据切为若干切片（纯函数，无网络）。
///
/// - 空 `data` 返回空 vec
/// - `part_size == 0` 或 `part_size >= data.len()` 时按整段返回单片
///
/// ```
/// use ossx::split_parts;
///
/// let parts = split_parts(b"abcdefghij", 3);
/// assert_eq!(parts.len(), 4);
/// assert_eq!(parts[3], b"j");
/// ```
#[must_use]
pub fn split_parts(data: &[u8], part_size: usize) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    if part_size == 0 || part_size >= data.len() {
        return vec![data];
    }
    data.chunks(part_size).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_and_matches_fixed_vector() {
        let signature = sign_v1(
            "secret",
            "PUT",
            "",
            "application/octet-stream",
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "",
            "/bucket/key",
        );
        assert_eq!(signature, "i2eNP/BLD/pc/CxWss90UYPvKI4=");
        assert_eq!(
            authorization_header("AKID", &signature),
            format!("OSS AKID:{signature}")
        );
    }

    #[test]
    fn resource_format() {
        assert_eq!(canonicalized_resource("b", "a/b"), "/b/a/b");
        assert_eq!(canonicalized_resource("b", "/a"), "/b/a");
        assert_eq!(canonicalized_resource("b", ""), "/b/");
    }

    #[test]
    fn multipart_subresources_sorted() {
        let resource = canonicalized_resource_with_subresources(
            "bucket",
            "obj/key",
            &[("uploadId", Some("UID")), ("partNumber", Some("2"))],
        );
        assert_eq!(resource, "/bucket/obj/key?partNumber=2&uploadId=UID");

        let init = canonicalized_resource_with_subresources("b", "k", &[("uploads", None)]);
        assert_eq!(init, "/b/k?uploads");

        let complete =
            canonicalized_resource_with_subresources("b", "k", &[("uploadId", Some("u1"))]);
        assert_eq!(complete, "/b/k?uploadId=u1");

        // 空子资源集合退化为无 query 形态
        assert_eq!(
            canonicalized_resource_with_subresources("b", "k", &[]),
            "/b/k"
        );
        // 空值子资源退化为裸 key
        assert_eq!(
            canonicalized_resource_with_subresources("b", "k", &[("uploads", Some(""))]),
            "/b/k?uploads"
        );
    }

    /// 经公开入口 `sign_v1` 锁定空密钥与超长密钥的行为。
    ///
    /// 这两条路径原先用于论证 `sign_v1` 内 `expect` 不可达；该 `expect` 已被零 panic
    /// 实现取代（见 [`derive_key_block`]），但这组向量仍然有价值：它从**公开 API**
    /// 侧钉住密钥规整的两个分支，与下面的差分测试互为补充。
    #[test]
    fn hmac_accepts_any_key_length() {
        assert_eq!(
            sign_v1("", "GET", "", "", "0", "", "/b/k"),
            "ZzHpvyYxaoI4l7tLSO5f+Tw4Rso="
        );
        assert_eq!(
            sign_v1(&"k".repeat(200), "GET", "", "", "0", "", "/b/k"),
            "qD+QtQV2jO7MIau5+WtM5Nmk6RE="
        );
    }

    /// 把字节串渲染为小写十六进制（仅测试使用，避免为断言引入额外依赖）。
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 2202 的权威向量，覆盖**密钥长度**的各个分支：短于分组（左补零）、
    /// 恰等于分组（64 字节，不哈希）、超过分组（先哈希）。
    #[test]
    fn hmac_sha1_matches_rfc2202_vectors_across_key_lengths() {
        // TC1：20 字节密钥，短于分组。
        assert_eq!(
            to_hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        // TC2：`Jefe`。
        assert_eq!(
            to_hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        // TC6：80 字节密钥（> 64 字节分组，必须先哈希）。
        let long_key = [0xaa_u8; 80];
        assert_eq!(
            to_hex(&hmac_sha1(
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        // TC7：超长密钥 + 超长消息。
        assert_eq!(
            to_hex(&hmac_sha1(
                &long_key,
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
            )),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
        // 空密钥 + 空消息：仍须是合法的 20 字节摘要，而不是任何形式的空值。
        assert_eq!(
            to_hex(&hmac_sha1(b"", b"")),
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
        );
        // 分组边界：64 字节不哈希、65 字节先哈希。
        assert_eq!(
            to_hex(&hmac_sha1(&[0_u8; 64], b"msg")),
            "1df552b90836e9881b1873998715838bf13ae65e"
        );
        assert_eq!(
            to_hex(&hmac_sha1(&[0_u8; 65], b"msg")),
            "1aa547ff99ed84e61a2a906b907cbfd8d6843ce4"
        );
    }

    /// 差分测试：自实现的密钥规整必须与 `hmac` crate 的 `new_from_slice` 路径
    /// 在全部密钥长度分支上逐字节一致。
    ///
    /// 这是「自行规整 + 不可失败构造」方案的**正确性依据**：`derive_key_block` 一旦
    /// 与 crate 内部规则出现偏差（例如长密钥少哈希一次、补零位置写错），本用例会
    /// 立即失败，而不会退化成线上难以定位的签名错误。
    ///
    /// 参考实现只在本测试中使用；生产路径不含任何可失败分支。
    #[test]
    fn hmac_sha1_matches_hmac_crate_across_key_lengths() {
        for len in [0, 1, 19, 20, 21, 63, 64, 65, 100, 200, 1_000] {
            let key = vec![0x5a_u8; len];
            let msg = b"differential check";
            let mut reference = <HmacSha1 as Mac>::new_from_slice(&key)
                .expect("HMAC 接受任意长度密钥，参考实现不会失败");
            reference.update(msg);
            assert_eq!(
                hmac_sha1(&key, msg),
                reference.finalize().into_bytes().to_vec(),
                "密钥长度 {len} 的实现与 hmac crate 不一致"
            );
        }
    }

    #[test]
    fn split_parts_chunking() {
        let data = b"abcdefghij";
        let parts = split_parts(data, 3);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], b"abc");
        assert_eq!(parts[1], b"def");
        assert_eq!(parts[2], b"ghi");
        assert_eq!(parts[3], b"j");

        assert!(split_parts(b"", 4).is_empty());
        assert_eq!(split_parts(data, 0), vec![&data[..]]);
        assert_eq!(split_parts(data, 100), vec![&data[..]]);
        assert_eq!(split_parts(data, 10), vec![&data[..]]);
    }
}
