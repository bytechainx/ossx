//! 阿里云 OSS REST 签名 V1（`Authorization: OSS AccessKeyId:Signature`）。
//!
//! 本模块是协议正确性关键路径：函数语义与源实现**逐字节一致**，
//! 单元测试以固定 secret / date 断言 HMAC-SHA1 摘要（见 `tests/sign_pure.rs`）。

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

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
    // 不变量：HMAC 接受任意长度密钥（`new_from_slice` 的 Result 仅为 API 统一性），
    // 此处必然成功；失败即程序 bug。
    #[allow(clippy::expect_used)]
    let mut mac =
        HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC-SHA1 accepts any key length");
    mac.update(string_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
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

    /// 不变量：HMAC-SHA1 接受**任意长度**密钥，因此 `sign_v1` 内的
    /// `expect` 不可能触发。这里用空密钥与超长密钥的固定向量锁定该前提。
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
