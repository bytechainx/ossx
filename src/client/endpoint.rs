//! 虚拟主机端点 URL 与对象 key 辅助。
//!
//! 自 `src/client.rs` 下沉而来；三个函数均为 `pub(crate)`，经门面 `pub(crate) use`
//! 转出，故 `src/pool.rs` 的显式导入列表与各子模块的 `use super::*` 路径不变。

use url::Url;

use crate::error::{OssError, OssResult};

use super::MAX_OBJECT_KEY_BYTES;

/// 构造虚拟主机 base URL：`https://{bucket}.{endpoint_host}/`。
///
/// OSS 只支持虚拟主机风格访问，因此 `endpoint` 的 host 必须是可加前缀的**域名**；
/// IP 端点（如 `http://127.0.0.1:9000`）会被拒绝——WHATWG URL 规范不接受末尾为数字的域名。
/// 本地联调请使用 `*.localhost`（多数系统解析到回环地址）。
pub(crate) fn virtual_host_base(endpoint: &str, bucket: &str) -> OssResult<Url> {
    let mut parsed = Url::parse(endpoint.trim_end_matches('/'))
        .map_err(|error| OssError::Config(format!("oss endpoint URL 非法: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| OssError::Config("oss endpoint 缺少 host".into()))?
        .to_string();
    let virtual_host = format!("{bucket}.{host}");
    parsed.set_host(Some(&virtual_host)).map_err(|_| {
        OssError::Config(format!(
            "oss virtual host URL 非法：endpoint host `{host}` 无法承载 bucket 前缀（IP 端点不支持 OSS 虚拟主机风格，本地联调请用 *.localhost）"
        ))
    })?;
    parsed.set_path("/");
    Ok(parsed)
}

/// 按 key 逐段拼接对象 URL（保留 key 内的 `/`）。
pub(crate) fn object_url(base: &Url, key: &str) -> OssResult<Url> {
    let mut url = base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| OssError::Config("oss base URL 不能作为 path base".into()))?;
        segments.clear();
        for part in key.split('/') {
            if !part.is_empty() {
                segments.push(part);
            }
        }
    }
    Ok(url)
}

/// key 归一化与校验：去首尾空白与前导 `/`，拒绝空、`..` 与超长。
pub(crate) fn normalize_key(key: &str) -> OssResult<String> {
    let normalized = key.trim().trim_start_matches('/');
    if normalized.is_empty() {
        return Err(OssError::Config("object key 不得为空".into()));
    }
    if normalized.contains("..") {
        return Err(OssError::Config("object key 不得包含 '..'".into()));
    }
    if normalized.len() > MAX_OBJECT_KEY_BYTES {
        return Err(OssError::Config(format!(
            "object key 超过 {MAX_OBJECT_KEY_BYTES} 字节上限"
        )));
    }
    Ok(normalized.to_string())
}
