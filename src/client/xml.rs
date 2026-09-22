//! OSS XML 的解析 / 构造与 multipart 字段校验。
//!
//! 自 `src/client.rs` 下沉而来；`pub(crate)` 项经门面 `pub(crate) use` 转出，
//! 故 `src/pool.rs` 的显式导入列表与各子模块的 `use super::*` 路径均不变。

use std::collections::HashSet;

use crate::error::{OssError, OssResult};

use super::{MAX_ETAG_BYTES, MAX_MULTIPART_PARTS, MAX_PART_NUMBER, MAX_UPLOAD_ID_BYTES};

/// 从 InitiateMultipartUploadResult XML 中提取并校验 UploadId。
pub(crate) fn parse_upload_id(xml: &str) -> OssResult<String> {
    const OPEN: &str = "<UploadId>";
    const CLOSE: &str = "</UploadId>";
    let start = xml
        .find(OPEN)
        .map(|index| index + OPEN.len())
        .ok_or_else(|| OssError::Serialization("InitiateMultipart 响应缺 UploadId".into()))?;
    let end = xml[start..]
        .find(CLOSE)
        .map(|index| index + start)
        .ok_or_else(|| OssError::Serialization("InitiateMultipart UploadId 未闭合".into()))?;
    let upload_id = xml[start..end].trim();
    validate_upload_id(upload_id)?;
    Ok(upload_id.to_owned())
}

/// 构造 CompleteMultipartUpload XML（含 XML 转义与分片校验）。
pub(crate) fn build_complete_xml(parts: &[(u32, String)]) -> OssResult<String> {
    validate_complete_parts(parts)?;
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&number.to_string());
        xml.push_str("</PartNumber><ETag>");
        xml.push_str(&escape_xml_text(etag));
        xml.push_str("</ETag></Part>");
    }
    xml.push_str("</CompleteMultipartUpload>");
    Ok(xml)
}

fn escape_xml_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn validate_upload_id(upload_id: &str) -> OssResult<()> {
    if upload_id.is_empty()
        || upload_id.len() > MAX_UPLOAD_ID_BYTES
        || upload_id.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '&' | '"' | '\'')
        })
    {
        return Err(OssError::Config(
            "multipart upload_id 非法或超过上限".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_etag(etag: &str) -> OssResult<()> {
    if etag.is_empty() || etag.len() > MAX_ETAG_BYTES || etag.chars().any(char::is_control) {
        return Err(OssError::Config("multipart ETag 非法或超过上限".into()));
    }
    Ok(())
}

pub(crate) fn validate_part_number(part_number: u32) -> OssResult<()> {
    if part_number == 0 || part_number > MAX_PART_NUMBER {
        return Err(OssError::Config(format!(
            "multipart part_number 必须在 1..={MAX_PART_NUMBER} 范围内"
        )));
    }
    Ok(())
}

pub(crate) fn validate_complete_parts(parts: &[(u32, String)]) -> OssResult<()> {
    if parts.is_empty() || parts.len() > MAX_MULTIPART_PARTS {
        return Err(OssError::Config(format!(
            "complete_multipart part 数必须在 1..={MAX_MULTIPART_PARTS} 范围内"
        )));
    }
    let mut seen = HashSet::with_capacity(parts.len());
    for (part_number, etag) in parts {
        validate_part_number(*part_number)?;
        validate_etag(etag)?;
        if !seen.insert(*part_number) {
            return Err(OssError::Config(format!(
                "complete_multipart 含重复 part_number={part_number}"
            )));
        }
    }
    Ok(())
}
