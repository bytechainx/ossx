//! Bucket 生命周期配置（`?lifecycle` 子资源）：服务端规则下发。
//!
//! 典型用途是登记 `AbortMultipartUpload` 规则，让 OSS 服务端在分片上传发起
//! 一段时间后自动清理未完成的分片，从而回收客户端崩溃/断网留下的孤儿分片
//! 存储费用。客户端进程内的 [`MultipartOrphanAudit`](crate::MultipartOrphanAudit)
//! 只覆盖本进程可观测的中断，不替代服务端 lifecycle。

use reqwest::Method;
use reqwest::StatusCode;

use crate::error::{OssError, OssResult};
use crate::sign::canonicalized_resource_with_subresources;

use super::*;

/// 生命周期规则状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleStatus {
    /// 规则生效。
    Enabled,
    /// 规则保留但不生效。
    Disabled,
}

impl LifecycleStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "Enabled",
            Self::Disabled => "Disabled",
        }
    }

    fn parse(text: &str) -> OssResult<Self> {
        match text {
            "Enabled" => Ok(Self::Enabled),
            "Disabled" => Ok(Self::Disabled),
            _ => Err(OssError::Serialization(format!(
                "lifecycle Status 非法: {text}"
            ))),
        }
    }
}

/// Bucket 生命周期规则（本 crate 支持的子集）。
///
/// - `expiration_days`：对象创建多少天后过期删除；
/// - `abort_multipart_upload_days`：分片上传发起多少天后自动中止并清理分片；
/// - 两者至少填一个，否则规则无意义（构造期不强制，服务端会拒绝空规则）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleRule {
    /// 规则 ID（服务端要求非空，便于运维定位）。
    pub id: String,
    /// 规则前缀过滤；空串表示整个 bucket。
    pub prefix: String,
    /// 规则状态。
    pub status: LifecycleStatus,
    /// 对象过期天数。
    pub expiration_days: Option<u32>,
    /// 未完成分片上传自动中止天数。
    pub abort_multipart_upload_days: Option<u32>,
}

impl LifecycleRule {
    /// 构造一条「N 天后自动中止未完成分片上传」的规则。
    #[must_use]
    pub fn abort_multipart_upload(id: impl Into<String>, days: u32) -> Self {
        Self {
            id: id.into(),
            prefix: String::new(),
            status: LifecycleStatus::Enabled,
            expiration_days: None,
            abort_multipart_upload_days: Some(days),
        }
    }
}

fn validate_rule(rule: &LifecycleRule) -> OssResult<()> {
    if rule.id.trim().is_empty() {
        return Err(OssError::Config("lifecycle rule id 为空".into()));
    }
    if rule.expiration_days.is_none() && rule.abort_multipart_upload_days.is_none() {
        return Err(OssError::Config(format!(
            "lifecycle rule {} 至少需要 expiration_days 或 abort_multipart_upload_days",
            rule.id
        )));
    }
    for (name, days) in [
        ("expiration_days", rule.expiration_days),
        (
            "abort_multipart_upload_days",
            rule.abort_multipart_upload_days,
        ),
    ] {
        if let Some(days) = days {
            if days == 0 {
                return Err(OssError::Config(format!(
                    "lifecycle rule {} 的 {name} 必须大于 0",
                    rule.id
                )));
            }
        }
    }
    Ok(())
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

fn build_lifecycle_xml(rules: &[LifecycleRule]) -> OssResult<String> {
    let mut xml = String::from("<LifecycleConfiguration>");
    for rule in rules {
        validate_rule(rule)?;
        xml.push_str("<Rule><ID>");
        xml.push_str(&escape_xml_text(&rule.id));
        xml.push_str("</ID><Prefix>");
        xml.push_str(&escape_xml_text(&rule.prefix));
        xml.push_str("</Prefix><Status>");
        xml.push_str(rule.status.as_str());
        xml.push_str("</Status>");
        if let Some(days) = rule.expiration_days {
            xml.push_str("<Expiration><Days>");
            xml.push_str(&days.to_string());
            xml.push_str("</Days></Expiration>");
        }
        if let Some(days) = rule.abort_multipart_upload_days {
            xml.push_str("<AbortMultipartUpload><Days>");
            xml.push_str(&days.to_string());
            xml.push_str("</Days></AbortMultipartUpload>");
        }
        xml.push_str("</Rule>");
    }
    xml.push_str("</LifecycleConfiguration>");
    Ok(xml)
}

/// 与 `client::xml` 同款的字符串定位解析。
fn xml_find(xml: &str, open: &str, close: &str) -> Option<String> {
    let start = xml.find(open)? + open.len();
    let end = xml[start..].find(close)? + start;
    Some(xml[start..end].trim().to_owned())
}

fn parse_days(xml: &str, open: &str, close: &str) -> OssResult<Option<u32>> {
    match xml_find(xml, open, close) {
        Some(text) => text
            .parse::<u32>()
            .map(Some)
            .map_err(|_| OssError::Serialization(format!("lifecycle {open} 天数非法: {text}"))),
        None => Ok(None),
    }
}

/// 在 `<ExpTag>...</ExpTag>` 子块内取 `<Days>`，避免与其它规则子块串台。
fn parse_scoped_days(block: &str, tag: &str) -> OssResult<Option<u32>> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    match xml_find(block, &open, &close) {
        Some(inner) => parse_days(&inner, "<Days>", "</Days>"),
        None => Ok(None),
    }
}

fn parse_lifecycle_xml(xml: &str) -> OssResult<Vec<LifecycleRule>> {
    let mut rules = Vec::new();
    let mut rest = xml;
    while let Some(rule_start) = rest.find("<Rule>") {
        let after_open = &rest[rule_start + "<Rule>".len()..];
        let Some(rule_end) = after_open.find("</Rule>") else {
            return Err(OssError::Serialization("lifecycle Rule 未闭合".into()));
        };
        let block = &after_open[..rule_end];
        let id = xml_find(block, "<ID>", "</ID>")
            .ok_or_else(|| OssError::Serialization("lifecycle Rule 缺 ID".into()))?;
        let status_text = xml_find(block, "<Status>", "</Status>")
            .ok_or_else(|| OssError::Serialization("lifecycle Rule 缺 Status".into()))?;
        rules.push(LifecycleRule {
            id,
            prefix: xml_find(block, "<Prefix>", "</Prefix>").unwrap_or_default(),
            status: LifecycleStatus::parse(&status_text)?,
            expiration_days: parse_scoped_days(block, "Expiration")?,
            abort_multipart_upload_days: parse_scoped_days(block, "AbortMultipartUpload")?,
        });
        rest = &after_open[rule_end + "</Rule>".len()..];
    }
    Ok(rules)
}

impl OssClient {
    /// 下发 bucket 生命周期规则（整体覆盖服务端现有规则集）。
    ///
    /// 传空 slice 等价于清空规则（服务端会拒绝空 `LifecycleConfiguration`，
    /// 请改用 [`OssClient::delete_bucket_lifecycle`]）。
    ///
    /// 典型用法——让服务端自动清理 N 天前发起的未完成分片上传：
    ///
    /// ```no_run
    /// # use ossx::{LifecycleRule, OssClient, OssConfig};
    /// # async fn demo(client: &OssClient) -> Result<(), ossx::OssError> {
    /// client
    ///     .put_bucket_lifecycle(&[LifecycleRule::abort_multipart_upload("abort-mp-7d", 7)])
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(skip(self, rules))]
    pub async fn put_bucket_lifecycle(&self, rules: &[LifecycleRule]) -> OssResult<()> {
        if rules.is_empty() {
            return Err(OssError::Config(
                "put_bucket_lifecycle 规则为空，请改用 delete_bucket_lifecycle".into(),
            ));
        }
        let this = self.clone();
        let rules = rules.to_vec();
        with_retry_deadline(
            &self.inner.retry,
            "put_bucket_lifecycle",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                let rules = rules.clone();
                async move { this.put_bucket_lifecycle_once(&rules).await }
            },
        )
        .await
    }

    async fn put_bucket_lifecycle_once(&self, rules: &[LifecycleRule]) -> OssResult<()> {
        let _permit = self.acquire().await?;
        let config = &self.inner.config;
        let body = build_lifecycle_xml(rules)?;
        let resource =
            canonicalized_resource_with_subresources(&config.bucket, "", &[("lifecycle", None)]);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "PUT",
            "application/xml",
            &resource,
            config.sse_enabled,
        )?;
        let mut url = self.inner.base.clone();
        url.set_path("/");
        url.set_query(Some("lifecycle"));
        let response = self
            .inner
            .http
            .request(Method::PUT, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|error| map_network("PUT lifecycle", &error))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            config.max_error_body_bytes,
            "PUT lifecycle error body",
        )
        .await?;
        Err(status_error(
            "PUT lifecycle",
            "/",
            status,
            &String::from_utf8_lossy(&body),
        ))
    }

    /// 读取 bucket 生命周期规则。
    #[tracing::instrument(skip(self))]
    pub async fn get_bucket_lifecycle(&self) -> OssResult<Vec<LifecycleRule>> {
        let this = self.clone();
        with_retry_deadline(
            &self.inner.retry,
            "get_bucket_lifecycle",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                async move { this.get_bucket_lifecycle_once().await }
            },
        )
        .await
    }

    async fn get_bucket_lifecycle_once(&self) -> OssResult<Vec<LifecycleRule>> {
        let _permit = self.acquire().await?;
        let config = &self.inner.config;
        let resource =
            canonicalized_resource_with_subresources(&config.bucket, "", &[("lifecycle", None)]);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "GET",
            "",
            &resource,
            config.sse_enabled,
        )?;
        let mut url = self.inner.base.clone();
        url.set_path("/");
        url.set_query(Some("lifecycle"));
        let response = self
            .inner
            .http
            .request(Method::GET, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("GET lifecycle", &error))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            // 服务端无规则时返回 NoSuchLifecycle；按空规则集处理。
            return Ok(Vec::new());
        }
        if !status.is_success() {
            let body = read_limited_body(
                response,
                config.max_error_body_bytes,
                "GET lifecycle error body",
            )
            .await?;
            return Err(status_error(
                "GET lifecycle",
                "/",
                status,
                &String::from_utf8_lossy(&body),
            ));
        }
        let bytes = read_limited_body(response, self.read_limit(), "GET lifecycle body").await?;
        let xml = std::str::from_utf8(&bytes)
            .map_err(|_| OssError::Serialization("lifecycle 响应不是 UTF-8".into()))?
            .to_owned();
        parse_lifecycle_xml(&xml)
    }

    /// 删除 bucket 生命周期规则（清空服务端规则集）。
    #[tracing::instrument(skip(self))]
    pub async fn delete_bucket_lifecycle(&self) -> OssResult<()> {
        let this = self.clone();
        with_retry_deadline(
            &self.inner.retry,
            "delete_bucket_lifecycle",
            self.inner.config.operation_deadline,
            move || {
                let this = this.clone();
                async move { this.delete_bucket_lifecycle_once().await }
            },
        )
        .await
    }

    async fn delete_bucket_lifecycle_once(&self) -> OssResult<()> {
        let _permit = self.acquire().await?;
        let config = &self.inner.config;
        let resource =
            canonicalized_resource_with_subresources(&config.bucket, "", &[("lifecycle", None)]);
        let headers = signed_headers(
            &config.access_key_id,
            config.access_key_secret(),
            config.security_token(),
            "DELETE",
            "",
            &resource,
            config.sse_enabled,
        )?;
        let mut url = self.inner.base.clone();
        url.set_path("/");
        url.set_query(Some("lifecycle"));
        let response = self
            .inner
            .http
            .request(Method::DELETE, url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| map_network("DELETE lifecycle", &error))?;
        let status = response.status();
        if status.is_success()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_FOUND
        {
            return Ok(());
        }
        let body = read_limited_body(
            response,
            config.max_error_body_bytes,
            "DELETE lifecycle error body",
        )
        .await?;
        Err(status_error(
            "DELETE lifecycle",
            "/",
            status,
            &String::from_utf8_lossy(&body),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_lifecycle_xml_contains_abort_rule() {
        let xml = build_lifecycle_xml(&[LifecycleRule::abort_multipart_upload("abort-mp-7d", 7)])
            .expect("xml");
        assert!(xml.contains("<LifecycleConfiguration>"));
        assert!(xml.contains("<ID>abort-mp-7d</ID>"));
        assert!(xml.contains("<Status>Enabled</Status>"));
        assert!(xml.contains("<AbortMultipartUpload><Days>7</Days></AbortMultipartUpload>"));
    }

    #[test]
    fn build_lifecycle_xml_escapes_text() {
        let rule = LifecycleRule {
            id: "a<&b".into(),
            prefix: "p<>".into(),
            status: LifecycleStatus::Disabled,
            expiration_days: Some(30),
            abort_multipart_upload_days: None,
        };
        let xml = build_lifecycle_xml(&[rule]).expect("xml");
        assert!(xml.contains("a&lt;&amp;b"));
        assert!(xml.contains("<Prefix>p&lt;&gt;</Prefix>"));
        assert!(xml.contains("<Status>Disabled</Status>"));
        assert!(xml.contains("<Expiration><Days>30</Days></Expiration>"));
    }

    #[test]
    fn validate_rule_rejects_empty_and_zero() {
        assert!(validate_rule(&LifecycleRule::abort_multipart_upload("", 7)).is_err());
        assert!(validate_rule(&LifecycleRule::abort_multipart_upload("r", 0)).is_err());
        let empty = LifecycleRule {
            id: "r".into(),
            prefix: String::new(),
            status: LifecycleStatus::Enabled,
            expiration_days: None,
            abort_multipart_upload_days: None,
        };
        assert!(validate_rule(&empty).is_err());
    }

    #[test]
    fn parse_lifecycle_xml_roundtrip() {
        let xml = r#"<LifecycleConfiguration>
<Rule><ID>r1</ID><Prefix>logs/</Prefix><Status>Enabled</Status>
<Expiration><Days>30</Days></Expiration>
<AbortMultipartUpload><Days>7</Days></AbortMultipartUpload></Rule>
<Rule><ID>r2</ID><Prefix></Prefix><Status>Disabled</Status>
<AbortMultipartUpload><Days>1</Days></AbortMultipartUpload></Rule>
</LifecycleConfiguration>"#;
        let rules = parse_lifecycle_xml(xml).expect("parse");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "r1");
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(rules[0].expiration_days, Some(30));
        assert_eq!(rules[0].abort_multipart_upload_days, Some(7));
        assert_eq!(rules[1].status, LifecycleStatus::Disabled);
        assert_eq!(rules[1].expiration_days, None);
    }
}
