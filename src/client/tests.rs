//! `client` 模块单元测试。

use super::*;

#[test]
fn virtual_host_builds() {
    let url =
        virtual_host_base("https://oss-ap-northeast-1.aliyuncs.com", "x-go").expect("virtual host");
    assert_eq!(
        url.as_str(),
        "https://x-go.oss-ap-northeast-1.aliyuncs.com/"
    );
    assert_eq!(
        virtual_host_base("http://localhost:9000", "b")
            .expect("http")
            .as_str(),
        "http://b.localhost:9000/"
    );
    assert!(
        virtual_host_base("oss.example.com", "b").is_err(),
        "缺少 scheme"
    );
    // IP 端点无法承载虚拟主机风格前缀 → fail-closed 并给出可操作提示
    let error = virtual_host_base("http://127.0.0.1:9000", "b").expect_err("IP endpoint");
    assert!(error.to_string().contains("虚拟主机"), "{error}");
    assert!(error.to_string().contains("localhost"), "{error}");
}

#[test]
fn object_url_nested() {
    let base = Url::parse("https://b.oss.example.com").expect("base");
    let url = object_url(&base, "infra-draft/a/b.txt").expect("object url");
    assert_eq!(
        url.as_str(),
        "https://b.oss.example.com/infra-draft/a/b.txt"
    );
}

#[test]
fn parse_list_result_parses_keys_and_paging() {
    let xml = br#"<?xml version="1.0"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok123</NextContinuationToken>
  <Contents><Key>fred-raw/2026/08/09/series/observations/WALCL/a.json</Key></Contents>
  <Contents><Key>fred-raw/2026/08/09/series/observations/WALCL/b.json</Key></Contents>
</ListBucketResult>"#;
    let page = parse_list_result(xml).expect("parse list XML");
    assert_eq!(page.keys.len(), 2);
    assert!(page.keys[0].starts_with("fred-raw/"));
    assert_eq!(page.next_token.as_deref(), Some("tok123"));
    assert!(page.truncated);
}

#[test]
fn parse_list_result_untruncated_has_no_token() {
    let xml = br#"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>a</Key></Contents></ListBucketResult>"#;
    let page = parse_list_result(xml).expect("parse");
    assert_eq!(page.keys, vec!["a".to_string()]);
    assert!(!page.truncated);
    assert!(page.next_token.is_none());
}

#[test]
fn parse_list_result_handles_empty_document() {
    let page = parse_list_result(b"").expect("空文档应按空页处理");
    assert!(page.keys.is_empty());
    assert!(!page.truncated);
    assert!(page.next_token.is_none());
}

#[test]
fn normalize_key_bounds() {
    assert!(normalize_key("").is_err());
    assert!(normalize_key("  /  ").is_err());
    assert!(normalize_key("a/../b").is_err());
    assert_eq!(normalize_key("/a/b").expect("trim"), "a/b");
    assert!(normalize_key(&"x".repeat(MAX_OBJECT_KEY_BYTES)).is_ok());
    assert!(normalize_key(&"x".repeat(MAX_OBJECT_KEY_BYTES + 1)).is_err());
}

#[test]
fn parse_upload_id_from_xml() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
  <Bucket>b</Bucket>
  <Key>k</Key>
  <UploadId>0004B9894A22E5B1888A1E29F8236E2D</UploadId>
</InitiateMultipartUploadResult>"#;
    assert_eq!(
        parse_upload_id(xml).expect("upload id"),
        "0004B9894A22E5B1888A1E29F8236E2D"
    );
    assert!(parse_upload_id("<root/>").is_err());
    assert!(parse_upload_id("<UploadId>&xxe;</UploadId>").is_err());
}

#[test]
fn complete_xml_orders_and_escapes_parts() {
    let xml = build_complete_xml(&[(1, "\"etag1\"".into()), (2, "\"etag2\"".into())])
        .expect("complete XML");
    assert!(xml.contains("<PartNumber>1</PartNumber>"));
    assert!(xml.contains("<ETag>&quot;etag1&quot;</ETag>"));
    assert!(xml.starts_with("<CompleteMultipartUpload>"));
    assert!(xml.ends_with("</CompleteMultipartUpload>"));

    let escaped = build_complete_xml(&[(1, "\"a&<b>\"".into())]).expect("escaped");
    assert!(escaped.contains("&amp;"));
    assert!(escaped.contains("&lt;"));
    assert!(escaped.contains("&gt;"));
    assert!(!escaped.contains("<ETag>\"a&<b>\"</ETag>"));

    let error = build_complete_xml(&[(1, "a".into()), (1, "b".into())])
        .expect_err("重复 part_number 必须被拒绝");
    assert!(error.to_string().contains("重复"));
    assert!(build_complete_xml(&[]).is_err());
}

#[test]
fn multipart_plan_enforces_part_size_and_count() {
    assert!(validate_multipart_plan(MIN_MULTIPART_PART_BYTES + 1, 0).is_err());
    assert!(validate_multipart_plan(MIN_MULTIPART_PART_BYTES + 1, 1).is_err());
    assert!(validate_multipart_plan(1, 1).is_ok());
    assert_eq!(
        validate_multipart_plan(MIN_MULTIPART_PART_BYTES * 2, MIN_MULTIPART_PART_BYTES)
            .expect("plan"),
        2
    );
    let oversized = (MAX_MULTIPART_PARTS + 1) * MIN_MULTIPART_PART_BYTES;
    assert!(validate_multipart_plan(oversized, MIN_MULTIPART_PART_BYTES).is_err());
    assert!(validate_multipart_plan(0, 1).is_err());
    assert!(validate_multipart_plan(1, MAX_MULTIPART_PART_BYTES + 1).is_err());
}

#[test]
fn chunked_body_buffer_stops_at_hard_limit() {
    let mut body = BytesMut::new();
    append_limited(&mut body, b"abcd", 5, "error body").expect("first chunk");
    let error = append_limited(&mut body, b"ef", 5, "error body")
        .expect_err("chunked body 必须在追加前拒绝超限");
    assert!(error.to_string().contains("上限 5"));
    assert_eq!(&body[..], b"abcd");
}

#[test]
fn multipart_field_validators() {
    validate_upload_id("abc-123").expect("ok");
    assert!(validate_upload_id("").is_err());
    assert!(validate_upload_id(&"x".repeat(MAX_UPLOAD_ID_BYTES + 1)).is_err());
    assert!(validate_upload_id("bad<id>").is_err());
    assert!(validate_upload_id("bad&id").is_err());

    validate_etag("\"etag\"").expect("ok");
    assert!(validate_etag("").is_err());
    assert!(validate_etag("a\nb").is_err());

    validate_part_number(1).expect("1");
    assert!(validate_part_number(0).is_err());
    validate_part_number(MAX_PART_NUMBER).expect("max");
    assert!(validate_part_number(MAX_PART_NUMBER + 1).is_err());
    assert_eq!(
        usize::try_from(MAX_PART_NUMBER).expect("cast"),
        MAX_MULTIPART_PARTS
    );

    validate_complete_parts(&[(1, "e1".into()), (2, "e2".into())]).expect("ok");
    assert!(validate_complete_parts(&[]).is_err());
    assert!(validate_complete_parts(&[(1, "a".into()), (1, "b".into())]).is_err());
    assert!(validate_complete_parts(&[(0, "a".into())]).is_err());
}

#[test]
fn status_error_is_classified_and_never_retried_for_auth() {
    use crate::retry::is_oss_retryable;
    let unauthorized = status_error("get", "k", StatusCode::UNAUTHORIZED, "x");
    assert!(matches!(unauthorized, OssError::Backend(_)));
    assert!(!is_oss_retryable(&unauthorized));

    let forbidden = status_error("get", "k", StatusCode::FORBIDDEN, "x");
    assert!(matches!(forbidden, OssError::Backend(_)));
    assert!(!is_oss_retryable(&forbidden));

    let missing = status_error("get", "k", StatusCode::NOT_FOUND, "x");
    assert!(matches!(missing, OssError::Backend(_)));
    assert!(!is_oss_retryable(&missing));

    let server = status_error("get", "k", StatusCode::INTERNAL_SERVER_ERROR, "x");
    assert!(matches!(server, OssError::Connection(_)));
    assert!(is_oss_retryable(&server));

    let bad_request = status_error("get", "k", StatusCode::BAD_REQUEST, "x");
    assert!(matches!(bad_request, OssError::Backend(_)));
    assert!(!is_oss_retryable(&bad_request));

    let odd = status_error("get", "k", StatusCode::from_u16(599).expect("599"), "x");
    assert!(matches!(odd, OssError::Connection(_)));
}

#[test]
fn orphan_risk_markers() {
    let unknown = mark_unknown_initiate_orphan_risk(OssError::Connection("t".into()));
    assert!(matches!(unknown, OssError::Backend(_)));
    assert!(unknown.to_string().contains("orphan_risk=true"));
    let kept = mark_unknown_initiate_orphan_risk(OssError::Config("i".into()));
    assert!(matches!(kept, OssError::Config(_)));

    let timed_out = mark_known_orphan_risk(OssError::Timeout("d".into()), "up-1");
    assert!(matches!(timed_out, OssError::Timeout(_)));
    assert!(timed_out.to_string().contains("up-1"));
    let cancelled = mark_known_orphan_risk(OssError::Unsupported("c".into()), "up-2");
    assert!(matches!(cancelled, OssError::Unsupported(_)));
    let other = mark_known_orphan_risk(OssError::Connection("t".into()), "up-3");
    assert!(matches!(other, OssError::Backend(_)));

    let merged = merge_abort_result(
        OssError::Connection("primary".into()),
        Err(OssError::Connection("abort".into())),
        "upload-123",
    );
    assert!(matches!(merged, OssError::Backend(_)));
    assert!(merged.to_string().contains("orphan_risk=true"));
    assert!(merged.to_string().contains("upload-123"));
    let kept_primary =
        merge_abort_result(OssError::Connection("primary".into()), Ok(()), "upload-123");
    assert!(matches!(kept_primary, OssError::Connection(_)));
}

#[test]
fn remaining_deadline_shrinks_and_expires() {
    let remaining =
        remaining_deadline(Instant::now(), Duration::from_secs(5), "put").expect("remaining");
    assert!(remaining > Duration::ZERO);
    let spent = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .expect("clock");
    assert!(remaining_deadline(spent, Duration::from_millis(1), "put").is_err());
}

#[test]
fn oss_headers_are_canonicalized_and_signed() {
    let mut none = HeaderMap::new();
    assert_eq!(
        apply_oss_headers(&mut none, false, None).expect("empty"),
        ""
    );
    assert!(none.is_empty());

    let mut sse_only = HeaderMap::new();
    assert_eq!(
        apply_oss_headers(&mut sse_only, true, None).expect("sse"),
        "x-oss-server-side-encryption:AES256\n"
    );
    assert!(sse_only.contains_key("x-oss-server-side-encryption"));

    // 多值时按头名字典序排列：security-token 在 server-side-encryption 之前
    let mut both = HeaderMap::new();
    assert_eq!(
        apply_oss_headers(&mut both, true, Some("sts-token")).expect("both"),
        "x-oss-security-token:sts-token\nx-oss-server-side-encryption:AES256\n"
    );
    assert_eq!(
        both.get("x-oss-security-token")
            .and_then(|value| value.to_str().ok()),
        Some("sts-token")
    );
}

#[test]
fn signed_headers_cover_canonicalized_inputs() {
    fn authorization_of(headers: &HeaderMap) -> String {
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .expect("authorization header")
            .to_string()
    }

    // 无 x-oss-* 头：CanonicalizedOSSHeaders 为空，签名等同裸 sign_v1
    let headers = signed_headers(
        "id",
        "secret",
        None,
        "PUT",
        "application/octet-stream",
        "/bucket/key",
        false,
    )
    .expect("headers");
    let date = headers
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .expect("date");
    let plain = sign_v1(
        "secret",
        "PUT",
        "",
        "application/octet-stream",
        date,
        "",
        "/bucket/key",
    );
    assert_eq!(authorization_of(&headers), format!("OSS id:{plain}"));

    // 带 STS token：签名内容必须包含该头
    let with_token = signed_headers("id", "secret", Some("sts"), "GET", "", "/bucket/key", false)
        .expect("headers");
    let date = with_token
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .expect("date");
    let signed = sign_v1(
        "secret",
        "GET",
        "",
        "",
        date,
        "x-oss-security-token:sts\n",
        "/bucket/key",
    );
    assert_eq!(authorization_of(&with_token), format!("OSS id:{signed}"));
    assert_ne!(plain, signed, "STS token 必须改变签名");
}

#[test]
fn object_meta_from_headers_parses_all_fields() {
    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("128"));
    headers.insert("etag", HeaderValue::from_static("\"abc\""));
    headers.insert("x-oss-version-id", HeaderValue::from_static("v1"));
    headers.insert("x-oss-hash-crc64ecma", HeaderValue::from_static("1234"));
    headers.insert("content-type", HeaderValue::from_static("text/plain"));
    let meta = object_meta_from_headers(&headers);
    assert_eq!(meta.size, 128);
    assert_eq!(meta.etag.as_deref(), Some("abc"));
    assert_eq!(meta.version_id.as_deref(), Some("v1"));
    assert_eq!(meta.checksum.as_deref(), Some("1234"));
    assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        object_meta_from_headers(&HeaderMap::new()),
        ObjectMeta::default()
    );
}

fn loopback_config() -> OssConfig {
    OssConfig::builder()
        .endpoint("http://localhost:9000")
        .bucket("bucket")
        .access_key_id("test-id")
        .access_key_secret("super-secret-value")
        .build()
        .expect("config")
}

#[tokio::test]
async fn acquire_is_bounded_by_concurrency_and_timeout() {
    let config = OssConfig::builder()
        .endpoint("http://localhost:9000")
        .bucket("bucket")
        .access_key_id("id")
        .access_key_secret("sec")
        .max_in_flight(1)
        .acquire_timeout(Duration::from_millis(200))
        .build()
        .expect("config");
    let client = OssClient::new(config).expect("client");
    let permit = client.acquire().await.expect("first permit");
    let error = client
        .acquire()
        .await
        .expect_err("second permit must time out");
    assert!(matches!(error, OssError::Timeout(_)));
    drop(permit);
    let _permit = client.acquire().await.expect("permit released");
}

#[tokio::test]
async fn close_is_an_unsupported_boundary() {
    let client = OssClient::new(loopback_config()).expect("client");
    assert!(!client.is_closed());
    client.close();
    client.close();
    assert!(client.is_closed());
    let error = client
        .acquire()
        .await
        .expect_err("closed client must reject acquire");
    assert!(matches!(error, OssError::Unsupported(_)));
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn closed_client_reports_health_check_error() {
    let client = OssClient::new(loopback_config()).expect("client");
    client.close();
    assert!(client.health_check().await.is_err());
}

#[test]
fn orphan_registry_capacity_and_overflow_are_bounded() {
    let client = OssClient::new(loopback_config()).expect("client");
    for index in 0..=ORPHAN_AUDIT_CAPACITY {
        drop(MultipartAuditGuard::new(
            &client,
            "object",
            &format!("upload-{index}"),
        ));
    }
    assert_eq!(
        client.multipart_orphan_audits().len(),
        ORPHAN_AUDIT_CAPACITY
    );
    assert_eq!(client.orphan_audit_overflow_count(), 1);
}

#[test]
fn client_is_clone_and_debug_keeps_secret_hidden() {
    let client = OssClient::new(loopback_config()).expect("client");
    let cloned = client.clone();
    assert_eq!(cloned.config().bucket, "bucket");
    let debug = format!("{client:?}");
    assert!(debug.contains("<redacted>"));
    assert!(
        !debug.contains("super-secret-value"),
        "secret 绝不能出现在 Debug 中"
    );
    assert_eq!(client.retry_config(), default_retry_config());
}

#[tokio::test]
async fn presign_uses_client_credentials() {
    let config = OssConfig::builder()
        .endpoint("https://oss.example.com")
        .bucket("bucket")
        .access_key_id("id")
        .access_key_secret("sec")
        .build()
        .expect("config");
    let client = OssClient::new(config).expect("client");
    let url = client
        .presign_url("dir/object.txt", &PresignOptions::default())
        .expect("presign");
    assert!(url.starts_with("https://bucket.oss.example.com/dir/object.txt?"));
    assert!(url.contains("OSSAccessKeyId=id"));
}
