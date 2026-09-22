//! TOML 反序列化形态、凭据键拒绝与 `[oss]` 节到配置的转换。
//!
//! 自 `src/config.rs` 下沉而来（模块名避开与 `toml` crate 的同名遮蔽）；
//! `reject_secret_keys_in_toml` 与 `OssTomlFile` 由门面调用，
//! 故提为 `pub(super)`。`OssTomlSection` / `default_region` / `into_config_with_env` 仅本模块使用。

use std::time::Duration;

use serde::Deserialize;

use crate::error::{OssError, OssResult};

use super::envvars::{apply_optional_env_overrides, require_env};
use super::{OssConfig, DEFAULT_REGION, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET};

/// 拒绝 TOML 中出现凭据字段（根级与 `[oss]` 节均检查）。
pub(super) fn reject_secret_keys_in_toml(text: &str) -> OssResult<()> {
    let value: toml::Value = toml::from_str(text)
        .map_err(|error| OssError::Serialization(format!("oss toml 解析失败: {error}")))?;
    let Some(table) = value.as_table() else {
        return Err(OssError::Config("oss toml 根必须为表".into()));
    };
    for key in ["access_key_id", "access_key_secret"] {
        if table.contains_key(key) {
            return Err(OssError::Config(format!("oss toml 禁止根级字段 {key}")));
        }
    }
    if let Some(oss) = table.get("oss").and_then(|value| value.as_table()) {
        for key in ["access_key_id", "access_key_secret"] {
            if oss.contains_key(key) {
                return Err(OssError::Config(format!("oss toml 禁止字段 {key}")));
            }
        }
    }
    Ok(())
}

/// 环境配置文件根结构（无凭据字段）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OssTomlFile {
    pub(super) schema_version: u32,
    pub(super) oss: OssTomlSection,
}

/// 环境配置文件 `[oss]` 节。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OssTomlSection {
    pub(super) endpoint: String,
    pub(super) bucket: String,
    #[serde(default = "default_region")]
    pub(super) region: String,
    #[serde(default)]
    pub(super) request_timeout_ms: Option<u64>,
    #[serde(default)]
    pub(super) operation_deadline_ms: Option<u64>,
    #[serde(default)]
    pub(super) acquire_timeout_ms: Option<u64>,
    #[serde(default)]
    pub(super) max_in_flight: Option<usize>,
    #[serde(default)]
    pub(super) max_object_bytes: Option<usize>,
    #[serde(default)]
    pub(super) max_buffer_bytes: Option<usize>,
    #[serde(default)]
    pub(super) max_error_body_bytes: Option<usize>,
    #[serde(default)]
    pub(super) sse_enabled: Option<bool>,
}

fn default_region() -> String {
    DEFAULT_REGION.into()
}

impl OssTomlFile {
    pub(super) fn into_config_with_env(self) -> OssResult<OssConfig> {
        let section = self.oss;
        let mut builder = OssConfig::builder()
            .endpoint(section.endpoint)
            .bucket(section.bucket)
            .region(section.region);
        if let Some(value) = section.request_timeout_ms {
            builder = builder.request_timeout(Duration::from_millis(value));
        }
        if let Some(value) = section.operation_deadline_ms {
            builder = builder.operation_deadline(Duration::from_millis(value));
        }
        if let Some(value) = section.acquire_timeout_ms {
            builder = builder.acquire_timeout(Duration::from_millis(value));
        }
        if let Some(value) = section.max_in_flight {
            builder = builder.max_in_flight(value);
        }
        if let Some(value) = section.max_object_bytes {
            builder = builder.max_object_bytes(value);
        }
        if let Some(value) = section.max_buffer_bytes {
            builder = builder.max_buffer_bytes(value);
        }
        if let Some(value) = section.max_error_body_bytes {
            builder = builder.max_error_body_bytes(value);
        }
        if let Some(value) = section.sse_enabled {
            builder = builder.sse_enabled(value);
        }
        let builder = builder
            .access_key_id(require_env(ENV_ACCESS_KEY_ID)?)
            .access_key_secret(require_env(ENV_ACCESS_KEY_SECRET)?);
        apply_optional_env_overrides(builder)?.build()
    }
}
