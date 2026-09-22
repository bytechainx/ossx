//! 环境变量读取与环境变量覆盖。
//!
//! 自 `src/config.rs` 下沉而来（模块名避开与 `std::env` 的同名遮蔽）；
//! `apply_optional_env_overrides` 与 `require_env` 由门面与
//! `config/toml.rs` 调用，故提为 `pub(super)`。`optional_usize_env` / `optional_duration_env`
//! 仅本模块使用。

use std::env;
use std::time::Duration;

use crate::error::{OssError, OssResult};

use super::{
    OssConfigBuilder, ENV_ACQUIRE_TIMEOUT_MS, ENV_MAX_BUFFER_BYTES, ENV_MAX_ERROR_BODY_BYTES,
    ENV_MAX_IN_FLIGHT, ENV_MAX_OBJECT_BYTES, ENV_OPERATION_DEADLINE_MS, ENV_REGION,
    ENV_REQUEST_TIMEOUT_MS,
};

/// TOML 基线之上合并环境变量：数值/超时 env 可覆盖 TOML 调参。
pub(super) fn apply_optional_env_overrides(
    mut builder: OssConfigBuilder,
) -> OssResult<OssConfigBuilder> {
    if let Ok(value) = env::var(ENV_REGION) {
        builder = builder.region(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_IN_FLIGHT)? {
        builder = builder.max_in_flight(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_OBJECT_BYTES)? {
        builder = builder.max_object_bytes(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_BUFFER_BYTES)? {
        builder = builder.max_buffer_bytes(value);
    }
    if let Some(value) = optional_usize_env(ENV_MAX_ERROR_BODY_BYTES)? {
        builder = builder.max_error_body_bytes(value);
    }
    if let Some(value) = optional_duration_env(ENV_REQUEST_TIMEOUT_MS)? {
        builder = builder.request_timeout(value);
    }
    if let Some(value) = optional_duration_env(ENV_OPERATION_DEADLINE_MS)? {
        builder = builder.operation_deadline(value);
    }
    if let Some(value) = optional_duration_env(ENV_ACQUIRE_TIMEOUT_MS)? {
        builder = builder.acquire_timeout(value);
    }
    Ok(builder)
}

pub(super) fn require_env(key: &str) -> OssResult<String> {
    env::var(key).map_err(|_| OssError::Config(format!("环境变量 {key} 未设置")))
}

fn optional_usize_env(key: &str) -> OssResult<Option<usize>> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<usize>()
            .map(Some)
            .map_err(|error| OssError::Config(format!("环境变量 {key} 非法: {error}"))),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(OssError::Config(format!("环境变量 {key} 读取失败"))),
    }
}

fn optional_duration_env(key: &str) -> OssResult<Option<Duration>> {
    match optional_usize_env(key)? {
        Some(value) => {
            let millis = u64::try_from(value)
                .map_err(|error| OssError::Config(format!("环境变量 {key} 过大: {error}")))?;
            Ok(Some(Duration::from_millis(millis)))
        }
        None => Ok(None),
    }
}
