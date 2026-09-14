//! WebSocket and process configuration helpers.
use super::*;

pub(crate) fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_SIZE),
        max_frame_size: Some(MAX_FRAME_SIZE),
        ..WebSocketConfig::default()
    }
}

pub(crate) fn connection_limit_from_env(value: Option<&str>) -> usize {
    value
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_MAX_CONNECTIONS)
}

pub(crate) fn max_connections() -> usize {
    connection_limit_from_env(std::env::var("MAX_CONNECTIONS").ok().as_deref())
}
