//! Server configuration, protocol limits, and runtime defaults.
use super::*;
use std::sync::OnceLock;

pub(crate) const DEFAULT_MINIMUM_CLIENT_VERSION: &str = "3.8.0";
pub(crate) const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8445";
pub(crate) const DEFAULT_CLIENT_DOWNLOAD_URL: &str = "https://mctier.pmhs.top";
pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// 握手阶段允许客户端占用连接的最长时间。
pub(crate) const WEBSOCKET_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// 首次注册消息的绝对截止时间。
pub(crate) const REGISTRATION_TIMEOUT_SECS: u64 = 15;
/// 单次发送允许等待的最长时间。
pub(crate) const SEND_TIMEOUT_SECS: u64 = 5;
/// 单条 WebSocket 消息的最大大小。
pub(crate) const MAX_MESSAGE_SIZE: usize = 512 * 1024;
/// 单个 WebSocket 帧的最大大小。
pub(crate) const MAX_FRAME_SIZE: usize = 256 * 1024;

pub(crate) const MAX_LOBBY_MEMBERS: usize = 64;
pub(crate) const MAX_CLIENT_ID_LEN: usize = 128;
pub(crate) const MAX_PLAYER_NAME_LEN: usize = 128;
pub(crate) const MAX_LOBBY_NAME_LEN: usize = 128;
pub(crate) const MAX_LOBBY_PASSWORD_LEN: usize = 256;
pub(crate) const MAX_VIRTUAL_DOMAIN_LEN: usize = 253;
pub(crate) const MAX_CLIENT_VERSION_LEN: usize = 32;
pub(crate) const SIGNALING_PROTOCOL_VERSION: u32 = 3;
pub(crate) const CHALLENGE_BYTES: usize = 32;
pub(crate) const MAX_IDENTITY_PUBLIC_KEY_LEN: usize = 512;
pub(crate) const MAX_IDENTITY_SIGNATURE_LEN: usize = 256;
pub(crate) const MAX_SDP_LEN: usize = 128 * 1024;
pub(crate) const MAX_ICE_CANDIDATE_LEN: usize = 16 * 1024;
pub(crate) const MAX_CONTROL_TEXT_LEN: usize = 8 * 1024;
pub(crate) const MAX_MESSAGES_PER_WINDOW: u32 = 120;
pub(crate) const MESSAGE_RATE_WINDOW_SECS: u64 = 10;
pub(crate) const MAX_OUTBOUND_FRAMES_PER_WINDOW: u32 = 64;
pub(crate) const MAX_OUTBOUND_BYTES_PER_WINDOW: usize = 1024 * 1024;
pub(crate) const OUTBOUND_BUDGET_WINDOW_SECS: u64 = 1;
pub(crate) const COMMUNITY_NODE_SUBMIT_MAX_PER_WINDOW: u32 = 8;
pub(crate) const COMMUNITY_NODE_SUBMIT_WINDOW_SECS: u64 = 10 * 60;
pub(crate) const MAX_TRACKED_IP_SUBMITTERS: usize = 8192;
pub(crate) const COMMUNITY_NODE_PROBE_QUEUE_TIMEOUT_SECS: u64 = 1;
pub(crate) const MAX_REMOTE_SESSION_ID_LEN: usize = 128;
pub(crate) const MAX_SHARE_ID_LEN: usize = 128;
pub(crate) const MAX_SHARE_NAME_LEN: usize = 256;
pub(crate) const MAX_ERROR_TEXT_LEN: usize = 512;
/// 聊天签名公钥长度上限。
pub(crate) const MAX_CHAT_PUBLIC_KEY_LEN: usize = 512;
/// 已注册连接的空闲超时。
pub(crate) const REGISTERED_IDLE_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerConfig {
    pub(crate) bind_address: String,
    pub(crate) minimum_client_version: String,
    pub(crate) client_download_url: String,
    pub(crate) max_connections: usize,
    pub(crate) max_connections_per_source: Option<usize>,
    pub(crate) trusted_proxies: String,
    pub(crate) community_nodes_file: String,
    pub(crate) community_node_capacity: usize,
    pub(crate) community_node_allow_private_targets: bool,
}

impl ServerConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            bind_address: env_or("BIND_ADDRESS", DEFAULT_BIND_ADDRESS),
            minimum_client_version: env_or(
                "MINIMUM_CLIENT_VERSION",
                DEFAULT_MINIMUM_CLIENT_VERSION,
            ),
            client_download_url: env_or("CLIENT_DOWNLOAD_URL", DEFAULT_CLIENT_DOWNLOAD_URL),
            max_connections: connection_limit_from_env(
                std::env::var("MAX_CONNECTIONS").ok().as_deref(),
            ),
            max_connections_per_source: positive_limit_from_env(
                std::env::var("MAX_CONNECTIONS_PER_SOURCE").ok().as_deref(),
            ),
            trusted_proxies: std::env::var("TRUSTED_PROXIES").unwrap_or_default(),
            community_nodes_file: env_or(
                "COMMUNITY_NODES_FILE",
                community_nodes::DEFAULT_COMMUNITY_NODES_FILE,
            ),
            community_node_capacity: std::env::var("COMMUNITY_NODE_CAPACITY")
                .ok()
                .and_then(|raw| raw.trim().parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(community_nodes::DEFAULT_COMMUNITY_NODE_CAPACITY),
            community_node_allow_private_targets: parse_bool(
                std::env::var("COMMUNITY_NODE_ALLOW_PRIVATE_TARGETS")
                    .ok()
                    .as_deref(),
                false,
            ),
        }
    }
}

static SERVER_CONFIG: OnceLock<ServerConfig> = OnceLock::new();

pub(crate) fn initialize(config: ServerConfig) -> &'static ServerConfig {
    SERVER_CONFIG.get_or_init(|| config)
}

pub(crate) fn server_config() -> &'static ServerConfig {
    SERVER_CONFIG.get_or_init(ServerConfig::from_env)
}

pub(crate) fn env_or(key: &str, default: &str) -> String {
    env_value(std::env::var(key).ok().as_deref(), default)
}

fn env_value(value: Option<&str>, default: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .to_string()
}

fn parse_bool(value: Option<&str>, default: bool) -> bool {
    value
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

pub(crate) fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_SIZE),
        max_frame_size: Some(MAX_FRAME_SIZE),
        ..WebSocketConfig::default()
    }
}

pub(crate) fn connection_limit_from_env(value: Option<&str>) -> usize {
    positive_limit_from_env(value).unwrap_or(DEFAULT_MAX_CONNECTIONS)
}

pub(crate) fn positive_limit_from_env(value: Option<&str>) -> Option<usize> {
    value
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|limit| *limit > 0)
}

pub(crate) fn minimum_client_version() -> &'static str {
    &server_config().minimum_client_version
}

pub(crate) fn client_download_url() -> &'static str {
    &server_config().client_download_url
}

pub(crate) fn community_node_capacity() -> usize {
    server_config().community_node_capacity
}

pub(crate) fn community_nodes_file() -> &'static str {
    &server_config().community_nodes_file
}

pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_values_trim_whitespace_and_fall_back_for_empty_values() {
        assert_eq!(env_value(Some("  value  "), "default"), "value");
        assert_eq!(env_value(Some(" \t"), "default"), "default");
        assert_eq!(env_value(None, "default"), "default");
    }

    #[test]
    fn boolean_values_accept_common_true_spellings() {
        for value in ["1", "true", "TRUE", " yes ", "On"] {
            assert!(parse_bool(Some(value), false), "{value} should be true");
        }
        for value in ["0", "false", "off", "random"] {
            assert!(!parse_bool(Some(value), true), "{value} should be false");
        }
        assert!(parse_bool(None, true));
        assert!(!parse_bool(None, false));
    }

    #[test]
    fn numeric_limits_reject_zero_invalid_and_whitespace_only_values() {
        assert_eq!(positive_limit_from_env(Some(" 128 ")), Some(128));
        assert_eq!(positive_limit_from_env(Some("0")), None);
        assert_eq!(positive_limit_from_env(Some("invalid")), None);
        assert_eq!(positive_limit_from_env(Some(" \t")), None);
        assert_eq!(connection_limit_from_env(None), DEFAULT_MAX_CONNECTIONS);
        assert_eq!(
            connection_limit_from_env(Some("invalid")),
            DEFAULT_MAX_CONNECTIONS
        );
    }

    #[test]
    fn protocol_defaults_remain_stable() {
        assert_eq!(DEFAULT_BIND_ADDRESS, "0.0.0.0:8445");
        assert_eq!(DEFAULT_MINIMUM_CLIENT_VERSION, "3.8.0");
        assert_eq!(DEFAULT_CLIENT_DOWNLOAD_URL, "https://mctier.pmhs.top");
        assert_eq!(MAX_MESSAGE_SIZE, 512 * 1024);
        assert_eq!(MAX_FRAME_SIZE, 256 * 1024);
        assert_eq!(REGISTERED_IDLE_TIMEOUT_SECS, 60);
    }
}
