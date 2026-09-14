use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures_util::{future::join_all, SinkExt, StreamExt};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock, Semaphore};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
mod connection_guard;

/// 默认要求的最低客户端版本（可通过环境变量 MINIMUM_CLIENT_VERSION 覆盖）
const DEFAULT_MINIMUM_CLIENT_VERSION: &str = "3.0.0";

/// 默认监听地址（可通过环境变量 BIND_ADDRESS 覆盖）
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8445";

/// 握手阶段允许客户端占用连接的最长时间
const WEBSOCKET_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// 首次注册消息的绝对截止时间
const REGISTRATION_TIMEOUT_SECS: u64 = 15;

/// 单次发送允许等待的最长时间
const SEND_TIMEOUT_SECS: u64 = 5;

/// 单条 WebSocket 消息的最大大小
const MAX_MESSAGE_SIZE: usize = 512 * 1024;

/// 单个 WebSocket 帧的最大大小
const MAX_FRAME_SIZE: usize = 256 * 1024;

const MAX_LOBBY_MEMBERS: usize = 64;
const MAX_CLIENT_ID_LEN: usize = 128;
const MAX_PLAYER_NAME_LEN: usize = 128;
const MAX_LOBBY_NAME_LEN: usize = 128;
const MAX_LOBBY_PASSWORD_LEN: usize = 256;
const MAX_VIRTUAL_DOMAIN_LEN: usize = 253;
const MAX_CLIENT_VERSION_LEN: usize = 32;
const SIGNALING_PROTOCOL_VERSION: u32 = 3;
const CHALLENGE_BYTES: usize = 32;
const MAX_IDENTITY_PUBLIC_KEY_LEN: usize = 512;
const MAX_IDENTITY_SIGNATURE_LEN: usize = 256;
const MAX_SDP_LEN: usize = 128 * 1024;
const MAX_ICE_CANDIDATE_LEN: usize = 16 * 1024;
const MAX_CONTROL_TEXT_LEN: usize = 8 * 1024;
const MAX_MESSAGES_PER_WINDOW: u32 = 120;
const MESSAGE_RATE_WINDOW_SECS: u64 = 10;
const MAX_OUTBOUND_FRAMES_PER_WINDOW: u32 = 64;
const MAX_OUTBOUND_BYTES_PER_WINDOW: usize = 1024 * 1024;
const OUTBOUND_BUDGET_WINDOW_SECS: u64 = 1;
const COMMUNITY_NODE_SUBMIT_MAX_PER_WINDOW: u32 = 8;
const COMMUNITY_NODE_SUBMIT_WINDOW_SECS: u64 = 10 * 60;
const MAX_TRACKED_IP_SUBMITTERS: usize = 8192;
const COMMUNITY_NODE_PROBE_QUEUE_TIMEOUT_SECS: u64 = 1;
const MAX_REMOTE_SESSION_ID_LEN: usize = 128;
const MAX_SHARE_ID_LEN: usize = 128;
const MAX_SHARE_NAME_LEN: usize = 256;
const MAX_ERROR_TEXT_LEN: usize = 512;

/// 聊天签名公钥（X.509 SubjectPublicKeyInfo DER 的 base64）长度上限。
/// 未压缩 P-256 公钥 DER 为 91 字节，base64 后约 124 字符，留出余量后仍能
/// 拦住任何异常大的值；注册时还会在 P-256 解析阶段验证其密码学有效性。
const MAX_CHAT_PUBLIC_KEY_LEN: usize = 512;

/// 默认最大并发连接数（可通过环境变量 MAX_CONNECTIONS 覆盖）
const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// 已注册连接的空闲超时。
///
/// 客户端（桌面端与 Android 端）均以 15 秒周期发送应用层 {"type":"ping"}，
/// 因此正常连接不会触发该超时。半开连接（休眠 / 切换网络 / NAT 表超时，
/// 对端未发出 FIN）会一直停在 read.next() 上，若不回收则该 clientId 的
/// 会话永久留在大厅里；由于重复 clientId 会被拒绝注册，该玩家将无法重连。
const REGISTERED_IDLE_TIMEOUT_SECS: u64 = 60;

/// 版本过低时提示客户端的下载地址（可通过环境变量 CLIENT_DOWNLOAD_URL 覆盖）
const DEFAULT_CLIENT_DOWNLOAD_URL: &str = "https://mctier.pmhs.top";

/// 读取环境变量，并过滤掉空值
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// 客户端下载地址（进程内只解析一次）
fn client_download_url() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| env_or("CLIENT_DOWNLOAD_URL", DEFAULT_CLIENT_DOWNLOAD_URL))
}

/// 服务器要求的最低客户端版本（进程内只解析一次）
fn minimum_client_version() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| env_or("MINIMUM_CLIENT_VERSION", DEFAULT_MINIMUM_CLIENT_VERSION))
}

/// 投稿节点注册表容量上限（进程内只解析一次）
fn community_node_capacity() -> usize {
    static CELL: OnceLock<usize> = OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("COMMUNITY_NODE_CAPACITY")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_COMMUNITY_NODE_CAPACITY)
    })
}

/// 投稿节点持久化文件路径（进程内只解析一次）
fn community_nodes_file() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| env_or("COMMUNITY_NODES_FILE", DEFAULT_COMMUNITY_NODES_FILE))
}

/// 当前 Unix 时间戳（秒）
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod protocol;
use protocol::*;

mod security;
#[cfg(test)]
use security::*;

mod state;
use state::*;

mod config;
use config::*;

mod community_nodes;
use community_nodes::*;
mod connection;
use connection::*;

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::init();

    // 监听地址：默认 0.0.0.0:8445，可用环境变量 BIND_ADDRESS 覆盖
    let listen_addr = env_or("BIND_ADDRESS", DEFAULT_BIND_ADDRESS);

    log::info!("MCTier WebSocket 信令服务器");
    log::info!(
        "版本: {} (大厅隔离 - 仅 WebSocket)",
        env!("CARGO_PKG_VERSION")
    );
    log::info!("监听地址: {} (WebSocket Only)", listen_addr);
    log::info!("最低客户端版本: {}", minimum_client_version());
    let max_connections = max_connections();
    log::info!("最大并发连接数: {}", max_connections);
    let admission = connection_guard::admission();
    log::info!("Trusted reverse proxies: {:?}", admission.trusted_proxies);
    match admission.source_limit() {
        Some(limit) => log::info!("单来源并发连接上限: {}", limit),
        None => log::info!("单来源并发连接上限: 未启用"),
    }

    // 创建大厅列表和客户端映射
    let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
    let client_lobby_map: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));

    // 用户投稿的共享节点：从磁盘恢复（顺带剔除失效超过 1 天的条目），并启动后台巡检
    let community_nodes: CommunityNodes = Arc::new(RwLock::new(load_community_nodes_from_disk(
        community_nodes_file(),
        now_unix_secs(),
    )));
    let submit_cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));
    let submit_quotas: SubmitQuotas = Arc::new(Mutex::new(HashMap::new()));
    let probe_limiter: ProbeLimiter = Arc::new(Semaphore::new(COMMUNITY_NODE_PROBE_CONCURRENCY));
    log::info!(
        "共享节点：容量上限 {}，巡检周期 {} 秒，失效超过 {} 秒自动移除，存档 {}",
        community_node_capacity(),
        COMMUNITY_NODE_PROBE_INTERVAL_SECS,
        COMMUNITY_NODE_MAX_OFFLINE_SECS,
        community_nodes_file()
    );
    spawn_community_node_sweeper(Arc::clone(&community_nodes), Arc::clone(&probe_limiter)).await;

    // 绑定监听地址
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => {
            log::info!("✅ 服务器已启动，监听: {}", listen_addr);
            l
        }
        Err(e) => {
            log::error!("❌ 无法绑定地址 {}: {}", listen_addr, e);
            return;
        }
    };

    // 接受连接
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                log::info!("新客户端连接: {}", addr);

                let connection_permit = match admission.pending(addr.ip()) {
                    Ok(permit) => permit,
                    Err(reason) => {
                        log::warn!("Handshake admission rejected {}: {}", addr, reason);
                        continue;
                    }
                };
                let lobbies_clone = Arc::clone(&lobbies);
                let client_lobby_map_clone = Arc::clone(&client_lobby_map);
                let community_nodes_clone = Arc::clone(&community_nodes);
                let submit_cooldowns_clone = Arc::clone(&submit_cooldowns);
                let submit_quotas_clone = Arc::clone(&submit_quotas);
                let probe_limiter_clone = Arc::clone(&probe_limiter);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        stream,
                        addr,
                        lobbies_clone,
                        client_lobby_map_clone,
                        community_nodes_clone,
                        submit_cooldowns_clone,
                        submit_quotas_clone,
                        probe_limiter_clone,
                        connection_permit,
                    )
                    .await
                    {
                        log::error!("处理客户端连接失败 ({}): {}", addr, e);
                    }
                });
            }
            Err(e) => {
                log::error!("接受连接失败: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use serde_json::Value;
    use std::future::pending;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::time::{timeout, Duration};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::WebSocketStream;

    #[test]
    fn websocket_limits_are_explicit() {
        let config = websocket_config();
        assert_eq!(config.max_message_size, Some(512 * 1024));
        assert_eq!(config.max_frame_size, Some(256 * 1024));
    }

    #[test]
    fn screen_health_survives_signal_serialization() {
        let wire = serde_json::json!({
            "type": "screen-share-relay", "from": "android", "to": "desktop",
            "shareId": "share-android-1800000000000", "action": "health", "routeVersion": 1,
            "sequence": 53, "sourceSequence": 53, "sentSequence": 49, "limited": false,
            "reason": "stalled"
        });
        let message: SignalingMessage = serde_json::from_value(wire.clone()).unwrap();
        assert!(validate_message_shape(&message));
        let forwarded = serde_json::to_value(message).unwrap();
        assert_eq!(forwarded, wire);
        let mut invalid = wire;
        invalid["sourceSequence"] = serde_json::json!(1_000_000_001u64);
        assert!(!validate_message_shape(
            &serde_json::from_value(invalid).unwrap()
        ));
    }

    #[tokio::test]
    async fn screen_health_reaches_authenticated_viewer_intact() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut publisher, _) = connect_async(&url).await.unwrap();
        let registered = register(&mut publisher, "phone", "screen-room").await;
        let (mut viewer, _) = connect_async(&url).await.unwrap();
        register(&mut viewer, "desktop", "screen-room").await;
        assert_eq!(
            next_json(&mut publisher).await["type"],
            "chat-token-rotated"
        );
        assert_eq!(next_json(&mut publisher).await["type"], "player-joined");
        let (_, _, publisher_id) = test_identity_key("phone");
        let (_, _, viewer_id) = test_identity_key("desktop");
        let health = serde_json::json!({
            "type": "screen-share-relay", "from": publisher_id, "to": viewer_id,
            "shareId": format!("share-{publisher_id}-1800000000000"),
            "action": "health", "routeVersion": 1,
            "sequence": 53, "sourceSequence": 53, "sentSequence": 49, "limited": false,
            "reason": "stalled"
        });
        publisher
            .send(Message::Text(health.to_string()))
            .await
            .unwrap();
        let received = next_json(&mut viewer).await;
        for (key, value) in health.as_object().unwrap() {
            assert_eq!(&received[key], value, "forwarded field {key}");
        }
        assert_eq!(
            received["sessionGeneration"],
            registered["sessionGeneration"]
        );
        server.abort();
    }

    /// 测试用客户端版本：直接取当前门槛值，避免写死字面量。
    /// 此前各处硬编码 "2.1.0" / "2.7.5"，门槛一提高就会有一批测试因为
    /// 「版本过低」集体失败，而失败原因与被测逻辑无关，属于噪音。
    const TEST_CLIENT_VERSION: &str = DEFAULT_MINIMUM_CLIENT_VERSION;

    #[test]
    fn version_gate_rejects_partial_or_malformed_versions() {
        assert!(is_version_valid("2.8.0", "2.1.0"));
        assert!(!is_version_valid("999.invalid", "2.1.0"));
        assert!(!is_version_valid("2.1", "2.1.0"));
        assert!(!is_version_valid("2.1.0.1", "2.1.0"));
    }

    /// 门槛提到 3.0.0 后，2.x 客户端必须被拒、3.0.0 及以上必须放行。
    /// 这条固定住「最低版本要求」这个产品决策本身，而不只是比较函数的行为。
    #[test]
    fn minimum_client_version_blocks_pre_3_clients() {
        assert_eq!(DEFAULT_MINIMUM_CLIENT_VERSION, "3.0.0");

        // 低于门槛：一律拒绝
        for old in ["1.0.0", "2.0.0", "2.1.0", "2.7.5", "2.8.0", "2.9.9"] {
            assert!(
                !is_version_valid(old, DEFAULT_MINIMUM_CLIENT_VERSION),
                "client {old} must be rejected"
            );
        }

        // 达到或高于门槛：放行
        for ok in ["3.0.0", "3.0.1", "3.1.0", "4.0.0"] {
            assert!(
                is_version_valid(ok, DEFAULT_MINIMUM_CLIENT_VERSION),
                "client {ok} must be allowed"
            );
        }

        // 未提供版本号的客户端也必须被拒（注册分支里 "unknown" 直接判负）
        assert!(!is_version_valid("unknown", DEFAULT_MINIMUM_CLIENT_VERSION));
        assert!(!is_version_valid("", DEFAULT_MINIMUM_CLIENT_VERSION));
    }

    #[test]
    fn public_lobby_metadata_never_contains_a_password() {
        let json = serde_json::to_value(PublicLobbyInfo {
            lobby_name: "open".to_string(),
            player_count: 1,
            max_players: Some(64),
            host_name: "host".to_string(),
            description: String::new(),
            server_node: String::new(),
        })
        .unwrap();
        assert!(json.get("password").is_none());
    }

    #[test]
    fn password_protected_lobbies_cannot_be_public() {
        assert!(effective_public_setting(true, true));
        assert!(!effective_public_setting(true, false));
        assert!(!effective_public_setting(false, true));
        assert!(!effective_public_setting(false, false));
    }

    #[test]
    fn connection_limit_defaults_and_rejects_invalid_values() {
        assert_eq!(connection_limit_from_env(None), DEFAULT_MAX_CONNECTIONS);
        assert_eq!(
            connection_limit_from_env(Some("0")),
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            connection_limit_from_env(Some("not-a-number")),
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(connection_limit_from_env(Some("7")), 7);
    }

    #[tokio::test]
    async fn slow_send_times_out_after_five_seconds() {
        let send = tokio::spawn(send_with_timeout(pending::<Result<(), &'static str>>()));
        tokio::task::yield_now().await;
        assert!(!send.is_finished());
        tokio::time::sleep(tokio::time::Duration::from_secs(SEND_TIMEOUT_SECS)).await;
        assert!(!send.await.expect("send timeout task should finish"));
    }

    #[tokio::test]
    async fn broadcast_does_not_hold_lobby_lock_while_sender_is_busy() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let client_connect = tokio::spawn(TcpStream::connect(address));
        let (server_stream, _) = listener.accept().await.expect("accept test connection");
        let _client_stream = client_connect
            .await
            .expect("connect task should finish")
            .expect("connect test client");
        let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_stream,
            Role::Server,
            Some(websocket_config()),
        )
        .await;
        let (sink, _read) = ws_stream.split();
        let sender = Arc::new(ClientSenderState {
            sink: RwLock::new(sink),
            budget: Mutex::new(OutboundBudget::new()),
        });
        let (disconnect, _disconnect_rx) = watch::channel(false);
        let _busy_sender = sender.sink.write().await;

        let mut clients = HashMap::new();
        clients.insert(
            "slow".to_string(),
            ClientInfo {
                player_id: "slow".to_string(),
                player_name: "slow".to_string(),
                virtual_ip: None,
                virtual_domain: None,
                use_domain: None,
                chat_public_key: None,
                session_generation: 1,
                sender: Arc::clone(&sender),
                disconnect,
            },
        );
        let mut lobby_map = HashMap::new();
        lobby_map.insert(
            "lobby".to_string(),
            LobbyInfo {
                lobby_name: "lobby".to_string(),
                password_hash: String::new(),
                password_salt: String::new(),
                clients,
                host_id: "slow".to_string(),
                max_players: None,
                is_public: false,
                is_passwordless: true,
                description: String::new(),
                server_node: String::new(),
                muted: HashSet::new(),
                chat_token: generate_chat_token(),
                chat_token_epoch: 1,
            },
        );
        let lobbies = Arc::new(RwLock::new(lobby_map));
        let lock_acquired = tokio::select! {
            lock = lobbies.write() => Some(lock),
            _ = broadcast_to_lobby(
                &lobbies,
                "lobby",
                "",
                SignalingMessage::PlayerLeft {
                    player_id: "other".to_string(),
                    session_generation: 1,
                },
            ) => None,
        };
        assert!(
            lock_acquired.is_some(),
            "broadcast should release lobbies lock before send"
        );
    }

    async fn start_connection_server(
        registration_timeout: tokio::time::Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let lobbies = Arc::new(RwLock::new(HashMap::new()));
        let client_lobby_map = Arc::new(RwLock::new(HashMap::new()));
        let community_nodes: CommunityNodes = Arc::new(RwLock::new(HashMap::new()));
        let submit_cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));
        let server_task = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.expect("accept test client");
            handle_connection_with_timeouts(
                stream,
                addr,
                lobbies,
                client_lobby_map,
                community_nodes,
                submit_cooldowns,
                tokio::time::Duration::from_secs(1),
                registration_timeout,
                tokio::time::Duration::from_secs(300),
            )
            .await
            .expect("test server connection should finish cleanly");
        });
        (address, server_task)
    }

    #[tokio::test]
    async fn websocket_client_can_register_before_deadline() {
        let (address, server_task) =
            start_connection_server(tokio::time::Duration::from_secs(1)).await;
        let (mut client, _) = connect_async(format!("ws://{}", address))
            .await
            .expect("WebSocket handshake should succeed");
        send_register_with_ip(
            &mut client,
            "test-client",
            "test-lobby",
            "test-password",
            "10.126.126.10",
        )
        .await;

        let register_success = next_json(&mut client).await;
        let players_list = next_json(&mut client).await;
        assert!(matches!(
            serde_json::from_value::<SignalingMessage>(register_success)
                .expect("register-success should parse"),
            SignalingMessage::RegisterSuccess { .. }
        ));
        assert!(matches!(
            serde_json::from_value::<SignalingMessage>(players_list)
                .expect("players-list should parse"),
            SignalingMessage::PlayersList { .. }
        ));

        client.close(None).await.expect("client close should send");
        server_task.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn legacy_register_old_versions_receive_upgrade_error_and_disconnect() {
        for version in [Some("2.7.5"), Some("2.9.99"), None] {
            let (address, server_task) =
                start_connection_server(tokio::time::Duration::from_secs(1)).await;
            let (mut client, _) = connect_async(format!("ws://{address}"))
                .await
                .expect("WebSocket handshake should succeed");
            // v2.7.5 registers immediately and ignores the server challenge.
            let mut registration = serde_json::json!({
                "type": "register", "clientId": "legacy", "playerName": "Legacy",
                "virtualIp": "10.126.126.10", "lobbyName": "room", "lobbyPassword": "password"
            });
            if let Some(version) = version {
                registration["clientVersion"] = serde_json::json!(version);
            }
            client
                .send(Message::Text(registration.to_string()))
                .await
                .unwrap();
            next_server_challenge(&mut client).await;
            let error = next_json(&mut client).await;
            assert_eq!(error["type"], "version-too-old");
            assert_eq!(error["currentVersion"], version.unwrap_or("unknown"));
            assert_eq!(error["minimumVersion"], "3.0.0");
            assert_eq!(error["downloadUrl"], client_download_url());
            match timeout(Duration::from_secs(1), client.next())
                .await
                .unwrap()
            {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
                Some(Ok(message)) => panic!("legacy client must not be admitted: {message:?}"),
            }
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn legacy_register_protocol_is_rejected_after_challenge() {
        let (address, server_task) =
            start_connection_server(tokio::time::Duration::from_secs(1)).await;
        let (mut client, _) = connect_async(format!("ws://{}", address))
            .await
            .expect("WebSocket handshake should succeed");
        let _challenge = next_server_challenge(&mut client).await;
        client
            .send(Message::Text(
                serde_json::json!({
                    "type": "register",
                    "clientId": "legacy",
                    "playerName": "Legacy",
                    "virtualIp": "10.126.126.10",
                    "lobbyName": "room",
                    "lobbyPassword": "password",
                    "clientVersion": TEST_CLIENT_VERSION
                })
                .to_string(),
            ))
            .await
            .expect("legacy registration should send");
        let error = next_json(&mut client).await;
        assert_eq!(error["type"], "register-error");
        assert!(error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("register-v3"));
        match timeout(Duration::from_secs(1), client.next())
            .await
            .expect("legacy protocol should be closed")
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
            Some(Ok(message)) => panic!("legacy session remained open with {message:?}"),
        }
        server_task.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn unregistered_connection_closes_at_absolute_deadline() {
        let (address, server_task) =
            start_connection_server(tokio::time::Duration::from_millis(100)).await;
        let (mut client, _) = connect_async(format!("ws://{}", address))
            .await
            .expect("WebSocket handshake should succeed");

        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        client
            .send(Message::Text(
                serde_json::to_string(&SignalingMessage::Ping).expect("ping should serialize"),
            ))
            .await
            .expect("ping should send");
        let pong = next_json(&mut client).await;
        assert!(matches!(
            serde_json::from_value::<SignalingMessage>(pong).expect("pong should parse"),
            SignalingMessage::Pong
        ));

        let closed = tokio::time::timeout(tokio::time::Duration::from_secs(1), client.next())
            .await
            .expect("unregistered connection should close by deadline");
        assert!(closed.is_none() || matches!(closed, Some(Err(_))));
        server_task.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn oversized_message_is_rejected_by_websocket_limits() {
        let (server_io, client_io) = tokio::io::duplex(4 * 1024 * 1024);
        let (mut server, mut client) = tokio::join!(
            tokio_tungstenite::WebSocketStream::from_raw_socket(
                server_io,
                Role::Server,
                Some(websocket_config()),
            ),
            tokio_tungstenite::WebSocketStream::from_raw_socket(
                client_io,
                Role::Client,
                Some(WebSocketConfig {
                    max_message_size: Some(4 * 1024 * 1024),
                    max_frame_size: Some(4 * 1024 * 1024),
                    ..WebSocketConfig::default()
                }),
            ),
        );
        let server_read = tokio::spawn(async move { server.next().await });
        client
            .send(Message::Text("x".repeat(MAX_MESSAGE_SIZE + 1)))
            .await
            .expect("client should send test frame");
        let server_result = server_read.await.expect("server reader should finish");
        assert!(
            matches!(server_result, Some(Err(_))),
            "oversized message should be rejected"
        );
    }
    #[test]
    fn lobby_password_hash_uses_salt_and_constant_time_compare() {
        let salt = random_hex::<LOBBY_PASSWORD_SALT_BYTES>();
        let correct = hash_lobby_password(&salt, "pw");
        assert_eq!(correct, hash_lobby_password(&salt, "pw"));
        assert_ne!(correct, hash_lobby_password(&salt, "PW"));
        assert_ne!(
            correct,
            hash_lobby_password(&random_hex::<LOBBY_PASSWORD_SALT_BYTES>(), "pw")
        );
        assert!(ct_eq(
            correct.as_bytes(),
            hash_lobby_password(&salt, "pw").as_bytes()
        ));
        assert!(!ct_eq(correct.as_bytes(), b"different"));
        assert!(!ct_eq(b"short", b"longer value"));
    }

    #[test]
    fn register_password_failures_lock_after_threshold_and_expire() {
        let key = ("192.0.2.9".parse().unwrap(), "lock-lobby".to_string());
        let now = Instant::now();
        let mut tracker = RegisterPasswordFailures {
            attempts: HashMap::new(),
        };
        for _ in 0..MAX_REGISTER_PASSWORD_FAILURES {
            assert!(!tracker.is_locked(&key, now));
            tracker.record_failure(&key, now);
        }
        assert!(tracker.is_locked(&key, now));
        let later = now + std::time::Duration::from_secs(REGISTER_PASSWORD_FAILURE_WINDOW_SECS + 1);
        assert!(!tracker.is_locked(&key, later));
        assert!(tracker.attempts.is_empty());
        tracker.record_failure(&key, later);
        tracker.clear(&key);
        assert!(tracker.attempts.is_empty());
        assert!(!tracker.is_locked(&key, later));
    }

    #[tokio::test]
    async fn repeated_wrong_passwords_close_connections_and_lock_the_source() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut host,
            "brute-host",
            "brute-room",
            "correct",
            "10.126.126.1",
        )
        .await;
        assert_eq!(next_json(&mut host).await["type"], "register-success");
        assert_eq!(next_json(&mut host).await["type"], "players-list");
        for _ in 0..MAX_REGISTER_PASSWORD_FAILURES {
            let (mut wrong, _) = connect_async(&url).await.unwrap();
            send_register_with_ip(&mut wrong, "brute", "brute-room", "bad", "10.126.126.2").await;
            let rejected = next_json(&mut wrong).await;
            assert_eq!(rejected["type"], "register-error");
            assert_eq!(rejected["message"], "密码错误");
            // 每次失败都必须断开连接，攻击者无法在同一连接内继续枚举。
            match timeout(Duration::from_secs(1), wrong.next()).await.unwrap() {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
                Some(Ok(message)) => panic!("wrong-password session stayed open with {message:?}"),
            }
        }
        // 锁定期内即使密码正确也拒绝，且连接同样被关闭。
        let (mut locked, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut locked,
            "brute",
            "brute-room",
            "correct",
            "10.126.126.3",
        )
        .await;
        let rejected = next_json(&mut locked).await;
        assert_eq!(rejected["type"], "register-error");
        assert_eq!(rejected["message"], "密码错误次数过多，请稍后再试");
        match timeout(Duration::from_secs(1), locked.next())
            .await
            .unwrap()
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
            Some(Ok(message)) => panic!("locked session stayed open with {message:?}"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn wrong_password_cannot_create_a_second_room_or_obtain_credentials() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut host,
            "password-host",
            "unique-room",
            "correct",
            "10.126.126.1",
        )
        .await;
        let accepted = next_json(&mut host).await;
        assert_eq!(accepted["type"], "register-success");
        assert_eq!(next_json(&mut host).await["type"], "players-list");
        let (mut wrong, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut wrong,
            "password-wrong",
            "unique-room",
            "incorrect",
            "10.126.126.2",
        )
        .await;
        let rejected = next_json(&mut wrong).await;
        assert_eq!(rejected["type"], "register-error");
        assert_eq!(rejected["message"], "密码错误");
        assert!(rejected.get("chatToken").is_none());
        let (mut member, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut member,
            "password-member",
            "unique-room",
            "correct",
            "10.126.126.3",
        )
        .await;
        let joined = next_json(&mut member).await;
        assert_eq!(joined["type"], "register-success");
        assert_eq!(joined["lobbyId"], accepted["lobbyId"]);
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut host).await["type"], "player-joined");
        server.abort();
    }

    #[tokio::test]
    async fn proxy_headers_isolate_connection_and_submission_limits_over_websocket() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let policy = Arc::new(connection_guard::Admission::new(16, Some(2), "127.0.0.1").unwrap());
        let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
        let clients: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));
        let nodes: CommunityNodes = Arc::new(RwLock::new(HashMap::new()));
        let cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));
        let quotas: SubmitQuotas = Arc::new(Mutex::new(HashMap::new()));
        // Saturate only the probe queue so submissions exercise quotas without network I/O.
        let probes = Arc::new(Semaphore::new(0));
        let server = tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let (policy, lobbies, clients, nodes, cooldowns, quotas, probes) = (
                    policy.clone(),
                    lobbies.clone(),
                    clients.clone(),
                    nodes.clone(),
                    cooldowns.clone(),
                    quotas.clone(),
                    probes.clone(),
                );
                tokio::spawn(async move {
                    let _ = handle_connection_with_timeouts_and_limits(
                        stream,
                        peer,
                        lobbies,
                        clients,
                        nodes,
                        cooldowns,
                        quotas,
                        probes,
                        Duration::from_secs(2),
                        Duration::from_secs(15),
                        Duration::from_secs(60),
                        None,
                        &policy,
                    )
                    .await;
                });
            }
        });
        let request = |ip: &str| {
            let mut request = format!("ws://{address}").into_client_request().unwrap();
            request
                .headers_mut()
                .insert("x-forwarded-for", ip.parse().unwrap());
            request
        };
        let (mut a, _) = connect_async(request("192.0.2.1")).await.unwrap();
        let (_a2, _) = connect_async(request("192.0.2.1")).await.unwrap();
        let rejected = connect_async(request("192.0.2.1")).await.unwrap_err();
        match rejected {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status().as_u16(), 429);
                assert_eq!(response.headers()["Retry-After"], "5");
                assert_eq!(
                    response.body().as_deref(),
                    Some(b"source connection capacity reached".as_slice())
                );
            }
            other => panic!("expected an explicit quota rejection, got {other}"),
        }
        let (mut b, _) = connect_async(request("192.0.2.2")).await.unwrap();
        assert!(
            connect_async(format!("ws://{address}")).await.is_err(),
            "missing forwarded identity must not share the proxy IP"
        );
        let submit = Message::Text(serde_json::json!({"type":"community-node-submit", "name":"test", "address":"tcp://127.0.0.1:9"}).to_string());
        a.send(submit.clone()).await.unwrap();
        let first = next_json(&mut a).await;
        assert_eq!(first["ok"], false);
        a.send(submit.clone()).await.unwrap();
        let limited = next_json(&mut a).await;
        assert!(limited["message"].as_str().unwrap().contains("频繁"));
        b.send(submit).await.unwrap();
        let independent = next_json(&mut b).await;
        assert!(!independent["message"].as_str().unwrap().contains("频繁"));
        server.abort();
    }

    async fn spawn_test_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_test_server_with_idle_timeout(tokio::time::Duration::from_secs(
            REGISTERED_IDLE_TIMEOUT_SECS,
        ))
        .await
    }

    async fn spawn_test_server_with_idle_timeout(
        idle_timeout: tokio::time::Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
        let client_lobby_map: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));
        let community_nodes: CommunityNodes = Arc::new(RwLock::new(HashMap::new()));
        let submit_cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    break;
                };
                let lobbies = Arc::clone(&lobbies);
                let client_lobby_map = Arc::clone(&client_lobby_map);
                let community_nodes = Arc::clone(&community_nodes);
                let submit_cooldowns = Arc::clone(&submit_cooldowns);
                tokio::spawn(async move {
                    let _ = handle_connection_with_timeouts(
                        stream,
                        peer,
                        lobbies,
                        client_lobby_map,
                        community_nodes,
                        submit_cooldowns,
                        tokio::time::Duration::from_secs(WEBSOCKET_HANDSHAKE_TIMEOUT_SECS),
                        tokio::time::Duration::from_secs(REGISTRATION_TIMEOUT_SECS),
                        idle_timeout,
                    )
                    .await;
                });
            }
        });

        (address, task)
    }

    async fn next_frame<S>(socket: &mut WebSocketStream<S>) -> Option<Message>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
        {
            Some(Ok(message)) => Some(message),
            Some(Err(error)) => panic!("test WebSocket failed: {error}"),
            None => None,
        }
    }

    async fn next_json<S>(socket: &mut WebSocketStream<S>) -> Value
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let message = next_frame(socket)
                .await
                .expect("test WebSocket closed before receiving JSON");
            if let Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["type"] == "server-challenge" {
                    continue;
                }
                return value;
            }
        }
    }

    async fn next_server_challenge<S>(socket: &mut WebSocketStream<S>) -> String
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let value = loop {
            let message = next_frame(socket)
                .await
                .expect("test WebSocket closed before receiving challenge");
            if let Message::Text(text) = message {
                break serde_json::from_str::<Value>(&text).unwrap();
            }
        };
        assert_eq!(value["type"], "server-challenge");
        assert_eq!(value["protocolVersion"], SIGNALING_PROTOCOL_VERSION);
        let challenge = value["challenge"]
            .as_str()
            .expect("challenge must be text")
            .to_string();
        assert_eq!(challenge.len(), CHALLENGE_BYTES * 2);
        assert!(challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        challenge
    }

    fn test_virtual_ip(client_id: &str) -> String {
        let digest = Sha256::digest(client_id.as_bytes());
        let host = ((u16::from(digest[0]) << 8) | u16::from(digest[1])) % 254 + 1;
        format!("10.126.126.{host}")
    }

    fn test_signing_key(label: &str) -> SigningKey {
        let mut bytes = [0u8; 32];
        let digest = Sha256::digest(format!("mctier-test-identity:{label}").as_bytes());
        bytes.copy_from_slice(&digest);
        for _ in 0..256 {
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                return key;
            }
            bytes[31] = bytes[31].wrapping_add(1);
        }
        panic!("unable to derive a test P-256 key");
    }

    fn test_identity_key(label: &str) -> (SigningKey, String, String) {
        let key = test_signing_key(label);
        let der = key
            .verifying_key()
            .to_public_key_der()
            .expect("test public key should encode");
        let encoded = BASE64_STANDARD.encode(der.as_bytes());
        let digest = Sha256::digest(der.as_bytes());
        let client_id = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        (key, encoded, client_id)
    }

    fn test_client_id(label: &str) -> String {
        test_identity_key(label).2
    }

    fn register_message_for_challenge(
        client_id: &str,
        lobby_name: &str,
        lobby_password: &str,
        virtual_ip: &str,
        challenge: &str,
    ) -> Message {
        let (key, identity_public_key, _) = test_identity_key(client_id);
        let signature: p256::ecdsa::Signature =
            key.sign(&registration_canonical(challenge, lobby_name, virtual_ip));
        Message::Text(
            serde_json::json!({
                "type": "register-v3",
                "protocolVersion": SIGNALING_PROTOCOL_VERSION,
                "identityPublicKey": identity_public_key,
                "challengeSignature": BASE64_STANDARD.encode(signature.to_der().as_bytes()),
                "playerName": client_id,
                "virtualIp": virtual_ip,
                "lobbyName": lobby_name,
                "lobbyPassword": lobby_password,
                "clientVersion": TEST_CLIENT_VERSION
            })
            .to_string(),
        )
    }

    async fn send_register_with_ip<S>(
        socket: &mut WebSocketStream<S>,
        client_id: &str,
        lobby_name: &str,
        lobby_password: &str,
        virtual_ip: &str,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let challenge = next_server_challenge(socket).await;
        socket
            .send(register_message_for_challenge(
                client_id,
                lobby_name,
                lobby_password,
                virtual_ip,
                &challenge,
            ))
            .await
            .unwrap();
    }

    async fn register<S>(
        socket: &mut WebSocketStream<S>,
        client_id: &str,
        lobby_name: &str,
    ) -> Value
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        send_register_with_ip(
            socket,
            client_id,
            lobby_name,
            "password",
            &test_virtual_ip(client_id),
        )
        .await;
        let success = next_json(socket).await;
        assert_eq!(success["type"], "register-success");
        assert_eq!(next_json(socket).await["type"], "players-list");
        success
    }

    #[test]
    fn extracts_sender_from_typed_host_command() {
        let raw = r#"{"type":"kick-player","from":"host-id","target":"peer-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw).as_deref(), Some("host-id"));
    }

    #[test]
    fn extracts_sender_from_forwarded_message() {
        let raw = r#"{"type":"remote-control-request","from":"controller-id","to":"phone-id","sessionId":"rc-1","fromName":"Controller"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert!(matches!(
            message,
            SignalingMessage::RemoteControlRequest { .. }
        ));
        assert_eq!(
            message.claimed_sender(raw).as_deref(),
            Some("controller-id")
        );
    }

    #[test]
    fn server_messages_do_not_claim_a_client_identity() {
        let raw = r#"{"type":"kicked","reason":"removed"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw), None);
    }

    #[test]
    fn extracts_sender_from_status_update() {
        let raw = r#"{"type":"status-update","clientId":"player-id","micEnabled":true}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw).as_deref(), Some("player-id"));
    }

    #[test]
    fn extracts_sender_from_explicit_leave() {
        let raw = r#"{"type":"leave","clientId":"player-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw).as_deref(), Some("player-id"));
    }

    #[test]
    fn register_message_does_not_claim_a_sender() {
        let raw = r#"{"type":"register","clientId":"player-id","playerName":"player","lobbyName":"room","lobbyPassword":"password","clientVersion":"2.7.5"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw), None);
    }

    #[test]
    fn registration_proof_is_bound_to_challenge_lobby_and_virtual_ip() {
        let challenge = "ab".repeat(CHALLENGE_BYTES);
        let (key, encoded_key, expected_id) = test_identity_key("proof-owner");
        let signature: p256::ecdsa::Signature =
            key.sign(&registration_canonical(&challenge, "room", "10.126.126.7"));
        let (client_id, stored_key, virtual_domain) = verify_registration_identity(
            &challenge,
            "room",
            "10.126.126.7",
            &encoded_key,
            &BASE64_STANDARD.encode(signature.to_der().as_bytes()),
        )
        .expect("valid P-256 proof should verify");
        assert_eq!(client_id, expected_id);
        assert_eq!(stored_key, encoded_key);
        assert_eq!(virtual_domain, format!("{}.mct.net", &expected_id[..32]));

        let wrong_lobby = verify_registration_identity(
            &challenge,
            "other-room",
            "10.126.126.7",
            &encoded_key,
            &BASE64_STANDARD.encode(signature.to_der().as_bytes()),
        );
        assert!(wrong_lobby.is_none(), "proof must include the lobby name");
        assert!(
            verify_registration_identity(
                &challenge,
                "room",
                "10.126.126.8",
                &encoded_key,
                &BASE64_STANDARD.encode(signature.to_der().as_bytes()),
            )
            .is_none(),
            "proof must include the virtual IP"
        );
    }

    #[test]
    fn message_and_outbound_budgets_are_bounded() {
        let mut inbound = MessageRateLimiter::new();
        for _ in 0..MAX_MESSAGES_PER_WINDOW {
            assert!(inbound.allow());
        }
        assert!(!inbound.allow());

        let mut outbound = OutboundBudget::new();
        for _ in 0..MAX_OUTBOUND_FRAMES_PER_WINDOW {
            assert!(outbound.allow(1));
        }
        assert!(!outbound.allow(1));
        assert!(valid_session_description(
            "offer",
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n",
            "offer"
        ));
        assert!(!valid_session_description("offer", "v=0\u{0000}", "offer"));
    }

    #[test]
    fn peer_metadata_is_canonicalized_on_server_output() {
        let raw = serde_json::json!({
            "type": "offer",
            "from": "attacker",
            "to": "peer",
            "sessionGeneration": 1,
            "offer": {"type": "offer", "sdp": "v=0"}
        })
        .to_string();
        let value: Value =
            serde_json::from_str(&inject_session_metadata(raw, "canonical-peer", 42)).unwrap();
        assert_eq!(value["from"], "canonical-peer");
        assert_eq!(value["sessionGeneration"], 42);
    }

    #[test]
    fn community_submit_quota_has_a_fixed_source_budget() {
        let mut quota = SubmitQuota {
            window_started: tokio::time::Instant::now(),
            submissions: 0,
        };
        for _ in 0..COMMUNITY_NODE_SUBMIT_MAX_PER_WINDOW {
            assert!(allow_submit_quota(&mut quota));
        }
        assert!(!allow_submit_quota(&mut quota));
    }

    #[test]
    fn forwarded_message_without_string_sender_does_not_claim_identity() {
        let raw = r#"{"type":"remote-control-request","from":123,"to":"phone-id"}"#;
        assert!(serde_json::from_str::<SignalingMessage>(raw).is_err());
    }

    #[test]
    fn chat_public_keys_are_shape_checked_before_entering_a_roster() {
        let (_, valid_key, _) = test_identity_key("valid-key");
        assert!(valid_chat_public_key(&valid_key));
        assert!(!valid_chat_public_key(""));
        // Anything outside the base64 alphabet is refused, which keeps quoting
        // and injection tricks out of a field that is later echoed to peers.
        assert!(!valid_chat_public_key("has spaces"));
        assert!(!valid_chat_public_key("bad\ncontrol"));
        assert!(!valid_chat_public_key("<script>"));
        assert!(!valid_chat_public_key(
            &"A".repeat(MAX_CHAT_PUBLIC_KEY_LEN + 1)
        ));

        // Normalization trims but never repairs malformed input.
        assert_eq!(
            normalize_chat_public_key(Some("  AAAA  ".to_string())),
            None
        );
        assert_eq!(normalize_chat_public_key(Some("!!".to_string())), None);
        assert_eq!(normalize_chat_public_key(None), None);
    }

    #[tokio::test]
    async fn chat_public_keys_reach_peers_bound_to_their_owner() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut host,
            "host-id",
            "room",
            "password",
            &test_virtual_ip("host-id"),
        )
        .await;
        let host_success = next_json(&mut host).await;
        assert_eq!(host_success["type"], "register-success");
        assert_eq!(next_json(&mut host).await["type"], "players-list");

        let (mut peer, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut peer,
            "peer-id",
            "room",
            "password",
            &test_virtual_ip("peer-id"),
        )
        .await;
        let peer_success = next_json(&mut peer).await;
        assert_eq!(peer_success["type"], "register-success");

        // The joiner's roster must carry the host's key, bound to the host id.
        let roster = next_json(&mut peer).await;
        assert_eq!(roster["type"], "players-list");
        let players = roster["players"].as_array().unwrap();
        assert_eq!(players.len(), 1);
        let (_, host_key, host_id) = test_identity_key("host-id");
        let (_, peer_key, peer_id) = test_identity_key("peer-id");
        assert_eq!(players[0]["playerId"], host_id);
        assert_eq!(players[0]["chatPublicKey"], host_key);
        assert_eq!(
            players[0]["sessionGeneration"],
            host_success["sessionGeneration"]
        );

        // And the incremental join event must carry the joiner's own key, so a
        // member never has to guess which key belongs to which player.
        let rotated = next_json(&mut host).await;
        assert_eq!(rotated["type"], "chat-token-rotated");
        let joined = next_json(&mut host).await;
        assert_eq!(joined["type"], "player-joined");
        assert_eq!(joined["playerId"], peer_id);
        assert_eq!(joined["chatPublicKey"], peer_key);
        assert_eq!(
            joined["sessionGeneration"],
            peer_success["sessionGeneration"]
        );

        server.abort();
    }

    #[tokio::test]
    async fn membership_changes_rotate_chat_token_without_broadcasting_it_in_roster_events() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        let first = register(&mut host, "host-id", "room").await;
        let first_token = first["chatToken"].as_str().unwrap().to_string();
        assert_eq!(first_token.len(), CHAT_TOKEN_BYTES * 2);
        assert!(first_token.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(first["chatTokenEpoch"], 1);

        let (mut peer, _) = connect_async(&url).await.unwrap();
        let second = register(&mut peer, "peer-id", "room").await;
        let second_token = second["chatToken"].as_str().unwrap().to_string();
        assert_ne!(second_token, first_token);
        assert_eq!(second["chatTokenEpoch"], 2);

        let rotated = next_json(&mut host).await;
        assert_eq!(rotated["type"], "chat-token-rotated");
        assert_eq!(rotated["chatToken"], second_token);
        assert_eq!(rotated["chatTokenEpoch"], 2);
        let joined = next_json(&mut host).await;
        assert_eq!(joined["type"], "player-joined");
        assert!(joined.get("chatToken").is_none());

        peer.close(None).await.unwrap();
        let left = next_json(&mut host).await;
        assert_eq!(left["type"], "player-left");
        assert!(left.get("chatToken").is_none());
        let rotated_after_leave = next_json(&mut host).await;
        assert_eq!(rotated_after_leave["type"], "chat-token-rotated");
        assert_eq!(rotated_after_leave["chatTokenEpoch"], 3);
        assert_ne!(rotated_after_leave["chatToken"], second_token);

        server.abort();
    }

    #[tokio::test]
    async fn registration_rejects_non_routable_and_duplicate_virtual_ips() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");

        for (index, ip) in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "10.126.126.0",
            "10.126.126.255",
            "10.126.125.10",
            "192.168.1.10",
            "8.8.8.8",
            "::1",
            "::",
            "2001:db8::1",
        ]
        .iter()
        .enumerate()
        {
            let (mut socket, _) = connect_async(&url).await.unwrap();
            send_register_with_ip(
                &mut socket,
                &format!("invalid-{index}"),
                "room",
                "password",
                ip,
            )
            .await;
            assert_eq!(next_json(&mut socket).await["type"], "register-error");
            socket.close(None).await.unwrap();
        }

        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-id", "room").await;
        let (mut duplicate_ip, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut duplicate_ip,
            "other-id",
            "room",
            "password",
            &test_virtual_ip("host-id"),
        )
        .await;
        assert_eq!(next_json(&mut duplicate_ip).await["type"], "register-error");

        server.abort();
    }

    #[tokio::test]
    async fn explicit_leave_immediately_removes_member_and_rotates_token() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-id", "room").await;

        let (mut peer, _) = connect_async(&url).await.unwrap();
        register(&mut peer, "peer-id", "room").await;
        let peer_id = test_client_id("peer-id");
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        peer.send(Message::Text(
            serde_json::json!({
                "type": "leave",
                "clientId": peer_id
            })
            .to_string(),
        ))
        .await
        .unwrap();

        assert_eq!(next_json(&mut host).await["type"], "player-left");
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        match timeout(Duration::from_secs(2), peer.next()).await.unwrap() {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
            Some(Ok(message)) => panic!("leaving connection stayed open with {message:?}"),
        }

        server.abort();
    }

    #[tokio::test]
    async fn same_client_id_reconnect_replaces_existing_session() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut first, _) = connect_async(&url).await.unwrap();
        register(&mut first, "same-id", "same-room").await;

        let (mut duplicate, _) = connect_async(&url).await.unwrap();
        send_register_with_ip(
            &mut duplicate,
            "same-id",
            "same-room",
            "password",
            &test_virtual_ip("same-id"),
        )
        .await;
        assert_eq!(next_json(&mut duplicate).await["type"], "register-success");
        assert_eq!(next_json(&mut duplicate).await["type"], "players-list");
        match timeout(Duration::from_secs(2), first.next()).await.unwrap() {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
            Some(Ok(message)) => panic!("stale session stayed open with {message:?}"),
        }

        server.abort();
    }

    #[tokio::test]
    async fn forged_host_command_does_not_remove_authenticated_peer() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-id", "room").await;

        let (mut peer, _) = connect_async(&url).await.unwrap();
        register(&mut peer, "peer-id", "room").await;
        let host_id = test_client_id("host-id");
        let peer_id = test_client_id("peer-id");
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        peer.send(Message::Text(
            serde_json::json!({
                "type": "kick-player",
                "from": host_id,
                "target": peer_id
            })
            .to_string(),
        ))
        .await
        .unwrap();

        peer.send(Message::Text(
            serde_json::json!({
                "type": "offer",
                "from": peer_id,
                "to": host_id,
                "offer": {"type": "offer", "sdp": "test"}
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let offer = next_json(&mut host).await;
        assert_eq!(offer["type"], "offer");
        assert_eq!(offer["from"], test_client_id("peer-id"));

        server.abort();
    }

    #[tokio::test]
    async fn kicked_old_socket_cannot_forward_after_same_id_reconnects() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-id", "room").await;
        let host_id = test_client_id("host-id");
        let peer_id = test_client_id("peer-id");

        let (mut old_peer, _) = connect_async(&url).await.unwrap();
        register(&mut old_peer, "peer-id", "room").await;
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        host.send(Message::Text(
            serde_json::json!({
                "type": "kick-player",
                "from": host_id,
                "target": peer_id
            })
            .to_string(),
        ))
        .await
        .unwrap();
        assert_eq!(next_json(&mut old_peer).await["type"], "kicked");
        assert_eq!(next_json(&mut host).await["type"], "player-left");
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");

        let (mut new_peer, _) = connect_async(&url).await.unwrap();
        register(&mut new_peer, "peer-id", "room").await;
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        let _ = old_peer
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": peer_id,
                    "to": host_id,
                    "offer": {"type": "offer", "sdp": "stale"}
                })
                .to_string(),
            ))
            .await;
        assert!(timeout(Duration::from_millis(250), host.next())
            .await
            .is_err());

        new_peer
            .send(Message::Text(
                serde_json::json!({
                "type": "offer",
                "from": test_client_id("peer-id"),
                "to": test_client_id("host-id"),
                    "offer": {"type": "offer", "sdp": "current"}
                })
                .to_string(),
            ))
            .await
            .unwrap();
        let offer = next_json(&mut host).await;
        assert_eq!(offer["type"], "offer");
        assert_eq!(offer["offer"]["sdp"], "current");

        server.abort();
    }

    // 半开连接（对端未发 FIN）必须被空闲超时回收，否则该 clientId 的会话会永久
    // 留在大厅里；又因为重复 clientId 会被拒绝注册，该玩家将再也无法重连。
    #[tokio::test]
    async fn half_open_session_is_reclaimed_so_same_id_can_reconnect() {
        let (address, server) =
            spawn_test_server_with_idle_timeout(tokio::time::Duration::from_millis(200)).await;
        let url = format!("ws://{address}");

        let (mut ghost, _) = connect_async(&url).await.unwrap();
        register(&mut ghost, "ghost-id", "room").await;

        // 保持 socket 打开但不再发送任何数据，也不发 Close，模拟半开连接。
        let leaked = ghost;

        // 空闲超时到达后，旧会话被回收，同 clientId 可以重新注册成功。
        let mut reconnected = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (mut retry, _) = connect_async(&url).await.unwrap();
            send_register_with_ip(
                &mut retry,
                "ghost-id",
                "room",
                "password",
                &test_virtual_ip("ghost-id"),
            )
            .await;
            if next_json(&mut retry).await["type"] == "register-success" {
                reconnected = true;
                break;
            }
        }
        assert!(
            reconnected,
            "half-open session was never reclaimed, same clientId is permanently locked out"
        );

        drop(leaked);
        server.abort();
    }

    // 正常连接不应被空闲超时误杀：客户端持续发送应用层 ping 即可续期。
    #[tokio::test]
    async fn voice_reconnect_routes_only_between_authenticated_lobby_members() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut sender, _) = connect_async(&url).await.unwrap();
        let registered = register(&mut sender, "voice-sender", "voice-room").await;
        let (mut receiver, _) = connect_async(&url).await.unwrap();
        register(&mut receiver, "voice-receiver", "voice-room").await;
        next_json(&mut sender).await; // Token rotation.
        next_json(&mut sender).await; // Player joined.
        let (mut outsider, _) = connect_async(&url).await.unwrap();
        register(&mut outsider, "voice-outsider", "other-room").await;
        let (_, _, sender_id) = test_identity_key("voice-sender");
        let (_, _, receiver_id) = test_identity_key("voice-receiver");
        let (_, _, outsider_id) = test_identity_key("voice-outsider");

        let request =
            serde_json::json!({"type":"voice-reconnect", "from":sender_id, "to":receiver_id});
        sender
            .send(Message::Text(request.to_string()))
            .await
            .unwrap();
        let forwarded = next_json(&mut receiver).await;
        assert_eq!(forwarded["type"], "voice-reconnect");
        assert_eq!(forwarded["from"], sender_id);
        assert_eq!(forwarded["to"], receiver_id);
        assert_eq!(
            forwarded["sessionGeneration"],
            registered["sessionGeneration"]
        );

        for from in [&outsider_id, &sender_id] {
            // Both an authentic outsider and one claiming the sender's ID fail.
            outsider
                .send(Message::Text(
                    serde_json::json!({
                        "type":"voice-reconnect", "from":from, "to":receiver_id
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            outsider
                .send(Message::Text(r#"{"type":"ping"}"#.into()))
                .await
                .unwrap();
            assert_eq!(next_json(&mut outsider).await["type"], "pong");
            receiver
                .send(Message::Text(r#"{"type":"ping"}"#.into()))
                .await
                .unwrap();
            assert_eq!(next_json(&mut receiver).await["type"], "pong");
        }
        let (mut unregistered, _) = connect_async(&url).await.unwrap();
        next_server_challenge(&mut unregistered).await;
        unregistered
            .send(Message::Text(request.to_string()))
            .await
            .unwrap();
        unregistered
            .send(Message::Text(r#"{"type":"ping"}"#.into()))
            .await
            .unwrap();
        assert_eq!(next_json(&mut unregistered).await["type"], "pong");
        receiver
            .send(Message::Text(r#"{"type":"ping"}"#.into()))
            .await
            .unwrap();
        assert_eq!(next_json(&mut receiver).await["type"], "pong");
        for (from, to) in [
            ("", receiver_id.as_str()),
            (sender_id.as_str(), "bad\ntarget"),
            (sender_id.as_str(), sender_id.as_str()),
        ] {
            let invalid = SignalingMessage::VoiceReconnect {
                from: from.into(),
                to: to.into(),
            };
            assert!(!validate_message_shape(&invalid));
        }
        server.abort();
    }

    #[tokio::test]
    async fn proxy_clients_do_not_share_message_budget() {
        let (address, server) = spawn_test_server().await;
        let mut clients = Vec::new();
        for _ in 0..3 {
            let (mut client, _) = connect_async(format!("ws://{address}")).await.unwrap();
            next_server_challenge(&mut client).await;
            clients.push(client);
        }
        // 135 messages from one TCP source exceed the former shared 120-message
        // budget while every individual connection remains below its limit.
        for _ in 0..45 {
            for client in &mut clients {
                client
                    .send(Message::Text(r#"{"type":"ping"}"#.into()))
                    .await
                    .unwrap();
                assert_eq!(next_json(client).await["type"], "pong");
            }
        }
        for mut client in clients {
            client.close(None).await.unwrap();
        }
        server.abort();
    }

    #[tokio::test]
    async fn active_session_is_not_closed_by_idle_timeout() {
        let (address, server) =
            spawn_test_server_with_idle_timeout(tokio::time::Duration::from_millis(300)).await;
        let url = format!("ws://{address}");

        let (mut client, _) = connect_async(&url).await.unwrap();
        register(&mut client, "active-id", "room").await;

        // 以远小于空闲超时的间隔发送 ping，累计时长超过空闲超时。
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            client
                .send(Message::Text(
                    serde_json::json!({"type":"ping"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(next_json(&mut client).await["type"], "pong");
        }

        server.abort();
    }
    #[tokio::test]
    async fn kick_does_not_remove_mapping_for_target_in_another_lobby() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-a", "room-a").await;
        let host_id = test_client_id("host-a");

        let (mut target, _) = connect_async(&url).await.unwrap();
        register(&mut target, "target-b", "room-b").await;
        let target_id = test_client_id("target-b");
        let (mut peer, _) = connect_async(&url).await.unwrap();
        register(&mut peer, "peer-b", "room-b").await;
        let peer_id = test_client_id("peer-b");
        assert_eq!(next_json(&mut target).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut target).await["type"], "player-joined");

        host.send(Message::Text(
            serde_json::json!({
                "type": "kick-player",
                "from": host_id,
                "target": target_id
            })
            .to_string(),
        ))
        .await
        .unwrap();
        assert!(timeout(Duration::from_millis(250), host.next())
            .await
            .is_err());

        target
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": target_id,
                    "to": peer_id,
                    "offer": {"type": "offer", "sdp": "other-lobby"}
                })
                .to_string(),
            ))
            .await
            .unwrap();
        let offer = next_json(&mut peer).await;
        assert_eq!(offer["type"], "offer");
        assert_eq!(offer["offer"]["sdp"], "other-lobby");

        server.abort();
    }

    // ==================== 用户投稿共享节点 ====================

    fn node_at(address: &str, last_ok_at: u64) -> CommunityNodeInfo {
        CommunityNodeInfo {
            name: "测试节点".to_string(),
            address: address.to_string(),
            submitter: None,
            submitted_at: last_ok_at,
            last_ok_at,
            online: false,
            latency_ms: None,
        }
    }

    #[test]
    fn community_address_normalization_dedupes_equivalent_spellings() {
        let a = normalize_community_node_address("TCP://Example.COM:11010").unwrap();
        let b = normalize_community_node_address("  tcp://example.com:11010 ").unwrap();
        assert_eq!(a, b, "大小写与空白差异必须归一化为同一个 key");
        assert_eq!(a, "tcp://example.com:11010");

        // 缺省端口按协议补齐，确保 tcp://host 与 tcp://host:11010 视为同一节点
        assert_eq!(
            normalize_community_node_address("tcp://example.com").unwrap(),
            "tcp://example.com:11010"
        );
        assert_eq!(
            normalize_community_node_address("wss://example.com").unwrap(),
            "wss://example.com:443"
        );
        assert_eq!(
            normalize_community_node_address("wss://example.com/signaling").unwrap(),
            "wss://example.com:443/signaling"
        );
        assert_eq!(
            normalize_community_node_address("udp://[2001:db8::1]:11010").unwrap(),
            "udp://[2001:db8::1]:11010"
        );
    }

    #[test]
    fn community_address_rejects_unsupported_and_malformed_input() {
        for bad in [
            "",
            "   ",
            "example.com:11010",
            "http://example.com",
            "file:///etc/passwd",
            "tcp://",
            "tcp://例子.com:0",
            "tcp://exa mple.com:11010",
        ] {
            assert!(
                normalize_community_node_address(bad).is_err(),
                "应拒绝非法地址: {:?}",
                bad
            );
        }
        assert!(
            normalize_community_node_address(&format!("tcp://{}.com:11010", "a".repeat(200)))
                .is_err(),
            "超长地址应被拒绝"
        );
    }

    #[test]
    fn community_text_sanitizer_strips_controls_and_truncates() {
        assert_eq!(sanitize_community_text("  节点\u{0007}名  ", 32), "节点名");
        assert_eq!(sanitize_community_text("abcdef", 3), "abc");
        assert_eq!(sanitize_community_text("\n\t ", 32), "");
    }

    #[test]
    fn community_node_expires_only_after_one_full_day_offline() {
        let now = 10 * COMMUNITY_NODE_MAX_OFFLINE_SECS;
        // 恰好 1 天未成功：仍保留（需求是“超过 1 天”才移除）
        let boundary = node_at(
            "tcp://a.example:11010",
            now - COMMUNITY_NODE_MAX_OFFLINE_SECS,
        );
        assert!(!is_community_node_expired(&boundary, now));
        // 超过 1 天：移除
        let expired = node_at(
            "tcp://b.example:11010",
            now - COMMUNITY_NODE_MAX_OFFLINE_SECS - 1,
        );
        assert!(is_community_node_expired(&expired, now));
        // 刚探测成功
        assert!(!is_community_node_expired(
            &node_at("tcp://c.example:11010", now),
            now
        ));
    }

    #[tokio::test]
    async fn sweep_removes_long_dead_nodes_and_refreshes_live_ones() {
        // 本地监听器充当“存活节点”，探测必然成功
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
        let live = format!("tcp://{}:{}", live_addr.ip(), live_addr.port());
        let live_key = normalize_community_node_address(&live).unwrap();

        // 未监听的端口 -> 探测失败；用足够久的 last_ok_at 触发淘汰
        let dead_key = normalize_community_node_address("tcp://127.0.0.1:9").unwrap();
        let now = now_unix_secs();

        let mut map = HashMap::new();
        map.insert(
            live_key.clone(),
            node_at(&live_key, now - 10 * COMMUNITY_NODE_MAX_OFFLINE_SECS),
        );
        map.insert(
            dead_key.clone(),
            node_at(&dead_key, now - COMMUNITY_NODE_MAX_OFFLINE_SECS - 60),
        );
        let nodes: CommunityNodes = Arc::new(RwLock::new(map));

        let (online, removed) = sweep_community_nodes(&nodes).await;
        assert_eq!(online, 1, "只有本地监听器应探测成功");
        assert_eq!(removed, 1, "失效超过 1 天的节点应被移除");

        let read = nodes.read().await;
        assert!(!read.contains_key(&dead_key), "死节点必须被移除");
        let refreshed = read.get(&live_key).expect("存活节点应保留");
        assert!(refreshed.online);
        assert!(refreshed.latency_ms.is_some());
        assert!(
            refreshed.last_ok_at >= now,
            "探测成功必须刷新 last_ok_at，否则存活节点会被误删"
        );
    }

    #[tokio::test]
    async fn sweep_keeps_recently_alive_node_that_is_currently_unreachable() {
        // 刚掉线（未超过 1 天）的节点应保留，只把 online 标记为 false
        let dead_key = normalize_community_node_address("tcp://127.0.0.1:9").unwrap();
        let now = now_unix_secs();
        let mut node = node_at(&dead_key, now - 60);
        node.online = true;
        node.latency_ms = Some(12);
        let mut map = HashMap::new();
        map.insert(dead_key.clone(), node);
        let nodes: CommunityNodes = Arc::new(RwLock::new(map));

        let (online, removed) = sweep_community_nodes(&nodes).await;
        assert_eq!(online, 0);
        assert_eq!(removed, 0, "短暂不可达不应立刻删除");
        let read = nodes.read().await;
        let kept = read.get(&dead_key).expect("节点应保留");
        assert!(!kept.online);
        assert!(kept.latency_ms.is_none());
    }

    #[test]
    fn probe_target_filter_blocks_loopback_private_and_metadata_addresses() {
        let blocked = [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.5.9",
            "192.168.1.1",
            // 云厂商元数据地址：SSRF 的首要目标
            "169.254.169.254",
            // 运营商级 NAT / 协议专用 / 基准测试 / 保留段
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            // 192.0.2.0/24 / 198.51.100.0/24 / 203.0.113.0/24 文档保留段
            "192.0.2.10",
            "198.51.100.10",
            "203.0.113.9",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            // IPv4-mapped 形式不得绕过 IPv4 规则
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ];
        for raw in blocked {
            let ip: std::net::IpAddr = raw.parse().unwrap();
            assert!(!is_public_probe_target(&ip), "{} 必须被拒绝为探测目标", raw);
        }

        let allowed = ["1.1.1.1", "8.8.8.8", "119.29.29.29", "2400:3200::1"];
        for raw in allowed {
            let ip: std::net::IpAddr = raw.parse().unwrap();
            assert!(is_public_probe_target(&ip), "{} 应允许探测", raw);
        }
    }

    #[tokio::test]
    async fn probe_refuses_private_targets_when_private_probing_is_disabled() {
        // 用一个真实在监听的回环端口：只有“地址不允许”这一条规则能拦住它
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let blocked = resolve_probe_targets("127.0.0.1", addr.port(), false).await;
        assert!(blocked.is_empty(), "禁用内网探测时回环地址必须被过滤掉");

        let allowed = resolve_probe_targets("127.0.0.1", addr.port(), true).await;
        assert_eq!(allowed.len(), 1, "显式允许内网时才可探测回环地址");

        // 公网地址即使解析成功也只保留有限个目标，避免被 DNS 放大
        let capped = resolve_probe_targets("localhost", addr.port(), true).await;
        assert!(
            capped.len() <= COMMUNITY_NODE_PROBE_MAX_TARGETS,
            "探测目标数量必须有上限"
        );
    }

    #[tokio::test]
    async fn submit_rejects_unreachable_node_and_accepts_live_one() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
        let live = format!("tcp://{}:{}", live_addr.ip(), live_addr.port());

        let nodes: CommunityNodes = Arc::new(RwLock::new(HashMap::new()));
        let cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));

        // 不可达地址：直接拒绝，不入库
        let peer_a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let resp = handle_community_node_submit(
            &nodes,
            &cooldowns,
            peer_a,
            "死节点".to_string(),
            "tcp://127.0.0.1:9".to_string(),
            None,
        )
        .await;
        match resp {
            SignalingMessage::CommunityNodeSubmitResult { ok, node, .. } => {
                assert!(!ok);
                assert!(node.is_none());
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert!(nodes.read().await.is_empty(), "不可达节点不得入库");

        // 可达地址：入库，并带上首次投稿时间
        let peer_b: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let resp = handle_community_node_submit(
            &nodes,
            &cooldowns,
            peer_b,
            "  活节点\u{0007}  ".to_string(),
            live.to_uppercase(),
            Some("玩家A".to_string()),
        )
        .await;
        match resp {
            SignalingMessage::CommunityNodeSubmitResult { ok, node, .. } => {
                assert!(ok);
                let node = node.expect("成功时应回传节点");
                assert_eq!(node.name, "活节点", "名称需清理控制字符与空白");
                assert_eq!(node.submitter.as_deref(), Some("玩家A"));
                assert!(node.online);
                assert!(node.last_ok_at > 0);
            }
            other => panic!("unexpected response: {:?}", other),
        }
        assert_eq!(nodes.read().await.len(), 1);
    }

    #[tokio::test]
    async fn submit_is_rate_limited_per_source_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();
        let live = format!("tcp://{}:{}", live_addr.ip(), live_addr.port());

        let nodes: CommunityNodes = Arc::new(RwLock::new(HashMap::new()));
        let cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));
        let peer: SocketAddr = "10.0.0.3:5000".parse().unwrap();

        let first = handle_community_node_submit(
            &nodes,
            &cooldowns,
            peer,
            "节点1".to_string(),
            live.clone(),
            None,
        )
        .await;
        assert!(matches!(
            first,
            SignalingMessage::CommunityNodeSubmitResult { ok: true, .. }
        ));

        // 同一 IP 立刻再投稿：应被冷却拒绝
        let second = handle_community_node_submit(
            &nodes,
            &cooldowns,
            peer,
            "节点2".to_string(),
            live.clone(),
            None,
        )
        .await;
        assert!(matches!(
            second,
            SignalingMessage::CommunityNodeSubmitResult { ok: false, .. }
        ));

        // 换一个 IP 提交同一地址：视为刷新而非新增
        let other_peer: SocketAddr = "10.0.0.4:5000".parse().unwrap();
        let third = handle_community_node_submit(
            &nodes,
            &cooldowns,
            other_peer,
            "节点1改名".to_string(),
            live,
            None,
        )
        .await;
        assert!(matches!(
            third,
            SignalingMessage::CommunityNodeSubmitResult { ok: true, .. }
        ));
        assert_eq!(nodes.read().await.len(), 1, "同一地址不得重复入库");
        assert_eq!(
            nodes.read().await.values().next().unwrap().name,
            "节点1改名"
        );
    }

    #[test]
    fn loading_from_disk_drops_expired_and_invalid_entries() {
        let now = 10 * COMMUNITY_NODE_MAX_OFFLINE_SECS;
        let dir = std::env::temp_dir().join(format!("mctier-nodes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("community_nodes.json");

        let payload = serde_json::json!([
            { "name": "存活", "address": "tcp://keep.example:11010", "lastOkAt": now - 60 },
            { "name": "过期", "address": "tcp://drop.example:11010",
              "lastOkAt": now - COMMUNITY_NODE_MAX_OFFLINE_SECS - 1 },
            { "name": "非法", "address": "not-a-node", "lastOkAt": now }
        ]);
        std::fs::write(&path, payload.to_string()).unwrap();

        let loaded = load_community_nodes_from_disk(path.to_str().unwrap(), now);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("tcp://keep.example:11010"));

        // 文件缺失 / 内容损坏时都应回退为空表而不是 panic
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_community_nodes_from_disk(path.to_str().unwrap(), now).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            load_community_nodes_from_disk(dir.join("missing.json").to_str().unwrap(), now)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn community_node_list_sorts_online_first_then_by_latency() {
        let now = now_unix_secs();
        let mut map = HashMap::new();
        let mut offline = node_at("tcp://offline.example:11010", now);
        offline.name = "离线".to_string();
        let mut slow = node_at("tcp://slow.example:11010", now);
        slow.name = "慢".to_string();
        slow.online = true;
        slow.latency_ms = Some(300);
        let mut fast = node_at("tcp://fast.example:11010", now);
        fast.name = "快".to_string();
        fast.online = true;
        fast.latency_ms = Some(20);
        map.insert(offline.address.clone(), offline);
        map.insert(slow.address.clone(), slow);
        map.insert(fast.address.clone(), fast);

        let list = community_node_list(&Arc::new(RwLock::new(map))).await;
        let names: Vec<&str> = list.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["快", "慢", "离线"]);
    }

    #[tokio::test]
    async fn unregistered_client_can_query_and_submit_community_nodes() {
        // 与公开广场一致：这两条消息在注册之前也必须被服务
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let nodes: CommunityNodes = Arc::new(RwLock::new(HashMap::new()));
        let cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));
        let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
        let client_lobby_map: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let _ = handle_connection_with_timeouts(
                stream,
                peer,
                lobbies,
                client_lobby_map,
                nodes,
                cooldowns,
                tokio::time::Duration::from_secs(5),
                tokio::time::Duration::from_secs(5),
                tokio::time::Duration::from_secs(30),
            )
            .await;
        });

        let (mut client, _) = connect_async(format!("ws://{}", address)).await.unwrap();
        client
            .send(Message::Text(
                serde_json::json!({ "type": "community-node-list-request" }).to_string(),
            ))
            .await
            .unwrap();
        let list = next_json(&mut client).await;
        assert_eq!(list["type"], "community-node-list-response");
        assert_eq!(list["nodes"].as_array().unwrap().len(), 0);

        // 未注册连接投稿一个不可达地址：应收到失败结果而不是被直接断开。
        // 这里不能用 next_json（2 秒上界）：服务器要先真实探测该地址，
        // Windows 上对被拒绝端口的 connect 会重试到 2 秒以上，
        // 因此按探测超时给足等待时间。
        client
            .send(Message::Text(
                serde_json::json!({
                    "type": "community-node-submit",
                    "name": "死节点",
                    "address": "tcp://127.0.0.1:9"
                })
                .to_string(),
            ))
            .await
            .unwrap();
        let frame = timeout(
            Duration::from_secs(COMMUNITY_NODE_PROBE_TIMEOUT_SECS + 5),
            client.next(),
        )
        .await
        .expect("投稿结果应在探测超时内返回")
        .expect("连接不应被关闭")
        .expect("不应收到 WebSocket 错误");
        let result: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
        assert_eq!(result["type"], "community-node-submit-result");
        assert_eq!(result["ok"], false);
        assert!(
            result["message"].as_str().unwrap().contains("不可达"),
            "应说明原因: {}",
            result["message"]
        );

        server.abort();
    }

    #[tokio::test]
    async fn wrong_password_is_rejected_and_does_not_create_ghost_lobby() {
        let (address, server) = spawn_test_server().await;
        let (mut host, _) = connect_async(format!("ws://{}", address)).await.unwrap();
        let (mut peer, _) = connect_async(format!("ws://{}", address)).await.unwrap();

        // 房主创建房间（默认密码为 "password"）
        let host_success = register(&mut host, "host_user", "private_room").await;
        assert_eq!(host_success["type"], "register-success");

        // 第二个玩家输入错误密码尝试加入同名大厅
        send_register_with_ip(
            &mut peer,
            "peer_user",
            "private_room",
            "wrong_pass",
            "10.126.126.12",
        )
        .await;
        let peer_err = next_json(&mut peer).await;
        assert_eq!(peer_err["type"], "register-error");
        assert_eq!(peer_err["message"], "密码错误");
        assert!(peer_err.get("chatToken").is_none());

        let (mut member, _) = connect_async(format!("ws://{}", address)).await.unwrap();
        send_register_with_ip(
            &mut member,
            "correct_peer",
            "private_room",
            "password",
            "10.126.126.13",
        )
        .await;
        let member_success = next_json(&mut member).await;
        assert_eq!(member_success["type"], "register-success");
        assert_eq!(member_success["lobbyId"], host_success["lobbyId"]);

        host.close(None).await.unwrap();
        peer.close(None).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn separator_in_lobby_credentials_cannot_merge_distinct_rooms() {
        let (address, server) = spawn_test_server().await;
        let (mut host, _) = connect_async(format!("ws://{address}")).await.unwrap();
        send_register_with_ip(
            &mut host,
            "separator-host",
            "alpha:beta",
            "gamma",
            "10.126.126.1",
        )
        .await;
        let first = next_json(&mut host).await;
        assert_eq!(first["type"], "register-success");
        let (mut other, _) = connect_async(format!("ws://{address}")).await.unwrap();
        send_register_with_ip(
            &mut other,
            "separator-other",
            "alpha",
            "beta:gamma",
            "10.126.126.2",
        )
        .await;
        let second = next_json(&mut other).await;
        assert_eq!(second["type"], "register-success");
        assert_ne!(
            first["lobbyId"], second["lobbyId"],
            "distinct lobby names must not share a room"
        );
        assert_ne!(first["hostId"], second["hostId"]);
        assert_ne!(first["chatToken"], second["chatToken"]);
        let roster = next_json(&mut other).await;
        assert_eq!(roster["type"], "players-list");
        assert!(!roster
            .to_string()
            .contains(&test_client_id("separator-host")));
        server.abort();
    }
}
