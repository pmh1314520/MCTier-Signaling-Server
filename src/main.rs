use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::{RwLock, Semaphore};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{accept_async_with_config, tungstenite::Message};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio::net::{TcpListener, TcpStream};
use futures_util::{future::join_all, StreamExt, SinkExt};
use sha2::{Sha256, Digest};

/// 默认要求的最低客户端版本（可通过环境变量 MINIMUM_CLIENT_VERSION 覆盖）
const DEFAULT_MINIMUM_CLIENT_VERSION: &str = "2.1.0";

/// 默认监听地址（可通过环境变量 BIND_ADDRESS 覆盖）
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8445";

/// 握手阶段允许客户端占用连接的最长时间
const WEBSOCKET_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// 首次注册消息的绝对截止时间
const REGISTRATION_TIMEOUT_SECS: u64 = 15;

/// 单次发送允许等待的最长时间
const SEND_TIMEOUT_SECS: u64 = 5;

/// 单条 WebSocket 消息的最大大小
const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

/// 单个 WebSocket 帧的最大大小
const MAX_FRAME_SIZE: usize = 512 * 1024;

/// 默认最大并发连接数（可通过环境变量 MAX_CONNECTIONS 覆盖）
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// 版本过低时提示客户端的下载地址（可通过环境变量 CLIENT_DOWNLOAD_URL 覆盖）
const DEFAULT_CLIENT_DOWNLOAD_URL: &str = "https://github.com/pmh1314520/MCTier/releases";

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

/// WebSocket 信令消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SignalingMessage {
    /// 注册客户端
    Register {
        #[serde(rename = "clientId")]
        client_id: String,
        #[serde(rename = "playerName")]
        player_name: String,
        #[serde(rename = "virtualIp", skip_serializing_if = "Option::is_none")]
        virtual_ip: Option<String>,
        #[serde(rename = "virtualDomain", skip_serializing_if = "Option::is_none")]
        virtual_domain: Option<String>,
        #[serde(rename = "useDomain", skip_serializing_if = "Option::is_none")]
        use_domain: Option<bool>,
        #[serde(rename = "lobbyName")]
        lobby_name: String,
        #[serde(rename = "lobbyPassword")]
        lobby_password: String,
        #[serde(rename = "clientVersion", skip_serializing_if = "Option::is_none")]
        client_version: Option<String>,
    },
    /// 注册成功
    RegisterSuccess {
        #[serde(rename = "lobbyId")]
        lobby_id: String,
        #[serde(rename = "hostId", skip_serializing_if = "Option::is_none")]
        host_id: Option<String>,
        #[serde(rename = "maxPlayers", skip_serializing_if = "Option::is_none")]
        max_players: Option<u32>,
        #[serde(rename = "isPublic", skip_serializing_if = "Option::is_none")]
        is_public: Option<bool>,
        #[serde(rename = "mutedPlayers", skip_serializing_if = "Option::is_none")]
        muted_players: Option<Vec<String>>,
    },
    /// 注册失败
    RegisterError {
        message: String,
    },
    /// 版本过低错误
    VersionTooOld {
        message: String,
        #[serde(rename = "currentVersion")]
        current_version: String,
        #[serde(rename = "minimumVersion")]
        minimum_version: String,
        #[serde(rename = "downloadUrl")]
        download_url: String,
    },
    /// 玩家列表
    PlayersList {
        players: Vec<PlayerInfo>,
    },
    /// 玩家加入
    PlayerJoined {
        #[serde(rename = "playerId")]
        player_id: String,
        #[serde(rename = "playerName")]
        player_name: String,
        #[serde(rename = "virtualIp", skip_serializing_if = "Option::is_none")]
        virtual_ip: Option<String>,
        #[serde(rename = "virtualDomain", skip_serializing_if = "Option::is_none")]
        virtual_domain: Option<String>,
        #[serde(rename = "useDomain", skip_serializing_if = "Option::is_none")]
        use_domain: Option<bool>,
    },
    /// 玩家离开
    PlayerLeft {
        #[serde(rename = "playerId")]
        player_id: String,
    },
    /// WebRTC Offer
    Offer {
        from: String,
        to: String,
        offer: OfferData,
        #[serde(rename = "playerName", skip_serializing_if = "Option::is_none")]
        player_name: Option<String>,
    },
    /// WebRTC Answer
    Answer {
        from: String,
        to: String,
        answer: AnswerData,
    },
    /// ICE Candidate
    IceCandidate {
        from: String,
        to: String,
        candidate: CandidateData,
    },
    /// 聊天消息（已废弃 - 现在使用P2P传输）
    #[serde(rename = "chat-message")]
    ChatMessage {
        from: String,
        #[serde(rename = "playerId")]
        player_id: String,
        #[serde(rename = "playerName")]
        player_name: String,
        content: String,
        timestamp: i64,
    },
    /// 状态更新
    StatusUpdate {
        #[serde(rename = "clientId")]
        client_id: String,
        #[serde(rename = "micEnabled")]
        mic_enabled: bool,
    },
    /// 屏幕共享开始
    #[serde(rename = "screen-share-start")]
    ScreenShareStart {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "playerName")]
        player_name: String,
        #[serde(rename = "hasPassword")]
        has_password: bool,
    },
    /// 屏幕共享停止
    #[serde(rename = "screen-share-stop")]
    ScreenShareStop {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
    },
    /// 屏幕共享链式中继控制消息（仅在同大厅内定向转发）
    #[serde(rename = "screen-share-relay")]
    ScreenShareRelay {
        from: String,
        to: String,
        #[serde(rename = "shareId")]
        share_id: String,
        action: String,
        #[serde(rename = "playerName", skip_serializing_if = "Option::is_none")]
        player_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(rename = "upstreamId", skip_serializing_if = "Option::is_none")]
        upstream_id: Option<String>,
        #[serde(rename = "downstreamId", skip_serializing_if = "Option::is_none")]
        downstream_id: Option<String>,
        #[serde(rename = "routeVersion", skip_serializing_if = "Option::is_none")]
        route_version: Option<u64>,
    },
    /// 屏幕共享 Offer
    #[serde(rename = "screen-share-offer")]
    ScreenShareOffer {
        from: String,
        to: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "playerName", skip_serializing_if = "Option::is_none")]
        player_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(rename = "routeVersion", skip_serializing_if = "Option::is_none")]
        route_version: Option<u64>,
        offer: OfferData,
    },
    /// 屏幕共享 Answer
    #[serde(rename = "screen-share-answer")]
    ScreenShareAnswer {
        from: String,
        to: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "routeVersion", skip_serializing_if = "Option::is_none")]
        route_version: Option<u64>,
        answer: AnswerData,
    },
    /// 屏幕共享 ICE Candidate
    #[serde(rename = "screen-share-ice-candidate")]
    ScreenShareIceCandidate {
        from: String,
        to: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "connectionRole", skip_serializing_if = "Option::is_none")]
        connection_role: Option<String>,
        #[serde(rename = "routeVersion", skip_serializing_if = "Option::is_none")]
        route_version: Option<u64>,
        candidate: CandidateData,
    },
    /// 屏幕共享错误
    #[serde(rename = "screen-share-error")]
    ScreenShareError {
        from: String,
        to: String,
        #[serde(rename = "shareId")]
        share_id: String,
        error: String,
    },
    /// 屏幕共享列表请求
    #[serde(rename = "screen-share-list-request")]
    ScreenShareListRequest {
        from: String,
    },
    /// 屏幕共享列表响应
    #[serde(rename = "screen-share-list-response")]
    ScreenShareListResponse {
        from: String,
        to: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "playerName")]
        player_name: String,
        #[serde(rename = "hasPassword")]
        has_password: bool,
    },
    /// 屏幕共享查看者离开
    #[serde(rename = "screen-share-viewer-left")]
    ScreenShareViewerLeft {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
    },
    /// 屏幕共享状态更新
    #[serde(rename = "screen-share-update")]
    ScreenShareUpdate {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "viewerId", skip_serializing_if = "Option::is_none")]
        viewer_id: Option<String>,
        #[serde(rename = "viewerName", skip_serializing_if = "Option::is_none")]
        viewer_name: Option<String>,
        #[serde(rename = "viewerCount", skip_serializing_if = "Option::is_none")]
        viewer_count: Option<usize>,
    },
    /// 文件共享添加
    #[serde(rename = "file-share-added")]
    FileShareAdded {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "shareName")]
        share_name: String,
        #[serde(rename = "playerName")]
        player_name: String,
        #[serde(rename = "hasPassword")]
        has_password: bool,
    },
    /// 文件共享删除
    #[serde(rename = "file-share-removed")]
    FileShareRemoved {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
    },
    /// 文件共享列表请求
    #[serde(rename = "file-share-list-request")]
    FileShareListRequest {
        from: String,
    },
    /// 文件共享列表响应
    #[serde(rename = "file-share-list-response")]
    FileShareListResponse {
        from: String,
        to: String,
        shares: Vec<FileShareInfo>,
    },
    /// 心跳检测 ping（客户端 -> 服务器）
    Ping,
    /// 心跳检测 pong（服务器 -> 客户端）
    Pong,

    // ==================== 房主管理 ====================
    /// 踢出玩家（仅房主，客户端 -> 服务器）
    #[serde(rename = "kick-player")]
    KickPlayer {
        from: String,
        target: String,
    },
    /// 被踢出通知（服务器 -> 目标客户端）
    #[serde(rename = "kicked")]
    Kicked {
        reason: String,
    },
    /// 禁言/解除禁言玩家（仅房主，客户端 -> 服务器）
    #[serde(rename = "mute-player")]
    MutePlayer {
        from: String,
        target: String,
        muted: bool,
    },
    /// 玩家禁言状态变化（服务器 -> 大厅内所有客户端）
    #[serde(rename = "player-mute-changed")]
    PlayerMuteChanged {
        #[serde(rename = "playerId")]
        player_id: String,
        muted: bool,
    },
    /// 转让房主（仅房主，客户端 -> 服务器）
    #[serde(rename = "transfer-host")]
    TransferHost {
        from: String,
        target: String,
    },
    /// 房主变更通知（服务器 -> 大厅内所有客户端）
    #[serde(rename = "host-changed")]
    HostChanged {
        #[serde(rename = "hostId")]
        host_id: String,
    },
    /// 设置大厅选项（仅房主，客户端 -> 服务器）
    #[serde(rename = "set-lobby-options")]
    SetLobbyOptions {
        from: String,
        #[serde(rename = "maxPlayers", skip_serializing_if = "Option::is_none")]
        max_players: Option<u32>,
        #[serde(rename = "isPublic", skip_serializing_if = "Option::is_none")]
        is_public: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// 公开大厅需附带明文密码，供广场内陌生人加入
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// 房主创建大厅时使用的 EasyTier 节点地址，供广场加入者自动同步（避免节点不一致无法互通）
        #[serde(rename = "serverNode", skip_serializing_if = "Option::is_none")]
        server_node: Option<String>,
    },
    /// 大厅选项变化通知（服务器 -> 大厅内所有客户端）
    #[serde(rename = "lobby-options-changed")]
    LobbyOptionsChanged {
        #[serde(rename = "maxPlayers", skip_serializing_if = "Option::is_none")]
        max_players: Option<u32>,
        #[serde(rename = "isPublic")]
        is_public: bool,
    },
    /// 公开大厅广场列表请求（无需注册，客户端 -> 服务器）
    #[serde(rename = "public-lobby-list-request")]
    PublicLobbyListRequest,
    /// 公开大厅广场列表响应（服务器 -> 客户端）
    #[serde(rename = "public-lobby-list-response")]
    PublicLobbyListResponse {
        lobbies: Vec<PublicLobbyInfo>,
    },

    /// 通用转发消息（用于文件共享等功能）
    #[serde(other)]
    Forward,
}

impl SignalingMessage {
    /// Return the identity claimed by a client-originated message.
    ///
    /// The WebSocket connection is the authentication boundary. Callers must
    /// compare this value with the id registered on that same connection before
    /// routing or authorizing the message.
    fn claimed_sender(&self, raw: &str) -> Option<String> {
        match self {
            Self::Offer { from, .. }
            | Self::Answer { from, .. }
            | Self::IceCandidate { from, .. }
            | Self::ChatMessage { from, .. }
            | Self::ScreenShareStart { from, .. }
            | Self::ScreenShareStop { from, .. }
            | Self::ScreenShareRelay { from, .. }
            | Self::ScreenShareOffer { from, .. }
            | Self::ScreenShareAnswer { from, .. }
            | Self::ScreenShareIceCandidate { from, .. }
            | Self::ScreenShareError { from, .. }
            | Self::ScreenShareListRequest { from }
            | Self::ScreenShareListResponse { from, .. }
            | Self::ScreenShareViewerLeft { from, .. }
            | Self::ScreenShareUpdate { from, .. }
            | Self::FileShareAdded { from, .. }
            | Self::FileShareRemoved { from, .. }
            | Self::FileShareListRequest { from }
            | Self::FileShareListResponse { from, .. }
            | Self::KickPlayer { from, .. }
            | Self::MutePlayer { from, .. }
            | Self::TransferHost { from, .. }
            | Self::SetLobbyOptions { from, .. } => Some(from.clone()),
            Self::StatusUpdate { client_id, .. } => Some(client_id.clone()),
            Self::Forward => serde_json::from_str::<serde_json::Value>(raw)
                .ok()?
                .get("from")?
                .as_str()
                .map(str::to_owned),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileShareInfo {
    #[serde(rename = "shareId")]
    pub share_id: String,
    #[serde(rename = "shareName")]
    pub share_name: String,
    #[serde(rename = "playerName")]
    pub player_name: String,
    #[serde(rename = "hasPassword")]
    pub has_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicLobbyInfo {
    #[serde(rename = "lobbyName")]
    pub lobby_name: String,
    #[serde(rename = "playerCount")]
    pub player_count: u32,
    #[serde(rename = "maxPlayers", skip_serializing_if = "Option::is_none")]
    pub max_players: Option<u32>,
    #[serde(rename = "hostName")]
    pub host_name: String,
    pub description: String,
    /// 明文密码，供广场内一键加入（公开大厅）
    pub password: String,
    /// 房主使用的 EasyTier 节点地址，加入者据此自动同步节点（空串=未知，回退加入者默认节点）
    #[serde(rename = "serverNode", default)]
    pub server_node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerInfo {
    #[serde(rename = "playerId")]
    pub player_id: String,
    #[serde(rename = "playerName")]
    pub player_name: String,
    #[serde(rename = "virtualIp", skip_serializing_if = "Option::is_none")]
    pub virtual_ip: Option<String>,
    #[serde(rename = "virtualDomain", skip_serializing_if = "Option::is_none")]
    pub virtual_domain: Option<String>,
    #[serde(rename = "useDomain", skip_serializing_if = "Option::is_none")]
    pub use_domain: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferData {
    #[serde(rename = "type")]
    pub sdp_type: String,
    pub sdp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerData {
    #[serde(rename = "type")]
    pub sdp_type: String,
    pub sdp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateData {
    pub candidate: String,
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_m_line_index: Option<u16>,
    #[serde(rename = "sdpMid")]
    pub sdp_mid: Option<String>,
}

/// 客户端信息
#[derive(Debug, Clone)]
struct ClientInfo {
    player_id: String,
    player_name: String,
    virtual_ip: Option<String>,
    virtual_domain: Option<String>,
    use_domain: Option<bool>,
    sender: ClientSender,
}

/// 大厅信息
#[derive(Debug, Clone)]
struct LobbyInfo {
    lobby_name: String,
    password_hash: String,
    clients: HashMap<String, ClientInfo>,
    /// 房主客户端ID
    host_id: String,
    /// 人数上限（None = 不限）
    max_players: Option<u32>,
    /// 是否发布到公开广场
    is_public: bool,
    /// 广场描述
    description: String,
    /// 公开广场加入用的明文密码
    public_password: String,
    /// 房主使用的 EasyTier 节点地址（公开大厅时下发给加入者，保证节点一致可互通）
    server_node: String,
    /// 被禁言的客户端ID集合
    muted: std::collections::HashSet<String>,
}

/// 全局大厅列表
type Lobbies = Arc<RwLock<HashMap<String, LobbyInfo>>>;

/// 客户端ID到大厅ID的映射
type ClientLobbyMap = Arc<RwLock<HashMap<String, String>>>;

type ClientSender = Arc<RwLock<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>>>;

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_SIZE),
        max_frame_size: Some(MAX_FRAME_SIZE),
        ..WebSocketConfig::default()
    }
}

fn connection_limit_from_env(value: Option<&str>) -> usize {
    value
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_MAX_CONNECTIONS)
}

fn max_connections() -> usize {
    connection_limit_from_env(std::env::var("MAX_CONNECTIONS").ok().as_deref())
}

async fn send_with_timeout<F, E>(send: F) -> bool
where
    F: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(SEND_TIMEOUT_SECS),
        send,
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            log::debug!("发送 WebSocket 消息失败: {}", error);
            false
        }
        Err(_) => {
            log::warn!("发送 WebSocket 消息超时（{} 秒）", SEND_TIMEOUT_SECS);
            false
        }
    }
}

async fn send_message(sender: &ClientSender, message: Message) -> bool {
    send_with_timeout(async {
        let mut sender = sender.write().await;
        sender.send(message).await
    })
    .await
}

async fn send_text(sender: &ClientSender, text: String) -> bool {
    send_message(sender, Message::Text(text)).await
}

async fn send_to_lobby_client(
    lobbies: &Lobbies,
    lobby_id: &str,
    client_id: &str,
    message: Message,
) -> bool {
    let sender = {
        let lobbies_read = lobbies.read().await;
        lobbies_read
            .get(lobby_id)
            .and_then(|lobby| lobby.clients.get(client_id))
            .map(|client| Arc::clone(&client.sender))
    };

    match sender {
        Some(sender) => send_message(&sender, message).await,
        None => false,
    }
}

async fn is_current_session(
    lobbies: &Lobbies,
    lobby_id: &str,
    client_id: &str,
    sender: &ClientSender,
) -> bool {
    let lobbies_read = lobbies.read().await;
    lobbies_read
        .get(lobby_id)
        .and_then(|lobby| lobby.clients.get(client_id))
        .map(|client| Arc::ptr_eq(&client.sender, sender))
        .unwrap_or(false)
}

/// 生成大厅ID（基于大厅名称和密码的哈希）
fn generate_lobby_id(lobby_name: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(lobby_name.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// 比较版本号
/// 返回 true 如果 version >= minimum_version
fn is_version_valid(version: &str, minimum_version: &str) -> bool {
    let parse_version = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|s| s.parse::<u32>().ok())
            .collect()
    };
    
    let ver = parse_version(version);
    let min_ver = parse_version(minimum_version);
    
    // 比较版本号
    for i in 0..std::cmp::max(ver.len(), min_ver.len()) {
        let v = ver.get(i).copied().unwrap_or(0);
        let m = min_ver.get(i).copied().unwrap_or(0);
        
        if v > m {
            return true;
        } else if v < m {
            return false;
        }
    }
    
    true // 版本相同
}

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::init();
    
    // 监听地址：默认 0.0.0.0:8445，可用环境变量 BIND_ADDRESS 覆盖
    let listen_addr = env_or("BIND_ADDRESS", DEFAULT_BIND_ADDRESS);
    
    log::info!("MCTier WebSocket 信令服务器");
    log::info!("版本: {} (大厅隔离 - 仅 WebSocket)", env!("CARGO_PKG_VERSION"));
    log::info!("监听地址: {} (WebSocket Only)", listen_addr);
    log::info!("最低客户端版本: {}", minimum_client_version());
    let max_connections = max_connections();
    log::info!("最大并发连接数: {}", max_connections);
    let connection_semaphore = Arc::new(Semaphore::new(max_connections));
    
    // 创建大厅列表和客户端映射
    let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
    let client_lobby_map: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));
    
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

                let connection_permit = match Arc::clone(&connection_semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!("连接数已达上限（{}），拒绝客户端: {}", max_connections, addr);
                        continue;
                    }
                };
                
                let lobbies_clone = Arc::clone(&lobbies);
                let client_lobby_map_clone = Arc::clone(&client_lobby_map);
                
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    if let Err(e) = handle_connection(stream, addr, lobbies_clone, client_lobby_map_clone).await {
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

/// 处理客户端连接
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    lobbies: Lobbies,
    client_lobby_map: ClientLobbyMap,
) -> Result<(), Box<dyn std::error::Error>> {
    handle_connection_with_timeouts(
        stream,
        addr,
        lobbies,
        client_lobby_map,
        tokio::time::Duration::from_secs(WEBSOCKET_HANDSHAKE_TIMEOUT_SECS),
        tokio::time::Duration::from_secs(REGISTRATION_TIMEOUT_SECS),
    )
    .await
}

async fn handle_connection_with_timeouts(
    stream: TcpStream,
    addr: SocketAddr,
    lobbies: Lobbies,
    client_lobby_map: ClientLobbyMap,
    handshake_timeout: tokio::time::Duration,
    registration_timeout: tokio::time::Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // 升级到 WebSocket
    let ws_stream = match tokio::time::timeout(
        handshake_timeout,
        accept_async_with_config(stream, Some(websocket_config())),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            log::warn!("WebSocket 握手超时（{} 毫秒）: {}", handshake_timeout.as_millis(), addr);
            return Ok(());
        }
    };
    
    log::info!("✅ WebSocket 连接已建立: {}", addr);
    
    let (write, mut read) = ws_stream.split();
    let write = Arc::new(RwLock::new(write));
    
    let mut client_id: Option<String> = None;
    let mut lobby_id: Option<String> = None;
    
    // 标记是否已注册
    let mut is_registered = false;
    let registration_deadline = tokio::time::Instant::now()
        + registration_timeout;
    
    // 处理消息
    loop {
        let msg_result = if is_registered {
            match read.next().await {
                Some(msg_result) => msg_result,
                None => break,
            }
        } else {
            match tokio::time::timeout_at(registration_deadline, read.next()).await {
                Ok(Some(msg_result)) => msg_result,
                Ok(None) => break,
                Err(_) => {
                    log::warn!("客户端首次注册超时（{} 毫秒）: {}", registration_timeout.as_millis(), addr);
                    break;
                }
            }
        };

        match msg_result {
            Ok(msg) => {
                if is_registered {
                    let current = match (client_id.as_deref(), lobby_id.as_deref()) {
                        (Some(client_id), Some(lobby_id)) => {
                            is_current_session(&lobbies, lobby_id, client_id, &write).await
                        }
                        _ => false,
                    };
                    if !current {
                        log::warn!("拒绝已失效 WebSocket 会话的消息: peer={}", addr);
                        let _ = send_message(&write, Message::Close(None)).await;
                        break;
                    }
                }

                if msg.is_text() {
                    let text = msg.to_text()?;
                    
                    match serde_json::from_str::<SignalingMessage>(text) {
                        Ok(message) => {
                            if let Some(claimed_sender) = message.claimed_sender(text) {
                                if client_id.as_deref() != Some(claimed_sender.as_str()) {
                                    log::warn!(
                                        "拒绝发送者身份不匹配的消息: registered={:?}, claimed={}, peer={}",
                                        client_id,
                                        claimed_sender,
                                        addr
                                    );
                                    continue;
                                }
                            }

                            match message {
                                SignalingMessage::Register { client_id: cid, player_name, virtual_ip, virtual_domain, use_domain, lobby_name, lobby_password, client_version } => {
                                    if is_registered {
                                        log::warn!("拒绝同一连接重复注册: peer={}, registered={:?}", addr, client_id);
                                        break;
                                    }

                                    log::info!("客户端注册: {} ({}) - 大厅: {} - 版本: {:?} - 虚拟IP: {:?} - 虚拟域名: {:?} - 使用域名: {:?}", 
                                        player_name, cid, lobby_name, client_version, virtual_ip, virtual_domain, use_domain);
                                    
                                    // 检查客户端版本
                                    let version_str = client_version.as_deref().unwrap_or("unknown");
                                    if version_str == "unknown" || !is_version_valid(version_str, minimum_client_version()) {
                                        log::warn!("❌ 版本过低或未提供版本: {} (版本: {}) 尝试加入大厅 {}", player_name, version_str, lobby_name);
                                        let error_msg = SignalingMessage::VersionTooOld {
                                            message: format!("您的客户端版本过低（当前版本: {}），请更新到最新版本（最低要求: {}）", version_str, minimum_client_version()),
                                            current_version: version_str.to_string(),
                                            minimum_version: minimum_client_version().to_string(),
                                            download_url: client_download_url().to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        // 等待一小段时间确保消息发送，然后强制关闭连接
                                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                        log::warn!("🚫 强制断开版本过低的客户端连接: {} ({})", addr, version_str);
                                        break;
                                    }
                                    
                                    if cid.trim().is_empty() {
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: "clientId 不能为空".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        continue;
                                    }

                                    log::info!("✅ 版本检查通过: {} (版本: {})", player_name, version_str);
                                    
                                    // 生成大厅ID
                                    let lid = generate_lobby_id(&lobby_name, &lobby_password);
                                    
                                    // 生成密码哈希
                                    let mut hasher = Sha256::new();
                                    hasher.update(lobby_password.as_bytes());
                                    let password_hash = format!("{:x}", hasher.finalize());
                                    
                                    // 保存客户端信息
                                    let client_info = ClientInfo {
                                        player_id: cid.clone(),
                                        player_name: player_name.clone(),
                                        virtual_ip: virtual_ip.clone(),
                                        virtual_domain: virtual_domain.clone(),
                                        use_domain,
                                        sender: Arc::clone(&write),
                                    };
                                    
                                    // 获取或创建大厅
                                    let mut lobbies_write = lobbies.write().await;
                                    if lobbies_write
                                        .values()
                                        .any(|existing_lobby| existing_lobby.clients.contains_key(&cid))
                                    {
                                        log::warn!("拒绝重复 clientId 注册: {} ({})", player_name, cid);
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: "客户端身份已在使用中，请重新连接".to_string(),
                                        };
                                        drop(lobbies_write);
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        // Close the duplicate session so reconnecting clients can
                                        // retry after the previous connection finishes cleanup.
                                        break;
                                    }
                                    let lobby = lobbies_write.entry(lid.clone()).or_insert_with(|| {
                                        log::info!("🏠 创建新大厅: {} (ID: {})，房主: {}", lobby_name, lid, cid);
                                        LobbyInfo {
                                            lobby_name: lobby_name.clone(),
                                            password_hash: password_hash.clone(),
                                            clients: HashMap::new(),
                                            host_id: cid.clone(), // 首个创建者即房主
                                            max_players: None,
                                            is_public: false,
                                            description: String::new(),
                                            public_password: String::new(),
                                            server_node: String::new(),
                                            muted: std::collections::HashSet::new(),
                                        }
                                    });
                                    
                                    // 验证密码
                                    if lobby.password_hash != password_hash {
                                        log::warn!("❌ 密码错误: {} 尝试加入大厅 {}", player_name, lobby_name);
                                        drop(lobbies_write);
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: "密码错误".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        continue;
                                    }

                                    // 人数上限检查（房主自己创建时 clients 为空，不受影响）
                                    if let Some(max) = lobby.max_players {
                                        if !lobby.clients.contains_key(&cid) && lobby.clients.len() as u32 >= max {
                                            log::warn!("❌ 大厅 {} 已满（{}/{}），拒绝 {}", lobby_name, lobby.clients.len(), max, player_name);
                                            drop(lobbies_write);
                                            let error_msg = SignalingMessage::RegisterError {
                                                message: format!("大厅人数已满（上限 {} 人）", max),
                                            };
                                            if let Ok(json) = serde_json::to_string(&error_msg) {
                                                send_text(&write, json).await;
                                            }
                                            continue;
                                        }
                                    }
                                    
                                    // 添加客户端到大厅
                                    lobby.clients.insert(cid.clone(), client_info);
                                    let host_id_now = lobby.host_id.clone();
                                    let max_players_now = lobby.max_players;
                                    let is_public_now = lobby.is_public;
                                    let muted_now: Vec<String> = lobby.muted.iter().cloned().collect();
                                    drop(lobbies_write);
                                    
                                    // 记录客户端所在大厅
                                    client_lobby_map.write().await.insert(cid.clone(), lid.clone());
                                    client_id = Some(cid.clone());
                                    lobby_id = Some(lid.clone());
                                    is_registered = true;
                                    
                                    log::info!("✅ 客户端 {} 已加入大厅 {} (当前 {} 人)", player_name, lobby_name, 
                                        lobbies.read().await.get(&lid).map(|l| l.clients.len()).unwrap_or(0));
                                    
                                    // 发送注册成功消息（携带房主/选项/禁言列表）
                                    let success_msg = SignalingMessage::RegisterSuccess {
                                        lobby_id: lid.clone(),
                                        host_id: Some(host_id_now),
                                        max_players: max_players_now,
                                        is_public: Some(is_public_now),
                                        muted_players: Some(muted_now),
                                    };
                                    if let Ok(json) = serde_json::to_string(&success_msg) {
                                        send_text(&write, json).await;
                                    }
                                    
                                    // 发送当前大厅内的玩家列表
                                    let players = {
                                        let lobbies_read = lobbies.read().await;
                                        lobbies_read
                                            .get(&lid)
                                            .map(|lobby| {
                                                lobby
                                                    .clients
                                                    .iter()
                                                    .filter(|(id, _)| **id != cid)
                                                    .map(|(_, info)| PlayerInfo {
                                                        player_id: info.player_id.clone(),
                                                        player_name: info.player_name.clone(),
                                                        virtual_ip: info.virtual_ip.clone(),
                                                        virtual_domain: info.virtual_domain.clone(),
                                                        use_domain: info.use_domain,
                                                    })
                                                    .collect::<Vec<_>>()
                                            })
                                            .unwrap_or_default()
                                    };
                                    let players_list = SignalingMessage::PlayersList { players };
                                    if let Ok(json) = serde_json::to_string(&players_list) {
                                        send_text(&write, json).await;
                                    }
                                    
                                    // 通知大厅内其他客户端有新玩家加入
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &cid,
                                        SignalingMessage::PlayerJoined {
                                            player_id: cid.clone(),
                                            player_name: player_name.clone(),
                                            virtual_ip: virtual_ip.clone(),
                                            virtual_domain: virtual_domain.clone(),
                                            use_domain,
                                        },
                                    ).await;
                                }
                                SignalingMessage::Offer { from, to, offer, .. } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送 Offer，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("转发 Offer from {} to {}", from, to);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 获取发送者名称
                                    let player_name = {
                                        let lobbies_read = lobbies.read().await;
                                        lobbies_read
                                            .get(&lid)
                                            .and_then(|lobby| lobby.clients.get(&from))
                                            .map(|info| info.player_name.clone())
                                    };

                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::Offer {
                                        from,
                                        to,
                                        offer,
                                        player_name,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::Answer { from, to, answer } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送 Answer，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("转发 Answer from {} to {}", from, to);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::Answer { from, to, answer };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::IceCandidate { from, to, candidate } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送 ICE Candidate，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::debug!("转发 ICE Candidate from {} to {}", from, to);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::IceCandidate { from, to, candidate };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::StatusUpdate { client_id, mic_enabled } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送状态更新，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("转发状态更新 from {}: 麦克风{}", client_id, if mic_enabled { "开启" } else { "关闭" });
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&client_id) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", client_id);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    let client_id_clone = client_id.clone();
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &client_id,
                                        SignalingMessage::StatusUpdate {
                                            client_id: client_id_clone,
                                            mic_enabled,
                                        },
                                    ).await;
                                }
                                SignalingMessage::ScreenShareStart { from, share_id, player_name, has_password } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试开始屏幕共享，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📺 屏幕共享开始 from {}: shareId={}, hasPassword={}", from, share_id, has_password);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::ScreenShareStart {
                                            from: from.clone(),
                                            share_id,
                                            player_name,
                                            has_password,
                                        },
                                    ).await;
                                }
                                SignalingMessage::ScreenShareStop { from, share_id } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试停止屏幕共享，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📺 屏幕共享停止 from {}: shareId={}", from, share_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::ScreenShareStop {
                                            from: from.clone(),
                                            share_id,
                                        },
                                    ).await;
                                }
                                SignalingMessage::ScreenShareRelay { from, to, share_id, action, player_name, password, upstream_id, downstream_id, route_version } => {
                                    if !is_registered {
                                        log::warn!("未注册的客户端尝试发送屏幕共享中继控制消息: {}", addr);
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!("拒绝伪造的屏幕共享中继消息: registered={:?}, from={}", client_id, from);
                                        continue;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareRelay {
                                        from, to, share_id, action, player_name, password,
                                        upstream_id, downstream_id, route_version,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareOffer { from, to, share_id, player_name, password, route_version, offer } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送屏幕共享Offer，拒绝: {}", addr);
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!("拒绝伪造的屏幕共享 Offer: registered={:?}, from={}", client_id, from);
                                        continue;
                                    }
                                    
                                    log::info!("📺 转发屏幕共享Offer from {} to {}, shareId={}, playerName={:?}, hasPassword={}", from, to, share_id, player_name, password.is_some());
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareOffer {
                                        from,
                                        to,
                                        share_id,
                                        player_name,
                                        password,
                                        route_version,
                                        offer,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareAnswer { from, to, share_id, route_version, answer } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送屏幕共享Answer，拒绝: {}", addr);
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!("拒绝伪造的屏幕共享 Answer: registered={:?}, from={}", client_id, from);
                                        continue;
                                    }
                                    
                                    log::info!("📺 转发屏幕共享Answer from {} to {}, shareId={}", from, to, share_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareAnswer {
                                        from,
                                        to,
                                        share_id,
                                        route_version,
                                        answer,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareIceCandidate { from, to, share_id, connection_role, route_version, candidate } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送屏幕共享ICE，拒绝: {}", addr);
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!("拒绝伪造的屏幕共享 ICE: registered={:?}, from={}", client_id, from);
                                        continue;
                                    }
                                    
                                    log::debug!("📺 转发屏幕共享ICE from {} to {}, shareId={}", from, to, share_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareIceCandidate {
                                        from,
                                        to,
                                        share_id,
                                        connection_role,
                                        route_version,
                                        candidate,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareError { from, to, share_id, error } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送屏幕共享错误，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📺 转发屏幕共享错误 from {} to {}, shareId={}, error={}", from, to, share_id, error);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareError {
                                        from,
                                        to,
                                        share_id,
                                        error,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareListRequest { from } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试请求屏幕共享列表，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📋 收到屏幕共享列表请求 from {}", from);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    log::info!("📢 广播屏幕共享列表请求到大厅内所有其他客户端");
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::ScreenShareListRequest {
                                            from: from.clone(),
                                        },
                                    ).await;
                                }
                                SignalingMessage::ScreenShareListResponse { from, to, share_id, player_name, has_password } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送屏幕共享列表响应，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📋 转发屏幕共享列表响应 from {} to {}, shareId={}", from, to, share_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareListResponse {
                                        from,
                                        to,
                                        share_id,
                                        player_name,
                                        has_password,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareViewerLeft { from, share_id } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送查看者离开消息，拒绝: {}", addr);
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!("拒绝伪造的屏幕共享离开消息: registered={:?}, from={}", client_id, from);
                                        continue;
                                    }
                                    
                                    log::info!("👋 收到查看者离开消息 from {}, shareId={}", from, share_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::ScreenShareViewerLeft {
                                            from: from.clone(),
                                            share_id,
                                        },
                                    ).await;
                                }
                                SignalingMessage::ScreenShareUpdate { from, share_id, viewer_id, viewer_name, viewer_count } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送共享状态更新，拒绝: {}", addr);
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!("拒绝伪造的屏幕共享状态更新: registered={:?}, from={}", client_id, from);
                                        continue;
                                    }
                                    
                                    log::info!("🔄 收到共享状态更新 from {}, shareId={}, viewerId={:?}", from, share_id, viewer_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::ScreenShareUpdate {
                                            from: from.clone(),
                                            share_id,
                                            viewer_id,
                                            viewer_name,
                                            viewer_count,
                                        },
                                    ).await;
                                }
                                SignalingMessage::FileShareAdded { from, share_id, share_name, player_name, has_password } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试添加文件共享，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📁 文件共享添加 from {}: shareId={}, shareName={}, hasPassword={}", from, share_id, share_name, has_password);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::FileShareAdded {
                                            from: from.clone(),
                                            share_id,
                                            share_name,
                                            player_name,
                                            has_password,
                                        },
                                    ).await;
                                }
                                SignalingMessage::FileShareRemoved { from, share_id } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试删除文件共享，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📁 文件共享删除 from {}: shareId={}", from, share_id);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::FileShareRemoved {
                                            from: from.clone(),
                                            share_id,
                                        },
                                    ).await;
                                }
                                SignalingMessage::FileShareListRequest { from } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试请求文件共享列表，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📋 收到文件共享列表请求 from {}", from);
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 广播给大厅内所有其他客户端
                                    log::info!("📢 广播文件共享列表请求到大厅内所有其他客户端");
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::FileShareListRequest {
                                            from: from.clone(),
                                        },
                                    ).await;
                                }
                                SignalingMessage::FileShareListResponse { from, to, shares } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试发送文件共享列表响应，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    log::info!("📋 转发文件共享列表响应 from {} to {}, shares={}", from, to, shares.len());
                                    
                                    // 获取发送者所在大厅
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => {
                                            log::warn!("发送者不在任何大厅: {}", from);
                                            continue;
                                        }
                                    };
                                    
                                    // 转发到目标客户端（必须在同一大厅）
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::FileShareListResponse {
                                        from,
                                        to,
                                        shares,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(&lobbies, &lid, &target_id, Message::Text(json)).await {
                                            log::warn!("目标客户端不在同一大厅或发送失败: {}", target_id);
                                        }
                                    }
                                }
                                SignalingMessage::Ping => {
                                    // 心跳检测：立即回复 pong，保持连接存活
                                    // 注意：浏览器/WebView 的 WebSocket API 无法发送协议级 ping 帧，
                                    // 客户端使用应用层 {type:"ping"}，服务器必须回 {type:"pong"}，
                                    // 否则客户端会因 5 秒收不到 pong 而误判断线并不断重连。
                                    if let Ok(json) = serde_json::to_string(&SignalingMessage::Pong) {
                                        send_text(&write, json).await;
                                    }
                                }
                                SignalingMessage::Pong => {
                                    // 一般不会收到客户端发来的 pong，忽略即可
                                }
                                SignalingMessage::PublicLobbyListRequest => {
                                    // 公开广场列表请求：无需注册即可查询
                                    log::info!("📋 收到公开大厅广场列表请求 from {}", addr);
                                    let lobbies_read = lobbies.read().await;
                                    let mut public_list: Vec<PublicLobbyInfo> = Vec::new();
                                    for lobby in lobbies_read.values() {
                                        if lobby.is_public {
                                            let host_name = lobby
                                                .clients
                                                .get(&lobby.host_id)
                                                .map(|c| c.player_name.clone())
                                                .unwrap_or_else(|| "房主".to_string());
                                            public_list.push(PublicLobbyInfo {
                                                lobby_name: lobby.lobby_name.clone(),
                                                player_count: lobby.clients.len() as u32,
                                                max_players: lobby.max_players,
                                                host_name,
                                                description: lobby.description.clone(),
                                                password: lobby.public_password.clone(),
                                                server_node: lobby.server_node.clone(),
                                            });
                                        }
                                    }
                                    drop(lobbies_read);
                                    let resp = SignalingMessage::PublicLobbyListResponse { lobbies: public_list };
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        send_text(&write, json).await;
                                    }
                                }
                                SignalingMessage::KickPlayer { from, target } => {
                                    if !is_registered {
                                        log::warn!("🚫 未注册客户端尝试踢人，拒绝: {}", addr);
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    // 校验房主身份并取出目标 sender
                                    let mut target_sender = None;
                                    let mut target_removed = false;
                                    {
                                        let mut lobbies_write = lobbies.write().await;
                                        if let Some(lobby) = lobbies_write.get_mut(&lid) {
                                            if lobby.host_id != from {
                                                log::warn!("🚫 非房主尝试踢人: {}", from);
                                                continue;
                                            }
                                            if from == target {
                                                continue; // 不能踢自己
                                            }
                                            if let Some(t) = lobby.clients.remove(&target) {
                                                target_sender = Some(Arc::clone(&t.sender));
                                                lobby.muted.remove(&target);
                                                target_removed = true;
                                                let mut client_lobby_map_write = client_lobby_map.write().await;
                                                if client_lobby_map_write
                                                    .get(&target)
                                                    .map(|mapped_lobby| mapped_lobby == &lid)
                                                    .unwrap_or(false)
                                                {
                                                    client_lobby_map_write.remove(&target);
                                                }
                                            }
                                        }
                                    }
                                    if !target_removed {
                                        continue;
                                    }
                                    // 通知被踢者
                                    if let Some(sender) = target_sender {
                                        let kicked = SignalingMessage::Kicked { reason: "你已被房主移出大厅".to_string() };
                                        if let Ok(json) = serde_json::to_string(&kicked) {
                                            send_text(&sender, json).await;
                                        }
                                        let _ = send_message(&sender, Message::Close(None)).await;
                                    }
                                    log::info!("👢 房主 {} 踢出了 {}", from, target);
                                    // 广播玩家离开
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &target,
                                        SignalingMessage::PlayerLeft { player_id: target.clone() },
                                    ).await;
                                }
                                SignalingMessage::MutePlayer { from, target, muted } => {
                                    if !is_registered {
                                        log::warn!("🚫 未注册客户端尝试禁言，拒绝: {}", addr);
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    {
                                        let mut lobbies_write = lobbies.write().await;
                                        if let Some(lobby) = lobbies_write.get_mut(&lid) {
                                            if lobby.host_id != from {
                                                log::warn!("🚫 非房主尝试禁言: {}", from);
                                                continue;
                                            }
                                            if muted {
                                                lobby.muted.insert(target.clone());
                                            } else {
                                                lobby.muted.remove(&target);
                                            }
                                        }
                                    }
                                    log::info!("🔇 房主 {} 设置 {} 禁言={}", from, target, muted);
                                    // 广播禁言状态给所有人（含目标本人）
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        "",
                                        SignalingMessage::PlayerMuteChanged { player_id: target, muted },
                                    ).await;
                                }
                                SignalingMessage::TransferHost { from, target } => {
                                    if !is_registered {
                                        log::warn!("🚫 未注册客户端尝试转让房主，拒绝: {}", addr);
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let mut new_host: Option<String> = None;
                                    {
                                        let mut lobbies_write = lobbies.write().await;
                                        if let Some(lobby) = lobbies_write.get_mut(&lid) {
                                            if lobby.host_id != from {
                                                log::warn!("🚫 非房主尝试转让房主: {}", from);
                                                continue;
                                            }
                                            if lobby.clients.contains_key(&target) {
                                                lobby.host_id = target.clone();
                                                new_host = Some(target.clone());
                                            }
                                        }
                                    }
                                    if let Some(host_id) = new_host {
                                        log::info!("👑 房主从 {} 转让给 {}", from, host_id);
                                        broadcast_to_lobby(
                                            &lobbies,
                                            &lid,
                                            "",
                                            SignalingMessage::HostChanged { host_id },
                                        ).await;
                                    }
                                }
                                SignalingMessage::SetLobbyOptions { from, max_players, is_public, description, password, server_node } => {
                                    if !is_registered {
                                        log::warn!("🚫 未注册客户端尝试修改大厅选项，拒绝: {}", addr);
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let mut changed: Option<(Option<u32>, bool)> = None;
                                    {
                                        let mut lobbies_write = lobbies.write().await;
                                        if let Some(lobby) = lobbies_write.get_mut(&lid) {
                                            if lobby.host_id != from {
                                                log::warn!("🚫 非房主尝试修改大厅选项: {}", from);
                                                continue;
                                            }
                                            if let Some(mp) = max_players {
                                                // 0 表示取消上限
                                                lobby.max_players = if mp == 0 { None } else { Some(mp) };
                                            }
                                            if let Some(desc) = description {
                                                lobby.description = desc;
                                            }
                                            // 记录房主节点（供公开广场加入者同步）
                                            if let Some(node) = server_node {
                                                if !node.trim().is_empty() {
                                                    lobby.server_node = node;
                                                }
                                            }
                                            if let Some(pubf) = is_public {
                                                lobby.is_public = pubf;
                                                if pubf {
                                                    // 公开时记录明文密码（供广场加入）
                                                    if let Some(pwd) = password {
                                                        lobby.public_password = pwd;
                                                    }
                                                } else {
                                                    lobby.public_password.clear();
                                                }
                                            }
                                            changed = Some((lobby.max_players, lobby.is_public));
                                        }
                                    }
                                    if let Some((mp, pubf)) = changed {
                                        log::info!("⚙️ 房主 {} 更新大厅选项: max={:?}, public={}", from, mp, pubf);
                                        broadcast_to_lobby(
                                            &lobbies,
                                            &lid,
                                            "",
                                            SignalingMessage::LobbyOptionsChanged { max_players: mp, is_public: pubf },
                                        ).await;
                                    }
                                }
                                SignalingMessage::Forward => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试转发消息，拒绝: {}", addr);
                                        break;
                                    }
                                    
                                    // 解析原始JSON以获取from和to字段
                                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(text) {
                                        // 检查消息类型
                                        let msg_type = json_value.get("type").and_then(|v| v.as_str());
                                        
                                        // 文件共享广播消息（share-added, share-removed, share-updated）
                                        if matches!(msg_type, Some("share-added") | Some("share-removed") | Some("share-updated")) {
                                            if let Some(from) = json_value.get("from").and_then(|v| v.as_str()) {
                                                log::debug!("广播文件共享消息: {:?} from {}", msg_type, from);
                                                
                                                // 获取发送者所在大厅
                                                let lid = match client_lobby_map.read().await.get(from) {
                                                    Some(id) => id.clone(),
                                                    None => {
                                                        log::warn!("发送者不在任何大厅: {}", from);
                                                        continue;
                                                    }
                                                };
                                                
                                                // 广播给大厅内所有其他客户端
                                                let senders = {
                                                    let lobbies_read = lobbies.read().await;
                                                    lobbies_read
                                                        .get(&lid)
                                                        .map(|lobby| {
                                                            lobby
                                                                .clients
                                                                .iter()
                                                                .filter(|(id, _)| id.as_str() != from)
                                                                .map(|(_, client)| Arc::clone(&client.sender))
                                                                .collect::<Vec<_>>()
                                                        })
                                                        .unwrap_or_default()
                                                };
                                                let sends = senders.into_iter().map(|sender| {
                                                    let text = text.to_string();
                                                    async move { send_text(&sender, text).await }
                                                });
                                                let _ = join_all(sends).await;
                                                continue;
                                            }
                                        }
                                        
                                        // 点对点转发消息（需要to字段）
                                        if let (Some(from), Some(to)) = (
                                            json_value.get("from").and_then(|v| v.as_str()),
                                            json_value.get("to").and_then(|v| v.as_str())
                                        ) {
                                            log::debug!("转发消息 from {} to {}", from, to);
                                            
                                            // 获取发送者所在大厅
                                            let lid = match client_lobby_map.read().await.get(from) {
                                                Some(id) => id.clone(),
                                                None => {
                                                    log::warn!("发送者不在任何大厅: {}", from);
                                                    continue;
                                                }
                                            };
                                            
                                            // 转发到目标客户端（必须在同一大厅）
                                            if !send_to_lobby_client(&lobbies, &lid, to, Message::Text(text.to_string())).await {
                                                log::warn!("目标客户端不在同一大厅或发送失败: {}", to);
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    log::warn!("未知消息类型");
                                }
                            }
                        }
                        Err(e) => {
                            let error_msg = e.to_string();
                            log::error!("解析消息失败: {}", error_msg);
                            
                            // 检查是否是旧版本客户端（缺少必需字段）
                            if error_msg.contains("missing field") {
                                log::warn!("🚫 检测到旧版本客户端（缺少必需字段），拒绝连接: {}", addr);
                                
                                // 尝试发送错误消息（如果可能）
                                let error_response = SignalingMessage::RegisterError {
                                    message: format!("您的客户端版本过低，不支持大厅隔离功能。请访问 {} 下载最新版本。", client_download_url()),
                                };
                                if let Ok(json) = serde_json::to_string(&error_response) {
                                    send_text(&write, json).await;
                                }
                                
                                // 等待消息发送后强制断开连接
                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                break;
                            }
                            
                            // 如果客户端还未注册就发送了其他消息，也拒绝连接
                            if !is_registered {
                                log::warn!("🚫 未注册的客户端尝试发送消息，拒绝连接: {}", addr);
                                break;
                            }
                        }
                    }
                } else if msg.is_close() {
                    log::info!("客户端关闭连接: {}", addr);
                    break;
                }
            }
            Err(e) => {
                log::error!("接收消息失败: {}", e);
                break;
            }
        }
    }
    
    // 客户端断开连接，清理资源
    if let (Some(cid), Some(lid)) = (client_id, lobby_id) {
        log::info!("客户端断开: {} (大厅: {})", cid, lid);
        
        // 从大厅中移除客户端
        let mut lobbies_write = lobbies.write().await;
        let mut new_host: Option<String> = None;
        // 【竞态修复】仅当大厅内该 cid 记录的 sender 仍是"本连接"时才清理。
        // 否则说明同一 clientId 已用新连接重连并覆盖了记录，此时旧连接的延迟断开
        // 若继续 remove，会误删刚重连上来的新连接，导致该玩家在服务器侧变成"幽灵"
        // （自己在线但服务器不再转发信令、他人看到其离开）。
        let mut is_current_connection = false;
        if let Some(lobby) = lobbies_write.get_mut(&lid) {
            is_current_connection = lobby
                .clients
                .get(&cid)
                .map(|c| Arc::ptr_eq(&c.sender, &write))
                .unwrap_or(false);

            if is_current_connection {
                lobby.clients.remove(&cid);
                lobby.muted.remove(&cid);

                // 如果大厅为空，删除大厅
                if lobby.clients.is_empty() {
                    log::info!("🏠 大厅 {} 已空，删除", lobby.lobby_name);
                    lobbies_write.remove(&lid);
                } else {
                    // 若离开的是房主，自动把房主转移给任意一个剩余玩家
                    if lobby.host_id == cid {
                        if let Some(next) = lobby.clients.keys().next().cloned() {
                            lobby.host_id = next.clone();
                            new_host = Some(next);
                            log::info!("👑 房主离开，自动转移给 {}", lobby.host_id);
                        }
                    }
                    log::info!("大厅 {} 剩余 {} 人", lobby.lobby_name, lobby.clients.len());
                }
            } else {
                log::info!("ℹ️ 旧连接断开，但 {} 已被新连接替换，跳过清理避免误删", cid);
            }
        }
        drop(lobbies_write);

        // 不是当前连接（已被重连替换）：不移除映射、不广播离开，直接返回
        if !is_current_connection {
            return Ok(());
        }
        
        // 从映射中移除（仅当仍指向本大厅时，避免误删已重连到其它大厅的映射）
        {
            let mut map = client_lobby_map.write().await;
            if map.get(&cid).map(|v| v == &lid).unwrap_or(false) {
                map.remove(&cid);
            }
        }
        
        // 通知大厅内其他客户端
        broadcast_to_lobby(
            &lobbies,
            &lid,
            &cid,
            SignalingMessage::PlayerLeft {
                player_id: cid.clone(),
            },
        ).await;

        // 若房主已自动转移，广播房主变更
        if let Some(host_id) = new_host {
            broadcast_to_lobby(
                &lobbies,
                &lid,
                "", // 通知所有人（含新房主）
                SignalingMessage::HostChanged { host_id },
            ).await;
        }
    }
    
    Ok(())
}

/// 广播消息到大厅内所有客户端（排除指定客户端）
async fn broadcast_to_lobby(
    lobbies: &Lobbies,
    lobby_id: &str,
    exclude_id: &str,
    message: SignalingMessage,
) {
    if let Ok(json) = serde_json::to_string(&message) {
        let senders = {
            let lobbies_read = lobbies.read().await;
            lobbies_read
                .get(lobby_id)
                .map(|lobby| {
                    lobby
                        .clients
                        .iter()
                        .filter(|(id, _)| id.as_str() != exclude_id)
                        .map(|(_, client)| Arc::clone(&client.sender))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };

        // 只在锁内复制发送端句柄；实际网络写入全部在锁外执行。
        let sends = senders.into_iter().map(|sender| {
            let message = Message::Text(json.clone());
            async move { send_message(&sender, message).await }
        });
        let _ = join_all(sends).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use serde_json::Value;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::time::{timeout, Duration};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::WebSocketStream;

    #[test]
    fn websocket_limits_are_explicit() {
        let config = websocket_config();
        assert_eq!(config.max_message_size, Some(2 * 1024 * 1024));
        assert_eq!(config.max_frame_size, Some(512 * 1024));
    }

    #[test]
    fn connection_limit_defaults_and_rejects_invalid_values() {
        assert_eq!(connection_limit_from_env(None), DEFAULT_MAX_CONNECTIONS);
        assert_eq!(connection_limit_from_env(Some("0")), DEFAULT_MAX_CONNECTIONS);
        assert_eq!(connection_limit_from_env(Some("not-a-number")), DEFAULT_MAX_CONNECTIONS);
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
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
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
        let sender = Arc::new(RwLock::new(sink));
        let _busy_sender = sender.write().await;

        let mut clients = HashMap::new();
        clients.insert(
            "slow".to_string(),
            ClientInfo {
                player_id: "slow".to_string(),
                player_name: "slow".to_string(),
                virtual_ip: None,
                virtual_domain: None,
                use_domain: None,
                sender: Arc::clone(&sender),
            },
        );
        let mut lobby_map = HashMap::new();
        lobby_map.insert(
            "lobby".to_string(),
            LobbyInfo {
                lobby_name: "lobby".to_string(),
                password_hash: String::new(),
                clients,
                host_id: "slow".to_string(),
                max_players: None,
                is_public: false,
                description: String::new(),
                public_password: String::new(),
                server_node: String::new(),
                muted: std::collections::HashSet::new(),
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
                },
            ) => None,
        };
        assert!(lock_acquired.is_some(), "broadcast should release lobbies lock before send");
    }

    async fn start_connection_server(
        registration_timeout: tokio::time::Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let lobbies = Arc::new(RwLock::new(HashMap::new()));
        let client_lobby_map = Arc::new(RwLock::new(HashMap::new()));
        let server_task = tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.expect("accept test client");
            handle_connection_with_timeouts(
                stream,
                addr,
                lobbies,
                client_lobby_map,
                tokio::time::Duration::from_secs(1),
                registration_timeout,
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
        let register = SignalingMessage::Register {
            client_id: "test-client".to_string(),
            player_name: "Test Player".to_string(),
            virtual_ip: None,
            virtual_domain: None,
            use_domain: None,
            lobby_name: "test-lobby".to_string(),
            lobby_password: "test-password".to_string(),
            client_version: Some("2.1.0".to_string()),
        };
        client
            .send(Message::Text(
                serde_json::to_string(&register).expect("register should serialize"),
            ))
            .await
            .expect("register should send");

        let register_success = client
            .next()
            .await
            .expect("register-success should arrive")
            .expect("register-success should be valid WebSocket message");
        let players_list = client
            .next()
            .await
            .expect("players-list should arrive")
            .expect("players-list should be valid WebSocket message");
        assert!(matches!(
            serde_json::from_str::<SignalingMessage>(register_success.to_text().expect("text response"))
                .expect("register-success should parse"),
            SignalingMessage::RegisterSuccess { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<SignalingMessage>(players_list.to_text().expect("text response"))
                .expect("players-list should parse"),
            SignalingMessage::PlayersList { .. }
        ));

        client.close(None).await.expect("client close should send");
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
        let pong = client
            .next()
            .await
            .expect("pong should arrive before deadline")
            .expect("pong should be valid WebSocket message");
        assert!(matches!(
            serde_json::from_str::<SignalingMessage>(pong.to_text().expect("text response"))
                .expect("pong should parse"),
            SignalingMessage::Pong
        ));

        let closed = tokio::time::timeout(
            tokio::time::Duration::from_secs(1),
            client.next(),
        )
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
        assert!(matches!(server_result, Some(Err(_))), "oversized message should be rejected");
    }
    async fn spawn_test_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
        let client_lobby_map: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));

        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    break;
                };
                let lobbies = Arc::clone(&lobbies);
                let client_lobby_map = Arc::clone(&client_lobby_map);
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer, lobbies, client_lobby_map).await;
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
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    fn register_message(client_id: &str, lobby_name: &str, lobby_password: &str) -> Message {
        Message::Text(
            serde_json::json!({
                "type": "register",
                "clientId": client_id,
                "playerName": client_id,
                "lobbyName": lobby_name,
                "lobbyPassword": lobby_password,
                "clientVersion": "2.7.5"
            })
            .to_string(),
        )
    }

    async fn register<S>(socket: &mut WebSocketStream<S>, client_id: &str, lobby_name: &str)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        socket
            .send(register_message(client_id, lobby_name, "password"))
            .await
            .unwrap();
        assert_eq!(next_json(socket).await["type"], "register-success");
        assert_eq!(next_json(socket).await["type"], "players-list");
    }

    #[test]
    fn extracts_sender_from_typed_host_command() {
        let raw = r#"{"type":"kick-player","from":"host-id","target":"peer-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw).as_deref(), Some("host-id"));
    }

    #[test]
    fn extracts_sender_from_forwarded_message() {
        let raw = r#"{"type":"remote-control-request","from":"controller-id","to":"phone-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert!(matches!(message, SignalingMessage::Forward));
        assert_eq!(message.claimed_sender(raw).as_deref(), Some("controller-id"));
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
    fn register_message_does_not_claim_a_sender() {
        let raw = r#"{"type":"register","clientId":"player-id","playerName":"player","lobbyName":"room","lobbyPassword":"password","clientVersion":"2.7.5"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert_eq!(message.claimed_sender(raw), None);
    }

    #[test]
    fn forwarded_message_without_string_sender_does_not_claim_identity() {
        let raw = r#"{"type":"remote-control-request","from":123,"to":"phone-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert!(matches!(message, SignalingMessage::Forward));
        assert_eq!(message.claimed_sender(raw), None);
    }

    #[tokio::test]
    async fn duplicate_client_id_is_rejected_without_replacing_existing_session() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut first, _) = connect_async(&url).await.unwrap();
        register(&mut first, "same-id", "same-room").await;

        let (mut duplicate, _) = connect_async(&url).await.unwrap();
        duplicate
            .send(register_message("same-id", "same-room", "password"))
            .await
            .unwrap();
        assert_eq!(next_json(&mut duplicate).await["type"], "register-error");
        match timeout(Duration::from_secs(2), duplicate.next())
            .await
            .unwrap()
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
            Some(Ok(message)) => panic!("duplicate session stayed open with {message:?}"),
        }

        first
            .send(Message::Text(
                serde_json::json!({"type":"ping"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(next_json(&mut first).await["type"], "pong");

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
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        peer.send(Message::Text(
            serde_json::json!({
                "type": "kick-player",
                "from": "host-id",
                "target": "peer-id"
            })
            .to_string(),
        ))
        .await
        .unwrap();

        peer.send(Message::Text(
            serde_json::json!({
                "type": "offer",
                "from": "peer-id",
                "to": "host-id",
                "offer": {"type": "offer", "sdp": "test"}
            })
            .to_string(),
        ))
        .await
        .unwrap();

        let offer = next_json(&mut host).await;
        assert_eq!(offer["type"], "offer");
        assert_eq!(offer["from"], "peer-id");

        server.abort();
    }

    #[tokio::test]
    async fn kicked_old_socket_cannot_forward_after_same_id_reconnects() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-id", "room").await;

        let (mut old_peer, _) = connect_async(&url).await.unwrap();
        register(&mut old_peer, "peer-id", "room").await;
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        host.send(Message::Text(
            serde_json::json!({
                "type": "kick-player",
                "from": "host-id",
                "target": "peer-id"
            })
            .to_string(),
        ))
        .await
        .unwrap();
        assert_eq!(next_json(&mut old_peer).await["type"], "kicked");
        assert_eq!(next_json(&mut host).await["type"], "player-left");

        let (mut new_peer, _) = connect_async(&url).await.unwrap();
        register(&mut new_peer, "peer-id", "room").await;
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        let _ = old_peer
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": "peer-id",
                    "to": "host-id",
                    "offer": {"type": "offer", "sdp": "stale"}
                })
                .to_string(),
            ))
            .await;
        assert!(timeout(Duration::from_millis(250), host.next()).await.is_err());

        new_peer
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": "peer-id",
                    "to": "host-id",
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

    #[tokio::test]
    async fn kick_does_not_remove_mapping_for_target_in_another_lobby() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-a", "room-a").await;

        let (mut target, _) = connect_async(&url).await.unwrap();
        register(&mut target, "target-b", "room-b").await;
        let (mut peer, _) = connect_async(&url).await.unwrap();
        register(&mut peer, "peer-b", "room-b").await;
        assert_eq!(next_json(&mut target).await["type"], "player-joined");

        host.send(Message::Text(
            serde_json::json!({
                "type": "kick-player",
                "from": "host-a",
                "target": "target-b"
            })
            .to_string(),
        ))
        .await
        .unwrap();
        assert!(timeout(Duration::from_millis(250), host.next()).await.is_err());

        target
            .send(Message::Text(
                serde_json::json!({
                    "type": "offer",
                    "from": "target-b",
                    "to": "peer-b",
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
}
