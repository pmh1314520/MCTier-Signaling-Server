use futures_util::{future::join_all, SinkExt, StreamExt};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock, Semaphore};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{accept_async_with_config, tungstenite::Message};

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

/// 聊天签名公钥（X.509 SubjectPublicKeyInfo DER 的 base64）长度上限。
/// 未压缩 P-256 公钥 DER 为 91 字节，base64 后约 124 字符，留出余量后仍能
/// 拦住任何异常大的值——服务器只做长度与字符集校验，不解析密钥本身。
const MAX_CHAT_PUBLIC_KEY_LEN: usize = 512;

/// 默认最大并发连接数（可通过环境变量 MAX_CONNECTIONS 覆盖）
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// 已注册连接的空闲超时。
///
/// 客户端（桌面端与 Android 端）均以 15 秒周期发送应用层 {"type":"ping"}，
/// 因此正常连接不会触发该超时。半开连接（休眠 / 切换网络 / NAT 表超时，
/// 对端未发出 FIN）会一直停在 read.next() 上，若不回收则该 clientId 的
/// 会话永久留在大厅里；由于重复 clientId 会被拒绝注册，该玩家将无法重连。
const REGISTERED_IDLE_TIMEOUT_SECS: u64 = 60;

/// 版本过低时提示客户端的下载地址（可通过环境变量 CLIENT_DOWNLOAD_URL 覆盖）
const DEFAULT_CLIENT_DOWNLOAD_URL: &str = "https://github.com/pmh1314520/MCTier/releases";

// ==================== 用户投稿的共享节点 ====================

/// 节点连续探测失败（或从未成功）超过该时长后自动移除。
///
/// 需求为“节点失效超过 1 天时自动移除”，因此这里以“最近一次探测成功时间”
/// 为基准：只要 now - last_ok_at 超过该阈值即淘汰。刚投稿的节点必须先通过
/// 一次探测才会入库，因此 last_ok_at 不会是 0。
const COMMUNITY_NODE_MAX_OFFLINE_SECS: u64 = 24 * 60 * 60;

/// 后台巡检周期：每轮对全部投稿节点做一次可达性探测
const COMMUNITY_NODE_PROBE_INTERVAL_SECS: u64 = 5 * 60;

/// 单个节点的探测超时
const COMMUNITY_NODE_PROBE_TIMEOUT_SECS: u64 = 3;

/// 单轮巡检的最大并发探测数，避免节点很多时瞬间打满 fd
const COMMUNITY_NODE_PROBE_CONCURRENCY: usize = 16;

/// 注册表容量上限（可通过环境变量 COMMUNITY_NODE_CAPACITY 覆盖）
const DEFAULT_COMMUNITY_NODE_CAPACITY: usize = 200;

/// 持久化文件路径（可通过环境变量 COMMUNITY_NODES_FILE 覆盖）
const DEFAULT_COMMUNITY_NODES_FILE: &str = "community_nodes.json";

/// 同一来源 IP 两次投稿之间的最小间隔，防刷
const COMMUNITY_NODE_SUBMIT_COOLDOWN_SECS: u64 = 30;

/// 投稿节点名称长度上限
const COMMUNITY_NODE_NAME_MAX_LEN: usize = 32;

/// 投稿节点地址长度上限
const COMMUNITY_NODE_ADDRESS_MAX_LEN: usize = 128;

/// 投稿者昵称长度上限
const COMMUNITY_NODE_SUBMITTER_MAX_LEN: usize = 24;

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
        /// 该成员的聊天签名公钥。只有公钥经过服务器，私钥永不离开客户端；
        /// 服务器把它当作与 clientId 绑定的不透明凭据转发给其他成员。
        #[serde(rename = "chatPublicKey", skip_serializing_if = "Option::is_none")]
        chat_public_key: Option<String>,
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
        /// Per-lobby credential for the P2P chat HTTP service. This is sent
        /// only on the registering member's own session.
        #[serde(rename = "chatToken")]
        chat_token: String,
        #[serde(rename = "chatTokenEpoch")]
        chat_token_epoch: u64,
    },
    /// Rotated chat credential sent only to current lobby members.
    ChatTokenRotated {
        #[serde(rename = "lobbyId")]
        lobby_id: String,
        #[serde(rename = "chatToken")]
        chat_token: String,
        #[serde(rename = "chatTokenEpoch")]
        chat_token_epoch: u64,
    },
    /// 注册失败
    RegisterError { message: String },
    /// 客户端主动离开；身份必须与当前 WebSocket 会话一致。
    Leave {
        #[serde(rename = "clientId")]
        client_id: String,
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
    PlayersList { players: Vec<PlayerInfo> },
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
        /// 与 players-list 同源的聊天签名公钥，保证增量事件也带齐验签材料。
        #[serde(rename = "chatPublicKey", skip_serializing_if = "Option::is_none")]
        chat_public_key: Option<String>,
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
    ScreenShareListRequest { from: String },
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
    FileShareListRequest { from: String },
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
    KickPlayer { from: String, target: String },
    /// 被踢出通知（服务器 -> 目标客户端）
    #[serde(rename = "kicked")]
    Kicked { reason: String },
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
    TransferHost { from: String, target: String },
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
    PublicLobbyListResponse { lobbies: Vec<PublicLobbyInfo> },
    /// 共享节点列表请求（无需注册，客户端 -> 服务器）
    #[serde(rename = "community-node-list-request")]
    CommunityNodeListRequest,
    /// 共享节点列表响应（服务器 -> 客户端）
    #[serde(rename = "community-node-list-response")]
    CommunityNodeListResponse { nodes: Vec<CommunityNodeInfo> },
    /// 投稿共享节点（无需注册，客户端 -> 服务器）
    #[serde(rename = "community-node-submit")]
    CommunityNodeSubmit {
        name: String,
        address: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        submitter: Option<String>,
    },
    /// 投稿结果（服务器 -> 客户端）
    #[serde(rename = "community-node-submit-result")]
    CommunityNodeSubmitResult {
        ok: bool,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node: Option<CommunityNodeInfo>,
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
            Self::StatusUpdate { client_id, .. } | Self::Leave { client_id } => {
                Some(client_id.clone())
            }
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
    /// 房主使用的 EasyTier 节点地址，加入者据此自动同步节点（空串=未知，回退加入者默认节点）
    #[serde(rename = "serverNode", default)]
    pub server_node: String,
}

/// 用户投稿的共享 EasyTier 节点
///
/// `lastOkAt` 是“最近一次探测成功”的 Unix 秒；`COMMUNITY_NODE_MAX_OFFLINE_SECS`
/// 就是基于它判断是否淘汰。`online` 只反映最近一轮巡检结果，供客户端展示，
/// 不参与淘汰判定（避免一次网络抖动就删节点）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityNodeInfo {
    pub name: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter: Option<String>,
    /// 首次投稿时间（Unix 秒）
    #[serde(rename = "submittedAt", default)]
    pub submitted_at: u64,
    /// 最近一次探测成功时间（Unix 秒）
    #[serde(rename = "lastOkAt", default)]
    pub last_ok_at: u64,
    /// 最近一轮巡检是否可达
    #[serde(default)]
    pub online: bool,
    /// 最近一次成功探测的 TCP 握手耗时（毫秒）
    #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
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
    /// 该成员的聊天签名公钥。收到名册的客户端据此验签，从而不必再用
    /// 数据包源 IP 判断消息作者——虚拟 IP 可被同大厅成员伪造，公钥不能。
    #[serde(rename = "chatPublicKey", skip_serializing_if = "Option::is_none")]
    pub chat_public_key: Option<String>,
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
    /// 注册时提交的聊天签名公钥。绑定在这里意味着它只能随该连接的注册身份
    /// 进入名册，别的成员无法替它声明或改写。
    chat_public_key: Option<String>,
    sender: ClientSender,
    disconnect: watch::Sender<bool>,
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
    /// 公开大厅必须使用空网络密码，不得通过广场传播密钥。
    is_passwordless: bool,
    /// 广场描述
    description: String,
    /// 房主使用的 EasyTier 节点地址（公开大厅时下发给加入者，保证节点一致可互通）
    server_node: String,
    /// 被禁言的客户端ID集合
    muted: std::collections::HashSet<String>,
    /// CSPRNG credential shared by active members for the P2P chat service.
    /// The lobby entry is destroyed when its last member leaves, so the next
    /// incarnation receives a fresh token.
    chat_token: String,
    chat_token_epoch: u64,
}

/// 全局大厅列表
type Lobbies = Arc<RwLock<HashMap<String, LobbyInfo>>>;

/// 客户端ID到大厅ID的映射
type ClientLobbyMap = Arc<RwLock<HashMap<String, String>>>;

/// 用户投稿的共享节点注册表（key = 归一化后的地址）
type CommunityNodes = Arc<RwLock<HashMap<String, CommunityNodeInfo>>>;

/// 投稿限流表：来源 IP -> 最近一次投稿时间（Unix 秒）
type SubmitCooldowns = Arc<RwLock<HashMap<std::net::IpAddr, u64>>>;

type ClientSender = Arc<
    RwLock<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>>,
>;

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

const CHAT_TOKEN_BYTES: usize = 32;

fn generate_chat_token() -> String {
    let mut bytes = [0u8; CHAT_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn rotate_chat_token(lobby: &mut LobbyInfo) -> (String, u64) {
    lobby.chat_token = generate_chat_token();
    lobby.chat_token_epoch = lobby.chat_token_epoch.saturating_add(1).max(1);
    (lobby.chat_token.clone(), lobby.chat_token_epoch)
}

fn parse_virtual_ipv4(raw: Option<&str>) -> Option<Ipv4Addr> {
    let ip = raw?.trim().parse::<Ipv4Addr>().ok()?;
    let octets = ip.octets();
    if octets[..3] != [10, 126, 126] || octets[3] == 0 || octets[3] == 255 {
        return None;
    }
    Some(ip)
}

fn valid_text(value: &str, max_len: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty())
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
}

/// 聊天签名公钥只做形状校验：base64 字符集 + 长度上限。
///
/// 服务器刻意不解析曲线点——它不需要，也不应该成为密码学解析器的攻击面。
/// 真正的解析与验签由收到名册的客户端完成，非法公钥在那里被拒绝。
fn valid_chat_public_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CHAT_PUBLIC_KEY_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

/// 归一化注册时提交的公钥：非法值一律丢弃成 None，而不是原样入册。
///
/// 丢弃而非报错是为了兼容旧客户端——它们不发这个字段，仍可加入大厅，
/// 只是拿不到签名能力（对端会因缺签名而拒收其消息）。
fn normalize_chat_public_key(raw: Option<String>) -> Option<String> {
    let trimmed = raw?.trim().to_string();
    if valid_chat_public_key(&trimmed) {
        Some(trimmed)
    } else {
        log::warn!("丢弃格式非法的聊天签名公钥");
        None
    }
}

fn effective_public_setting(requested_public: bool, is_passwordless: bool) -> bool {
    requested_public && is_passwordless
}

async fn send_with_timeout<F, E>(send: F) -> bool
where
    F: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(tokio::time::Duration::from_secs(SEND_TIMEOUT_SECS), send).await {
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
    let parse_version = |value: &str| -> Option<[u32; 3]> {
        if value.is_empty() || value.len() > MAX_CLIENT_VERSION_LEN {
            return None;
        }
        let mut parts = value.split('.');
        let parsed = [
            parts.next()?.parse::<u32>().ok()?,
            parts.next()?.parse::<u32>().ok()?,
            parts.next()?.parse::<u32>().ok()?,
        ];
        if parts.next().is_some() {
            return None;
        }
        Some(parsed)
    };

    matches!((parse_version(version), parse_version(minimum_version)), (Some(current), Some(minimum)) if current >= minimum)
}

// ==================== 投稿共享节点：校验 / 探测 / 持久化 ====================

/// 从节点地址中解析出 (host, port)。
///
/// 与桌面端 `parse_node_host_port` 保持同样的默认端口约定，避免两端对
/// “同一个地址是否可达”得出不同结论。
fn parse_node_host_port(address: &str) -> Option<(String, u16)> {
    let trimmed = address.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => (String::new(), trimmed),
    };
    let host_port = rest.split('/').next().unwrap_or(rest);
    if host_port.is_empty() {
        return None;
    }
    let default_port: u16 = match scheme.as_str() {
        "wss" | "https" => 443,
        "ws" | "http" => 80,
        _ => 11010,
    };

    // IPv6 字面量形如 [::1]:11010
    if let Some(stripped) = host_port.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse::<u16>().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            if host.is_empty() {
                return None;
            }
            return Some((host.to_string(), port));
        }
    }
    Some((host_port.to_string(), default_port))
}

/// 校验并归一化投稿地址。
///
/// 只接受 EasyTier 支持的协议前缀，并且必须能解析出 host/port，
/// 归一化结果用作注册表的 key，保证“同一节点写法不同”不会重复入库。
fn normalize_community_node_address(address: &str) -> Result<String, &'static str> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err("节点地址不能为空");
    }
    if trimmed.len() > COMMUNITY_NODE_ADDRESS_MAX_LEN {
        return Err("节点地址过长");
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("节点地址不能包含空白或控制字符");
    }
    let (scheme, _) = trimmed
        .split_once("://")
        .ok_or("节点地址必须以 tcp:// udp:// ws:// wss:// 开头")?;
    let scheme_lower = scheme.to_lowercase();
    if !matches!(scheme_lower.as_str(), "tcp" | "udp" | "ws" | "wss") {
        return Err("节点地址协议不支持，仅支持 tcp:// udp:// ws:// wss://");
    }
    let (host, port) = parse_node_host_port(trimmed).ok_or("节点地址无法解析出主机与端口")?;
    if port == 0 {
        return Err("节点端口无效");
    }
    // 归一化：协议小写 + 主机小写 + 显式端口
    let rest = trimmed.split_once("://").map(|(_, r)| r).unwrap_or(trimmed);
    let path = match rest.split_once('/') {
        Some((_, p)) if !p.is_empty() => format!("/{}", p),
        _ => String::new(),
    };
    let host_lower = host.to_lowercase();
    let host_part = if host_lower.contains(':') {
        format!("[{}]", host_lower)
    } else {
        host_lower
    };
    Ok(format!("{}://{}:{}{}", scheme_lower, host_part, port, path))
}

/// 清理投稿的展示文本（名称 / 昵称）：去掉控制字符并截断
fn sanitize_community_text(raw: &str, max_len: usize) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

/// 探测目标数量上限：DNS 可能返回大量地址，逐个探测会把服务器变成放大器
const COMMUNITY_NODE_PROBE_MAX_TARGETS: usize = 4;

/// 探测结果：区分“确实不可达”与“地址不允许探测”，便于给投稿者精确回执
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    Alive(u64),
    Dead,
    Blocked,
}

/// 判断 IP 是否允许作为探测目标。
///
/// 投稿接口对任何人开放，而服务器会主动连接投稿地址：若不加限制，攻击者就能
/// 借信令服务器扫描回环/内网/云厂商元数据地址（169.254.169.254），再通过
/// “投稿成功 / 不可达”的回执读出端口开放状态，等于白送一个 SSRF + 端口扫描器。
/// 因此这里只放行公网可路由的单播地址。
fn is_public_probe_target(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // 100.64.0.0/10 运营商级 NAT
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
                // 192.0.0.0/24 IETF 协议专用
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                // 198.18.0.0/15 基准测试保留
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                // 240.0.0.0/4 保留
                || octets[0] >= 240)
        }
        std::net::IpAddr::V6(v6) => {
            // 先判 IPv6 自身的特殊地址：`::1` 属于 `::a.b.c.d` 形式，若先走 IPv4
            // 折叠会被当成 0.0.0.1 而误判为公网，这里必须放在折叠之前。
            if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                return false;
            }
            // ::ffff:a.b.c.d 按其 IPv4 语义判定，避免用映射地址绕过 IPv4 规则
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_probe_target(&std::net::IpAddr::V4(mapped));
            }
            let segments = v6.segments();
            // 已废弃的 IPv4-compatible ::a.b.c.d：语义混乱且易被用于绕过，直接拒绝
            if segments[..6] == [0, 0, 0, 0, 0, 0] {
                return false;
            }
            !(
                // fc00::/7 唯一本地地址
                (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10 链路本地
                || (segments[0] & 0xffc0) == 0xfe80
                // 2001:db8::/32 文档用
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
            )
        }
    }
}

/// 自建部署可能把信令服务器和 EasyTier 节点放在同一内网，此时内网地址是合法的。
/// 默认关闭，必须由部署者显式开启（公网部署切勿开启）。
fn probe_allows_private_targets() -> bool {
    #[cfg(test)]
    {
        true
    }
    #[cfg(not(test))]
    {
        static CELL: OnceLock<bool> = OnceLock::new();
        *CELL.get_or_init(|| {
            matches!(
                env_or("COMMUNITY_NODE_ALLOW_PRIVATE_TARGETS", "false")
                    .to_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    }
}

/// 解析投稿地址得到探测目标，并按白名单规则过滤。
///
/// 这里一次性解析出 `SocketAddr` 再交给探测函数，探测阶段不再做第二次 DNS，
/// 因此不存在“校验用 A 记录、连接用 B 记录”的 DNS Rebinding 窗口。
async fn resolve_probe_targets(host: &str, port: u16, allow_private: bool) -> Vec<SocketAddr> {
    let resolved = match tokio::time::timeout(
        tokio::time::Duration::from_secs(COMMUNITY_NODE_PROBE_TIMEOUT_SECS),
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(iter)) => iter,
        _ => return Vec::new(),
    };
    resolved
        .filter(|addr| allow_private || is_public_probe_target(&addr.ip()))
        .take(COMMUNITY_NODE_PROBE_MAX_TARGETS)
        .collect()
}

/// TCP 握手探测：只有真正建立连接才算存活。
///
/// 注意这里**故意不**沿用桌面端 `test_node_latency` 把 `ConnectionRefused`
/// 当作“可达”的做法。桌面端那样处理是为了给用户展示“主机在线”，而这里的结果
/// 直接决定节点是否会被淘汰：若把“端口拒绝连接”也算存活，那么 EasyTier 进程挂掉
/// 之后节点仍会被永久判活，“失效超过 1 天自动移除”就完全不会触发。
async fn probe_community_node_tcp(targets: &[SocketAddr]) -> Option<u64> {
    let start = std::time::Instant::now();
    for target in targets {
        if let Ok(Ok(_stream)) = tokio::time::timeout(
            tokio::time::Duration::from_secs(COMMUNITY_NODE_PROBE_TIMEOUT_SECS),
            TcpStream::connect(target),
        )
        .await
        {
            return Some(start.elapsed().as_millis() as u64);
        }
    }
    None
}

/// UDP 探测：仅用于 `udp://` 节点。
///
/// UDP 无握手，只能借助 ICMP：已 connect 的 UDP socket 在收到
/// “port unreachable” 后，下一次 recv 会返回 ConnectionReset/ConnectionRefused，
/// 据此判定失效。完全没有回包时保守判定存活，避免把只监听 UDP、
/// 且上游丢弃 ICMP 的正常节点误删。
async fn probe_community_node_udp(target: SocketAddr) -> Option<u64> {
    let start = std::time::Instant::now();
    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
    socket.connect(target).await.ok()?;
    socket.send(&[0u8; 1]).await.ok()?;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(COMMUNITY_NODE_PROBE_TIMEOUT_SECS),
        socket.recv(&mut buf),
    )
    .await
    {
        // 有回包：确定存活
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
        // ICMP 端口不可达：确定失效
        Ok(Err(_)) => None,
        // 既无回包也无 ICMP：保守判活
        Err(_) => Some(start.elapsed().as_millis() as u64),
    }
}

/// 探测节点可达性。
///
/// EasyTier 默认会在同一端口同时监听 TCP 与 UDP，因此所有协议都先做 TCP 握手；
/// 只有 `udp://` 在 TCP 不通时才退化为 UDP 探测。
async fn probe_community_node(address: &str) -> ProbeOutcome {
    let Some((host, port)) = parse_node_host_port(address) else {
        return ProbeOutcome::Blocked;
    };
    let targets = resolve_probe_targets(&host, port, probe_allows_private_targets()).await;
    if targets.is_empty() {
        return ProbeOutcome::Blocked;
    }
    if let Some(ms) = probe_community_node_tcp(&targets).await {
        return ProbeOutcome::Alive(ms);
    }
    let scheme = address
        .split_once("://")
        .map(|(s, _)| s.to_lowercase())
        .unwrap_or_default();
    if scheme == "udp" {
        if let Some(ms) = probe_community_node_udp(targets[0]).await {
            return ProbeOutcome::Alive(ms);
        }
    }
    ProbeOutcome::Dead
}

/// 判断节点是否已失效超过阈值（失效超过 1 天 -> 应移除）
fn is_community_node_expired(node: &CommunityNodeInfo, now: u64) -> bool {
    now.saturating_sub(node.last_ok_at) > COMMUNITY_NODE_MAX_OFFLINE_SECS
}

/// 从磁盘载入投稿节点，顺带剔除已过期条目
fn load_community_nodes_from_disk(path: &str, now: u64) -> HashMap<String, CommunityNodeInfo> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("读取投稿节点文件失败（{}）：{}", path, e);
            }
            return HashMap::new();
        }
    };
    let nodes: Vec<CommunityNodeInfo> = match serde_json::from_str(&raw) {
        Ok(nodes) => nodes,
        Err(e) => {
            log::warn!("解析投稿节点文件失败（{}）：{}，按空表启动", path, e);
            return HashMap::new();
        }
    };
    let mut map = HashMap::new();
    for node in nodes {
        let key = match normalize_community_node_address(&node.address) {
            Ok(key) => key,
            Err(reason) => {
                log::warn!("丢弃非法投稿节点 {}：{}", node.address, reason);
                continue;
            }
        };
        if is_community_node_expired(&node, now) {
            log::info!("启动清理：投稿节点 {} 失效已超过 1 天，移除", node.address);
            continue;
        }
        map.insert(key, node);
    }
    log::info!("已载入 {} 个用户投稿节点（{}）", map.len(), path);
    map
}

/// 将投稿节点写回磁盘（先写临时文件再 rename，避免进程被杀时留下半截 JSON）
async fn persist_community_nodes(nodes: &CommunityNodes) {
    let snapshot: Vec<CommunityNodeInfo> = {
        let read = nodes.read().await;
        let mut list: Vec<CommunityNodeInfo> = read.values().cloned().collect();
        list.sort_by(|a, b| a.address.cmp(&b.address));
        list
    };
    let path = community_nodes_file().to_string();
    let json = match serde_json::to_string_pretty(&snapshot) {
        Ok(json) => json,
        Err(e) => {
            log::warn!("序列化投稿节点失败: {}", e);
            return;
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        let tmp = format!("{}.tmp", path);
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("写入投稿节点文件失败: {}", e),
        Err(e) => log::warn!("投稿节点持久化任务异常: {}", e),
    }
}

/// 取出对客户端可见的投稿节点列表（按在线优先、延迟升序排序）
async fn community_node_list(nodes: &CommunityNodes) -> Vec<CommunityNodeInfo> {
    let read = nodes.read().await;
    let mut list: Vec<CommunityNodeInfo> = read.values().cloned().collect();
    drop(read);
    list.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| {
                a.latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.latency_ms.unwrap_or(u64::MAX))
            })
            .then_with(|| a.name.cmp(&b.name))
    });
    list
}

/// 对全部投稿节点做一轮探测，并移除失效超过 1 天的条目。
///
/// 返回 (在线数, 移除数)。探测在锁外并发执行，只有回写结果时才短暂持写锁。
async fn sweep_community_nodes(nodes: &CommunityNodes) -> (usize, usize) {
    let targets: Vec<String> = {
        let read = nodes.read().await;
        read.keys().cloned().collect()
    };
    if targets.is_empty() {
        return (0, 0);
    }

    let mut results: Vec<(String, ProbeOutcome)> = Vec::with_capacity(targets.len());
    for chunk in targets.chunks(COMMUNITY_NODE_PROBE_CONCURRENCY) {
        let probes = chunk.iter().map(|address| {
            let address = address.clone();
            async move {
                let outcome = probe_community_node(&address).await;
                (address, outcome)
            }
        });
        results.extend(join_all(probes).await);
    }

    let now = now_unix_secs();
    let mut online = 0usize;
    let removed;
    {
        let mut write = nodes.write().await;
        for (address, outcome) in results {
            let Some(node) = write.get_mut(&address) else {
                // 该节点在本轮探测期间被并发移除，跳过
                continue;
            };
            match outcome {
                ProbeOutcome::Alive(ms) => {
                    node.online = true;
                    node.latency_ms = Some(ms);
                    node.last_ok_at = now;
                    online += 1;
                }
                // Dead：正常淘汰计时。Blocked 代表地址已不允许探测（例如历史数据
                // 里残留的内网地址），同样按失效处理，让它随时间被清理掉。
                ProbeOutcome::Dead | ProbeOutcome::Blocked => {
                    node.online = false;
                    node.latency_ms = None;
                }
            }
        }
        let before = write.len();
        write.retain(|_, node| {
            let keep = !is_community_node_expired(node, now);
            if !keep {
                log::info!(
                    "投稿节点 {}（{}）失效已超过 1 天，自动移除",
                    node.name,
                    node.address
                );
            }
            keep
        });
        removed = before - write.len();
    }

    if removed > 0 {
        persist_community_nodes(nodes).await;
    }
    (online, removed)
}

/// 后台巡检任务：周期性探测投稿节点并淘汰失效条目
async fn spawn_community_node_sweeper(nodes: CommunityNodes) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(
            COMMUNITY_NODE_PROBE_INTERVAL_SECS,
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let total = nodes.read().await.len();
            if total == 0 {
                continue;
            }
            let (online, removed) = sweep_community_nodes(&nodes).await;
            log::info!(
                "投稿节点巡检完成：共 {} 个，在线 {} 个，本轮移除 {} 个",
                total,
                online,
                removed
            );
        }
    });
}

/// 处理一次投稿请求，返回给客户端的结果消息。
///
/// 先校验、后探测、再入库：探测不通的节点直接拒绝，避免把死地址写进公共列表。
async fn handle_community_node_submit(
    nodes: &CommunityNodes,
    cooldowns: &SubmitCooldowns,
    peer: SocketAddr,
    name: String,
    address: String,
    submitter: Option<String>,
) -> SignalingMessage {
    let reject = |message: &str| SignalingMessage::CommunityNodeSubmitResult {
        ok: false,
        message: message.to_string(),
        node: None,
    };

    let normalized = match normalize_community_node_address(&address) {
        Ok(v) => v,
        Err(reason) => return reject(reason),
    };
    let clean_name = sanitize_community_text(&name, COMMUNITY_NODE_NAME_MAX_LEN);
    if clean_name.is_empty() {
        return reject("节点名称不能为空");
    }
    let clean_submitter = submitter
        .map(|s| sanitize_community_text(&s, COMMUNITY_NODE_SUBMITTER_MAX_LEN))
        .filter(|s| !s.is_empty());

    let now = now_unix_secs();

    // 限流：同一来源 IP 冷却期内只允许投稿一次
    {
        let mut write = cooldowns.write().await;
        write.retain(|_, at| now.saturating_sub(*at) <= COMMUNITY_NODE_SUBMIT_COOLDOWN_SECS);
        if let Some(last) = write.get(&peer.ip()) {
            let wait =
                COMMUNITY_NODE_SUBMIT_COOLDOWN_SECS.saturating_sub(now.saturating_sub(*last));
            return reject(&format!("投稿过于频繁，请 {} 秒后再试", wait.max(1)));
        }
        write.insert(peer.ip(), now);
    }

    let already_exists = nodes.read().await.contains_key(&normalized);
    if !already_exists && nodes.read().await.len() >= community_node_capacity() {
        return reject("共享节点列表已满，请稍后再试");
    }

    // 投稿即探测：不可达或不允许探测的地址都不入库
    let latency = match probe_community_node(&normalized).await {
        ProbeOutcome::Alive(ms) => ms,
        ProbeOutcome::Dead => return reject("该节点当前不可达，请确认地址与端口后重新提交"),
        ProbeOutcome::Blocked => {
            return reject("只接受公网可访问的节点地址，回环/内网/保留地址无法作为共享节点")
        }
    };

    let node = {
        let mut write = nodes.write().await;
        if let Some(existing) = write.get_mut(&normalized) {
            // 已存在：刷新存活信息与展示名，不重复占用容量
            existing.name = clean_name;
            if clean_submitter.is_some() {
                existing.submitter = clean_submitter;
            }
            existing.online = true;
            existing.latency_ms = Some(latency);
            existing.last_ok_at = now;
            existing.clone()
        } else {
            if write.len() >= community_node_capacity() {
                // 与上面的预检查之间存在并发窗口，这里再兜一次
                return reject("共享节点列表已满，请稍后再试");
            }
            let node = CommunityNodeInfo {
                name: clean_name,
                address: normalized.clone(),
                submitter: clean_submitter,
                submitted_at: now,
                last_ok_at: now,
                online: true,
                latency_ms: Some(latency),
            };
            write.insert(normalized.clone(), node.clone());
            node
        }
    };

    persist_community_nodes(nodes).await;
    log::info!(
        "✅ 收到投稿共享节点: {} ({}) from {}",
        node.name,
        node.address,
        peer
    );

    SignalingMessage::CommunityNodeSubmitResult {
        ok: true,
        message: if already_exists {
            "该节点已在共享列表中，已刷新存活状态".to_string()
        } else {
            "投稿成功，感谢分享".to_string()
        },
        node: Some(node),
    }
}

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
    let connection_semaphore = Arc::new(Semaphore::new(max_connections));

    // 创建大厅列表和客户端映射
    let lobbies: Lobbies = Arc::new(RwLock::new(HashMap::new()));
    let client_lobby_map: ClientLobbyMap = Arc::new(RwLock::new(HashMap::new()));

    // 用户投稿的共享节点：从磁盘恢复（顺带剔除失效超过 1 天的条目），并启动后台巡检
    let community_nodes: CommunityNodes = Arc::new(RwLock::new(load_community_nodes_from_disk(
        community_nodes_file(),
        now_unix_secs(),
    )));
    let submit_cooldowns: SubmitCooldowns = Arc::new(RwLock::new(HashMap::new()));
    log::info!(
        "共享节点：容量上限 {}，巡检周期 {} 秒，失效超过 {} 秒自动移除，存档 {}",
        community_node_capacity(),
        COMMUNITY_NODE_PROBE_INTERVAL_SECS,
        COMMUNITY_NODE_MAX_OFFLINE_SECS,
        community_nodes_file()
    );
    spawn_community_node_sweeper(Arc::clone(&community_nodes)).await;

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

                let connection_permit = match Arc::clone(&connection_semaphore).try_acquire_owned()
                {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!(
                            "连接数已达上限（{}），拒绝客户端: {}",
                            max_connections,
                            addr
                        );
                        continue;
                    }
                };

                let lobbies_clone = Arc::clone(&lobbies);
                let client_lobby_map_clone = Arc::clone(&client_lobby_map);
                let community_nodes_clone = Arc::clone(&community_nodes);
                let submit_cooldowns_clone = Arc::clone(&submit_cooldowns);

                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    if let Err(e) = handle_connection(
                        stream,
                        addr,
                        lobbies_clone,
                        client_lobby_map_clone,
                        community_nodes_clone,
                        submit_cooldowns_clone,
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

/// 处理客户端连接
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    lobbies: Lobbies,
    client_lobby_map: ClientLobbyMap,
    community_nodes: CommunityNodes,
    submit_cooldowns: SubmitCooldowns,
) -> Result<(), Box<dyn std::error::Error>> {
    handle_connection_with_timeouts(
        stream,
        addr,
        lobbies,
        client_lobby_map,
        community_nodes,
        submit_cooldowns,
        tokio::time::Duration::from_secs(WEBSOCKET_HANDSHAKE_TIMEOUT_SECS),
        tokio::time::Duration::from_secs(REGISTRATION_TIMEOUT_SECS),
        tokio::time::Duration::from_secs(REGISTERED_IDLE_TIMEOUT_SECS),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_with_timeouts(
    stream: TcpStream,
    addr: SocketAddr,
    lobbies: Lobbies,
    client_lobby_map: ClientLobbyMap,
    community_nodes: CommunityNodes,
    submit_cooldowns: SubmitCooldowns,
    handshake_timeout: tokio::time::Duration,
    registration_timeout: tokio::time::Duration,
    idle_timeout: tokio::time::Duration,
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
            log::warn!(
                "WebSocket 握手超时（{} 毫秒）: {}",
                handshake_timeout.as_millis(),
                addr
            );
            return Ok(());
        }
    };

    log::info!("✅ WebSocket 连接已建立: {}", addr);

    let (write, mut read) = ws_stream.split();
    let write = Arc::new(RwLock::new(write));
    let (disconnect_tx, mut disconnect_rx) = watch::channel(false);

    let mut client_id: Option<String> = None;
    let mut lobby_id: Option<String> = None;

    // 标记是否已注册
    let mut is_registered = false;
    let registration_deadline = tokio::time::Instant::now() + registration_timeout;

    // 处理消息
    loop {
        let msg_result = if is_registered {
            tokio::select! {
                changed = disconnect_rx.changed() => {
                    if changed.is_ok() && *disconnect_rx.borrow() {
                        log::info!("服务端终止客户端会话: peer={}", addr);
                    }
                    break;
                }
                message = tokio::time::timeout(idle_timeout, read.next()) => match message {
                    Ok(Some(msg_result)) => msg_result,
                    Ok(None) => break,
                    Err(_) => {
                        log::warn!(
                            "已注册连接空闲超时（{} 毫秒），回收会话: peer={}, client={:?}",
                            idle_timeout.as_millis(),
                            addr,
                            client_id
                        );
                        break;
                    }
                }
            }
        } else {
            match tokio::time::timeout_at(registration_deadline, read.next()).await {
                Ok(Some(msg_result)) => msg_result,
                Ok(None) => break,
                Err(_) => {
                    log::warn!(
                        "客户端首次注册超时（{} 毫秒）: {}",
                        registration_timeout.as_millis(),
                        addr
                    );
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
                                SignalingMessage::Register {
                                    client_id: cid,
                                    player_name,
                                    virtual_ip,
                                    virtual_domain,
                                    use_domain,
                                    lobby_name,
                                    lobby_password,
                                    client_version,
                                    chat_public_key,
                                } => {
                                    if is_registered {
                                        log::warn!(
                                            "拒绝同一连接重复注册: peer={}, registered={:?}",
                                            addr,
                                            client_id
                                        );
                                        break;
                                    }

                                    if !valid_text(&cid, MAX_CLIENT_ID_LEN, false)
                                        || !valid_text(&player_name, MAX_PLAYER_NAME_LEN, false)
                                        || !valid_text(&lobby_name, MAX_LOBBY_NAME_LEN, false)
                                        || !valid_text(
                                            &lobby_password,
                                            MAX_LOBBY_PASSWORD_LEN,
                                            true,
                                        )
                                        || virtual_domain.as_deref().is_some_and(|domain| {
                                            !valid_text(domain, MAX_VIRTUAL_DOMAIN_LEN, true)
                                        })
                                    {
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: "注册字段为空、过长或包含控制字符".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        continue;
                                    }

                                    let chat_public_key =
                                        normalize_chat_public_key(chat_public_key);

                                    log::info!("客户端注册: {} ({}) - 大厅: {} - 版本: {:?} - 虚拟IP: {:?} - 虚拟域名: {:?} - 使用域名: {:?} - 聊天公钥: {}", 
                                        player_name, cid, lobby_name, client_version, virtual_ip, virtual_domain, use_domain,
                                        if chat_public_key.is_some() { "已提交" } else { "未提交" });

                                    // 检查客户端版本
                                    let version_str =
                                        client_version.as_deref().unwrap_or("unknown");
                                    if version_str == "unknown"
                                        || !is_version_valid(version_str, minimum_client_version())
                                    {
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
                                        tokio::time::sleep(tokio::time::Duration::from_millis(500))
                                            .await;
                                        log::warn!(
                                            "🚫 强制断开版本过低的客户端连接: {} ({})",
                                            addr,
                                            version_str
                                        );
                                        break;
                                    }

                                    let virtual_ip = match parse_virtual_ipv4(virtual_ip.as_deref())
                                    {
                                        Some(ip) => ip,
                                        None => {
                                            let error_msg = SignalingMessage::RegisterError {
                                                message: "virtualIp 必须位于 10.126.126.1-254"
                                                    .to_string(),
                                            };
                                            if let Ok(json) = serde_json::to_string(&error_msg) {
                                                send_text(&write, json).await;
                                            }
                                            continue;
                                        }
                                    };

                                    log::info!(
                                        "✅ 版本检查通过: {} (版本: {})",
                                        player_name,
                                        version_str
                                    );

                                    // 生成大厅ID
                                    let lid = generate_lobby_id(&lobby_name, &lobby_password);

                                    // 生成密码哈希
                                    let mut hasher = Sha256::new();
                                    hasher.update(lobby_password.as_bytes());
                                    let password_hash = format!("{:x}", hasher.finalize());

                                    // 获取或创建大厅
                                    let mut lobbies_write = lobbies.write().await;
                                    if lobbies_write.values().any(|existing_lobby| {
                                        existing_lobby.clients.contains_key(&cid)
                                    }) {
                                        log::warn!(
                                            "拒绝重复 clientId 注册: {} ({})",
                                            player_name,
                                            cid
                                        );
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
                                    // Check an existing lobby before creating a new one. This avoids
                                    // leaving an empty, token-bearing lobby behind after a bad join.
                                    if let Some(existing) = lobbies_write.get(&lid) {
                                        if existing.password_hash != password_hash {
                                            log::warn!(
                                                "❌ 密码错误: {} 尝试加入大厅 {}",
                                                player_name,
                                                lobby_name
                                            );
                                            drop(lobbies_write);
                                            let error_msg = SignalingMessage::RegisterError {
                                                message: "密码错误".to_string(),
                                            };
                                            if let Ok(json) = serde_json::to_string(&error_msg) {
                                                send_text(&write, json).await;
                                            }
                                            continue;
                                        }
                                    }

                                    let lobby =
                                        lobbies_write.entry(lid.clone()).or_insert_with(|| {
                                            log::info!(
                                                "🏠 创建新大厅: {} (ID: {})，房主: {}",
                                                lobby_name,
                                                lid,
                                                cid
                                            );
                                            LobbyInfo {
                                                lobby_name: lobby_name.clone(),
                                                password_hash: password_hash.clone(),
                                                clients: HashMap::new(),
                                                host_id: cid.clone(), // 首个创建者即房主
                                                max_players: None,
                                                is_public: false,
                                                is_passwordless: lobby_password.is_empty(),
                                                description: String::new(),
                                                server_node: String::new(),
                                                muted: std::collections::HashSet::new(),
                                                chat_token: generate_chat_token(),
                                                chat_token_epoch: 1,
                                            }
                                        });

                                    // Virtual IP is the identity binding used by the chat HTTP
                                    // service. Do not allow two members to claim the same address.
                                    if lobby.clients.values().any(|info| {
                                        info.virtual_ip
                                            .as_deref()
                                            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                                            == Some(virtual_ip)
                                    }) {
                                        log::warn!(
                                            "❌ 虚拟IP已在大厅 {} 中使用: {}",
                                            lobby_name,
                                            virtual_ip
                                        );
                                        drop(lobbies_write);
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: "virtualIp 已被大厅内其他成员使用".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        continue;
                                    }

                                    // 保存客户端信息 only after all registration checks pass.
                                    let client_info = ClientInfo {
                                        player_id: cid.clone(),
                                        player_name: player_name.clone(),
                                        virtual_ip: Some(virtual_ip.to_string()),
                                        virtual_domain: virtual_domain.clone(),
                                        use_domain,
                                        chat_public_key: chat_public_key.clone(),
                                        sender: Arc::clone(&write),
                                        disconnect: disconnect_tx.clone(),
                                    };

                                    // 人数上限检查（房主自己创建时 clients 为空，不受影响）
                                    if lobby.clients.len() >= MAX_LOBBY_MEMBERS
                                        || lobby.max_players.is_some_and(|max| {
                                            !lobby.clients.contains_key(&cid)
                                                && lobby.clients.len() as u32 >= max
                                        })
                                    {
                                        log::warn!(
                                            "❌ 大厅 {} 已满（{}/{}），拒绝 {}",
                                            lobby_name,
                                            lobby.clients.len(),
                                            lobby
                                                .max_players
                                                .map(|max| max as usize)
                                                .unwrap_or(MAX_LOBBY_MEMBERS)
                                                .min(MAX_LOBBY_MEMBERS),
                                            player_name
                                        );
                                        drop(lobbies_write);
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: format!(
                                                "大厅人数已满（服务端上限 {} 人）",
                                                MAX_LOBBY_MEMBERS
                                            ),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        continue;
                                    }

                                    // 添加客户端到大厅。除首个成员外，每次成员加入都立即轮换
                                    // token；新成员从 register-success 获得新 token，旧成员只
                                    // 通过各自已认证的 WebSocket 会话收到轮换事件。
                                    let had_existing_members = !lobby.clients.is_empty();
                                    lobby.clients.insert(cid.clone(), client_info);
                                    let (chat_token_now, chat_token_epoch_now) =
                                        if had_existing_members {
                                            rotate_chat_token(lobby)
                                        } else {
                                            (lobby.chat_token.clone(), lobby.chat_token_epoch)
                                        };
                                    let rotation_targets = if had_existing_members {
                                        lobby
                                            .clients
                                            .iter()
                                            .filter(|(id, _)| id.as_str() != cid)
                                            .map(|(id, client)| {
                                                (id.clone(), Arc::clone(&client.sender))
                                            })
                                            .collect::<Vec<_>>()
                                    } else {
                                        Vec::new()
                                    };
                                    let host_id_now = lobby.host_id.clone();
                                    let max_players_now = lobby.max_players;
                                    let is_public_now = lobby.is_public;
                                    let muted_now: Vec<String> =
                                        lobby.muted.iter().cloned().collect();
                                    // Membership and client->lobby mapping are committed while the
                                    // lobby write lock is held, so kick/disconnect cannot delete a
                                    // freshly reconnected mapping for the same lobby.
                                    client_lobby_map
                                        .write()
                                        .await
                                        .insert(cid.clone(), lid.clone());
                                    drop(lobbies_write);

                                    client_id = Some(cid.clone());
                                    lobby_id = Some(lid.clone());
                                    is_registered = true;

                                    if *disconnect_rx.borrow()
                                        || !is_current_session(&lobbies, &lid, &cid, &write).await
                                    {
                                        log::warn!(
                                            "注册提交后会话已失效，拒绝发送 token: client={}",
                                            cid
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "✅ 客户端 {} 已加入大厅 {} (当前 {} 人)",
                                        player_name,
                                        lobby_name,
                                        lobbies
                                            .read()
                                            .await
                                            .get(&lid)
                                            .map(|l| l.clients.len())
                                            .unwrap_or(0)
                                    );

                                    // 发送注册成功消息（携带房主/选项/禁言列表）
                                    let success_msg = SignalingMessage::RegisterSuccess {
                                        lobby_id: lid.clone(),
                                        host_id: Some(host_id_now),
                                        max_players: max_players_now,
                                        is_public: Some(is_public_now),
                                        muted_players: Some(muted_now),
                                        chat_token: chat_token_now.clone(),
                                        chat_token_epoch: chat_token_epoch_now,
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
                                                        chat_public_key: info
                                                            .chat_public_key
                                                            .clone(),
                                                    })
                                                    .collect::<Vec<_>>()
                                            })
                                            .unwrap_or_default()
                                    };
                                    let players_list = SignalingMessage::PlayersList { players };
                                    if let Ok(json) = serde_json::to_string(&players_list) {
                                        send_text(&write, json).await;
                                    }

                                    if !rotation_targets.is_empty() {
                                        send_chat_token_rotation(
                                            &lobbies,
                                            rotation_targets,
                                            lid.clone(),
                                            chat_token_now,
                                            chat_token_epoch_now,
                                        )
                                        .await;
                                    }

                                    // 通知大厅内其他客户端有新玩家加入
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &cid,
                                        SignalingMessage::PlayerJoined {
                                            player_id: cid.clone(),
                                            player_name: player_name.clone(),
                                            virtual_ip: Some(virtual_ip.to_string()),
                                            virtual_domain: virtual_domain.clone(),
                                            use_domain,
                                            chat_public_key: chat_public_key.clone(),
                                        },
                                    )
                                    .await;
                                }
                                SignalingMessage::Leave { .. } => {
                                    if is_registered {
                                        log::info!("客户端主动离开: peer={}", addr);
                                    }
                                    break;
                                }
                                SignalingMessage::Offer {
                                    from, to, offer, ..
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送 Offer，拒绝: {}",
                                            addr
                                        );
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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::Answer { from, to, answer } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送 Answer，拒绝: {}",
                                            addr
                                        );
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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::IceCandidate {
                                    from,
                                    to,
                                    candidate,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送 ICE Candidate，拒绝: {}",
                                            addr
                                        );
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
                                    let forward_msg = SignalingMessage::IceCandidate {
                                        from,
                                        to,
                                        candidate,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::StatusUpdate {
                                    client_id,
                                    mic_enabled,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送状态更新，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "转发状态更新 from {}: 麦克风{}",
                                        client_id,
                                        if mic_enabled { "开启" } else { "关闭" }
                                    );

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
                                    )
                                    .await;
                                }
                                SignalingMessage::ScreenShareStart {
                                    from,
                                    share_id,
                                    player_name,
                                    has_password,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试开始屏幕共享，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "📺 屏幕共享开始 from {}: shareId={}, hasPassword={}",
                                        from,
                                        share_id,
                                        has_password
                                    );

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
                                    )
                                    .await;
                                }
                                SignalingMessage::ScreenShareStop { from, share_id } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试停止屏幕共享，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "📺 屏幕共享停止 from {}: shareId={}",
                                        from,
                                        share_id
                                    );

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
                                    )
                                    .await;
                                }
                                SignalingMessage::ScreenShareRelay {
                                    from,
                                    to,
                                    share_id,
                                    action,
                                    player_name,
                                    password,
                                    upstream_id,
                                    downstream_id,
                                    route_version,
                                } => {
                                    if !is_registered {
                                        log::warn!(
                                            "未注册的客户端尝试发送屏幕共享中继控制消息: {}",
                                            addr
                                        );
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!(
                                            "拒绝伪造的屏幕共享中继消息: registered={:?}, from={}",
                                            client_id,
                                            from
                                        );
                                        continue;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let forward_msg = SignalingMessage::ScreenShareRelay {
                                        from,
                                        to,
                                        share_id,
                                        action,
                                        player_name,
                                        password,
                                        upstream_id,
                                        downstream_id,
                                        route_version,
                                    };
                                    if let Ok(json) = serde_json::to_string(&forward_msg) {
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareOffer {
                                    from,
                                    to,
                                    share_id,
                                    player_name,
                                    password,
                                    route_version,
                                    offer,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送屏幕共享Offer，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!(
                                            "拒绝伪造的屏幕共享 Offer: registered={:?}, from={}",
                                            client_id,
                                            from
                                        );
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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareAnswer {
                                    from,
                                    to,
                                    share_id,
                                    route_version,
                                    answer,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送屏幕共享Answer，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!(
                                            "拒绝伪造的屏幕共享 Answer: registered={:?}, from={}",
                                            client_id,
                                            from
                                        );
                                        continue;
                                    }

                                    log::info!(
                                        "📺 转发屏幕共享Answer from {} to {}, shareId={}",
                                        from,
                                        to,
                                        share_id
                                    );

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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareIceCandidate {
                                    from,
                                    to,
                                    share_id,
                                    connection_role,
                                    route_version,
                                    candidate,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送屏幕共享ICE，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!(
                                            "拒绝伪造的屏幕共享 ICE: registered={:?}, from={}",
                                            client_id,
                                            from
                                        );
                                        continue;
                                    }

                                    log::debug!(
                                        "📺 转发屏幕共享ICE from {} to {}, shareId={}",
                                        from,
                                        to,
                                        share_id
                                    );

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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareError {
                                    from,
                                    to,
                                    share_id,
                                    error,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送屏幕共享错误，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "📺 转发屏幕共享错误 from {} to {}, shareId={}, error={}",
                                        from,
                                        to,
                                        share_id,
                                        error
                                    );

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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareListRequest { from } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试请求屏幕共享列表，拒绝: {}",
                                            addr
                                        );
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
                                    )
                                    .await;
                                }
                                SignalingMessage::ScreenShareListResponse {
                                    from,
                                    to,
                                    share_id,
                                    player_name,
                                    has_password,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送屏幕共享列表响应，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "📋 转发屏幕共享列表响应 from {} to {}, shareId={}",
                                        from,
                                        to,
                                        share_id
                                    );

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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::ScreenShareViewerLeft { from, share_id } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送查看者离开消息，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!(
                                            "拒绝伪造的屏幕共享离开消息: registered={:?}, from={}",
                                            client_id,
                                            from
                                        );
                                        continue;
                                    }

                                    log::info!(
                                        "👋 收到查看者离开消息 from {}, shareId={}",
                                        from,
                                        share_id
                                    );

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
                                    )
                                    .await;
                                }
                                SignalingMessage::ScreenShareUpdate {
                                    from,
                                    share_id,
                                    viewer_id,
                                    viewer_name,
                                    viewer_count,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送共享状态更新，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }
                                    if client_id.as_deref() != Some(from.as_str()) {
                                        log::warn!(
                                            "拒绝伪造的屏幕共享状态更新: registered={:?}, from={}",
                                            client_id,
                                            from
                                        );
                                        continue;
                                    }

                                    log::info!(
                                        "🔄 收到共享状态更新 from {}, shareId={}, viewerId={:?}",
                                        from,
                                        share_id,
                                        viewer_id
                                    );

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
                                    )
                                    .await;
                                }
                                SignalingMessage::FileShareAdded {
                                    from,
                                    share_id,
                                    share_name,
                                    player_name,
                                    has_password,
                                } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试添加文件共享，拒绝: {}",
                                            addr
                                        );
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
                                    )
                                    .await;
                                }
                                SignalingMessage::FileShareRemoved { from, share_id } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试删除文件共享，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "📁 文件共享删除 from {}: shareId={}",
                                        from,
                                        share_id
                                    );

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
                                    )
                                    .await;
                                }
                                SignalingMessage::FileShareListRequest { from } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试请求文件共享列表，拒绝: {}",
                                            addr
                                        );
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
                                    )
                                    .await;
                                }
                                SignalingMessage::FileShareListResponse { from, to, shares } => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册的客户端尝试发送文件共享列表响应，拒绝: {}",
                                            addr
                                        );
                                        break;
                                    }

                                    log::info!(
                                        "📋 转发文件共享列表响应 from {} to {}, shares={}",
                                        from,
                                        to,
                                        shares.len()
                                    );

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
                                        if !send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await
                                        {
                                            log::warn!(
                                                "目标客户端不在同一大厅或发送失败: {}",
                                                target_id
                                            );
                                        }
                                    }
                                }
                                SignalingMessage::Ping => {
                                    // 心跳检测：立即回复 pong，保持连接存活
                                    // 注意：浏览器/WebView 的 WebSocket API 无法发送协议级 ping 帧，
                                    // 客户端使用应用层 {type:"ping"}，服务器必须回 {type:"pong"}，
                                    // 否则客户端会因 5 秒收不到 pong 而误判断线并不断重连。
                                    if let Ok(json) = serde_json::to_string(&SignalingMessage::Pong)
                                    {
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
                                                server_node: lobby.server_node.clone(),
                                            });
                                        }
                                    }
                                    drop(lobbies_read);
                                    let resp = SignalingMessage::PublicLobbyListResponse {
                                        lobbies: public_list,
                                    };
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        send_text(&write, json).await;
                                    }
                                }
                                SignalingMessage::CommunityNodeListRequest => {
                                    // 共享节点列表：与公开广场一致，无需注册即可查询
                                    log::info!("🌐 收到共享节点列表请求 from {}", addr);
                                    let nodes = community_node_list(&community_nodes).await;
                                    let resp =
                                        SignalingMessage::CommunityNodeListResponse { nodes };
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        send_text(&write, json).await;
                                    }
                                }
                                SignalingMessage::CommunityNodeSubmit {
                                    name,
                                    address,
                                    submitter,
                                } => {
                                    // 投稿共享节点：无需注册（用户可能还没进大厅就想分享节点）
                                    let resp = handle_community_node_submit(
                                        &community_nodes,
                                        &submit_cooldowns,
                                        addr,
                                        name,
                                        address,
                                        submitter,
                                    )
                                    .await;
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        send_text(&write, json).await;
                                    }
                                }
                                SignalingMessage::CommunityNodeListResponse { .. }
                                | SignalingMessage::CommunityNodeSubmitResult { .. } => {
                                    // 服务器 -> 客户端方向的消息，客户端不应发送，忽略即可
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
                                    let mut target_disconnect = None;
                                    let mut target_removed = false;
                                    let mut chat_rotation = None;
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
                                                target_disconnect = Some(t.disconnect.clone());
                                                lobby.muted.remove(&target);
                                                target_removed = true;
                                                let (token, epoch) = rotate_chat_token(lobby);
                                                let targets = lobby
                                                    .clients
                                                    .iter()
                                                    .map(|(id, client)| {
                                                        (id.clone(), Arc::clone(&client.sender))
                                                    })
                                                    .collect::<Vec<_>>();
                                                chat_rotation = Some((targets, token, epoch));

                                                let mut map = client_lobby_map.write().await;
                                                if map
                                                    .get(&target)
                                                    .map(|mapped_lobby| mapped_lobby == &lid)
                                                    .unwrap_or(false)
                                                {
                                                    map.remove(&target);
                                                }
                                            }
                                        }
                                    }
                                    if !target_removed {
                                        continue;
                                    }
                                    if let Some(disconnect) = target_disconnect {
                                        let _ = disconnect.send(true);
                                    }
                                    // 通知被踢者
                                    if let Some(sender) = target_sender {
                                        let kicked = SignalingMessage::Kicked {
                                            reason: "你已被房主移出大厅".to_string(),
                                        };
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
                                        SignalingMessage::PlayerLeft {
                                            player_id: target.clone(),
                                        },
                                    )
                                    .await;
                                    if let Some((targets, token, epoch)) = chat_rotation {
                                        send_chat_token_rotation(
                                            &lobbies,
                                            targets,
                                            lid.clone(),
                                            token,
                                            epoch,
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::MutePlayer {
                                    from,
                                    target,
                                    muted,
                                } => {
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
                                        SignalingMessage::PlayerMuteChanged {
                                            player_id: target,
                                            muted,
                                        },
                                    )
                                    .await;
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
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::SetLobbyOptions {
                                    from,
                                    max_players,
                                    is_public,
                                    description,
                                    server_node,
                                } => {
                                    if !is_registered {
                                        log::warn!(
                                            "🚫 未注册客户端尝试修改大厅选项，拒绝: {}",
                                            addr
                                        );
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
                                                lobby.max_players = if mp == 0 {
                                                    None
                                                } else {
                                                    Some(mp.min(MAX_LOBBY_MEMBERS as u32))
                                                };
                                            }
                                            if let Some(desc) = description {
                                                if valid_text(&desc, 200, true) {
                                                    lobby.description = desc;
                                                }
                                            }
                                            // 记录房主节点（供公开广场加入者同步）
                                            if let Some(node) = server_node {
                                                if valid_text(&node, 512, false) {
                                                    lobby.server_node = node;
                                                }
                                            }
                                            if let Some(pubf) = is_public {
                                                lobby.is_public = effective_public_setting(
                                                    pubf,
                                                    lobby.is_passwordless,
                                                );
                                                if pubf && !lobby.is_passwordless {
                                                    log::warn!(
                                                        "拒绝将有密码大厅发布到公开广场: {}",
                                                        lobby.lobby_name
                                                    );
                                                }
                                            }
                                            changed = Some((lobby.max_players, lobby.is_public));
                                        }
                                    }
                                    if let Some((mp, pubf)) = changed {
                                        log::info!(
                                            "⚙️ 房主 {} 更新大厅选项: max={:?}, public={}",
                                            from,
                                            mp,
                                            pubf
                                        );
                                        broadcast_to_lobby(
                                            &lobbies,
                                            &lid,
                                            "",
                                            SignalingMessage::LobbyOptionsChanged {
                                                max_players: mp,
                                                is_public: pubf,
                                            },
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::Forward => {
                                    // 检查客户端是否已注册
                                    if !is_registered {
                                        log::warn!("🚫 未注册的客户端尝试转发消息，拒绝: {}", addr);
                                        break;
                                    }

                                    // 解析原始JSON以获取from和to字段
                                    if let Ok(json_value) =
                                        serde_json::from_str::<serde_json::Value>(text)
                                    {
                                        // 检查消息类型
                                        let msg_type =
                                            json_value.get("type").and_then(|v| v.as_str());

                                        // 文件共享广播消息（share-added, share-removed, share-updated）
                                        if matches!(
                                            msg_type,
                                            Some("share-added")
                                                | Some("share-removed")
                                                | Some("share-updated")
                                        ) {
                                            if let Some(from) =
                                                json_value.get("from").and_then(|v| v.as_str())
                                            {
                                                log::debug!(
                                                    "广播文件共享消息: {:?} from {}",
                                                    msg_type,
                                                    from
                                                );

                                                // 获取发送者所在大厅
                                                let lid = match client_lobby_map
                                                    .read()
                                                    .await
                                                    .get(from)
                                                {
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
                                                                .filter(|(id, _)| {
                                                                    id.as_str() != from
                                                                })
                                                                .map(|(_, client)| {
                                                                    Arc::clone(&client.sender)
                                                                })
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
                                            json_value.get("to").and_then(|v| v.as_str()),
                                        ) {
                                            log::debug!("转发消息 from {} to {}", from, to);

                                            // 获取发送者所在大厅
                                            let lid = match client_lobby_map.read().await.get(from)
                                            {
                                                Some(id) => id.clone(),
                                                None => {
                                                    log::warn!("发送者不在任何大厅: {}", from);
                                                    continue;
                                                }
                                            };

                                            // 转发到目标客户端（必须在同一大厅）
                                            if !send_to_lobby_client(
                                                &lobbies,
                                                &lid,
                                                to,
                                                Message::Text(text.to_string()),
                                            )
                                            .await
                                            {
                                                log::warn!(
                                                    "目标客户端不在同一大厅或发送失败: {}",
                                                    to
                                                );
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
                                log::warn!(
                                    "🚫 检测到旧版本客户端（缺少必需字段），拒绝连接: {}",
                                    addr
                                );

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
        let mut chat_rotation = None;
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
                    let (token, epoch) = rotate_chat_token(lobby);
                    let targets = lobby
                        .clients
                        .iter()
                        .map(|(id, client)| (id.clone(), Arc::clone(&client.sender)))
                        .collect::<Vec<_>>();
                    chat_rotation = Some((targets, token, epoch));
                    log::info!("大厅 {} 剩余 {} 人", lobby.lobby_name, lobby.clients.len());
                }

                let mut map = client_lobby_map.write().await;
                if map.get(&cid).map(|v| v == &lid).unwrap_or(false) {
                    map.remove(&cid);
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

        // 通知大厅内其他客户端
        broadcast_to_lobby(
            &lobbies,
            &lid,
            &cid,
            SignalingMessage::PlayerLeft {
                player_id: cid.clone(),
            },
        )
        .await;

        if let Some((targets, token, epoch)) = chat_rotation {
            send_chat_token_rotation(&lobbies, targets, lid.clone(), token, epoch).await;
        }

        // 若房主已自动转移，广播房主变更
        if let Some(host_id) = new_host {
            broadcast_to_lobby(
                &lobbies,
                &lid,
                "", // 通知所有人（含新房主）
                SignalingMessage::HostChanged { host_id },
            )
            .await;
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

async fn send_chat_token_rotation(
    lobbies: &Lobbies,
    targets: Vec<(String, ClientSender)>,
    lobby_id: String,
    chat_token: String,
    chat_token_epoch: u64,
) {
    let senders = {
        let lobbies_read = lobbies.read().await;
        let Some(lobby) = lobbies_read.get(&lobby_id) else {
            return;
        };
        // A newer membership change supersedes this notification. Dropping
        // stale epochs here prevents old tokens from arriving after new ones.
        if lobby.chat_token_epoch != chat_token_epoch || lobby.chat_token != chat_token {
            return;
        }
        targets
            .into_iter()
            .filter_map(|(client_id, sender)| {
                lobby
                    .clients
                    .get(&client_id)
                    .filter(|client| Arc::ptr_eq(&client.sender, &sender))
                    .map(|_| sender)
            })
            .collect::<Vec<_>>()
    };
    let message = SignalingMessage::ChatTokenRotated {
        lobby_id,
        chat_token,
        chat_token_epoch,
    };
    let Ok(json) = serde_json::to_string(&message) else {
        return;
    };
    let sends = senders.into_iter().map(|sender| {
        let json = json.clone();
        async move { send_text(&sender, json).await }
    });
    let _ = join_all(sends).await;
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn version_gate_rejects_partial_or_malformed_versions() {
        assert!(is_version_valid("2.8.0", "2.1.0"));
        assert!(!is_version_valid("999.invalid", "2.1.0"));
        assert!(!is_version_valid("2.1", "2.1.0"));
        assert!(!is_version_valid("2.1.0.1", "2.1.0"));
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
        let sender = Arc::new(RwLock::new(sink));
        let (disconnect, _disconnect_rx) = watch::channel(false);
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
                chat_public_key: None,
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
                clients,
                host_id: "slow".to_string(),
                max_players: None,
                is_public: false,
                is_passwordless: true,
                description: String::new(),
                server_node: String::new(),
                muted: std::collections::HashSet::new(),
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
        let register = SignalingMessage::Register {
            client_id: "test-client".to_string(),
            player_name: "Test Player".to_string(),
            virtual_ip: Some("10.126.126.10".to_string()),
            virtual_domain: None,
            use_domain: None,
            lobby_name: "test-lobby".to_string(),
            lobby_password: "test-password".to_string(),
            client_version: Some("2.1.0".to_string()),
            chat_public_key: None,
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
            serde_json::from_str::<SignalingMessage>(
                register_success.to_text().expect("text response")
            )
            .expect("register-success should parse"),
            SignalingMessage::RegisterSuccess { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<SignalingMessage>(
                players_list.to_text().expect("text response")
            )
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
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    fn test_virtual_ip(client_id: &str) -> String {
        let digest = Sha256::digest(client_id.as_bytes());
        let host = ((u16::from(digest[0]) << 8) | u16::from(digest[1])) % 254 + 1;
        format!("10.126.126.{host}")
    }

    fn register_message_with_ip(
        client_id: &str,
        lobby_name: &str,
        lobby_password: &str,
        virtual_ip: &str,
    ) -> Message {
        Message::Text(
            serde_json::json!({
                "type": "register",
                "clientId": client_id,
                "playerName": client_id,
                "virtualIp": virtual_ip,
                "lobbyName": lobby_name,
                "lobbyPassword": lobby_password,
                "clientVersion": "2.7.5"
            })
            .to_string(),
        )
    }

    fn register_message_with_chat_key(
        client_id: &str,
        lobby_name: &str,
        chat_public_key: &str,
    ) -> Message {
        Message::Text(
            serde_json::json!({
                "type": "register",
                "clientId": client_id,
                "playerName": client_id,
                "virtualIp": test_virtual_ip(client_id),
                "lobbyName": lobby_name,
                "lobbyPassword": "password",
                "clientVersion": "2.7.5",
                "chatPublicKey": chat_public_key
            })
            .to_string(),
        )
    }

    fn register_message(client_id: &str, lobby_name: &str, lobby_password: &str) -> Message {
        register_message_with_ip(
            client_id,
            lobby_name,
            lobby_password,
            &test_virtual_ip(client_id),
        )
    }

    async fn register<S>(
        socket: &mut WebSocketStream<S>,
        client_id: &str,
        lobby_name: &str,
    ) -> Value
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        socket
            .send(register_message(client_id, lobby_name, "password"))
            .await
            .unwrap();
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
        let raw = r#"{"type":"remote-control-request","from":"controller-id","to":"phone-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert!(matches!(message, SignalingMessage::Forward));
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
    fn forwarded_message_without_string_sender_does_not_claim_identity() {
        let raw = r#"{"type":"remote-control-request","from":123,"to":"phone-id"}"#;
        let message: SignalingMessage = serde_json::from_str(raw).unwrap();

        assert!(matches!(message, SignalingMessage::Forward));
        assert_eq!(message.claimed_sender(raw), None);
    }

    #[test]
    fn chat_public_keys_are_shape_checked_before_entering_a_roster() {
        // Well formed base64 of a plausible DER length is accepted.
        assert!(valid_chat_public_key(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        ));
        assert!(!valid_chat_public_key(""));
        // Anything outside the base64 alphabet is refused, which keeps quoting
        // and injection tricks out of a field that is later echoed to peers.
        assert!(!valid_chat_public_key("has spaces"));
        assert!(!valid_chat_public_key("bad\ncontrol"));
        assert!(!valid_chat_public_key("<script>"));
        assert!(!valid_chat_public_key(
            &"A".repeat(MAX_CHAT_PUBLIC_KEY_LEN + 1)
        ));

        // Normalization trims but never repairs: invalid input becomes None so
        // an old client can still join, just without signing capability.
        assert_eq!(
            normalize_chat_public_key(Some("  AAAA  ".to_string())),
            Some("AAAA".to_string())
        );
        assert_eq!(normalize_chat_public_key(Some("!!".to_string())), None);
        assert_eq!(normalize_chat_public_key(None), None);
    }

    #[tokio::test]
    async fn chat_public_keys_reach_peers_bound_to_their_owner() {
        let (address, server) = spawn_test_server().await;
        let url = format!("ws://{address}");
        let host_key = "SG9zdEtleQ==";
        let peer_key = "UGVlcktleQ==";

        let (mut host, _) = connect_async(&url).await.unwrap();
        host.send(register_message_with_chat_key("host-id", "room", host_key))
            .await
            .unwrap();
        assert_eq!(next_json(&mut host).await["type"], "register-success");
        assert_eq!(next_json(&mut host).await["type"], "players-list");

        let (mut peer, _) = connect_async(&url).await.unwrap();
        peer.send(register_message_with_chat_key("peer-id", "room", peer_key))
            .await
            .unwrap();
        assert_eq!(next_json(&mut peer).await["type"], "register-success");

        // The joiner's roster must carry the host's key, bound to the host id.
        let roster = next_json(&mut peer).await;
        assert_eq!(roster["type"], "players-list");
        let players = roster["players"].as_array().unwrap();
        assert_eq!(players.len(), 1);
        assert_eq!(players[0]["playerId"], "host-id");
        assert_eq!(players[0]["chatPublicKey"], host_key);

        // And the incremental join event must carry the joiner's own key, so a
        // member never has to guess which key belongs to which player.
        let rotated = next_json(&mut host).await;
        assert_eq!(rotated["type"], "chat-token-rotated");
        let joined = next_json(&mut host).await;
        assert_eq!(joined["type"], "player-joined");
        assert_eq!(joined["playerId"], "peer-id");
        assert_eq!(joined["chatPublicKey"], peer_key);

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
            socket
                .send(register_message_with_ip(
                    &format!("invalid-{index}"),
                    "room",
                    "password",
                    ip,
                ))
                .await
                .unwrap();
            assert_eq!(next_json(&mut socket).await["type"], "register-error");
            socket.close(None).await.unwrap();
        }

        let (mut host, _) = connect_async(&url).await.unwrap();
        register(&mut host, "host-id", "room").await;
        let (mut duplicate_ip, _) = connect_async(&url).await.unwrap();
        duplicate_ip
            .send(register_message_with_ip(
                "other-id",
                "room",
                "password",
                &test_virtual_ip("host-id"),
            ))
            .await
            .unwrap();
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
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
        assert_eq!(next_json(&mut host).await["type"], "player-joined");

        peer.send(Message::Text(
            serde_json::json!({
                "type": "leave",
                "clientId": "peer-id"
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
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
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
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
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
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");

        let (mut new_peer, _) = connect_async(&url).await.unwrap();
        register(&mut new_peer, "peer-id", "room").await;
        assert_eq!(next_json(&mut host).await["type"], "chat-token-rotated");
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
        assert!(timeout(Duration::from_millis(250), host.next())
            .await
            .is_err());

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
            retry
                .send(register_message("ghost-id", "room", "password"))
                .await
                .unwrap();
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

        let (mut target, _) = connect_async(&url).await.unwrap();
        register(&mut target, "target-b", "room-b").await;
        let (mut peer, _) = connect_async(&url).await.unwrap();
        register(&mut peer, "peer-b", "room-b").await;
        assert_eq!(next_json(&mut target).await["type"], "chat-token-rotated");
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
        assert!(timeout(Duration::from_millis(250), host.next())
            .await
            .is_err());

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
}
