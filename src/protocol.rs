//! Wire protocol: message schema, bounded payload validation, and roster types.
use super::*;

/// WebSocket 信令消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SignalingMessage {
    /// 服务端在连接建立后立即下发的一次性注册挑战。
    ServerChallenge {
        challenge: String,
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
    },
    /// 协议 v3 注册。身份由 identityPublicKey 的 SHA-256 指纹派生，客户端
    /// 不能再自行选择 clientId。
    #[serde(rename = "register-v3")]
    RegisterV3 {
        #[serde(rename = "protocolVersion")]
        protocol_version: u32,
        #[serde(rename = "identityPublicKey")]
        identity_public_key: String,
        #[serde(rename = "challengeSignature")]
        challenge_signature: String,
        #[serde(rename = "playerName")]
        player_name: String,
        #[serde(rename = "virtualIp", skip_serializing_if = "Option::is_none")]
        virtual_ip: Option<String>,
        #[serde(rename = "lobbyName")]
        lobby_name: String,
        #[serde(rename = "lobbyPassword")]
        lobby_password: String,
        #[serde(rename = "clientVersion", skip_serializing_if = "Option::is_none")]
        client_version: Option<String>,
        #[serde(rename = "virtualDomain", skip_serializing_if = "Option::is_none")]
        virtual_domain: Option<String>,
        #[serde(rename = "useDomain", skip_serializing_if = "Option::is_none")]
        use_domain: Option<bool>,
    },
    /// 旧协议注册消息。仅为返回明确的迁移错误而保留，绝不进入注册流程。
    #[serde(rename = "register")]
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
        #[serde(rename = "chatPublicKey", skip_serializing_if = "Option::is_none")]
        chat_public_key: Option<String>,
    },
    /// 注册成功
    RegisterSuccess {
        #[serde(rename = "clientId")]
        client_id: String,
        #[serde(rename = "sessionGeneration")]
        session_generation: u64,
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
    /// 当前连接请求一次权威成员快照；不会触发第二次注册。
    #[serde(rename = "players-list-request")]
    PlayersListRequest,
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
        #[serde(rename = "sessionGeneration")]
        session_generation: u64,
    },
    /// 玩家离开
    PlayerLeft {
        #[serde(rename = "playerId")]
        player_id: String,
        #[serde(rename = "sessionGeneration")]
        session_generation: u64,
    },
    /// WebRTC Offer
    Offer {
        from: String,
        to: String,
        offer: OfferData,
        #[serde(rename = "playerName", skip_serializing_if = "Option::is_none")]
        player_name: Option<String>,
    },
    /// Request a fresh voice negotiation with one authenticated lobby member.
    VoiceReconnect { from: String, to: String },
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
        #[serde(skip_serializing_if = "Option::is_none")]
        sequence: Option<u64>,
        #[serde(rename = "sourceSequence", skip_serializing_if = "Option::is_none")]
        source_sequence: Option<u64>,
        #[serde(rename = "sentSequence", skip_serializing_if = "Option::is_none")]
        sent_sequence: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        limited: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
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
    /// 文件共享状态更新。显式建模，禁止通过 wildcard Forward 注入任意 JSON。
    #[serde(rename = "share-updated")]
    ShareUpdated {
        from: String,
        #[serde(rename = "shareId")]
        share_id: String,
        #[serde(rename = "shareName", skip_serializing_if = "Option::is_none")]
        share_name: Option<String>,
        #[serde(rename = "playerName", skip_serializing_if = "Option::is_none")]
        player_name: Option<String>,
        #[serde(rename = "hasPassword", skip_serializing_if = "Option::is_none")]
        has_password: Option<bool>,
    },
    /// 远程控制信令全部使用显式 schema，并且每一种消息都带 from。
    #[serde(rename = "remote-control-request")]
    RemoteControlRequest {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "fromName")]
        from_name: String,
    },
    #[serde(rename = "remote-control-accept")]
    RemoteControlAccept {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
    },
    #[serde(rename = "remote-control-reject")]
    RemoteControlReject {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        reason: String,
    },
    #[serde(rename = "remote-control-offer")]
    RemoteControlOffer {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        offer: OfferData,
    },
    #[serde(rename = "remote-control-answer")]
    RemoteControlAnswer {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        answer: AnswerData,
    },
    #[serde(rename = "remote-control-ice")]
    RemoteControlIce {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        candidate: CandidateData,
    },
    #[serde(rename = "remote-control-stop")]
    RemoteControlStop {
        from: String,
        to: String,
        #[serde(rename = "sessionId")]
        session_id: String,
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
}

impl SignalingMessage {
    /// Return the identity claimed by a client-originated message.
    ///
    /// The WebSocket connection is the authentication boundary. Callers must
    /// compare this value with the id registered on that same connection before
    /// routing or authorizing the message.
    pub(crate) fn claimed_sender(&self, _raw: &str) -> Option<String> {
        match self {
            Self::Offer { from, .. }
            | Self::VoiceReconnect { from, .. }
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
            | Self::ShareUpdated { from, .. }
            | Self::RemoteControlRequest { from, .. }
            | Self::RemoteControlAccept { from, .. }
            | Self::RemoteControlReject { from, .. }
            | Self::RemoteControlOffer { from, .. }
            | Self::RemoteControlAnswer { from, .. }
            | Self::RemoteControlIce { from, .. }
            | Self::RemoteControlStop { from, .. }
            | Self::KickPlayer { from, .. }
            | Self::MutePlayer { from, .. }
            | Self::TransferHost { from, .. }
            | Self::SetLobbyOptions { from, .. } => Some(from.clone()),
            Self::StatusUpdate { client_id, .. } | Self::Leave { client_id } => {
                Some(client_id.clone())
            }
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
    #[serde(rename = "sessionGeneration")]
    pub session_generation: u64,
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

pub(crate) fn parse_virtual_ipv4(raw: Option<&str>) -> Option<Ipv4Addr> {
    let ip = raw?.trim().parse::<Ipv4Addr>().ok()?;
    let octets = ip.octets();
    if octets[..3] != [10, 126, 126] || octets[3] == 0 || octets[3] == 255 {
        return None;
    }
    Some(ip)
}

pub(crate) fn valid_text(value: &str, max_len: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty())
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    valid_text(value, MAX_CLIENT_ID_LEN, false)
}

pub(crate) fn valid_control_text(value: &str, max_len: usize, allow_empty: bool) -> bool {
    valid_text(value, max_len.min(MAX_CONTROL_TEXT_LEN), allow_empty)
}

pub(crate) fn valid_session_id(value: &str) -> bool {
    valid_text(value, MAX_REMOTE_SESSION_ID_LEN, false)
}

pub(crate) fn valid_share_id(value: &str) -> bool {
    valid_text(value, MAX_SHARE_ID_LEN, false)
}

pub(crate) fn valid_session_description(sdp_type: &str, sdp: &str, expected_type: &str) -> bool {
    sdp_type == expected_type
        && sdp.len() <= MAX_SDP_LEN
        && !sdp.is_empty()
        // SDP is conventionally CRLF-delimited; reject other controls while
        // preserving the wire format emitted by WebRTC implementations.
        && !sdp
            .chars()
            .any(|ch| ch.is_control() && ch != '\r' && ch != '\n')
}

pub(crate) fn valid_offer_data(data: &OfferData, expected_type: &str) -> bool {
    valid_session_description(&data.sdp_type, &data.sdp, expected_type)
}

pub(crate) fn valid_answer_data(data: &AnswerData, expected_type: &str) -> bool {
    valid_session_description(&data.sdp_type, &data.sdp, expected_type)
}

pub(crate) fn valid_candidate_data(data: &CandidateData) -> bool {
    !data.candidate.is_empty()
        && data.candidate.len() <= MAX_ICE_CANDIDATE_LEN
        && !data.candidate.chars().any(char::is_control)
        && data.sdp_m_line_index.is_none_or(|index| index <= 256)
        && data
            .sdp_mid
            .as_deref()
            .is_none_or(|mid| valid_control_text(mid, 128, true))
}

/// Apply payload limits before any routing or logging. WebSocket frame limits
/// protect the parser; these bounds protect downstream consumers and logs.
pub(crate) fn validate_message_shape(message: &SignalingMessage) -> bool {
    let ids = |from: &str, to: &str| valid_identifier(from) && valid_identifier(to);
    let optional_control = |value: Option<&String>, max_len: usize| {
        value.is_none() || value.is_some_and(|value| valid_control_text(value, max_len, true))
    };
    match message {
        SignalingMessage::ServerChallenge { challenge, .. } => {
            challenge.len() == CHALLENGE_BYTES * 2
                && challenge
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        SignalingMessage::RegisterV3 {
            identity_public_key,
            challenge_signature,
            player_name,
            virtual_ip,
            virtual_domain,
            lobby_name,
            lobby_password,
            client_version,
            ..
        } => {
            identity_public_key.len() <= MAX_IDENTITY_PUBLIC_KEY_LEN
                && challenge_signature.len() <= MAX_IDENTITY_SIGNATURE_LEN
                && valid_control_text(player_name, MAX_PLAYER_NAME_LEN, false)
                && virtual_ip
                    .as_deref()
                    .is_some_and(|ip| valid_control_text(ip, 32, false))
                && optional_control(virtual_domain.as_ref(), MAX_VIRTUAL_DOMAIN_LEN)
                && valid_control_text(lobby_name, MAX_LOBBY_NAME_LEN, false)
                && valid_control_text(lobby_password, MAX_LOBBY_PASSWORD_LEN, true)
                && optional_control(client_version.as_ref(), MAX_CLIENT_VERSION_LEN)
        }
        SignalingMessage::Register {
            client_id,
            player_name,
            virtual_ip,
            virtual_domain,
            lobby_name,
            lobby_password,
            client_version,
            chat_public_key,
            ..
        } => {
            valid_identifier(client_id)
                && valid_control_text(player_name, MAX_PLAYER_NAME_LEN, false)
                && virtual_ip
                    .as_deref()
                    .is_none_or(|ip| valid_control_text(ip, 32, false))
                && optional_control(virtual_domain.as_ref(), MAX_VIRTUAL_DOMAIN_LEN)
                && valid_control_text(lobby_name, MAX_LOBBY_NAME_LEN, false)
                && valid_control_text(lobby_password, MAX_LOBBY_PASSWORD_LEN, true)
                && optional_control(client_version.as_ref(), MAX_CLIENT_VERSION_LEN)
                && optional_control(chat_public_key.as_ref(), MAX_CHAT_PUBLIC_KEY_LEN)
        }
        SignalingMessage::Offer {
            from, to, offer, ..
        } => ids(from, to) && valid_offer_data(offer, "offer"),
        SignalingMessage::Answer { from, to, answer } => {
            ids(from, to) && valid_answer_data(answer, "answer")
        }
        SignalingMessage::VoiceReconnect { from, to } => ids(from, to) && from != to,
        SignalingMessage::IceCandidate {
            from,
            to,
            candidate,
        } => ids(from, to) && valid_candidate_data(candidate),
        SignalingMessage::ChatMessage {
            from,
            player_id,
            player_name,
            content,
            ..
        } => {
            valid_identifier(from)
                && valid_identifier(player_id)
                && valid_control_text(player_name, MAX_PLAYER_NAME_LEN, false)
                && valid_control_text(content, MAX_CONTROL_TEXT_LEN, false)
        }
        SignalingMessage::StatusUpdate { client_id, .. } => valid_identifier(client_id),
        SignalingMessage::ScreenShareStart {
            from,
            share_id,
            player_name,
            ..
        } => {
            valid_identifier(from)
                && valid_share_id(share_id)
                && valid_control_text(player_name, MAX_PLAYER_NAME_LEN, false)
        }
        SignalingMessage::ScreenShareStop { from, share_id }
        | SignalingMessage::ScreenShareViewerLeft { from, share_id } => {
            valid_identifier(from) && valid_share_id(share_id)
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
            sequence,
            source_sequence,
            sent_sequence,
            reason,
            ..
        } => {
            ids(from, to)
                && valid_share_id(share_id)
                && valid_control_text(action, 32, false)
                && optional_control(player_name.as_ref(), MAX_PLAYER_NAME_LEN)
                && optional_control(password.as_ref(), MAX_CONTROL_TEXT_LEN)
                && optional_control(upstream_id.as_ref(), MAX_CLIENT_ID_LEN)
                && optional_control(downstream_id.as_ref(), MAX_CLIENT_ID_LEN)
                && optional_control(reason.as_ref(), 256)
                && [sequence, source_sequence, sent_sequence]
                    .iter()
                    .all(|value| value.is_none_or(|n| n <= 1_000_000_000))
        }
        SignalingMessage::ScreenShareOffer {
            from,
            to,
            share_id,
            player_name,
            password,
            offer,
            ..
        } => {
            ids(from, to)
                && valid_share_id(share_id)
                && optional_control(player_name.as_ref(), MAX_PLAYER_NAME_LEN)
                && optional_control(password.as_ref(), MAX_CONTROL_TEXT_LEN)
                && valid_offer_data(offer, "offer")
        }
        SignalingMessage::ScreenShareAnswer {
            from,
            to,
            share_id,
            answer,
            ..
        } => ids(from, to) && valid_share_id(share_id) && valid_answer_data(answer, "answer"),
        SignalingMessage::ScreenShareIceCandidate {
            from,
            to,
            share_id,
            candidate,
            connection_role,
            ..
        } => {
            ids(from, to)
                && valid_share_id(share_id)
                && optional_control(connection_role.as_ref(), 32)
                && valid_candidate_data(candidate)
        }
        SignalingMessage::ScreenShareError {
            from,
            to,
            share_id,
            error,
        } => {
            ids(from, to)
                && valid_share_id(share_id)
                && valid_control_text(error, MAX_ERROR_TEXT_LEN, false)
        }
        SignalingMessage::ScreenShareListRequest { from }
        | SignalingMessage::FileShareListRequest { from } => valid_identifier(from),
        SignalingMessage::ScreenShareListResponse {
            from,
            to,
            share_id,
            player_name,
            ..
        } => {
            ids(from, to)
                && valid_share_id(share_id)
                && valid_control_text(player_name, MAX_PLAYER_NAME_LEN, false)
        }
        SignalingMessage::ScreenShareUpdate {
            from,
            share_id,
            viewer_id,
            viewer_name,
            ..
        } => {
            valid_identifier(from)
                && valid_share_id(share_id)
                && optional_control(viewer_id.as_ref(), MAX_CLIENT_ID_LEN)
                && optional_control(viewer_name.as_ref(), MAX_PLAYER_NAME_LEN)
        }
        SignalingMessage::FileShareAdded {
            from,
            share_id,
            share_name,
            player_name,
            ..
        } => {
            valid_identifier(from)
                && valid_share_id(share_id)
                && valid_control_text(share_name, MAX_SHARE_NAME_LEN, false)
                && valid_control_text(player_name, MAX_PLAYER_NAME_LEN, false)
        }
        SignalingMessage::FileShareRemoved { from, share_id } => {
            valid_identifier(from) && valid_share_id(share_id)
        }
        SignalingMessage::FileShareListResponse {
            from, to, shares, ..
        } => {
            ids(from, to)
                && shares.len() <= 256
                && shares.iter().all(|share| {
                    valid_share_id(&share.share_id)
                        && valid_control_text(&share.share_name, MAX_SHARE_NAME_LEN, false)
                        && valid_control_text(&share.player_name, MAX_PLAYER_NAME_LEN, false)
                })
        }
        SignalingMessage::ShareUpdated {
            from,
            share_id,
            share_name,
            player_name,
            ..
        } => {
            valid_identifier(from)
                && valid_share_id(share_id)
                && optional_control(share_name.as_ref(), MAX_SHARE_NAME_LEN)
                && optional_control(player_name.as_ref(), MAX_PLAYER_NAME_LEN)
        }
        SignalingMessage::RemoteControlRequest {
            from,
            to,
            session_id,
            from_name,
        } => {
            ids(from, to)
                && valid_session_id(session_id)
                && valid_control_text(from_name, 64, false)
        }
        SignalingMessage::RemoteControlAccept {
            from,
            to,
            session_id,
        }
        | SignalingMessage::RemoteControlStop {
            from,
            to,
            session_id,
        } => ids(from, to) && valid_session_id(session_id),
        SignalingMessage::RemoteControlReject {
            from,
            to,
            session_id,
            reason,
        } => {
            ids(from, to)
                && valid_session_id(session_id)
                && valid_control_text(reason, MAX_ERROR_TEXT_LEN, false)
        }
        SignalingMessage::RemoteControlOffer {
            from,
            to,
            session_id,
            offer,
        } => ids(from, to) && valid_session_id(session_id) && valid_offer_data(offer, "offer"),
        SignalingMessage::RemoteControlAnswer {
            from,
            to,
            session_id,
            answer,
        } => ids(from, to) && valid_session_id(session_id) && valid_answer_data(answer, "answer"),
        SignalingMessage::RemoteControlIce {
            from,
            to,
            session_id,
            candidate,
        } => ids(from, to) && valid_session_id(session_id) && valid_candidate_data(candidate),
        SignalingMessage::Leave { client_id } => valid_identifier(client_id),
        SignalingMessage::KickPlayer { from, target }
        | SignalingMessage::MutePlayer { from, target, .. }
        | SignalingMessage::TransferHost { from, target } => {
            valid_identifier(from) && valid_identifier(target)
        }
        SignalingMessage::SetLobbyOptions {
            from,
            description,
            server_node,
            ..
        } => {
            valid_identifier(from)
                && optional_control(description.as_ref(), MAX_CONTROL_TEXT_LEN)
                && optional_control(server_node.as_ref(), MAX_LOBBY_PASSWORD_LEN)
        }
        SignalingMessage::CommunityNodeSubmit {
            name,
            address,
            submitter,
        } => {
            valid_control_text(name, COMMUNITY_NODE_NAME_MAX_LEN, false)
                && valid_control_text(address, COMMUNITY_NODE_ADDRESS_MAX_LEN, false)
                && optional_control(submitter.as_ref(), COMMUNITY_NODE_SUBMITTER_MAX_LEN)
        }
        _ => true,
    }
}

/// Identity keys are parsed and verified during v3 registration. This helper is
/// retained for tests and roster assertions only.
pub(crate) fn valid_chat_public_key(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CHAT_PUBLIC_KEY_LEN {
        return false;
    }
    BASE64_STANDARD
        .decode(value)
        .ok()
        .is_some_and(|der| VerifyingKey::from_public_key_der(&der).is_ok())
}

/// 归一化注册时提交的公钥：非法值一律丢弃成 None，而不是原样入册。
pub(crate) fn normalize_chat_public_key(raw: Option<String>) -> Option<String> {
    let trimmed = raw?.trim().to_string();
    if valid_chat_public_key(&trimmed) {
        Some(trimmed)
    } else {
        log::warn!("丢弃格式非法的聊天签名公钥");
        None
    }
}

pub(crate) fn effective_public_setting(requested_public: bool, is_passwordless: bool) -> bool {
    requested_public && is_passwordless
}
