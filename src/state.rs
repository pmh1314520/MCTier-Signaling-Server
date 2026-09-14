//! Shared lobby/session state and bounded runtime counters.
use super::security::generate_chat_token;
use super::*;

/// 客户端信息
#[derive(Debug, Clone)]
pub(crate) struct ClientInfo {
    pub(crate) player_id: String,
    pub(crate) player_name: String,
    pub(crate) virtual_ip: Option<String>,
    pub(crate) virtual_domain: Option<String>,
    pub(crate) use_domain: Option<bool>,
    /// 协议 v3 身份公钥，同时用于 P2P 聊天请求验签。
    pub(crate) chat_public_key: Option<String>,
    pub(crate) session_generation: u64,
    pub(crate) sender: ClientSender,
    pub(crate) disconnect: watch::Sender<bool>,
}

/// 大厅信息
#[derive(Debug, Clone)]
pub(crate) struct LobbyInfo {
    pub(crate) lobby_name: String,
    pub(crate) password_hash: String,
    /// 密码哈希盐：大厅创建时随机生成，杜绝无盐彩虹表命中。
    pub(crate) password_salt: String,
    pub(crate) clients: HashMap<String, ClientInfo>,
    /// 房主客户端ID
    pub(crate) host_id: String,
    /// 人数上限（None = 不限）
    pub(crate) max_players: Option<u32>,
    /// 是否发布到公开广场
    pub(crate) is_public: bool,
    /// 公开大厅必须使用空网络密码，不得通过广场传播密钥。
    pub(crate) is_passwordless: bool,
    /// 广场描述
    pub(crate) description: String,
    /// 房主使用的 EasyTier 节点地址（公开大厅时下发给加入者，保证节点一致可互通）
    pub(crate) server_node: String,
    /// 被禁言的客户端ID集合
    pub(crate) muted: HashSet<String>,
    /// CSPRNG credential shared by active members for the P2P chat service.
    /// The lobby entry is destroyed when its last member leaves, so the next
    /// incarnation receives a fresh token.
    pub(crate) chat_token: String,
    pub(crate) chat_token_epoch: u64,
}

/// 全局大厅列表
pub(crate) type Lobbies = Arc<RwLock<HashMap<String, LobbyInfo>>>;

/// 客户端ID到大厅ID的映射
pub(crate) type ClientLobbyMap = Arc<RwLock<HashMap<String, String>>>;

/// 用户投稿的共享节点注册表（key = 归一化后的地址）
pub(crate) type CommunityNodes = Arc<RwLock<HashMap<String, CommunityNodeInfo>>>;

/// 投稿限流表：来源 IP -> 最近一次投稿时间（Unix 秒）
pub(crate) type SubmitCooldowns = Arc<RwLock<HashMap<std::net::IpAddr, u64>>>;

#[derive(Debug)]
pub(crate) struct SubmitQuota {
    pub(crate) window_started: tokio::time::Instant,
    pub(crate) submissions: u32,
}

pub(crate) fn allow_submit_quota(quota: &mut SubmitQuota) -> bool {
    if quota.window_started.elapsed()
        >= tokio::time::Duration::from_secs(COMMUNITY_NODE_SUBMIT_WINDOW_SECS)
    {
        quota.window_started = tokio::time::Instant::now();
        quota.submissions = 0;
    }
    if quota.submissions >= COMMUNITY_NODE_SUBMIT_MAX_PER_WINDOW {
        return false;
    }
    quota.submissions += 1;
    true
}

pub(crate) type SubmitQuotas = Arc<Mutex<HashMap<std::net::IpAddr, SubmitQuota>>>;
pub(crate) type ProbeLimiter = Arc<Semaphore>;

#[derive(Debug)]
pub(crate) struct OutboundBudget {
    pub(crate) window_started: tokio::time::Instant,
    pub(crate) frames: u32,
    pub(crate) bytes: usize,
}

impl OutboundBudget {
    pub(crate) fn new() -> Self {
        Self {
            window_started: tokio::time::Instant::now(),
            frames: 0,
            bytes: 0,
        }
    }

    pub(crate) fn allow(&mut self, bytes: usize) -> bool {
        if self.window_started.elapsed()
            >= tokio::time::Duration::from_secs(OUTBOUND_BUDGET_WINDOW_SECS)
        {
            self.window_started = tokio::time::Instant::now();
            self.frames = 0;
            self.bytes = 0;
        }
        if bytes > MAX_OUTBOUND_BYTES_PER_WINDOW
            || self.frames >= MAX_OUTBOUND_FRAMES_PER_WINDOW
            || self.bytes.saturating_add(bytes) > MAX_OUTBOUND_BYTES_PER_WINDOW
        {
            return false;
        }
        self.frames += 1;
        self.bytes += bytes;
        true
    }
}

#[derive(Debug)]
pub(crate) struct ClientSenderState {
    pub(crate) sink: RwLock<
        futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, Message>,
    >,
    pub(crate) budget: Mutex<OutboundBudget>,
}

pub(crate) type ClientSender = Arc<ClientSenderState>;

#[derive(Debug)]
pub(crate) struct MessageRateLimiter {
    pub(crate) window_started: tokio::time::Instant,
    pub(crate) messages: u32,
}

impl MessageRateLimiter {
    pub(crate) fn new() -> Self {
        Self {
            window_started: tokio::time::Instant::now(),
            messages: 0,
        }
    }

    pub(crate) fn allow(&mut self) -> bool {
        if self.window_started.elapsed()
            >= tokio::time::Duration::from_secs(MESSAGE_RATE_WINDOW_SECS)
        {
            self.window_started = tokio::time::Instant::now();
            self.messages = 0;
        }
        if self.messages >= MAX_MESSAGES_PER_WINDOW {
            return false;
        }
        self.messages += 1;
        true
    }
}

pub(crate) const MAX_REGISTER_PASSWORD_FAILURES: usize = 5;
pub(crate) const REGISTER_PASSWORD_FAILURE_WINDOW_SECS: u64 = 300;
/// 失败表键数量上限，防止攻击者通过轮换来源 IP 撑大内存。
pub(crate) const MAX_REGISTER_PASSWORD_KEYS: usize = 4096;

/// 大厅密码失败限制器：与 file_transfer 的共享密码限制器同构。
/// 同一来源 IP 对同一大厅的连续错误密码会触发锁定，且错误会直接断开
/// WebSocket，迫使攻击者每次尝试都重新完成握手与身份签名。
pub(crate) struct RegisterPasswordFailures {
    pub(crate) attempts: HashMap<(IpAddr, String), VecDeque<Instant>>,
}

impl RegisterPasswordFailures {
    pub(crate) fn prune(&mut self, now: Instant) {
        let window = tokio::time::Duration::from_secs(REGISTER_PASSWORD_FAILURE_WINDOW_SECS);
        self.attempts.retain(|_, attempts| {
            while attempts
                .front()
                .is_some_and(|attempt| now.duration_since(*attempt) > window)
            {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
    }

    /// Only failures for this source and lobby may lock its registration.
    pub(crate) fn is_locked(&mut self, key: &(IpAddr, String), now: Instant) -> bool {
        self.prune(now);
        match self.attempts.get(key) {
            Some(attempts) => attempts.len() >= MAX_REGISTER_PASSWORD_FAILURES,
            None => false,
        }
    }

    pub(crate) fn record_failure(&mut self, key: &(IpAddr, String), now: Instant) {
        self.prune(now);
        if !self.attempts.contains_key(key) && self.attempts.len() >= MAX_REGISTER_PASSWORD_KEYS {
            // Bound memory by retiring the least recently failed key, never by
            // denying registration to unrelated users when the table is full.
            let oldest = self
                .attempts
                .iter()
                .min_by_key(|(_, attempts)| attempts.back().copied())
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.attempts.remove(&oldest);
            }
        }
        let attempts = self.attempts.entry(key.clone()).or_default();
        if attempts.len() < MAX_REGISTER_PASSWORD_FAILURES {
            attempts.push_back(now);
        }
    }

    pub(crate) fn clear(&mut self, key: &(IpAddr, String)) {
        self.attempts.remove(key);
    }
}

pub(crate) fn register_password_failures() -> &'static std::sync::Mutex<RegisterPasswordFailures> {
    static VALUE: std::sync::OnceLock<std::sync::Mutex<RegisterPasswordFailures>> =
        std::sync::OnceLock::new();
    VALUE.get_or_init(|| {
        std::sync::Mutex::new(RegisterPasswordFailures {
            attempts: HashMap::new(),
        })
    })
}

pub(crate) fn rotate_chat_token(lobby: &mut LobbyInfo) -> (String, u64) {
    lobby.chat_token = generate_chat_token();
    lobby.chat_token_epoch = lobby.chat_token_epoch.saturating_add(1).max(1);
    (lobby.chat_token.clone(), lobby.chat_token_epoch)
}

#[cfg(test)]
mod password_capacity_tests {
    use super::*;

    #[test]
    fn full_failure_table_does_not_lock_unrelated_users_and_stays_bounded() {
        let now = Instant::now();
        let mut failures = RegisterPasswordFailures {
            attempts: HashMap::new(),
        };
        let attacker = "192.0.2.1".parse().unwrap();
        for index in 0..MAX_REGISTER_PASSWORD_KEYS {
            failures.record_failure(&(attacker, format!("room-{index}")), now);
        }
        let innocent = ("192.0.2.2".parse().unwrap(), "new-room".to_string());
        assert!(!failures.is_locked(&innocent, now));
        failures.record_failure(&innocent, now);
        assert!(failures.attempts.len() <= MAX_REGISTER_PASSWORD_KEYS);
        for _ in 1..MAX_REGISTER_PASSWORD_FAILURES {
            failures.record_failure(&innocent, now);
        }
        assert!(failures.is_locked(&innocent, now));
        let stranger = ("192.0.2.3".parse().unwrap(), "another-room".to_string());
        assert!(!failures.is_locked(&stranger, now));
    }
}
