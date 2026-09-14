//! Community node submission, persistence, and reachability sweeping.
use super::*;
#[cfg(not(test))]
use crate::state::*;

// ==================== 用户投稿的共享节点 ====================

/// 节点连续探测失败（或从未成功）超过该时长后自动移除。
///
/// 需求为“节点失效超过 1 天时自动移除”，因此这里以“最近一次探测成功时间”
/// 为基准：只要 now - last_ok_at 超过该阈值即淘汰。刚投稿的节点必须先通过
/// 一次探测才会入库，因此 last_ok_at 不会是 0。
pub(crate) const COMMUNITY_NODE_MAX_OFFLINE_SECS: u64 = 24 * 60 * 60;

/// 后台巡检周期：每轮对全部投稿节点做一次可达性探测
pub(crate) const COMMUNITY_NODE_PROBE_INTERVAL_SECS: u64 = 5 * 60;

/// 单个节点的探测超时
pub(crate) const COMMUNITY_NODE_PROBE_TIMEOUT_SECS: u64 = 3;

/// 单轮巡检的最大并发探测数，避免节点很多时瞬间打满 fd
pub(crate) const COMMUNITY_NODE_PROBE_CONCURRENCY: usize = 16;

/// 注册表容量上限（可通过环境变量 COMMUNITY_NODE_CAPACITY 覆盖）
pub(crate) const DEFAULT_COMMUNITY_NODE_CAPACITY: usize = 200;

/// 持久化文件路径（可通过环境变量 COMMUNITY_NODES_FILE 覆盖）
pub(crate) const DEFAULT_COMMUNITY_NODES_FILE: &str = "community_nodes.json";

/// 同一来源 IP 两次投稿之间的最小间隔，防刷
pub(crate) const COMMUNITY_NODE_SUBMIT_COOLDOWN_SECS: u64 = 30;

/// 投稿节点名称长度上限
pub(crate) const COMMUNITY_NODE_NAME_MAX_LEN: usize = 32;

/// 投稿节点地址长度上限
pub(crate) const COMMUNITY_NODE_ADDRESS_MAX_LEN: usize = 128;

/// 投稿者昵称长度上限
pub(crate) const COMMUNITY_NODE_SUBMITTER_MAX_LEN: usize = 24;

/// 与桌面端 `parse_node_host_port` 保持同样的默认端口约定，避免两端对
/// “同一个地址是否可达”得出不同结论。
pub(crate) fn parse_node_host_port(address: &str) -> Option<(String, u16)> {
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
pub(crate) fn normalize_community_node_address(address: &str) -> Result<String, &'static str> {
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
pub(crate) fn sanitize_community_text(raw: &str, max_len: usize) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

/// 探测目标数量上限：DNS 可能返回大量地址，逐个探测会把服务器变成放大器
pub(crate) const COMMUNITY_NODE_PROBE_MAX_TARGETS: usize = 4;

/// 探测结果：区分“确实不可达”与“地址不允许探测”，便于给投稿者精确回执
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    Alive(u64),
    Dead,
    Blocked,
    Busy,
}

/// 判断 IP 是否允许作为探测目标。
///
/// 投稿接口对任何人开放，而服务器会主动连接投稿地址：若不加限制，攻击者就能
/// 借信令服务器扫描回环/内网/云厂商元数据地址（169.254.169.254），再通过
/// “投稿成功 / 不可达”的回执读出端口开放状态，等于白送一个 SSRF + 端口扫描器。
/// 因此这里只放行公网可路由的单播地址。
pub(crate) fn is_public_probe_target(ip: &std::net::IpAddr) -> bool {
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
pub(crate) fn probe_allows_private_targets() -> bool {
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
pub(crate) async fn resolve_probe_targets(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Vec<SocketAddr> {
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
pub(crate) async fn probe_community_node_tcp(targets: &[SocketAddr]) -> Option<u64> {
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
/// 据此判定失效。完全没有回包时按失败处理，避免把任意静默 UDP 端口
/// 当成“共享节点在线”并长期保留。
pub(crate) async fn probe_community_node_udp(target: SocketAddr) -> Option<u64> {
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
        // 既无回包也无 ICMP：不能证明节点存活，按失败处理
        Err(_) => None,
    }
}

pub(crate) async fn probe_community_node_limited(
    address: &str,
    probe_limiter: &ProbeLimiter,
) -> ProbeOutcome {
    let permit = match tokio::time::timeout(
        tokio::time::Duration::from_secs(COMMUNITY_NODE_PROBE_QUEUE_TIMEOUT_SECS),
        probe_limiter.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => return ProbeOutcome::Busy,
    };
    let outcome = probe_community_node(address).await;
    drop(permit);
    outcome
}

/// 探测节点可达性。
///
/// EasyTier 默认会在同一端口同时监听 TCP 与 UDP，因此所有协议都先做 TCP 握手；
/// 只有 `udp://` 在 TCP 不通时才退化为 UDP 探测。
pub(crate) async fn probe_community_node(address: &str) -> ProbeOutcome {
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
pub(crate) fn is_community_node_expired(node: &CommunityNodeInfo, now: u64) -> bool {
    now.saturating_sub(node.last_ok_at) > COMMUNITY_NODE_MAX_OFFLINE_SECS
}

/// 从磁盘载入投稿节点，顺带剔除已过期条目
pub(crate) fn load_community_nodes_from_disk(
    path: &str,
    now: u64,
) -> HashMap<String, CommunityNodeInfo> {
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

pub(crate) fn community_persist_lock() -> &'static Arc<Mutex<()>> {
    static LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
    LOCK.get_or_init(|| Arc::new(Mutex::new(())))
}

static COMMUNITY_PERSIST_GENERATION: AtomicU64 = AtomicU64::new(0);

/// 将投稿节点写回磁盘。所有写入经过同一串行锁，并使用带 generation 的
/// 唯一临时文件，避免并发投稿时旧快照覆盖新快照或争用固定 `.tmp`。
pub(crate) async fn persist_community_nodes(nodes: &CommunityNodes) {
    let _guard = community_persist_lock().lock().await;
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
    let generation = COMMUNITY_PERSIST_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let result = tokio::task::spawn_blocking(move || {
        let tmp = format!("{}.{}.{}.tmp", path, std::process::id(), generation);
        std::fs::write(&tmp, json)?;
        let rename_result = std::fs::rename(&tmp, &path);
        if rename_result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        rename_result
    })
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("写入投稿节点文件失败: {}", e),
        Err(e) => log::warn!("投稿节点持久化任务异常: {}", e),
    }
}

/// 取出对客户端可见的投稿节点列表（按在线优先、延迟升序排序）
pub(crate) async fn community_node_list(nodes: &CommunityNodes) -> Vec<CommunityNodeInfo> {
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
#[allow(dead_code)]
pub(crate) async fn sweep_community_nodes(nodes: &CommunityNodes) -> (usize, usize) {
    sweep_community_nodes_with_limiter(
        nodes,
        &Arc::new(Semaphore::new(COMMUNITY_NODE_PROBE_CONCURRENCY)),
    )
    .await
}

pub(crate) async fn sweep_community_nodes_with_limiter(
    nodes: &CommunityNodes,
    probe_limiter: &ProbeLimiter,
) -> (usize, usize) {
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
                let outcome = probe_community_node_limited(&address, probe_limiter).await;
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
                // 竞争到达共享探测预算时保留上一次状态，不把排队失败误记为掉线。
                ProbeOutcome::Busy => {}
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
pub(crate) async fn spawn_community_node_sweeper(
    nodes: CommunityNodes,
    probe_limiter: ProbeLimiter,
) {
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
            let (online, removed) =
                sweep_community_nodes_with_limiter(&nodes, &probe_limiter).await;
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
#[allow(dead_code)]
pub(crate) async fn handle_community_node_submit(
    nodes: &CommunityNodes,
    cooldowns: &SubmitCooldowns,
    peer: SocketAddr,
    name: String,
    address: String,
    submitter: Option<String>,
) -> SignalingMessage {
    handle_community_node_submit_with_limits(
        nodes,
        cooldowns,
        &Arc::new(Mutex::new(HashMap::new())),
        &Arc::new(Semaphore::new(COMMUNITY_NODE_PROBE_CONCURRENCY)),
        peer,
        name,
        address,
        submitter,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_community_node_submit_with_limits(
    nodes: &CommunityNodes,
    cooldowns: &SubmitCooldowns,
    quotas: &SubmitQuotas,
    probe_limiter: &ProbeLimiter,
    peer: SocketAddr,
    name: String,
    address: String,
    submitter: Option<String>,
) -> SignalingMessage {
    let peer = SocketAddr::new(connection_guard::quota_source(peer.ip()), peer.port());
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

    {
        let mut quotas = quotas.lock().await;
        quotas.retain(|_, quota| {
            quota.window_started.elapsed()
                < tokio::time::Duration::from_secs(COMMUNITY_NODE_SUBMIT_WINDOW_SECS * 2)
        });
        if !quotas.contains_key(&peer.ip()) && quotas.len() >= MAX_TRACKED_IP_SUBMITTERS {
            return reject("投稿来源过多，请稍后再试");
        }
        let quota = quotas.entry(peer.ip()).or_insert_with(|| SubmitQuota {
            window_started: tokio::time::Instant::now(),
            submissions: 0,
        });
        if !allow_submit_quota(quota) {
            return reject("该来源的投稿配额已用尽，请稍后再试");
        }
    }

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
    let latency = match probe_community_node_limited(&normalized, probe_limiter).await {
        ProbeOutcome::Alive(ms) => ms,
        ProbeOutcome::Dead => return reject("该节点当前不可达，请确认地址与端口后重新提交"),
        ProbeOutcome::Blocked => {
            return reject("只接受公网可访问的节点地址，回环/内网/保留地址无法作为共享节点")
        }
        ProbeOutcome::Busy => return reject("当前探测队列繁忙，请稍后再试"),
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
