//! WebSocket connection lifecycle, authenticated routing, and lobby state transitions.
use super::*;
#[cfg(not(test))]
use crate::{protocol::*, security::*, state::*};

pub(crate) async fn send_with_timeout<F, E>(send: F) -> bool
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

pub(crate) async fn send_message(sender: &ClientSender, message: Message) -> bool {
    let message_bytes = match &message {
        Message::Text(text) => text.len(),
        Message::Binary(bytes) => bytes.len(),
        Message::Ping(bytes) | Message::Pong(bytes) => bytes.len(),
        Message::Close(_) => 0,
        Message::Frame(_) => 0,
    };
    {
        let mut budget = sender.budget.lock().await;
        if !budget.allow(message_bytes) {
            log::warn!(
                "丢弃超出出站预算的消息: bytes={}, frames_limit={}, bytes_limit={}",
                message_bytes,
                MAX_OUTBOUND_FRAMES_PER_WINDOW,
                MAX_OUTBOUND_BYTES_PER_WINDOW
            );
            return false;
        }
    }
    send_with_timeout(async {
        let mut sink = sender.sink.write().await;
        sink.send(message).await
    })
    .await
}

pub(crate) async fn send_text(sender: &ClientSender, text: String) -> bool {
    send_message(sender, Message::Text(text)).await
}

pub(crate) fn json_sender_id(raw: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    value
        .get("from")
        .or_else(|| value.get("clientId"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

pub(crate) fn inject_session_metadata(raw: String, sender_id: &str, generation: u64) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return raw;
    };
    let Some(object) = value.as_object_mut() else {
        return raw;
    };
    if object.contains_key("from") {
        object.insert(
            "from".to_string(),
            serde_json::Value::String(sender_id.to_string()),
        );
    }
    if object.contains_key("clientId") {
        object.insert(
            "clientId".to_string(),
            serde_json::Value::String(sender_id.to_string()),
        );
    }
    object.insert(
        "sessionGeneration".to_string(),
        serde_json::Value::from(generation),
    );
    serde_json::to_string(&value).unwrap_or(raw)
}

pub(crate) async fn send_to_lobby_client(
    lobbies: &Lobbies,
    lobby_id: &str,
    client_id: &str,
    message: Message,
) -> bool {
    let raw_text = match &message {
        Message::Text(text) => Some(text.clone()),
        _ => None,
    };
    let source_id = raw_text.as_deref().and_then(json_sender_id);
    let sender_info = {
        let lobbies_read = lobbies.read().await;
        lobbies_read.get(lobby_id).and_then(|lobby| {
            let target = lobby.clients.get(client_id)?;
            let generation = source_id
                .as_deref()
                .and_then(|source_id| lobby.clients.get(source_id))
                .map(|source| source.session_generation);
            Some((
                Arc::clone(&target.sender),
                target.disconnect.clone(),
                generation,
            ))
        })
    };

    match (sender_info, raw_text) {
        (Some((sender, disconnect, Some(generation))), Some(text)) => {
            let ok = send_message(
                &sender,
                Message::Text(inject_session_metadata(
                    text,
                    source_id.as_deref().unwrap_or_default(),
                    generation,
                )),
            )
            .await;
            if !ok {
                let _ = disconnect.send(true);
            }
            ok
        }
        (Some((sender, disconnect, _)), _) => {
            let ok = send_message(&sender, message).await;
            if !ok {
                let _ = disconnect.send(true);
            }
            ok
        }
        (None, _) => false,
    }
}

pub(crate) async fn is_current_session(
    lobbies: &Lobbies,
    lobby_id: &str,
    client_id: &str,
    session_generation: u64,
    sender: &ClientSender,
) -> bool {
    let lobbies_read = lobbies.read().await;
    lobbies_read
        .get(lobby_id)
        .and_then(|lobby| lobby.clients.get(client_id))
        .map(|client| {
            client.session_generation == session_generation && Arc::ptr_eq(&client.sender, sender)
        })
        .unwrap_or(false)
}

/// A lobby name identifies one room; its password is checked separately.
pub(crate) fn generate_lobby_id(lobby_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(lobby_name.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// 比较版本号
/// 返回 true 如果 version >= minimum_version
pub(crate) fn is_version_valid(version: &str, minimum_version: &str) -> bool {
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

/// 处理客户端连接
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    lobbies: Lobbies,
    client_lobby_map: ClientLobbyMap,
    community_nodes: CommunityNodes,
    submit_cooldowns: SubmitCooldowns,
    submit_quotas: SubmitQuotas,
    probe_limiter: ProbeLimiter,
    pending: connection_guard::Lease,
) -> Result<(), Box<dyn std::error::Error>> {
    handle_connection_with_timeouts_and_limits(
        stream,
        addr,
        lobbies,
        client_lobby_map,
        community_nodes,
        submit_cooldowns,
        submit_quotas,
        probe_limiter,
        tokio::time::Duration::from_secs(WEBSOCKET_HANDSHAKE_TIMEOUT_SECS),
        tokio::time::Duration::from_secs(REGISTRATION_TIMEOUT_SECS),
        tokio::time::Duration::from_secs(REGISTERED_IDLE_TIMEOUT_SECS),
        Some(pending),
        connection_guard::admission(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) async fn handle_connection_with_timeouts(
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
    handle_connection_with_timeouts_and_limits(
        stream,
        addr,
        lobbies,
        client_lobby_map,
        community_nodes,
        submit_cooldowns,
        Arc::new(Mutex::new(HashMap::new())),
        Arc::new(Semaphore::new(COMMUNITY_NODE_PROBE_CONCURRENCY)),
        handshake_timeout,
        registration_timeout,
        idle_timeout,
        None,
        connection_guard::admission(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connection_with_timeouts_and_limits(
    stream: TcpStream,
    addr: SocketAddr,
    lobbies: Lobbies,
    client_lobby_map: ClientLobbyMap,
    community_nodes: CommunityNodes,
    submit_cooldowns: SubmitCooldowns,
    submit_quotas: SubmitQuotas,
    probe_limiter: ProbeLimiter,
    handshake_timeout: tokio::time::Duration,
    registration_timeout: tokio::time::Duration,
    idle_timeout: tokio::time::Duration,
    pending: Option<connection_guard::Lease>,
    admission: &connection_guard::Admission,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut active_lease = None;
    let mut source_ip = addr.ip();
    let mut pending = pending;
    // 升级到 WebSocket
    let ws_stream = match tokio::time::timeout(
        handshake_timeout,
        tokio_tungstenite::accept_hdr_async_with_config(stream, |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
            let result = admission.source(addr.ip(), request.headers()).and_then(|ip| {
                source_ip = ip;
                if let Some(pending) = pending.as_mut() {
                    pending.resolve_source(ip)?;
                }
                let lease = admission.active(ip)?;
                active_lease = Some(lease);
                Ok(())
            });
            match result {
                Ok(()) => Ok(response),
                Err(reason) => {
                    // Throttle diagnostics during floods; never log request headers
                    // or lobby credentials. Preserve the rejected quota source.
                    static LAST_REJECTION_LOG: AtomicU64 = AtomicU64::new(0);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let last = LAST_REJECTION_LOG.load(Ordering::Relaxed);
                    if now.saturating_sub(last) >= 5 && LAST_REJECTION_LOG.compare_exchange(
                        last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
                    {
                        log::warn!("拒绝 WebSocket 握手: tcp_peer={} quota_source={} trusted_proxy={} forwarded_header={} reason={}; 反代部署请核对 TRUSTED_PROXIES 与真实来源转发配置",
                            addr.ip(), connection_guard::quota_source(source_ip),
                            admission.trusted_proxies.contains(&addr.ip()),
                            request.headers().contains_key("x-forwarded-for") || request.headers().contains_key("x-real-ip"), reason);
                    }
                    Err(tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(429).header("Retry-After", "5")
                        .body(Some(reason.to_owned())).unwrap())
                },
            }
        }, Some(websocket_config())),
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
    drop(pending);
    let _active_lease = active_lease;
    let source_addr = SocketAddr::new(source_ip, addr.port());

    log::info!(
        "✅ WebSocket 连接已建立: {} quota_source={}",
        addr,
        connection_guard::quota_source(source_ip)
    );

    let (write, mut read) = ws_stream.split();
    let write = Arc::new(ClientSenderState {
        sink: RwLock::new(write),
        budget: Mutex::new(OutboundBudget::new()),
    });
    let (disconnect_tx, mut disconnect_rx) = watch::channel(false);

    let mut client_id: Option<String> = None;
    let mut lobby_id: Option<String> = None;
    let mut session_generation = 0u64;
    let challenge = random_hex::<CHALLENGE_BYTES>();
    let challenge_message = SignalingMessage::ServerChallenge {
        challenge: challenge.clone(),
        protocol_version: SIGNALING_PROTOCOL_VERSION,
    };
    if let Ok(json) = serde_json::to_string(&challenge_message) {
        if !send_text(&write, json).await {
            return Ok(());
        }
    }
    let mut connection_rate_limiter = MessageRateLimiter::new();

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
                // TCP peers behind a reverse proxy share one address. Give each
                // bounded connection its own budget so users cannot evict peers.
                if !connection_rate_limiter.allow() {
                    log::warn!("连接消息速率超限，关闭连接: {}", addr);
                    let _ = send_message(&write, Message::Close(None)).await;
                    break;
                }
                if is_registered {
                    let current = match (client_id.as_deref(), lobby_id.as_deref()) {
                        (Some(client_id), Some(lobby_id)) => {
                            is_current_session(
                                &lobbies,
                                lobby_id,
                                client_id,
                                session_generation,
                                &write,
                            )
                            .await
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
                            if !validate_message_shape(&message) {
                                log::warn!("拒绝超出字段边界的信令消息: peer={}", addr);
                                let error_msg = SignalingMessage::RegisterError {
                                    message: "信令字段无效或超出长度限制".to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&error_msg) {
                                    send_text(&write, json).await;
                                }
                                break;
                            }
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
                                SignalingMessage::Register { client_version, .. } => {
                                    // Old clients show the upgrade screen only for version-too-old.
                                    // Reject here without admitting a legacy identity to the lobby.
                                    let version_str =
                                        client_version.as_deref().unwrap_or("unknown");
                                    let error_msg = if !is_version_valid(
                                        version_str,
                                        minimum_client_version(),
                                    ) {
                                        SignalingMessage::VersionTooOld {
                                            message: format!("您的客户端版本过低（当前版本: {}），请更新到最新版本（最低要求: {}）", version_str, minimum_client_version()),
                                            current_version: version_str.to_string(),
                                            minimum_version: minimum_client_version().to_string(),
                                            download_url: client_download_url().to_string(),
                                        }
                                    } else {
                                        SignalingMessage::RegisterError {
                                            message: "已拒绝旧注册协议，请先等待 server-challenge 后使用 register-v3"
                                                .to_string(),
                                        }
                                    };
                                    if let Ok(json) = serde_json::to_string(&error_msg) {
                                        send_text(&write, json).await;
                                    }
                                    break;
                                }
                                SignalingMessage::RegisterV3 {
                                    protocol_version,
                                    identity_public_key,
                                    challenge_signature,
                                    player_name,
                                    virtual_ip,
                                    virtual_domain: _client_virtual_domain,
                                    use_domain: _client_use_domain,
                                    lobby_name,
                                    lobby_password,
                                    client_version,
                                } => {
                                    if is_registered {
                                        log::warn!(
                                            "拒绝同一连接重复注册: peer={}, registered={:?}",
                                            addr,
                                            client_id
                                        );
                                        break;
                                    }

                                    if protocol_version != SIGNALING_PROTOCOL_VERSION {
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: format!(
                                                "不支持的信令协议版本，要求 {}",
                                                SIGNALING_PROTOCOL_VERSION
                                            ),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        break;
                                    }

                                    let virtual_ip_text =
                                        match parse_virtual_ipv4(virtual_ip.as_deref()) {
                                            Some(ip) => ip.to_string(),
                                            None => {
                                                let error_msg = SignalingMessage::RegisterError {
                                                    message: "virtualIp 必须位于 10.126.126.1-254"
                                                        .to_string(),
                                                };
                                                if let Ok(json) = serde_json::to_string(&error_msg)
                                                {
                                                    send_text(&write, json).await;
                                                }
                                                continue;
                                            }
                                        };
                                    let (cid, identity_key, derived_virtual_domain) =
                                        match verify_registration_identity(
                                            &challenge,
                                            &lobby_name,
                                            &virtual_ip_text,
                                            &identity_public_key,
                                            &challenge_signature,
                                        ) {
                                            Some(identity) => identity,
                                            None => {
                                                let error_msg = SignalingMessage::RegisterError {
                                                    message: "身份公钥或 challengeSignature 无效"
                                                        .to_string(),
                                                };
                                                if let Ok(json) = serde_json::to_string(&error_msg)
                                                {
                                                    send_text(&write, json).await;
                                                }
                                                break;
                                            }
                                        };
                                    let chat_public_key = Some(identity_key);
                                    // The domain is an address derived from the authenticated
                                    // public-key fingerprint. Never accept a caller-selected name.
                                    let virtual_domain = Some(derived_virtual_domain);
                                    let use_domain = _client_use_domain.or(Some(true));

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
                                    let lid = generate_lobby_id(&lobby_name);

                                    let mut lobbies_write = lobbies.write().await;
                                    let existing_client_lobby = lobbies_write.iter().find_map(
                                        |(existing_lid, existing_lobby)| {
                                            existing_lobby
                                                .clients
                                                .contains_key(&cid)
                                                .then(|| existing_lid.clone())
                                        },
                                    );
                                    if existing_client_lobby
                                        .as_deref()
                                        .is_some_and(|existing_lid| existing_lid != lid)
                                    {
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

                                    // 密码失败熔断以 (来源IP, 大厅) 为键。先查锁定再比较，
                                    // 锁定期间即使密码正确也拒绝，防止把熔断当作校验预言机。
                                    let quota_ip = connection_guard::quota_source(source_ip);
                                    let failure_key = (quota_ip, lid.clone());
                                    let now = Instant::now();
                                    let locked = {
                                        let mut failures = register_password_failures()
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        failures.is_locked(&failure_key, now)
                                    };
                                    if locked {
                                        drop(lobbies_write);
                                        log::warn!(
                                            "🚫 密码失败次数过多，暂时拒绝 {} 加入大厅 {}",
                                            player_name,
                                            lobby_name
                                        );
                                        let error_msg = SignalingMessage::RegisterError {
                                            message: "密码错误次数过多，请稍后再试".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&error_msg) {
                                            send_text(&write, json).await;
                                        }
                                        break;
                                    }

                                    // 获取或创建大厅
                                    if let Some(existing) = lobbies_write.get(&lid) {
                                        let supplied_hash = hash_lobby_password(
                                            &existing.password_salt,
                                            &lobby_password,
                                        );
                                        if !ct_eq(
                                            supplied_hash.as_bytes(),
                                            existing.password_hash.as_bytes(),
                                        ) {
                                            let locked = {
                                                let mut failures = register_password_failures()
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner());
                                                if failures.is_locked(&failure_key, now) {
                                                    true
                                                } else {
                                                    failures.record_failure(&failure_key, now);
                                                    false
                                                }
                                            };
                                            drop(lobbies_write);
                                            log::warn!(
                                                "❌ 密码错误: {} 尝试加入大厅 {}",
                                                player_name,
                                                lobby_name
                                            );
                                            let message = if locked {
                                                "密码错误次数过多，请稍后再试".to_string()
                                            } else {
                                                "密码错误".to_string()
                                            };
                                            let error_msg =
                                                SignalingMessage::RegisterError { message };
                                            if let Ok(json) = serde_json::to_string(&error_msg) {
                                                send_text(&write, json).await;
                                            }
                                            // 断开连接：每次猜测都必须重新握手并重新签名，
                                            // 无法在同一连接内高速枚举大厅密码。
                                            break;
                                        }
                                        register_password_failures()
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .clear(&failure_key);
                                    }

                                    let lobby =
                                        lobbies_write.entry(lid.clone()).or_insert_with(|| {
                                            log::info!(
                                                "🏠 创建新大厅: {} (ID: {})，房主: {}",
                                                lobby_name,
                                                lid,
                                                cid
                                            );
                                            let password_salt =
                                                random_hex::<LOBBY_PASSWORD_SALT_BYTES>();
                                            LobbyInfo {
                                                lobby_name: lobby_name.clone(),
                                                password_hash: hash_lobby_password(
                                                    &password_salt,
                                                    &lobby_password,
                                                ),
                                                password_salt,
                                                clients: HashMap::new(),
                                                host_id: cid.clone(), // 首个创建者即房主
                                                max_players: None,
                                                is_public: false,
                                                is_passwordless: lobby_password.is_empty(),
                                                description: String::new(),
                                                server_node: String::new(),
                                                muted: HashSet::new(),
                                                chat_token: generate_chat_token(),
                                                chat_token_epoch: 1,
                                            }
                                        });

                                    // Virtual IP is the identity binding used by the chat HTTP
                                    // service. Do not allow two members to claim the same address.
                                    // A reconnect of the same signed identity must replace its
                                    // stale websocket session. Checking the old record as a
                                    // competing owner rejects every reconnect with
                                    // "virtualIp already in use" and leaves the old HTTP/chat
                                    // credentials bound to a dead connection.
                                    if lobby.clients.values().any(|info| {
                                        info.player_id != cid
                                            && info
                                                .virtual_ip
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
                                    let new_session_generation = random_session_generation();
                                    let client_info = ClientInfo {
                                        player_id: cid.clone(),
                                        player_name: player_name.clone(),
                                        virtual_ip: Some(virtual_ip.to_string()),
                                        virtual_domain: virtual_domain.clone(),
                                        use_domain,
                                        chat_public_key: chat_public_key.clone(),
                                        session_generation: new_session_generation,
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
                                    if let Some(previous) = lobby.clients.get(&cid) {
                                        // Explicitly terminate the stale transport. Its delayed
                                        // cleanup is generation/sender guarded below, so it cannot
                                        // remove the replacement session.
                                        let _ = previous.disconnect.send(true);
                                    }
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
                                    session_generation = new_session_generation;
                                    is_registered = true;

                                    if *disconnect_rx.borrow()
                                        || !is_current_session(
                                            &lobbies,
                                            &lid,
                                            &cid,
                                            session_generation,
                                            &write,
                                        )
                                        .await
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
                                        client_id: cid.clone(),
                                        session_generation,
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
                                    let players = current_players(&lobbies, &lid, Some(&cid)).await;
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
                                            session_generation,
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
                                SignalingMessage::PlayersListRequest => {
                                    if !is_registered {
                                        log::warn!("未注册客户端请求成员列表，关闭连接: {}", addr);
                                        break;
                                    }
                                    let Some(lid) = lobby_id.as_deref() else {
                                        break;
                                    };
                                    let players =
                                        current_players(&lobbies, lid, client_id.as_deref()).await;
                                    if let Ok(json) =
                                        serde_json::to_string(&SignalingMessage::PlayersList {
                                            players,
                                        })
                                    {
                                        send_text(&write, json).await;
                                    }
                                }
                                SignalingMessage::VoiceReconnect { from, to } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let Some(lid) = lobby_id.as_deref() else {
                                        break;
                                    };
                                    let target_id = to.clone();
                                    let forwarded = SignalingMessage::VoiceReconnect { from, to };
                                    if let Ok(json) = serde_json::to_string(&forwarded) {
                                        send_to_lobby_client(
                                            &lobbies,
                                            lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
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
                                    sequence,
                                    source_sequence,
                                    sent_sequence,
                                    limited,
                                    reason,
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
                                        sequence,
                                        source_sequence,
                                        sent_sequence,
                                        limited,
                                        reason,
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
                                SignalingMessage::ShareUpdated {
                                    from,
                                    share_id,
                                    share_name,
                                    player_name,
                                    has_password,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    broadcast_to_lobby(
                                        &lobbies,
                                        &lid,
                                        &from,
                                        SignalingMessage::ShareUpdated {
                                            from: from.clone(),
                                            share_id,
                                            share_name,
                                            player_name,
                                            has_password,
                                        },
                                    )
                                    .await;
                                }
                                SignalingMessage::RemoteControlRequest {
                                    from,
                                    to,
                                    session_id,
                                    from_name,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlRequest {
                                        from,
                                        to,
                                        session_id,
                                        from_name,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::RemoteControlAccept {
                                    from,
                                    to,
                                    session_id,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlAccept {
                                        from,
                                        to,
                                        session_id,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::RemoteControlReject {
                                    from,
                                    to,
                                    session_id,
                                    reason,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlReject {
                                        from,
                                        to,
                                        session_id,
                                        reason,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::RemoteControlOffer {
                                    from,
                                    to,
                                    session_id,
                                    offer,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlOffer {
                                        from,
                                        to,
                                        session_id,
                                        offer,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::RemoteControlAnswer {
                                    from,
                                    to,
                                    session_id,
                                    answer,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlAnswer {
                                        from,
                                        to,
                                        session_id,
                                        answer,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::RemoteControlIce {
                                    from,
                                    to,
                                    session_id,
                                    candidate,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlIce {
                                        from,
                                        to,
                                        session_id,
                                        candidate,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
                                    }
                                }
                                SignalingMessage::RemoteControlStop {
                                    from,
                                    to,
                                    session_id,
                                } => {
                                    if !is_registered {
                                        break;
                                    }
                                    let lid = match client_lobby_map.read().await.get(&from) {
                                        Some(id) => id.clone(),
                                        None => continue,
                                    };
                                    let target_id = to.clone();
                                    let message = SignalingMessage::RemoteControlStop {
                                        from,
                                        to,
                                        session_id,
                                    };
                                    if let Ok(json) = serde_json::to_string(&message) {
                                        let _ = send_to_lobby_client(
                                            &lobbies,
                                            &lid,
                                            &target_id,
                                            Message::Text(json),
                                        )
                                        .await;
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
                                    let resp = handle_community_node_submit_with_limits(
                                        &community_nodes,
                                        &submit_cooldowns,
                                        &submit_quotas,
                                        &probe_limiter,
                                        source_addr,
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
                                    let mut target_generation = 0u64;
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
                                                target_generation = t.session_generation;
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
                                            session_generation: target_generation,
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
                                            if !lobby.clients.contains_key(&target) {
                                                log::warn!(
                                                    "🚫 房主尝试禁言不在大厅内的成员: {}",
                                                    target
                                                );
                                                continue;
                                            }
                                            if muted {
                                                if lobby.muted.len() >= MAX_LOBBY_MEMBERS
                                                    && !lobby.muted.contains(&target)
                                                {
                                                    log::warn!("🚫 大厅禁言集合已达上限: {}", lid);
                                                    continue;
                                                }
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
                                _ => {
                                    log::warn!("未知消息类型");
                                }
                            }
                        }
                        Err(e) => {
                            let error_msg = e.to_string();
                            log::error!("解析消息失败: {}", error_msg);
                            let error_response = SignalingMessage::RegisterError {
                                message: if error_msg.contains("unknown variant") {
                                    "不支持的信令消息类型".to_string()
                                } else if !is_registered {
                                    "请先使用 register-v3 完成注册".to_string()
                                } else {
                                    "信令消息格式无效".to_string()
                                },
                            };
                            if let Ok(json) = serde_json::to_string(&error_response) {
                                send_text(&write, json).await;
                            }
                            break;
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
                session_generation,
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

pub(crate) async fn current_players(
    lobbies: &Lobbies,
    lobby_id: &str,
    exclude_id: Option<&str>,
) -> Vec<PlayerInfo> {
    let lobbies_read = lobbies.read().await;
    lobbies_read
        .get(lobby_id)
        .map(|lobby| {
            lobby
                .clients
                .iter()
                .filter(|(id, _)| exclude_id.is_none_or(|exclude| id.as_str() != exclude))
                .map(|(_, info)| PlayerInfo {
                    player_id: info.player_id.clone(),
                    player_name: info.player_name.clone(),
                    virtual_ip: info.virtual_ip.clone(),
                    virtual_domain: info.virtual_domain.clone(),
                    use_domain: info.use_domain,
                    chat_public_key: info.chat_public_key.clone(),
                    session_generation: info.session_generation,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 广播消息到大厅内所有客户端（排除指定客户端）
pub(crate) async fn broadcast_to_lobby(
    lobbies: &Lobbies,
    lobby_id: &str,
    exclude_id: &str,
    message: SignalingMessage,
) {
    if let Ok(json) = serde_json::to_string(&message) {
        let source_id = json_sender_id(&json);
        let (senders, generation) = {
            let lobbies_read = lobbies.read().await;
            let Some(lobby) = lobbies_read.get(lobby_id) else {
                return;
            };
            let generation = source_id
                .as_deref()
                .and_then(|source_id| lobby.clients.get(source_id))
                .map(|source| source.session_generation);
            let senders = lobby
                .clients
                .iter()
                .filter(|(id, _)| id.as_str() != exclude_id)
                .map(|(_, client)| (Arc::clone(&client.sender), client.disconnect.clone()))
                .collect::<Vec<_>>();
            (senders, generation)
        };
        let json = generation
            .zip(source_id.as_deref())
            .map(|(generation, source_id)| {
                inject_session_metadata(json.clone(), source_id, generation)
            })
            .unwrap_or(json);
        // 只在锁内复制发送端句柄；实际网络写入全部在锁外执行。
        let sends = senders.into_iter().map(|(sender, disconnect)| {
            let message = Message::Text(json.clone());
            async move {
                let ok = send_message(&sender, message).await;
                if !ok {
                    let _ = disconnect.send(true);
                }
                ok
            }
        });
        let _ = join_all(sends).await;
    }
}

pub(crate) async fn send_chat_token_rotation(
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
                    .map(|client| (sender, client.disconnect.clone()))
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
    let sends = senders.into_iter().map(|(sender, disconnect)| {
        let json = json.clone();
        async move {
            let ok = send_text(&sender, json).await;
            if !ok {
                let _ = disconnect.send(true);
            }
            ok
        }
    });
    let _ = join_all(sends).await;
}
