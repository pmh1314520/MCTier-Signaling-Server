//! WebSocket connection lifecycle, authenticated routing, and lobby state transitions.
use super::*;
use crate::moderation::{ModerationDispatch, ModerationSession};
use crate::registration::{RegistrationContext, RegistrationOutcome, RegistrationRequest};
#[cfg(not(test))]
use crate::security::*;

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
        lobby_entry_modes: true,
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

                            let moderation_session = if is_registered {
                                client_id.as_deref().zip(lobby_id.as_deref()).map(
                                    |(client_id, lobby_id)| ModerationSession {
                                        client_id,
                                        lobby_id,
                                        session_generation,
                                        sender: &write,
                                    },
                                )
                            } else {
                                None
                            };
                            match moderation::handle_moderation_message(
                                &message,
                                moderation_session,
                                &lobbies,
                                &client_lobby_map,
                            )
                            .await
                            {
                                ModerationDispatch::NotHandled => {}
                                ModerationDispatch::Handled => continue,
                                ModerationDispatch::CloseConnection => break,
                            }

                            match message {
                                SignalingMessage::Register { client_version, .. } => {
                                    registration::reject_legacy(&write, client_version.as_deref())
                                        .await;
                                    break;
                                }
                                SignalingMessage::RegisterV3 {
                                    entry_mode,
                                    protocol_version,
                                    identity_public_key,
                                    challenge_signature,
                                    player_name,
                                    virtual_ip,
                                    virtual_domain: _,
                                    use_domain,
                                    lobby_name,
                                    lobby_password,
                                    client_version,
                                } => {
                                    let outcome = registration::handle_v3(
                                        RegistrationContext {
                                            lobbies: &lobbies,
                                            client_lobby_map: &client_lobby_map,
                                            sender: &write,
                                            disconnect_tx: &disconnect_tx,
                                            disconnect_rx: &disconnect_rx,
                                            challenge: &challenge,
                                            peer_addr: addr,
                                            source_ip,
                                            is_registered,
                                            client_id: client_id.as_deref(),
                                        },
                                        RegistrationRequest {
                                            entry_mode,
                                            protocol_version,
                                            identity_public_key,
                                            challenge_signature,
                                            player_name,
                                            virtual_ip,
                                            use_domain,
                                            lobby_name,
                                            lobby_password,
                                            client_version,
                                        },
                                    )
                                    .await;
                                    match outcome {
                                        RegistrationOutcome::Retry => continue,
                                        RegistrationOutcome::Disconnect => break,
                                        RegistrationOutcome::Committed {
                                            session,
                                            disconnect,
                                        } => {
                                            client_id = Some(session.client_id);
                                            lobby_id = Some(session.lobby_id);
                                            session_generation = session.generation;
                                            is_registered = true;
                                            if disconnect {
                                                break;
                                            }
                                        }
                                    }
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
                            lobby.muted.remove(&next);
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
                "",
                SignalingMessage::PlayerMuteChanged {
                    player_id: host_id.clone(),
                    muted: false,
                },
            )
            .await;
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
