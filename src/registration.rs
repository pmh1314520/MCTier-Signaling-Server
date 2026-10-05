//! Registration validation, atomic lobby admission, and ordered membership events.
use crate::config::{
    client_download_url, minimum_client_version, MAX_CLIENT_ID_LEN, MAX_CLIENT_VERSION_LEN,
    MAX_LOBBY_MEMBERS, MAX_LOBBY_NAME_LEN, MAX_LOBBY_PASSWORD_LEN, MAX_PLAYER_NAME_LEN,
    MAX_VIRTUAL_DOMAIN_LEN, SIGNALING_PROTOCOL_VERSION,
};
use crate::protocol::{
    normalize_chat_public_key, parse_virtual_ipv4, valid_text, LobbyEntryMode, SignalingMessage,
};
use crate::security::{
    ct_eq, generate_chat_token, hash_lobby_password, random_hex, random_session_generation,
    verify_registration_identity, LOBBY_PASSWORD_SALT_BYTES,
};
use crate::state::{
    register_password_failures, rotate_chat_token, ClientInfo, ClientLobbyMap, ClientSender,
    Lobbies, LobbyInfo,
};
use crate::transport::{
    broadcast_to_lobby, current_players, is_current_session, send_chat_token_rotation, send_text,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

pub(crate) struct RegistrationRequest {
    pub(crate) entry_mode: Option<LobbyEntryMode>,
    pub(crate) protocol_version: u32,
    pub(crate) identity_public_key: String,
    pub(crate) challenge_signature: String,
    pub(crate) player_name: String,
    pub(crate) virtual_ip: Option<String>,
    pub(crate) use_domain: Option<bool>,
    pub(crate) lobby_name: String,
    pub(crate) lobby_password: String,
    pub(crate) client_version: Option<String>,
}

pub(crate) struct RegistrationContext<'a> {
    pub(crate) lobbies: &'a Lobbies,
    pub(crate) client_lobby_map: &'a ClientLobbyMap,
    pub(crate) sender: &'a ClientSender,
    pub(crate) disconnect_tx: &'a watch::Sender<bool>,
    pub(crate) disconnect_rx: &'a watch::Receiver<bool>,
    pub(crate) challenge: &'a str,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) source_ip: IpAddr,
    pub(crate) is_registered: bool,
    pub(crate) client_id: Option<&'a str>,
}

pub(crate) struct RegisteredSession {
    pub(crate) client_id: String,
    pub(crate) lobby_id: String,
    pub(crate) generation: u64,
}

pub(crate) enum RegistrationOutcome {
    Retry,
    Disconnect,
    /// Return committed state even if it became stale before sending credentials,
    /// so connection cleanup retains the same ownership checks.
    Committed {
        session: RegisteredSession,
        disconnect: bool,
    },
}

/// A lobby name identifies one room; its password is checked separately.
pub(crate) fn generate_lobby_id(lobby_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(lobby_name.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

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

async fn send_response(sender: &ClientSender, message: SignalingMessage) {
    if let Ok(json) = serde_json::to_string(&message) {
        send_text(sender, json).await;
    }
}

fn version_error(version: &str) -> SignalingMessage {
    SignalingMessage::VersionTooOld {
        message: format!(
            "您的客户端版本过低（当前版本: {}），请更新到最新版本（最低要求: {}）",
            version,
            minimum_client_version()
        ),
        current_version: version.to_string(),
        minimum_version: minimum_client_version().to_string(),
        download_url: client_download_url().to_string(),
    }
}

pub(crate) async fn reject_legacy(
    sender: &ClientSender,
    client_version: Option<&str>,
) -> RegistrationOutcome {
    // Old clients show the upgrade screen only for version-too-old.
    // Reject without admitting a legacy identity to the lobby.
    let version = client_version.unwrap_or("unknown");
    let message = if !is_version_valid(version, minimum_client_version()) {
        version_error(version)
    } else {
        SignalingMessage::RegisterError {
            message: "已拒绝旧注册协议，请先等待 server-challenge 后使用 register-v3".to_string(),
        }
    };
    send_response(sender, message).await;
    RegistrationOutcome::Disconnect
}

pub(crate) async fn handle_v3(
    context: RegistrationContext<'_>,
    request: RegistrationRequest,
) -> RegistrationOutcome {
    let RegistrationRequest {
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
    } = request;
    let RegistrationContext {
        lobbies,
        client_lobby_map,
        sender,
        disconnect_tx,
        disconnect_rx,
        challenge,
        peer_addr,
        source_ip,
        is_registered,
        client_id,
    } = context;

    if is_registered {
        log::warn!(
            "拒绝同一连接重复注册: peer={}, registered={:?}",
            peer_addr,
            client_id
        );
        return RegistrationOutcome::Disconnect;
    }

    if protocol_version != SIGNALING_PROTOCOL_VERSION {
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: format!("不支持的信令协议版本，要求 {}", SIGNALING_PROTOCOL_VERSION),
            },
        )
        .await;
        return RegistrationOutcome::Disconnect;
    }

    let virtual_ip_text = match parse_virtual_ipv4(virtual_ip.as_deref()) {
        Some(ip) => ip.to_string(),
        None => {
            send_response(
                sender,
                SignalingMessage::RegisterError {
                    message: "virtualIp 必须位于 10.126.126.1-254".to_string(),
                },
            )
            .await;
            return RegistrationOutcome::Retry;
        }
    };
    let (cid, identity_key, derived_virtual_domain) = match verify_registration_identity(
        challenge,
        &lobby_name,
        &virtual_ip_text,
        &identity_public_key,
        &challenge_signature,
    ) {
        Some(identity) => identity,
        None => {
            send_response(
                sender,
                SignalingMessage::RegisterError {
                    message: "身份公钥或 challengeSignature 无效".to_string(),
                },
            )
            .await;
            return RegistrationOutcome::Disconnect;
        }
    };
    let chat_public_key = Some(identity_key);
    // The domain is derived from the authenticated public-key fingerprint.
    // A caller-selected virtualDomain is never passed into registration.
    let virtual_domain = Some(derived_virtual_domain);
    let use_domain = use_domain.or(Some(true));

    if !valid_text(&cid, MAX_CLIENT_ID_LEN, false)
        || !valid_text(&player_name, MAX_PLAYER_NAME_LEN, false)
        || !valid_text(&lobby_name, MAX_LOBBY_NAME_LEN, false)
        || !valid_text(&lobby_password, MAX_LOBBY_PASSWORD_LEN, true)
        || virtual_domain
            .as_deref()
            .is_some_and(|domain| !valid_text(domain, MAX_VIRTUAL_DOMAIN_LEN, true))
    {
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: "注册字段为空、过长或包含控制字符".to_string(),
            },
        )
        .await;
        return RegistrationOutcome::Retry;
    }

    let chat_public_key = normalize_chat_public_key(chat_public_key);
    log::info!("客户端注册: {} ({}) - 大厅: {} - 版本: {:?} - 虚拟IP: {:?} - 虚拟域名: {:?} - 使用域名: {:?} - 聊天公钥: {}",
        player_name, cid, lobby_name, client_version, virtual_ip, virtual_domain, use_domain,
        if chat_public_key.is_some() { "已提交" } else { "未提交" });

    let version = client_version.as_deref().unwrap_or("unknown");
    if version == "unknown" || !is_version_valid(version, minimum_client_version()) {
        log::warn!(
            "❌ 版本过低或未提供版本: {} (版本: {}) 尝试加入大厅 {}",
            player_name,
            version,
            lobby_name
        );
        send_response(sender, version_error(version)).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        log::warn!(
            "🚫 强制断开版本过低的客户端连接: {} ({})",
            peer_addr,
            version
        );
        return RegistrationOutcome::Disconnect;
    }

    let virtual_ip = match parse_virtual_ipv4(virtual_ip.as_deref()) {
        Some(ip) => ip,
        None => {
            send_response(
                sender,
                SignalingMessage::RegisterError {
                    message: "virtualIp 必须位于 10.126.126.1-254".to_string(),
                },
            )
            .await;
            return RegistrationOutcome::Retry;
        }
    };

    log::info!("✅ 版本检查通过: {} (版本: {})", player_name, version);
    let lid = generate_lobby_id(&lobby_name);
    let mut lobbies_write = lobbies.write().await;
    // Validate entry mode under the insertion lock, before checking passwords.
    let entry_error = match (entry_mode, lobbies_write.contains_key(&lid)) {
        (Some(LobbyEntryMode::Create), true) => Some("大厅名称已被占用，请更换大厅名称后重试"),
        (Some(LobbyEntryMode::Join), false) => Some("大厅不存在或已关闭，请检查大厅名称或联系房主"),
        _ => None,
    };
    if let Some(message) = entry_error {
        drop(lobbies_write);
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: message.into(),
            },
        )
        .await;
        return RegistrationOutcome::Disconnect;
    }
    let existing_client_lobby = lobbies_write
        .iter()
        .find_map(|(existing_lid, existing_lobby)| {
            existing_lobby
                .clients
                .contains_key(&cid)
                .then(|| existing_lid.clone())
        });
    if existing_client_lobby
        .as_deref()
        .is_some_and(|existing_lid| existing_lid != lid)
    {
        log::warn!("拒绝重复 clientId 注册: {} ({})", player_name, cid);
        drop(lobbies_write);
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: "客户端身份已在使用中，请重新连接".to_string(),
            },
        )
        .await;
        return RegistrationOutcome::Disconnect;
    }

    // A locked (source IP, lobby) remains rejected even for a correct password.
    let quota_ip = crate::connection_guard::quota_source(source_ip);
    let failure_key = (quota_ip, lid.clone());
    let now = Instant::now();
    let locked = register_password_failures()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_locked(&failure_key, now);
    if locked {
        drop(lobbies_write);
        log::warn!(
            "🚫 密码失败次数过多，暂时拒绝 {} 加入大厅 {}",
            player_name,
            lobby_name
        );
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: "密码错误次数过多，请稍后再试".to_string(),
            },
        )
        .await;
        return RegistrationOutcome::Disconnect;
    }

    if let Some(existing) = lobbies_write.get(&lid) {
        let supplied_hash = hash_lobby_password(&existing.password_salt, &lobby_password);
        if !ct_eq(supplied_hash.as_bytes(), existing.password_hash.as_bytes()) {
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
            log::warn!("❌ 密码错误: {} 尝试加入大厅 {}", player_name, lobby_name);
            let message = if locked {
                "密码错误次数过多，请稍后再试".to_string()
            } else {
                "密码错误".to_string()
            };
            send_response(sender, SignalingMessage::RegisterError { message }).await;
            // Each password guess requires another handshake and signed proof.
            return RegistrationOutcome::Disconnect;
        }
        register_password_failures()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear(&failure_key);
    }

    let lobby = lobbies_write.entry(lid.clone()).or_insert_with(|| {
        log::info!("🏠 创建新大厅: {} (ID: {})，房主: {}", lobby_name, lid, cid);
        let password_salt = random_hex::<LOBBY_PASSWORD_SALT_BYTES>();
        LobbyInfo {
            lobby_name: lobby_name.clone(),
            password_hash: hash_lobby_password(&password_salt, &lobby_password),
            password_salt,
            clients: HashMap::new(),
            host_id: cid.clone(),
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

    // The same signed identity may replace its stale session at its own IP.
    if lobby.clients.values().any(|info| {
        info.player_id != cid
            && info
                .virtual_ip
                .as_deref()
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                == Some(virtual_ip)
    }) {
        log::warn!("❌ 虚拟IP已在大厅 {} 中使用: {}", lobby_name, virtual_ip);
        drop(lobbies_write);
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: "virtualIp 已被大厅内其他成员使用".to_string(),
            },
        )
        .await;
        return RegistrationOutcome::Retry;
    }

    let generation = random_session_generation();
    let client_info = ClientInfo {
        player_id: cid.clone(),
        player_name: player_name.clone(),
        virtual_ip: Some(virtual_ip.to_string()),
        virtual_domain: virtual_domain.clone(),
        use_domain,
        chat_public_key: chat_public_key.clone(),
        session_generation: generation,
        sender: Arc::clone(sender),
        disconnect: disconnect_tx.clone(),
    };

    // Preserve the absolute cap even for reconnects; only the host-configured
    // capacity exempts replacement of an existing identity.
    if lobby.clients.len() >= MAX_LOBBY_MEMBERS
        || lobby.max_players.is_some_and(|max| {
            !lobby.clients.contains_key(&cid) && lobby.clients.len() as u32 >= max
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
        send_response(
            sender,
            SignalingMessage::RegisterError {
                message: format!("大厅人数已满（服务端上限 {} 人）", MAX_LOBBY_MEMBERS),
            },
        )
        .await;
        return RegistrationOutcome::Retry;
    }

    let had_existing_members = !lobby.clients.is_empty();
    if let Some(previous) = lobby.clients.get(&cid) {
        let _ = previous.disconnect.send(true);
    }
    lobby.clients.insert(cid.clone(), client_info);
    let (chat_token_now, chat_token_epoch_now) = if had_existing_members {
        rotate_chat_token(lobby)
    } else {
        (lobby.chat_token.clone(), lobby.chat_token_epoch)
    };
    let rotation_targets = if had_existing_members {
        lobby
            .clients
            .iter()
            .filter(|(id, _)| id.as_str() != cid)
            .map(|(id, client)| (id.clone(), Arc::clone(&client.sender)))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let host_id_now = lobby.host_id.clone();
    let max_players_now = lobby.max_players;
    let is_public_now = lobby.is_public;
    let muted_now = lobby.muted.iter().cloned().collect();
    // Commit membership and the reverse mapping while holding the lobby lock.
    client_lobby_map
        .write()
        .await
        .insert(cid.clone(), lid.clone());
    drop(lobbies_write);

    let session = RegisteredSession {
        client_id: cid.clone(),
        lobby_id: lid.clone(),
        generation,
    };
    if *disconnect_rx.borrow() || !is_current_session(lobbies, &lid, &cid, generation, sender).await
    {
        log::warn!("注册提交后会话已失效，拒绝发送 token: client={}", cid);
        return RegistrationOutcome::Committed {
            session,
            disconnect: true,
        };
    }

    log::info!(
        "✅ 客户端 {} 已加入大厅 {} (当前 {} 人)",
        player_name,
        lobby_name,
        lobbies
            .read()
            .await
            .get(&lid)
            .map(|lobby| lobby.clients.len())
            .unwrap_or(0)
    );

    send_response(
        sender,
        SignalingMessage::RegisterSuccess {
            client_id: cid.clone(),
            session_generation: generation,
            lobby_id: lid.clone(),
            host_id: Some(host_id_now),
            max_players: max_players_now,
            is_public: Some(is_public_now),
            muted_players: Some(muted_now),
            chat_token: chat_token_now.clone(),
            chat_token_epoch: chat_token_epoch_now,
        },
    )
    .await;

    let players = current_players(lobbies, &lid, Some(&cid)).await;
    send_response(sender, SignalingMessage::PlayersList { players }).await;

    if !rotation_targets.is_empty() {
        send_chat_token_rotation(
            lobbies,
            rotation_targets,
            lid.clone(),
            chat_token_now,
            chat_token_epoch_now,
        )
        .await;
    }

    broadcast_to_lobby(
        lobbies,
        &lid,
        &cid,
        SignalingMessage::PlayerJoined {
            player_id: cid.clone(),
            player_name,
            virtual_ip: Some(virtual_ip.to_string()),
            virtual_domain,
            use_domain,
            chat_public_key,
            session_generation: generation,
        },
    )
    .await;

    RegistrationOutcome::Committed {
        session,
        disconnect: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        generate_lobby_id, handle_v3, reject_legacy, RegistrationContext, RegistrationOutcome,
        RegistrationRequest,
    };
    use crate::config::{
        minimum_client_version, websocket_config, MAX_LOBBY_MEMBERS, SIGNALING_PROTOCOL_VERSION,
    };
    use crate::security::{generate_chat_token, hash_lobby_password, registration_canonical};
    use crate::state::{
        ClientInfo, ClientLobbyMap, ClientSender, ClientSenderState, Lobbies, LobbyInfo,
        OutboundBudget,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use futures_util::StreamExt;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{watch, Mutex, RwLock};
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::WebSocketStream;

    const CHALLENGE: &str = "registration-module-test-challenge";

    struct TestConnection {
        sender: ClientSender,
        socket: WebSocketStream<TcpStream>,
        disconnect_tx: watch::Sender<bool>,
        disconnect_rx: watch::Receiver<bool>,
    }

    impl TestConnection {
        async fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, server) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let server = WebSocketStream::from_raw_socket(
                server.unwrap().0,
                Role::Server,
                Some(websocket_config()),
            )
            .await;
            let socket =
                WebSocketStream::from_raw_socket(client.unwrap(), Role::Client, None).await;
            let (sink, _) = server.split();
            let sender = Arc::new(ClientSenderState {
                sink: RwLock::new(sink),
                budget: Mutex::new(OutboundBudget::new()),
            });
            let (disconnect_tx, disconnect_rx) = watch::channel(false);
            Self {
                sender,
                socket,
                disconnect_tx,
                disconnect_rx,
            }
        }

        fn context<'a>(
            &'a self,
            lobbies: &'a Lobbies,
            client_lobby_map: &'a ClientLobbyMap,
        ) -> RegistrationContext<'a> {
            RegistrationContext {
                lobbies,
                client_lobby_map,
                sender: &self.sender,
                disconnect_tx: &self.disconnect_tx,
                disconnect_rx: &self.disconnect_rx,
                challenge: CHALLENGE,
                peer_addr: "198.51.100.45:1234".parse().unwrap(),
                source_ip: "198.51.100.45".parse().unwrap(),
                is_registered: false,
                client_id: None,
            }
        }

        fn member(&self, client_id: &str, virtual_ip: Option<&str>) -> ClientInfo {
            ClientInfo {
                player_id: client_id.to_string(),
                player_name: client_id.to_string(),
                virtual_ip: virtual_ip.map(str::to_string),
                virtual_domain: None,
                use_domain: None,
                chat_public_key: None,
                session_generation: 1,
                sender: Arc::clone(&self.sender),
                disconnect: self.disconnect_tx.clone(),
            }
        }

        async fn next_json(&mut self) -> Value {
            let frame =
                tokio::time::timeout(tokio::time::Duration::from_secs(2), self.socket.next())
                    .await
                    .expect("registration response should arrive")
                    .expect("test socket should remain open")
                    .expect("registration response should be valid");
            serde_json::from_str(frame.to_text().unwrap()).unwrap()
        }
    }

    fn signed_request(seed: u8, room: &str, virtual_ip: &str) -> (RegistrationRequest, String) {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public_key = key.verifying_key().to_public_key_der().unwrap();
        let client_id = Sha256::digest(public_key.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let signature: Signature = key.sign(&registration_canonical(CHALLENGE, room, virtual_ip));
        (
            RegistrationRequest {
                entry_mode: None,
                protocol_version: SIGNALING_PROTOCOL_VERSION,
                identity_public_key: STANDARD.encode(public_key.as_bytes()),
                challenge_signature: STANDARD.encode(signature.to_der().as_bytes()),
                player_name: format!("player-{seed}"),
                virtual_ip: Some(virtual_ip.to_string()),
                use_domain: None,
                lobby_name: room.to_string(),
                lobby_password: "password".to_string(),
                client_version: Some(minimum_client_version().to_string()),
            },
            client_id,
        )
    }

    fn seeded_lobby(
        room: &str,
        members: Vec<ClientInfo>,
        max_players: Option<u32>,
    ) -> (Lobbies, ClientLobbyMap) {
        let lid = generate_lobby_id(room);
        let host_id = members.first().unwrap().player_id.clone();
        let mapping = members
            .iter()
            .map(|member| (member.player_id.clone(), lid.clone()))
            .collect();
        let lobby = LobbyInfo {
            lobby_name: room.to_string(),
            password_hash: hash_lobby_password("test-salt", "password"),
            password_salt: "test-salt".to_string(),
            clients: members
                .into_iter()
                .map(|member| (member.player_id.clone(), member))
                .collect(),
            host_id,
            max_players,
            is_public: false,
            is_passwordless: false,
            description: String::new(),
            server_node: String::new(),
            muted: HashSet::new(),
            chat_token: generate_chat_token(),
            chat_token_epoch: 1,
        };
        (
            Arc::new(RwLock::new(HashMap::from([(lid, lobby)]))),
            Arc::new(RwLock::new(mapping)),
        )
    }

    #[tokio::test]
    async fn legacy_registration_never_enters_v3_admission() {
        let mut connection = TestConnection::new().await;
        for (version, response) in [
            (None, "version-too-old"),
            (Some("0.0.1"), "version-too-old"),
            (Some(minimum_client_version()), "register-error"),
        ] {
            assert!(matches!(
                reject_legacy(&connection.sender, version).await,
                RegistrationOutcome::Disconnect
            ));
            let error = connection.next_json().await;
            assert_eq!(error["type"], response);
            assert!(error.get("chatToken").is_none());
        }
    }

    #[tokio::test]
    async fn invalid_challenge_proof_does_not_create_membership() {
        let room = "module-invalid-challenge";
        let mut connection = TestConnection::new().await;
        let lobbies = Arc::new(RwLock::new(HashMap::new()));
        let mapping = Arc::new(RwLock::new(HashMap::new()));
        let (mut request, _) = signed_request(7, room, "10.126.126.7");
        request.challenge_signature = STANDARD.encode([1u8; 64]);
        assert!(matches!(
            handle_v3(connection.context(&lobbies, &mapping), request).await,
            RegistrationOutcome::Disconnect
        ));
        assert_eq!(
            connection.next_json().await["message"],
            "身份公钥或 challengeSignature 无效"
        );
        assert!(lobbies.read().await.is_empty());
        assert!(mapping.read().await.is_empty());
    }

    #[tokio::test]
    async fn host_capacity_allows_identity_replacement_but_rejects_new_identity() {
        let room = "module-host-capacity";
        let old = TestConnection::new().await;
        let mut replacement = TestConnection::new().await;
        let (request, client_id) = signed_request(7, room, "10.126.126.7");
        let (lobbies, mapping) = seeded_lobby(
            room,
            vec![old.member(&client_id, Some("10.126.126.7"))],
            Some(1),
        );
        let lid = generate_lobby_id(room);
        let previous_token = lobbies.read().await[&lid].chat_token.clone();

        let outcome = handle_v3(replacement.context(&lobbies, &mapping), request).await;
        let RegistrationOutcome::Committed {
            session,
            disconnect: false,
        } = outcome
        else {
            panic!("host-configured capacity should allow the same identity to reconnect");
        };
        assert_eq!(session.client_id, client_id);
        assert_eq!(session.lobby_id, lid);
        assert!(*old.disconnect_rx.borrow());
        let success = replacement.next_json().await;
        assert_eq!(success["type"], "register-success");
        assert_eq!(success["sessionGeneration"], session.generation);
        assert_eq!(success["chatTokenEpoch"], 2);
        assert_ne!(success["chatToken"], previous_token);
        assert_eq!(replacement.next_json().await["type"], "players-list");
        {
            let lobbies_read = lobbies.read().await;
            let lobby = &lobbies_read[&lid];
            assert_eq!(lobby.clients.len(), 1);
            assert!(Arc::ptr_eq(
                &lobby.clients[&client_id].sender,
                &replacement.sender
            ));
        }

        let mut newcomer = TestConnection::new().await;
        let (request, newcomer_id) = signed_request(8, room, "10.126.126.8");
        assert!(matches!(
            handle_v3(newcomer.context(&lobbies, &mapping), request).await,
            RegistrationOutcome::Retry
        ));
        assert_eq!(newcomer.next_json().await["type"], "register-error");
        assert!(!mapping.read().await.contains_key(&newcomer_id));
        assert_eq!(lobbies.read().await[&lid].clients.len(), 1);
    }

    #[tokio::test]
    async fn absolute_capacity_rejects_both_reconnect_and_new_identity_without_mutation() {
        let room = "module-absolute-capacity";
        let old = TestConnection::new().await;
        let (_, existing_id) = signed_request(7, room, "10.126.126.7");
        let mut members = vec![old.member(&existing_id, Some("10.126.126.7"))];
        members.extend(
            (1..MAX_LOBBY_MEMBERS).map(|index| old.member(&format!("existing-{index}"), None)),
        );
        let (lobbies, mapping) = seeded_lobby(room, members, None);
        let lid = generate_lobby_id(room);
        let previous_token = lobbies.read().await[&lid].chat_token.clone();
        let previous_mapping = mapping.read().await.clone();

        for (seed, ip) in [(7, "10.126.126.7"), (8, "10.126.126.8")] {
            let mut connection = TestConnection::new().await;
            let (request, _) = signed_request(seed, room, ip);
            assert!(matches!(
                handle_v3(connection.context(&lobbies, &mapping), request).await,
                RegistrationOutcome::Retry
            ));
            let error = connection.next_json().await;
            assert_eq!(error["type"], "register-error");
            assert_eq!(
                error["message"],
                format!("大厅人数已满（服务端上限 {} 人）", MAX_LOBBY_MEMBERS)
            );
            let lobbies_read = lobbies.read().await;
            let lobby = &lobbies_read[&lid];
            assert_eq!(lobby.clients.len(), MAX_LOBBY_MEMBERS);
            assert_eq!(lobby.chat_token, previous_token);
            assert_eq!(lobby.chat_token_epoch, 1);
            assert!(Arc::ptr_eq(
                &lobby.clients[&existing_id].sender,
                &old.sender
            ));
            assert!(!*old.disconnect_rx.borrow());
        }
        assert_eq!(*mapping.read().await, previous_mapping);
    }

    #[tokio::test]
    async fn admission_sends_success_roster_then_rotates_token_before_join_event() {
        let room = "module-membership-events";
        let mut host = TestConnection::new().await;
        let mut member = TestConnection::new().await;
        let (lobbies, mapping) =
            seeded_lobby(room, vec![host.member("host", Some("10.126.126.1"))], None);
        let (request, client_id) = signed_request(7, room, "10.126.126.7");
        let RegistrationOutcome::Committed {
            session,
            disconnect: false,
        } = handle_v3(member.context(&lobbies, &mapping), request).await
        else {
            panic!("member should be admitted");
        };
        let success = member.next_json().await;
        assert_eq!(success["type"], "register-success");
        let roster = member.next_json().await;
        assert_eq!(roster["type"], "players-list");
        assert_eq!(roster["players"][0]["playerId"], "host");
        let rotation = host.next_json().await;
        assert_eq!(rotation["type"], "chat-token-rotated");
        assert_eq!(rotation["chatToken"], success["chatToken"]);
        assert_eq!(rotation["chatTokenEpoch"], success["chatTokenEpoch"]);
        let joined = host.next_json().await;
        assert_eq!(joined["type"], "player-joined");
        assert_eq!(joined["playerId"], client_id);
        assert_eq!(joined["sessionGeneration"], session.generation);
        assert_eq!(joined["useDomain"], true);
        assert_eq!(
            joined["virtualDomain"],
            format!("{}.mct.net", &client_id[..32])
        );
        assert!(joined.get("chatToken").is_none());
        assert_eq!(mapping.read().await[&client_id], session.lobby_id);
    }

    #[tokio::test]
    async fn committed_disconnected_session_is_returned_for_connection_cleanup() {
        let room = "module-committed-disconnected";
        let connection = TestConnection::new().await;
        let lobbies = Arc::new(RwLock::new(HashMap::new()));
        let mapping = Arc::new(RwLock::new(HashMap::new()));
        connection.disconnect_tx.send(true).unwrap();
        let (request, client_id) = signed_request(7, room, "10.126.126.7");
        let RegistrationOutcome::Committed {
            session,
            disconnect: true,
        } = handle_v3(connection.context(&lobbies, &mapping), request).await
        else {
            panic!("committed state must be returned even when the session is disconnected");
        };
        assert_eq!(session.client_id, client_id);
        assert_eq!(mapping.read().await[&client_id], session.lobby_id);
        assert_eq!(
            lobbies.read().await[&session.lobby_id].clients[&client_id].session_generation,
            session.generation
        );
        assert_eq!(connection.sender.budget.lock().await.frames, 0);
    }
}
