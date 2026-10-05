//! Authenticated host actions and their lobby notifications.
use crate::config::MAX_LOBBY_MEMBERS;
use crate::protocol::{effective_public_setting, valid_text, SignalingMessage};
use crate::state::{rotate_chat_token, ClientLobbyMap, ClientSender, Lobbies, LobbyInfo};
use crate::transport::{broadcast_to_lobby, send_chat_token_rotation, send_message, send_text};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

/// Construct only after the connection has authenticated its current session.
pub(crate) struct ModerationSession<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) lobby_id: &'a str,
    pub(crate) session_generation: u64,
    pub(crate) sender: &'a ClientSender,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModerationDispatch {
    NotHandled,
    Handled,
    CloseConnection,
}

/// Consume only client-originated host actions, without admitting an unregistered
/// connection through a client id that happens to exist in the global map.
pub(crate) async fn handle_moderation_message(
    message: &SignalingMessage,
    session: Option<ModerationSession<'_>>,
    lobbies: &Lobbies,
    client_lobby_map: &ClientLobbyMap,
) -> ModerationDispatch {
    let from = match message {
        SignalingMessage::KickPlayer { from, .. }
        | SignalingMessage::MutePlayer { from, .. }
        | SignalingMessage::TransferHost { from, .. }
        | SignalingMessage::SetLobbyOptions { from, .. } => from,
        _ => return ModerationDispatch::NotHandled,
    };
    let Some(session) = session else {
        log::warn!("Rejecting an unregistered lobby moderation action");
        return ModerationDispatch::CloseConnection;
    };
    if from != session.client_id {
        log::warn!("Rejecting a moderation action with a mismatched sender");
        return ModerationDispatch::Handled;
    }
    let mapped_lobby = client_lobby_map
        .read()
        .await
        .get(session.client_id)
        .cloned();
    if mapped_lobby.as_deref() != Some(session.lobby_id) {
        return ModerationDispatch::Handled;
    }

    match message {
        SignalingMessage::KickPlayer { target, .. } => {
            kick_player(lobbies, client_lobby_map, &session, target).await
        }
        SignalingMessage::MutePlayer { target, muted, .. } => {
            mute_player(lobbies, &session, target, *muted).await
        }
        SignalingMessage::TransferHost { target, .. } => {
            transfer_host(lobbies, &session, target).await
        }
        SignalingMessage::SetLobbyOptions {
            max_players,
            is_public,
            description,
            server_node,
            ..
        } => {
            set_lobby_options(
                lobbies,
                &session,
                *max_players,
                *is_public,
                description.as_deref(),
                server_node.as_deref(),
            )
            .await
        }
        _ => ModerationDispatch::NotHandled,
    }
}

/// Recheck the session and host under the same lock used for the mutation.
fn authorize_host(
    lobby: &LobbyInfo,
    session: &ModerationSession<'_>,
) -> Result<(), ModerationDispatch> {
    let is_current = lobby.clients.get(session.client_id).is_some_and(|client| {
        client.session_generation == session.session_generation
            && Arc::ptr_eq(&client.sender, session.sender)
    });
    if !is_current {
        return Err(ModerationDispatch::CloseConnection);
    }
    if lobby.host_id != session.client_id {
        log::warn!("Rejecting a moderation action from a non-host");
        return Err(ModerationDispatch::Handled);
    }
    Ok(())
}

async fn kick_player(
    lobbies: &Lobbies,
    client_lobby_map: &ClientLobbyMap,
    session: &ModerationSession<'_>,
    target: &str,
) -> ModerationDispatch {
    let (removed, targets, token, epoch) = {
        let mut lobbies_write = lobbies.write().await;
        let Some(lobby) = lobbies_write.get_mut(session.lobby_id) else {
            return ModerationDispatch::Handled;
        };
        if let Err(result) = authorize_host(lobby, session) {
            return result;
        }
        if target == session.client_id {
            return ModerationDispatch::Handled;
        }
        let Some(removed) = lobby.clients.remove(target) else {
            return ModerationDispatch::Handled;
        };
        lobby.muted.remove(target);
        let (token, epoch) = rotate_chat_token(lobby);
        let targets = lobby
            .clients
            .iter()
            .map(|(id, client)| (id.clone(), Arc::clone(&client.sender)))
            .collect();
        let mut map = client_lobby_map.write().await;
        if map.get(target).is_some_and(|id| id == session.lobby_id) {
            map.remove(target);
        }
        (removed, targets, token, epoch)
    };

    let _ = removed.disconnect.send(true);
    let kicked = SignalingMessage::Kicked {
        reason: "你已被房主移出大厅".to_string(),
    };
    if let Ok(json) = serde_json::to_string(&kicked) {
        send_text(&removed.sender, json).await;
    }
    let _ = send_message(&removed.sender, Message::Close(None)).await;
    log::info!("Host {} kicked {}", session.client_id, target);
    broadcast_to_lobby(
        lobbies,
        session.lobby_id,
        target,
        SignalingMessage::PlayerLeft {
            player_id: target.to_string(),
            session_generation: removed.session_generation,
        },
    )
    .await;
    send_chat_token_rotation(lobbies, targets, session.lobby_id.to_string(), token, epoch).await;
    ModerationDispatch::Handled
}

async fn mute_player(
    lobbies: &Lobbies,
    session: &ModerationSession<'_>,
    target: &str,
    muted: bool,
) -> ModerationDispatch {
    {
        let mut lobbies_write = lobbies.write().await;
        let Some(lobby) = lobbies_write.get_mut(session.lobby_id) else {
            return ModerationDispatch::Handled;
        };
        if let Err(result) = authorize_host(lobby, session) {
            return result;
        }
        if target == lobby.host_id && muted {
            return ModerationDispatch::Handled;
        }
        if !lobby.clients.contains_key(target) {
            return ModerationDispatch::Handled;
        }
        if muted {
            if lobby.muted.len() >= MAX_LOBBY_MEMBERS && !lobby.muted.contains(target) {
                return ModerationDispatch::Handled;
            }
            lobby.muted.insert(target.to_string());
        } else {
            lobby.muted.remove(target);
        }
    }
    log::info!("Host {} set {} muted={}", session.client_id, target, muted);
    broadcast_to_lobby(
        lobbies,
        session.lobby_id,
        "",
        SignalingMessage::PlayerMuteChanged {
            player_id: target.to_string(),
            muted,
        },
    )
    .await;
    ModerationDispatch::Handled
}

async fn transfer_host(
    lobbies: &Lobbies,
    session: &ModerationSession<'_>,
    target: &str,
) -> ModerationDispatch {
    {
        let mut lobbies_write = lobbies.write().await;
        let Some(lobby) = lobbies_write.get_mut(session.lobby_id) else {
            return ModerationDispatch::Handled;
        };
        if let Err(result) = authorize_host(lobby, session) {
            return result;
        }
        if !lobby.clients.contains_key(target) {
            return ModerationDispatch::Handled;
        }
        lobby.host_id = target.to_string();
        lobby.muted.remove(target);
    }
    log::info!("Host transferred from {} to {}", session.client_id, target);
    broadcast_to_lobby(
        lobbies,
        session.lobby_id,
        "",
        SignalingMessage::PlayerMuteChanged {
            player_id: target.to_string(),
            muted: false,
        },
    )
    .await;
    broadcast_to_lobby(
        lobbies,
        session.lobby_id,
        "",
        SignalingMessage::HostChanged {
            host_id: target.to_string(),
        },
    )
    .await;
    ModerationDispatch::Handled
}

async fn set_lobby_options(
    lobbies: &Lobbies,
    session: &ModerationSession<'_>,
    max_players: Option<u32>,
    is_public: Option<bool>,
    description: Option<&str>,
    server_node: Option<&str>,
) -> ModerationDispatch {
    let (max_players, is_public) = {
        let mut lobbies_write = lobbies.write().await;
        let Some(lobby) = lobbies_write.get_mut(session.lobby_id) else {
            return ModerationDispatch::Handled;
        };
        if let Err(result) = authorize_host(lobby, session) {
            return result;
        }
        if let Some(max_players) = max_players {
            lobby.max_players = if max_players == 0 {
                None
            } else {
                Some(max_players.min(MAX_LOBBY_MEMBERS as u32))
            };
        }
        if let Some(description) = description {
            if valid_text(description, 200, true) {
                lobby.description = description.to_string();
            }
        }
        if let Some(server_node) = server_node {
            if valid_text(server_node, 512, false) {
                lobby.server_node = server_node.to_string();
            }
        }
        if let Some(requested_public) = is_public {
            lobby.is_public = effective_public_setting(requested_public, lobby.is_passwordless);
            if requested_public && !lobby.is_passwordless {
                log::warn!("Rejecting public listing of a password-protected lobby");
            }
        }
        (lobby.max_players, lobby.is_public)
    };
    log::info!(
        "Host {} updated lobby options: max={:?}, public={}",
        session.client_id,
        max_players,
        is_public
    );
    broadcast_to_lobby(
        lobbies,
        session.lobby_id,
        "",
        SignalingMessage::LobbyOptionsChanged {
            max_players,
            is_public,
        },
    )
    .await;
    ModerationDispatch::Handled
}

#[cfg(test)]
mod tests {
    use crate::config::MAX_LOBBY_MEMBERS;
    use crate::moderation::{handle_moderation_message, ModerationDispatch, ModerationSession};
    use crate::protocol::SignalingMessage;
    use crate::state::{
        ClientInfo, ClientLobbyMap, ClientSender, ClientSenderState, Lobbies, LobbyInfo,
        OutboundBudget,
    };
    use futures_util::StreamExt;
    use serde_json::Value;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{watch, Mutex, RwLock};
    use tokio::time::{timeout, Duration};
    use tokio_tungstenite::tungstenite::{protocol::Role, Message};
    use tokio_tungstenite::WebSocketStream;

    const LOBBY_ID: &str = "room";
    const HOST_ID: &str = "host";
    const MEMBER_ID: &str = "member";

    struct Peer {
        wire: WebSocketStream<TcpStream>,
        sender: ClientSender,
        disconnect: watch::Sender<bool>,
        disconnect_rx: watch::Receiver<bool>,
    }

    impl Peer {
        fn client_info(&self, client_id: &str, generation: u64) -> ClientInfo {
            ClientInfo {
                player_id: client_id.to_string(),
                player_name: client_id.to_string(),
                virtual_ip: None,
                virtual_domain: None,
                use_domain: None,
                chat_public_key: None,
                session_generation: generation,
                sender: Arc::clone(&self.sender),
                disconnect: self.disconnect.clone(),
            }
        }
    }

    async fn peer() -> Peer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
        let (server, _) = server.unwrap();
        let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let (sink, _) = server.split();
        let wire = WebSocketStream::from_raw_socket(client.unwrap(), Role::Client, None).await;
        let (disconnect, disconnect_rx) = watch::channel(false);
        Peer {
            wire,
            sender: Arc::new(ClientSenderState {
                sink: RwLock::new(sink),
                budget: Mutex::new(OutboundBudget::new()),
            }),
            disconnect,
            disconnect_rx,
        }
    }

    struct Fixture {
        lobbies: Lobbies,
        client_lobby_map: ClientLobbyMap,
        host: Peer,
        member: Peer,
    }

    impl Fixture {
        async fn new(is_passwordless: bool) -> Self {
            let host = peer().await;
            let member = peer().await;
            let clients = HashMap::from([
                (HOST_ID.to_string(), host.client_info(HOST_ID, 1)),
                (MEMBER_ID.to_string(), member.client_info(MEMBER_ID, 2)),
            ]);
            let lobby = LobbyInfo {
                lobby_name: LOBBY_ID.to_string(),
                password_hash: String::new(),
                password_salt: String::new(),
                clients,
                host_id: HOST_ID.to_string(),
                max_players: Some(8),
                is_public: false,
                is_passwordless,
                description: "original description".to_string(),
                server_node: "udp://original".to_string(),
                muted: HashSet::new(),
                chat_token: "old-token".to_string(),
                chat_token_epoch: 7,
            };
            Self {
                lobbies: Arc::new(RwLock::new(HashMap::from([(LOBBY_ID.to_string(), lobby)]))),
                client_lobby_map: Arc::new(RwLock::new(HashMap::from([
                    (HOST_ID.to_string(), LOBBY_ID.to_string()),
                    (MEMBER_ID.to_string(), LOBBY_ID.to_string()),
                ]))),
                host,
                member,
            }
        }

        fn host_session(&self) -> ModerationSession<'_> {
            ModerationSession {
                client_id: HOST_ID,
                lobby_id: LOBBY_ID,
                session_generation: 1,
                sender: &self.host.sender,
            }
        }

        fn member_session(&self) -> ModerationSession<'_> {
            ModerationSession {
                client_id: MEMBER_ID,
                lobby_id: LOBBY_ID,
                session_generation: 2,
                sender: &self.member.sender,
            }
        }

        async fn host_action(&self, message: &SignalingMessage) -> ModerationDispatch {
            handle_moderation_message(
                message,
                Some(self.host_session()),
                &self.lobbies,
                &self.client_lobby_map,
            )
            .await
        }

        async fn assert_unchanged(&self) {
            let lobbies = self.lobbies.read().await;
            let lobby = &lobbies[LOBBY_ID];
            assert_eq!(lobby.clients.len(), 2);
            assert_eq!(lobby.host_id, HOST_ID);
            assert!(lobby.muted.is_empty());
            assert_eq!(lobby.max_players, Some(8));
            assert!(!lobby.is_public);
            assert_eq!(lobby.description, "original description");
            assert_eq!(lobby.server_node, "udp://original");
            assert_eq!(lobby.chat_token, "old-token");
            assert_eq!(lobby.chat_token_epoch, 7);
            assert!(!*self.host.disconnect_rx.borrow());
            assert!(!*self.member.disconnect_rx.borrow());
        }
    }

    async fn next_json(peer: &mut Peer) -> Value {
        let message = timeout(Duration::from_secs(1), peer.wire.next())
            .await
            .expect("notification should arrive")
            .expect("connection should remain open")
            .expect("notification should be valid");
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn unrelated_messages_are_not_handled_even_without_a_session() {
        let fixture = Fixture::new(true).await;
        assert_eq!(
            handle_moderation_message(
                &SignalingMessage::Ping,
                None,
                &fixture.lobbies,
                &fixture.client_lobby_map,
            )
            .await,
            ModerationDispatch::NotHandled,
        );
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn an_unregistered_connection_cannot_use_an_existing_host_mapping() {
        let fixture = Fixture::new(true).await;
        for message in [
            SignalingMessage::KickPlayer {
                from: HOST_ID.to_string(),
                target: MEMBER_ID.to_string(),
            },
            SignalingMessage::MutePlayer {
                from: HOST_ID.to_string(),
                target: MEMBER_ID.to_string(),
                muted: true,
            },
            SignalingMessage::TransferHost {
                from: HOST_ID.to_string(),
                target: MEMBER_ID.to_string(),
            },
            SignalingMessage::SetLobbyOptions {
                from: HOST_ID.to_string(),
                max_players: Some(1),
                is_public: Some(true),
                description: Some("changed".to_string()),
                server_node: Some("udp://changed".to_string()),
            },
        ] {
            assert_eq!(
                handle_moderation_message(
                    &message,
                    None,
                    &fixture.lobbies,
                    &fixture.client_lobby_map,
                )
                .await,
                ModerationDispatch::CloseConnection,
            );
        }
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn non_hosts_cannot_apply_any_moderation_action() {
        let fixture = Fixture::new(true).await;
        for message in [
            SignalingMessage::KickPlayer {
                from: MEMBER_ID.to_string(),
                target: HOST_ID.to_string(),
            },
            SignalingMessage::MutePlayer {
                from: MEMBER_ID.to_string(),
                target: MEMBER_ID.to_string(),
                muted: true,
            },
            SignalingMessage::TransferHost {
                from: MEMBER_ID.to_string(),
                target: MEMBER_ID.to_string(),
            },
            SignalingMessage::SetLobbyOptions {
                from: MEMBER_ID.to_string(),
                max_players: Some(1),
                is_public: Some(true),
                description: Some("changed".to_string()),
                server_node: Some("udp://changed".to_string()),
            },
        ] {
            assert_eq!(
                handle_moderation_message(
                    &message,
                    Some(fixture.member_session()),
                    &fixture.lobbies,
                    &fixture.client_lobby_map,
                )
                .await,
                ModerationDispatch::Handled,
            );
        }
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn missing_targets_do_not_change_membership_or_host_or_mute_state() {
        let fixture = Fixture::new(true).await;
        for message in [
            SignalingMessage::KickPlayer {
                from: HOST_ID.to_string(),
                target: "missing".to_string(),
            },
            SignalingMessage::MutePlayer {
                from: HOST_ID.to_string(),
                target: "missing".to_string(),
                muted: true,
            },
            SignalingMessage::TransferHost {
                from: HOST_ID.to_string(),
                target: "missing".to_string(),
            },
        ] {
            assert_eq!(
                fixture.host_action(&message).await,
                ModerationDispatch::Handled,
            );
        }
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn stale_generation_or_sender_cannot_apply_host_actions() {
        let fixture = Fixture::new(true).await;
        let message = SignalingMessage::KickPlayer {
            from: HOST_ID.to_string(),
            target: MEMBER_ID.to_string(),
        };
        for session in [
            ModerationSession {
                session_generation: 99,
                ..fixture.host_session()
            },
            ModerationSession {
                sender: &fixture.member.sender,
                ..fixture.host_session()
            },
        ] {
            assert_eq!(
                handle_moderation_message(
                    &message,
                    Some(session),
                    &fixture.lobbies,
                    &fixture.client_lobby_map,
                )
                .await,
                ModerationDispatch::CloseConnection,
            );
        }
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn queued_host_action_rechecks_session_after_lock_contention() {
        for message in [
            SignalingMessage::KickPlayer {
                from: HOST_ID.to_string(),
                target: MEMBER_ID.to_string(),
            },
            SignalingMessage::MutePlayer {
                from: HOST_ID.to_string(),
                target: MEMBER_ID.to_string(),
                muted: true,
            },
            SignalingMessage::TransferHost {
                from: HOST_ID.to_string(),
                target: MEMBER_ID.to_string(),
            },
        ] {
            let fixture = Fixture::new(true).await;
            let mut guard = fixture.lobbies.write().await;
            let mut action = std::pin::pin!(fixture.host_action(&message));
            // Poll until the handler has reached the contended lobby lock.
            // No sleep or scheduler timing is used to establish the race.
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(action.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            guard
                .get_mut(LOBBY_ID)
                .unwrap()
                .clients
                .get_mut(HOST_ID)
                .unwrap()
                .session_generation = 99;
            drop(guard);
            assert_eq!(action.await, ModerationDispatch::CloseConnection);
            fixture.assert_unchanged().await;
        }
    }

    #[tokio::test]
    async fn sender_and_lobby_mapping_must_match_the_authenticated_context() {
        let fixture = Fixture::new(true).await;
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::KickPlayer {
                    from: MEMBER_ID.to_string(),
                    target: HOST_ID.to_string(),
                })
                .await,
            ModerationDispatch::Handled,
        );
        fixture
            .client_lobby_map
            .write()
            .await
            .insert(HOST_ID.to_string(), "other-lobby".to_string());
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::KickPlayer {
                    from: HOST_ID.to_string(),
                    target: MEMBER_ID.to_string(),
                })
                .await,
            ModerationDispatch::Handled,
        );
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn host_cannot_kick_or_mute_itself() {
        let fixture = Fixture::new(true).await;
        for message in [
            SignalingMessage::KickPlayer {
                from: HOST_ID.to_string(),
                target: HOST_ID.to_string(),
            },
            SignalingMessage::MutePlayer {
                from: HOST_ID.to_string(),
                target: HOST_ID.to_string(),
                muted: true,
            },
        ] {
            assert_eq!(
                fixture.host_action(&message).await,
                ModerationDispatch::Handled,
            );
        }
        fixture.assert_unchanged().await;
    }

    #[tokio::test]
    async fn mute_and_unmute_notify_the_host_and_target() {
        let mut fixture = Fixture::new(true).await;
        for muted in [true, false] {
            assert_eq!(
                fixture
                    .host_action(&SignalingMessage::MutePlayer {
                        from: HOST_ID.to_string(),
                        target: MEMBER_ID.to_string(),
                        muted,
                    })
                    .await,
                ModerationDispatch::Handled,
            );
            assert_eq!(
                fixture.lobbies.read().await[LOBBY_ID]
                    .muted
                    .contains(MEMBER_ID),
                muted,
            );
            for peer in [&mut fixture.host, &mut fixture.member] {
                let notification = next_json(peer).await;
                assert_eq!(notification["type"], "player-mute-changed");
                assert_eq!(notification["playerId"], MEMBER_ID);
                assert_eq!(notification["muted"], muted);
            }
        }
    }

    #[tokio::test]
    async fn a_full_mute_set_rejects_new_entries_but_allows_existing_entries() {
        let mut fixture = Fixture::new(true).await;
        {
            let mut lobbies = fixture.lobbies.write().await;
            let lobby = lobbies.get_mut(LOBBY_ID).unwrap();
            lobby.muted = (0..MAX_LOBBY_MEMBERS)
                .map(|index| format!("muted-{index}"))
                .collect();
        }
        let message = SignalingMessage::MutePlayer {
            from: HOST_ID.to_string(),
            target: MEMBER_ID.to_string(),
            muted: true,
        };
        assert_eq!(
            fixture.host_action(&message).await,
            ModerationDispatch::Handled,
        );
        {
            let mut lobbies = fixture.lobbies.write().await;
            let lobby = lobbies.get_mut(LOBBY_ID).unwrap();
            assert!(!lobby.muted.contains(MEMBER_ID));
            assert_eq!(lobby.muted.len(), MAX_LOBBY_MEMBERS);
            lobby.muted.remove("muted-0");
            lobby.muted.insert(MEMBER_ID.to_string());
        }
        assert_eq!(
            fixture.host_action(&message).await,
            ModerationDispatch::Handled,
        );
        assert_eq!(
            fixture.lobbies.read().await[LOBBY_ID].muted.len(),
            MAX_LOBBY_MEMBERS,
        );
        for peer in [&mut fixture.host, &mut fixture.member] {
            let notification = next_json(peer).await;
            assert_eq!(notification["type"], "player-mute-changed");
            assert_eq!(notification["playerId"], MEMBER_ID);
            assert_eq!(notification["muted"], true);
        }
    }

    #[tokio::test]
    async fn host_transfer_unmutes_the_new_host_before_the_host_notification() {
        let mut fixture = Fixture::new(true).await;
        fixture
            .lobbies
            .write()
            .await
            .get_mut(LOBBY_ID)
            .unwrap()
            .muted
            .insert(MEMBER_ID.to_string());
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::TransferHost {
                    from: HOST_ID.to_string(),
                    target: MEMBER_ID.to_string(),
                })
                .await,
            ModerationDispatch::Handled,
        );
        {
            let lobbies = fixture.lobbies.read().await;
            assert_eq!(lobbies[LOBBY_ID].host_id, MEMBER_ID);
            assert!(!lobbies[LOBBY_ID].muted.contains(MEMBER_ID));
        }
        for peer in [&mut fixture.host, &mut fixture.member] {
            let unmute = next_json(peer).await;
            assert_eq!(unmute["type"], "player-mute-changed");
            assert_eq!(unmute["playerId"], MEMBER_ID);
            assert_eq!(unmute["muted"], false);
            let host = next_json(peer).await;
            assert_eq!(host["type"], "host-changed");
            assert_eq!(host["hostId"], MEMBER_ID);
        }
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::MutePlayer {
                    from: HOST_ID.to_string(),
                    target: MEMBER_ID.to_string(),
                    muted: true,
                })
                .await,
            ModerationDispatch::Handled,
        );
        assert!(!fixture.lobbies.read().await[LOBBY_ID]
            .muted
            .contains(MEMBER_ID));
    }

    #[tokio::test]
    async fn password_protected_lobbies_cannot_be_public_and_options_keep_their_limits() {
        let mut fixture = Fixture::new(false).await;
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::SetLobbyOptions {
                    from: HOST_ID.to_string(),
                    max_players: Some(u32::MAX),
                    is_public: Some(true),
                    description: Some("x".repeat(201)),
                    server_node: Some(" ".to_string()),
                })
                .await,
            ModerationDispatch::Handled,
        );
        {
            let lobbies = fixture.lobbies.read().await;
            let lobby = &lobbies[LOBBY_ID];
            assert_eq!(lobby.max_players, Some(MAX_LOBBY_MEMBERS as u32));
            assert!(!lobby.is_public);
            assert_eq!(lobby.description, "original description");
            assert_eq!(lobby.server_node, "udp://original");
        }
        for peer in [&mut fixture.host, &mut fixture.member] {
            let options = next_json(peer).await;
            assert_eq!(options["type"], "lobby-options-changed");
            assert_eq!(options["maxPlayers"], MAX_LOBBY_MEMBERS as u32);
            assert_eq!(options["isPublic"], false);
        }
    }

    #[tokio::test]
    async fn zero_max_players_removes_the_limit_and_passwordless_lobbies_can_be_public() {
        let mut fixture = Fixture::new(true).await;
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::SetLobbyOptions {
                    from: HOST_ID.to_string(),
                    max_players: Some(0),
                    is_public: Some(true),
                    description: Some(String::new()),
                    server_node: Some("udp://changed".to_string()),
                })
                .await,
            ModerationDispatch::Handled,
        );
        {
            let lobbies = fixture.lobbies.read().await;
            let lobby = &lobbies[LOBBY_ID];
            assert_eq!(lobby.max_players, None);
            assert!(lobby.is_public);
            assert!(lobby.description.is_empty());
            assert_eq!(lobby.server_node, "udp://changed");
        }
        for peer in [&mut fixture.host, &mut fixture.member] {
            let options = next_json(peer).await;
            assert_eq!(options["type"], "lobby-options-changed");
            assert!(options.get("maxPlayers").is_none());
            assert_eq!(options["isPublic"], true);
        }
    }

    #[tokio::test]
    async fn kicking_disconnects_the_target_clears_its_mapping_and_rotates_the_token() {
        let mut fixture = Fixture::new(true).await;
        fixture
            .lobbies
            .write()
            .await
            .get_mut(LOBBY_ID)
            .unwrap()
            .muted
            .insert(MEMBER_ID.to_string());
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::KickPlayer {
                    from: HOST_ID.to_string(),
                    target: MEMBER_ID.to_string(),
                })
                .await,
            ModerationDispatch::Handled,
        );
        let token = {
            let lobbies = fixture.lobbies.read().await;
            let lobby = &lobbies[LOBBY_ID];
            assert_eq!(lobby.clients.len(), 1);
            assert!(!lobby.clients.contains_key(MEMBER_ID));
            assert!(!lobby.muted.contains(MEMBER_ID));
            assert_eq!(lobby.host_id, HOST_ID);
            assert_ne!(lobby.chat_token, "old-token");
            assert_eq!(lobby.chat_token_epoch, 8);
            lobby.chat_token.clone()
        };
        assert!(!fixture
            .client_lobby_map
            .read()
            .await
            .contains_key(MEMBER_ID));
        assert!(*fixture.member.disconnect_rx.borrow());
        assert!(!*fixture.host.disconnect_rx.borrow());
        let kicked = next_json(&mut fixture.member).await;
        assert_eq!(kicked["type"], "kicked");
        assert_eq!(kicked["reason"], "你已被房主移出大厅");
        let close = timeout(Duration::from_secs(1), fixture.member.wire.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(close, Message::Close(_)));
        let left = next_json(&mut fixture.host).await;
        assert_eq!(left["type"], "player-left");
        assert_eq!(left["playerId"], MEMBER_ID);
        assert_eq!(left["sessionGeneration"], 2);
        let rotation = next_json(&mut fixture.host).await;
        assert_eq!(rotation["type"], "chat-token-rotated");
        assert_eq!(rotation["lobbyId"], LOBBY_ID);
        assert_eq!(rotation["chatToken"], token);
        assert_eq!(rotation["chatTokenEpoch"], 8);
    }

    #[tokio::test]
    async fn kicking_does_not_clear_a_target_mapping_that_points_to_another_lobby() {
        let fixture = Fixture::new(true).await;
        fixture
            .client_lobby_map
            .write()
            .await
            .insert(MEMBER_ID.to_string(), "other-lobby".to_string());
        assert_eq!(
            fixture
                .host_action(&SignalingMessage::KickPlayer {
                    from: HOST_ID.to_string(),
                    target: MEMBER_ID.to_string(),
                })
                .await,
            ModerationDispatch::Handled,
        );
        assert_eq!(
            fixture.client_lobby_map.read().await[MEMBER_ID],
            "other-lobby",
        );
        assert!(!fixture.lobbies.read().await[LOBBY_ID]
            .clients
            .contains_key(MEMBER_ID));
    }
}
