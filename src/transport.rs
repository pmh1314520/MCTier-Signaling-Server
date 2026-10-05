//! Bounded WebSocket writes, lobby delivery, and authenticated session metadata.
use crate::config::{
    MAX_OUTBOUND_BYTES_PER_WINDOW, MAX_OUTBOUND_FRAMES_PER_WINDOW, SEND_TIMEOUT_SECS,
};
use crate::protocol::{PlayerInfo, SignalingMessage};
use crate::state::{ClientSender, Lobbies};
use futures_util::{future::join_all, SinkExt};
use std::future::Future;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

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

/// 广播消息到大厅内所有客户端（排除指定客户端）。
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
        // Snapshot sender handles under the lobby lock; perform network I/O outside it.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn session_metadata_overrides_claimed_identity_without_changing_payload() {
        let raw = json!({
            "type": "offer",
            "from": "forged",
            "clientId": "forged",
            "to": "peer",
            "sessionGeneration": 1,
            "offer": {"type": "offer", "sdp": "v=0\r\n"}
        });
        let forwarded: Value = serde_json::from_str(&inject_session_metadata(
            raw.to_string(),
            "authenticated",
            42,
        ))
        .unwrap();
        assert_eq!(forwarded["from"], "authenticated");
        assert_eq!(forwarded["clientId"], "authenticated");
        assert_eq!(forwarded["sessionGeneration"], 42);
        assert_eq!(forwarded["offer"], raw["offer"]);
        assert_eq!(forwarded["to"], raw["to"]);
        assert_eq!(forwarded["type"], raw["type"]);
    }

    #[test]
    fn invalid_json_and_non_object_messages_remain_unchanged() {
        for raw in ["{invalid", "", "[1, 2]", "\"text\"", "null", "true"] {
            assert_eq!(
                inject_session_metadata(raw.to_string(), "authenticated", 42),
                raw
            );
        }
    }
}
