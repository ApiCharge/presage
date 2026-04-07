//! Message receiver — simple WebSocket receive loop via presage.
//!
//! Connects to Signal via presage's `receive_messages()` stream,
//! decrypts incoming envelopes, and forwards them to the HTTP API queue.

use crate::api::ReceivedMessage;

use ed25519_dalek::Signer;
use futures::StreamExt;
use presage::libsignal_service::content::{Content, ContentBody};
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::protocol::{Aci, ServiceId};
use presage::model::identity::OnNewIdentity;
use presage::model::messages::Received;
use presage::Manager;
use presage_store_sqlite::SqliteStore;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

pub async fn create_manager(
    db_path: &str,
) -> anyhow::Result<Manager<SqliteStore, presage::manager::Registered>> {
    let store = SqliteStore::open_with_passphrase(db_path, None, OnNewIdentity::Trust).await?;
    let manager = Manager::load_registered(store).await?;
    tracing::info!("Loaded registered manager, device_id={}", manager.device_id());
    Ok(manager)
}

/// Main receive loop: listens on WebSocket via presage, processes sends on a timer.
pub async fn run_receive_loop(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    _message_queue: Arc<Mutex<Vec<ReceivedMessage>>>,
    app_state: Arc<Mutex<crate::AppState>>,
) -> anyhow::Result<()> {
    tracing::info!("Starting WebSocket receive loop");

    let mut send_interval = tokio::time::interval(std::time::Duration::from_secs(2));

    let stream = manager.receive_messages().await?;
    futures::pin_mut!(stream);

    loop {
        tokio::select! {
            _ = send_interval.tick() => {
                process_pending_sends(manager, &app_state).await;
                process_pending_group_sends(manager, &app_state).await;
                process_pending_group_creates(manager, &app_state).await;
                process_pending_typing(manager, &app_state).await;
            }

            item = stream.next() => {
                match item {
                    Some(Received::Content { content, sender_key_msg, sender_key_seed, .. }) => {
                        handle_content(*content, sender_key_msg, sender_key_seed, &app_state).await;
                    }
                    Some(Received::SenderKeyDistribution { sender, signing_key, .. }) => {
                        let key_hex = signing_key.as_ref().map(hex::encode).unwrap_or_default();
                        tracing::info!("SenderKeyDistribution from {sender}, signing_key={key_hex}");

                        if let Some(sk) = signing_key {
                            // Queue SKDM event for the relay with TEE signature
                            let sender_uuid = if sender.is_empty() { "unknown".to_string() } else { sender };
                            let sk_hex = hex::encode(&sk);

                            // Sign: sender_uuid || signing_key
                            let mut sign_data = Vec::new();
                            sign_data.extend_from_slice(sender_uuid.as_bytes());
                            sign_data.extend_from_slice(&sk);
                            let tee_sig = {
                                let s = app_state.lock().await;
                                let sig = s.tee_signing_key.sign(&sign_data);
                                hex::encode(sig.to_bytes())
                            };

                            let msg = ReceivedMessage {
                                sender_uuid,
                                sender_phone: None,
                                sender_identity_key: None,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                                sealed_envelope: Default::default(),
                                verified_envelope: None,
                                tee_signature: Some(tee_sig),
                                decrypted_body: None,
                                group_id: None,
                                is_skdm: true,
                                skdm_signing_key: Some(sk_hex),
                                is_member_joined: false,
                                joined_member_uuid: None,
                                sender_key_msg: None,
                                sender_key_seed: None,
                            };

                            let mut s = app_state.lock().await;
                            s.message_queue.push(msg);
                            s.messages_received += 1;
                        }
                    }
                    Some(Received::QueueEmpty) => {
                        tracing::debug!("WebSocket queue empty");
                    }
                    Some(Received::Contacts) => {
                        tracing::debug!("Contacts sync received");
                    }
                    None => {
                        tracing::info!("WebSocket stream ended");
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn handle_content(
    content: Content,
    sender_key_msg: Option<Vec<u8>>,
    sender_key_seed: Option<Vec<u8>>,
    app_state: &Arc<Mutex<crate::AppState>>,
) {
    let sender_uuid = content.metadata.sender.raw_uuid().to_string();
    let body = extract_body_text(&content);

    let is_group = matches!(
        &content.body,
        ContentBody::DataMessage(dm) if dm.group_v2.is_some()
    );

    // Extract group_id if this is a group message
    let group_id = if let ContentBody::DataMessage(dm) = &content.body {
        dm.group_v2.as_ref().and_then(|g| {
            g.master_key.as_ref().map(|k| hex::encode(k))
        })
    } else {
        None
    };

    // Detect group member acceptance (group_change present and non-empty)
    let is_member_joined = if let ContentBody::DataMessage(dm) = &content.body {
        dm.group_v2.as_ref().map_or(false, |g| {
            g.group_change.as_ref().map_or(false, |c| !c.is_empty())
        })
    } else {
        false
    };

    if is_member_joined {
        tracing::info!(
            "Group member change detected from {} in group {:?}",
            sender_uuid,
            group_id,
        );
    }

    if is_group {
        tracing::info!(
            "Group message from {}: {}",
            sender_uuid,
            body.as_deref().unwrap_or("<non-text>"),
        );
    } else {
        tracing::info!(
            "Message from {}: {}",
            sender_uuid,
            body.as_deref().unwrap_or("<non-text>"),
        );
    }

    {
        let mut msg = ReceivedMessage {
            sender_uuid,
            sender_phone: None,
            sender_identity_key: None,
            timestamp: content.metadata.timestamp,
            sealed_envelope: Default::default(),
            verified_envelope: None,
            tee_signature: None,
            decrypted_body: body,
            group_id,
            is_skdm: false,
            skdm_signing_key: None,
            is_member_joined,
            joined_member_uuid: None,
            sender_key_msg: sender_key_msg.as_ref().map(hex::encode),
            sender_key_seed: sender_key_seed.as_ref().map(hex::encode),
        };

        // Sign the message with the TEE key.
        // We sign: sender_uuid || timestamp (big-endian 8 bytes) || body bytes
        // This binds the attestation to the specific message content.
        {
            let s = app_state.lock().await;
            let mut sign_data = Vec::new();
            sign_data.extend_from_slice(msg.sender_uuid.as_bytes());
            sign_data.extend_from_slice(&msg.timestamp.to_be_bytes());
            if let Some(ref body) = msg.decrypted_body {
                sign_data.extend_from_slice(body.as_bytes());
            }
            let signature = s.tee_signing_key.sign(&sign_data);
            msg.tee_signature = Some(hex::encode(signature.to_bytes()));
        }

        let mut s = app_state.lock().await;
        // Track group ID for /list-groups (persistent across session)
        if let Some(ref gid) = msg.group_id {
            s.known_group_ids.insert(gid.clone());
        }
        s.message_queue.push(msg);
        s.messages_received += 1;
    }
}

async fn process_pending_sends(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    app_state: &Arc<Mutex<crate::AppState>>,
) {
    let sends: Vec<crate::PendingSend> = {
        let mut s = app_state.lock().await;
        std::mem::take(&mut s.send_queue)
    };

    for send in sends {
        tracing::info!("Sending to {}", send.recipient);

        let service_id = if let Ok(uuid) = send.recipient.parse::<Uuid>() {
            ServiceId::Aci(uuid.into())
        } else {
            tracing::warn!("Cannot resolve recipient '{}' — UUID required", send.recipient);
            continue;
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let body = ContentBody::DataMessage(presage::libsignal_service::proto::DataMessage {
            body: Some(send.message.clone()),
            timestamp: Some(timestamp),
            ..Default::default()
        });

        match manager.send_message(service_id, body, timestamp).await {
            Ok(()) => tracing::info!("Sent successfully to {}", send.recipient),
            Err(e) => tracing::error!("Send failed to {}: {e:#}", send.recipient),
        }
    }
}

async fn process_pending_group_sends(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    app_state: &Arc<Mutex<crate::AppState>>,
) {
    let sends: Vec<crate::PendingGroupSend> = {
        let mut s = app_state.lock().await;
        std::mem::take(&mut s.group_send_queue)
    };

    for send in sends {
        tracing::info!("Sending to group {}", send.group_id);

        let master_key_bytes = match hex::decode(&send.group_id) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                tracing::error!("Invalid group_id hex: {}", send.group_id);
                continue;
            }
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let body = ContentBody::DataMessage(presage::libsignal_service::proto::DataMessage {
            body: Some(send.message.clone()),
            timestamp: Some(timestamp),
            ..Default::default()
        });

        match manager.send_message_to_group(&master_key_bytes, body, timestamp).await {
            Ok(()) => tracing::info!("Sent to group {} successfully", send.group_id),
            Err(e) => tracing::error!("Group send failed to {}: {e:#}", send.group_id),
        }
    }
}

async fn process_pending_group_creates(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    app_state: &Arc<Mutex<crate::AppState>>,
) {
    let creates: Vec<crate::PendingGroupCreate> = {
        let mut s = app_state.lock().await;
        std::mem::take(&mut s.group_create_queue)
    };

    for create in creates {
        tracing::info!("Creating group '{}' with {} members", create.name, create.members.len());

        // Parse member UUIDs to ACIs
        let mut member_acis = Vec::new();
        let mut parse_error = None;
        for member_str in &create.members {
            match member_str.parse::<Uuid>() {
                Ok(uuid) => member_acis.push(Aci::from(uuid)),
                Err(e) => {
                    parse_error = Some(format!("Invalid member UUID '{}': {}", member_str, e));
                    break;
                }
            }
        }

        if let Some(err) = parse_error {
            tracing::error!("{err}");
            let _ = create.response_tx.send(Err(err));
            continue;
        }

        match manager.create_group(&create.name, member_acis).await {
            Ok(master_key_bytes) => {
                let group_id = hex::encode(master_key_bytes);
                tracing::info!("Group '{}' created, id={}", create.name, group_id);
                // Track in known groups cache
                {
                    let mut s = app_state.lock().await;
                    s.known_group_ids.insert(group_id.clone());
                }
                let _ = create.response_tx.send(Ok(group_id));
            }
            Err(e) => {
                let err_msg = format!("Failed to create group: {e:#}");
                tracing::error!("{err_msg}");
                let _ = create.response_tx.send(Err(err_msg));
            }
        }
    }
}

async fn process_pending_typing(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    app_state: &Arc<Mutex<crate::AppState>>,
) {
    let typings: Vec<crate::PendingTyping> = {
        let mut s = app_state.lock().await;
        std::mem::take(&mut s.typing_queue)
    };

    for typing in typings {
        let action = if typing.started {
            presage::libsignal_service::proto::typing_message::Action::Started as i32
        } else {
            presage::libsignal_service::proto::typing_message::Action::Stopped as i32
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Some(ref group_id_hex) = typing.group_id {
            // Group typing indicator
            let master_key_bytes = match hex::decode(group_id_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    tracing::error!("Invalid group_id hex for typing: {}", group_id_hex);
                    continue;
                }
            };

            let typing_msg = presage::libsignal_service::proto::TypingMessage {
                timestamp: Some(timestamp),
                action: Some(action),
                group_id: Some(master_key_bytes.clone()),
            };
            let body = ContentBody::TypingMessage(typing_msg);

            match manager.send_message_to_group(&master_key_bytes, body, timestamp).await {
                Ok(()) => tracing::debug!("Typing indicator sent to group {}", group_id_hex),
                Err(e) => tracing::error!("Typing indicator failed for group {}: {e:#}", group_id_hex),
            }
        } else if let Some(ref recipient) = typing.recipient {
            // DM typing indicator
            let service_id = if let Ok(uuid) = recipient.parse::<Uuid>() {
                ServiceId::Aci(uuid.into())
            } else {
                tracing::warn!("Cannot resolve typing recipient '{}' — UUID required", recipient);
                continue;
            };

            let typing_msg = presage::libsignal_service::proto::TypingMessage {
                timestamp: Some(timestamp),
                action: Some(action),
                group_id: None,
            };
            let body = ContentBody::TypingMessage(typing_msg);

            match manager.send_message(service_id, body, timestamp).await {
                Ok(()) => tracing::debug!("Typing indicator sent to {}", recipient),
                Err(e) => tracing::error!("Typing indicator failed for {}: {e:#}", recipient),
            }
        }
    }
}

fn extract_body_text(content: &Content) -> Option<String> {
    match &content.body {
        ContentBody::DataMessage(dm) => dm.body.clone(),
        ContentBody::SynchronizeMessage(sync) => sync
            .sent
            .as_ref()
            .and_then(|s| s.message.as_ref())
            .and_then(|m| m.body.clone()),
        _ => None,
    }
}
