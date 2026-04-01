//! Message receiver — simple WebSocket receive loop via presage.
//!
//! Connects to Signal via presage's `receive_messages()` stream,
//! decrypts incoming envelopes, and forwards them to the HTTP API queue.

use crate::api::ReceivedMessage;
use crate::config::DaemonConfig;

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
    _config: &DaemonConfig,
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
                process_pending_group_creates(manager, &app_state).await;
            }

            item = stream.next() => {
                match item {
                    Some(Received::Content { content, .. }) => {
                        handle_content(*content, &app_state).await;
                    }
                    Some(Received::SenderKeyDistribution { sender, .. }) => {
                        tracing::info!("SenderKeyDistribution from {sender}");
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

async fn handle_content(content: Content, app_state: &Arc<Mutex<crate::AppState>>) {
    let sender_uuid = content.metadata.sender.raw_uuid().to_string();
    let body = extract_body_text(&content);

    let is_group = matches!(
        &content.body,
        ContentBody::DataMessage(dm) if dm.group_v2.is_some()
    );

    if is_group {
        tracing::info!(
            "Group message from {}: {}",
            sender_uuid,
            body.as_deref().unwrap_or("<non-text>"),
        );
        // SenderKey group messages — not relayed for now
    } else {
        tracing::info!(
            "Message from {}: {}",
            sender_uuid,
            body.as_deref().unwrap_or("<non-text>"),
        );

        let mut msg = ReceivedMessage {
            sender_uuid,
            sender_phone: None,
            sender_identity_key: None,
            timestamp: content.metadata.timestamp,
            sealed_envelope: Default::default(),
            verified_envelope: None,
            tee_signature: None,
            decrypted_body: body,
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
        tracing::info!("Sending to {}: {}", send.recipient, send.message);

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
