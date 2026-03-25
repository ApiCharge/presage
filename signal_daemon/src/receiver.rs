//! Message receiver with sealed sender extraction + send processing.

use crate::api::{ReceivedMessage, SealedEnvelopeDto};
use crate::config::DaemonConfig;
use crate::sealed_sender;

use futures::StreamExt;
use presage::libsignal_service::content::{Content, ContentBody};
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::protocol::ServiceId;
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

pub async fn run_receive_loop(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    message_queue: Arc<Mutex<Vec<ReceivedMessage>>>,
    config: &DaemonConfig,
    app_state: Arc<Mutex<crate::AppState>>,
) -> anyhow::Result<()> {
    tracing::info!("Starting receive loop...");

    let messages = manager.receive_messages().await?;
    futures::pin_mut!(messages);

    let mut send_interval = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        tokio::select! {
            received = messages.next() => {
                let Some(received) = received else { break };
                match received {
                    Received::Content { content, raw_content, message_key } => {
                        let body = extract_body_text(&content);
                        let sender_uuid = content.metadata.sender.raw_uuid().to_string();
                        let was_sealed = content.metadata.unidentified_sender;

                        let mut sealed_dto = None;
                        let mut sender_identity_hex = None;

                        if was_sealed {
                            if let Some(raw) = raw_content.as_deref() {
                                match sealed_sender::extract_sealed_sender(raw, &config.identity_private_key, &config.identity_public_key) {
                                    Ok(result) => {
                                        sender_identity_hex = Some(hex::encode(result.sender_identity_public));

                                        if let Some(ref mk) = message_key {
                                            tracing::info!("Got message_key from libsignal ({} bytes)", mk.len());
                                            sealed_dto = Some(SealedEnvelopeDto {
                                                s_cipher_key: hex::encode(result.envelope.s_cipher_key),
                                                s_mac_key: hex::encode(result.envelope.s_mac_key),
                                                s_ciphertext: hex::encode(&result.envelope.s_ciphertext),
                                                s_mac: hex::encode(result.envelope.s_mac),
                                                message_key: hex::encode(mk),
                                            });
                                        } else {
                                            tracing::warn!("No message_key captured from libsignal");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("Sealed sender extraction failed: {e:#}");
                                    }
                                }
                            }
                        }

                        tracing::info!(
                            "Message from {}: {} [sealed={}]",
                            sender_uuid,
                            body.as_deref().unwrap_or("<non-text>"),
                            sealed_dto.is_some(),
                        );

                        let msg = ReceivedMessage {
                            sender_uuid,
                            sender_phone: None,
                            sender_identity_key: sender_identity_hex,
                            timestamp: content.metadata.timestamp,
                            sealed_envelope: sealed_dto.unwrap_or_default(),
                            decrypted_body: body,
                        };

                        message_queue.lock().await.push(msg.clone());
                        {
                            let mut s = app_state.lock().await;
                            s.message_queue.push(msg);
                            s.messages_received += 1;
                        }
                    }
                    Received::QueueEmpty => {
                        tracing::debug!("Queue empty, waiting for messages...");
                    }
                    _ => {}
                }
            }
            _ = send_interval.tick() => {
                process_pending_sends(manager, &app_state).await;
            }
        }
    }

    Ok(())
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

        // Resolve recipient — could be phone number or UUID
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
