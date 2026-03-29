//! Message receiver with sealed sender extraction + send processing.
//!
//! When TLS polling is enabled (SIGNAL_HOST set), HTTP polling is the ONLY
//! receive path. The WebSocket is NOT used for receiving — only for sends.
//! When TLS polling is disabled, falls back to WebSocket reception.

use crate::api::{ReceivedMessage, SealedEnvelopeDto, VerifiedEnvelopeDto};
use crate::config::DaemonConfig;
use crate::sealed_sender;
use crate::tls_poll::TlsPollClient;

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

/// Main receive loop. Two modes:
///
/// **TLS polling mode** (SIGNAL_HOST set): HTTP poll is the ONLY receive path.
/// No WebSocket receive stream. Manager is used only for sends and decrypt_envelope.
///
/// **Legacy mode** (no SIGNAL_HOST): WebSocket via presage receive_messages().
pub async fn run_receive_loop(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    message_queue: Arc<Mutex<Vec<ReceivedMessage>>>,
    config: &DaemonConfig,
    app_state: Arc<Mutex<crate::AppState>>,
    tls_client: Option<Arc<TlsPollClient>>,
) -> anyhow::Result<()> {
    if tls_client.is_some() {
        run_tls_poll_loop(manager, config, app_state, tls_client.unwrap()).await
    } else {
        run_websocket_loop(manager, message_queue, config, app_state).await
    }
}

/// TLS polling mode: HTTP poll only, no WebSocket receive.
async fn run_tls_poll_loop(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    config: &DaemonConfig,
    app_state: Arc<Mutex<crate::AppState>>,
    tls_client: Arc<TlsPollClient>,
) -> anyhow::Result<()> {
    tracing::info!("Starting TLS poll receive loop (HTTP only, no WebSocket receive)");

    let mut send_interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_secs(3));

    loop {
        tokio::select! {
            // ---- Outbound sends (every 2s) ----
            _ = send_interval.tick() => {
                process_pending_sends(manager, &app_state).await;
            }

            // ---- TLS polling: the ONLY receive path ----
            _ = poll_interval.tick() => {
                match tls_client.poll_messages().await {
                    Ok(Some(tls_response)) => {
                        let session_id = tls_client.current_session_id();
                        tracing::info!(
                            "TLS poll: got response ({} records, session {}, ch={}B, sh={}B, eph={})",
                            tls_response.message_records.len(),
                            session_id,
                            tls_response.handshake_data.client_hello.len(),
                            tls_response.handshake_data.server_hello.len(),
                            hex::encode(&tls_response.session_keys.client_ephemeral_priv[..4]),
                        );

                        // Store TLS session setup for the relay
                        let session_setup = crate::api::TlsSessionSetupDto {
                            session_id,
                            client_hello: hex::encode(&tls_response.handshake_data.client_hello),
                            server_hello: hex::encode(&tls_response.handshake_data.server_hello),
                            encrypted_handshake: hex::encode(&tls_response.handshake_data.encrypted_handshake_records),
                            client_ephemeral_priv: hex::encode(tls_response.session_keys.client_ephemeral_priv),
                        };
                        {
                            let mut s = app_state.lock().await;
                            s.pending_tls_session = Some(session_setup);
                        }

                        // Parse envelopes from the HTTP response
                        let parsed = parse_envelopes_from_protobuf(&tls_response.response_body);
                        tracing::info!("TLS poll: parsed {} envelope(s)", parsed.len());

                        let mut ack_guids = Vec::new();

                        for (idx, parsed_env) in parsed.iter().enumerate() {
                            ack_guids.push(parsed_env.guid.clone());

                            let tls_record = tls_response.message_records.get(0);

                            // Extract ECDH shared secrets
                            let ecdh_result = sealed_sender::extract_sealed_sender(
                                &parsed_env.content,
                                &config.identity_private_key,
                                &config.identity_public_key,
                            );

                            // Construct libsignal Envelope for presage decryption
                            let envelope = presage::libsignal_service::envelope::Envelope {
                                r#type: Some(6), // UNIDENTIFIED_SENDER
                                content: Some(parsed_env.content.clone()),
                                timestamp: Some(parsed_env.timestamp),
                                server_timestamp: Some(parsed_env.server_timestamp),
                                ..Default::default()
                            };

                            match manager.decrypt_envelope(envelope).await {
                                Ok(Some((content, message_key, pqr_salt))) => {
                                    let sender_uuid = content.metadata.sender.raw_uuid().to_string();
                                    let body = extract_body_text(&content);

                                    tracing::info!(
                                        "TLS poll: decrypted from {} (mk={}, pqr={})",
                                        sender_uuid,
                                        message_key.as_ref().map(|k| hex::encode(&k[..4])).unwrap_or_else(|| "none".into()),
                                        pqr_salt.as_ref().map(|k| hex::encode(&k[..4])).unwrap_or_else(|| "none".into()),
                                    );

                                    let verified_dto = match (&ecdh_result, &message_key, tls_record) {
                                        (Ok(ecdh), Some(mk), Some(record)) => {
                                            let pqr_bytes = pqr_salt.as_deref().unwrap_or(&[0u8; 32]);
                                            Some(VerifiedEnvelopeDto {
                                                session_id,
                                                tls_record: hex::encode(&record.raw_bytes),
                                                tls_sequence_no: record.sequence_no,
                                                e_shared: hex::encode(ecdh.ecdh.e_shared),
                                                s_shared: hex::encode(ecdh.ecdh.s_shared),
                                                message_key: hex::encode(mk),
                                                pqr_salt: hex::encode(pqr_bytes),
                                            })
                                        }
                                        _ => {
                                            if let Err(ref e) = ecdh_result {
                                                tracing::warn!("TLS poll: sealed sender failed for {idx}: {e:#}");
                                            }
                                            if message_key.is_none() {
                                                tracing::warn!("TLS poll: message_key missing for {idx}");
                                            }
                                            if tls_record.is_none() {
                                                tracing::warn!("TLS poll: no TLS record for {idx}");
                                            }
                                            None
                                        }
                                    };

                                    let sender_identity_hex = ecdh_result.as_ref().ok()
                                        .map(|r| hex::encode(r.sender_identity_public));

                                    let msg = ReceivedMessage {
                                        sender_uuid,
                                        sender_phone: None,
                                        sender_identity_key: sender_identity_hex,
                                        timestamp: content.metadata.timestamp,
                                        sealed_envelope: SealedEnvelopeDto::default(),
                                        verified_envelope: verified_dto,
                                        decrypted_body: body,
                                    };

                                    {
                                        let mut s = app_state.lock().await;
                                        s.message_queue.push(msg);
                                        s.messages_received += 1;
                                    }
                                }
                                Ok(None) => {
                                    tracing::debug!("TLS poll: empty envelope {idx}");
                                }
                                Err(e) => {
                                    tracing::warn!("TLS poll: decrypt_envelope failed for {idx}: {e}");
                                }
                            }
                        }

                        // Acknowledge processed messages
                        let guids_to_ack: Vec<_> = ack_guids.into_iter()
                            .filter(|g| !g.is_empty())
                            .collect();
                        if !guids_to_ack.is_empty() {
                            if let Err(e) = tls_client.acknowledge_messages(&guids_to_ack).await {
                                tracing::warn!("TLS poll: ACK failed: {e:#}");
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::debug!("TLS poll: no messages");
                    }
                    Err(e) => {
                        tracing::warn!("TLS poll error: {e:#}");
                    }
                }
            }
        }
    }
}

/// Legacy WebSocket mode: presage receive_messages() stream.
async fn run_websocket_loop(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    message_queue: Arc<Mutex<Vec<ReceivedMessage>>>,
    config: &DaemonConfig,
    app_state: Arc<Mutex<crate::AppState>>,
) -> anyhow::Result<()> {
    tracing::info!("Starting WebSocket receive loop (legacy mode)");

    let messages = manager.receive_messages().await?;
    futures::pin_mut!(messages);

    let mut send_interval = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        tokio::select! {
            received = messages.next() => {
                let Some(received) = received else { break };
                match received {
                    Received::Content { content, raw_content, message_key, pqr_salt } => {
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
                                            let pqr_hex = pqr_salt.as_ref().map(|s| hex::encode(s)).unwrap_or_default();
                                            tracing::info!("Got message_key ({} bytes), pqr_salt={}", mk.len(), if pqr_hex.is_empty() { "none" } else { &pqr_hex[..8] });
                                            sealed_dto = Some(SealedEnvelopeDto {
                                                s_cipher_key: hex::encode(result.envelope.s_cipher_key),
                                                s_mac_key: hex::encode(result.envelope.s_mac_key),
                                                s_ciphertext: hex::encode(&result.envelope.s_ciphertext),
                                                s_mac: hex::encode(result.envelope.s_mac),
                                                message_key: hex::encode(mk),
                                                pqr_salt: pqr_hex,
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
                            verified_envelope: None,
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

// ============================================================================
// Protobuf envelope parsing for Signal's GET /v1/messages response
// ============================================================================

pub struct ParsedEnvelope {
    pub content: Vec<u8>,
    pub timestamp: u64,
    pub server_timestamp: u64,
    pub guid: String,
}

/// Parse envelopes from an HTTP response body.
/// Tries protobuf first, falls back to JSON.
fn parse_envelopes_from_protobuf(http_response: &[u8]) -> Vec<ParsedEnvelope> {
    let body = match find_http_body(http_response) {
        Some(b) => b,
        None => http_response,
    };

    if body.is_empty() {
        return Vec::new();
    }

    // Try protobuf first, fall back to JSON
    if body.first() == Some(&0x0a) || body.first().map(|b| b & 0x07 == 2).unwrap_or(false) {
        parse_incoming_message_list_protobuf(body)
    } else if body.first() == Some(&b'{') || body.first() == Some(&b'[') {
        parse_envelopes_json(body)
    } else {
        tracing::warn!("TLS poll: unknown response format (first byte: {:02x})", body.first().unwrap_or(&0));
        Vec::new()
    }
}

fn find_http_body(data: &[u8]) -> Option<&[u8]> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(&data[i + 4..]);
        }
    }
    None
}

fn parse_incoming_message_list_protobuf(data: &[u8]) -> Vec<ParsedEnvelope> {
    let mut envelopes = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let Ok((field, wire_type)) = pb_read_tag(data, &mut pos) else { break };
        match (field, wire_type) {
            (1, 2) => {
                let Ok(envelope_bytes) = pb_read_bytes(data, &mut pos) else { break };
                if let Some(env) = parse_signal_envelope_protobuf(&envelope_bytes) {
                    envelopes.push(env);
                }
            }
            (_, wt) => {
                if pb_skip_field(data, &mut pos, wt).is_err() {
                    break;
                }
            }
        }
    }

    envelopes
}

fn parse_signal_envelope_protobuf(data: &[u8]) -> Option<ParsedEnvelope> {
    let mut pos = 0;
    let mut content: Option<Vec<u8>> = None;
    let mut timestamp: u64 = 0;
    let mut server_timestamp: u64 = 0;
    let mut guid = String::new();
    let mut r#type: u32 = 0;

    while pos < data.len() {
        let Ok((field, wire_type)) = pb_read_tag(data, &mut pos) else { break };
        match (field, wire_type) {
            (1, 0) => { r#type = pb_read_varint(data, &mut pos).unwrap_or(0) as u32; }
            (3, 0) => { timestamp = pb_read_varint(data, &mut pos).unwrap_or(0); }
            (8, 2) => { content = pb_read_bytes(data, &mut pos).ok(); }
            (10, 0) => { server_timestamp = pb_read_varint(data, &mut pos).unwrap_or(0); }
            (13, 2) => {
                if let Ok(bytes) = pb_read_bytes(data, &mut pos) {
                    guid = String::from_utf8_lossy(&bytes).to_string();
                }
            }
            (_, wt) => {
                if pb_skip_field(data, &mut pos, wt).is_err() { break; }
            }
        }
    }

    let content = content?;
    if content.is_empty() { return None; }

    if r#type != 6 {
        tracing::debug!("Skipping non-sealed-sender envelope type {}", r#type);
        return None;
    }

    if timestamp == 0 { timestamp = server_timestamp; }

    Some(ParsedEnvelope { content, timestamp, server_timestamp, guid })
}

fn parse_envelopes_json(body: &[u8]) -> Vec<ParsedEnvelope> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let value: serde_json::Value = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let messages = match value.get("messages").and_then(|m| m.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    let mut envelopes = Vec::new();
    for msg in messages {
        let msg_type = msg.get("type").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
        if msg_type != 6 { continue; }

        let content_b64 = match msg.get("content").and_then(|c| c.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let content = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            content_b64,
        ) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let timestamp = msg.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0);
        let server_timestamp = msg.get("serverTimestamp").and_then(|t| t.as_u64()).unwrap_or(0);
        let guid = msg.get("guid").and_then(|g| g.as_str()).unwrap_or("").to_string();

        envelopes.push(ParsedEnvelope { content, timestamp, server_timestamp, guid });
    }

    envelopes
}

// ============================================================================
// Minimal protobuf wire format helpers
// ============================================================================

fn pb_read_varint(data: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        anyhow::ensure!(*pos < data.len(), "varint: unexpected end");
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { return Ok(result); }
        shift += 7;
        anyhow::ensure!(shift < 64, "varint overflow");
    }
}

fn pb_read_tag(data: &[u8], pos: &mut usize) -> anyhow::Result<(u32, u32)> {
    let v = pb_read_varint(data, pos)?;
    Ok(((v >> 3) as u32, (v & 0x07) as u32))
}

fn pb_read_bytes(data: &[u8], pos: &mut usize) -> anyhow::Result<Vec<u8>> {
    let len = pb_read_varint(data, pos)? as usize;
    anyhow::ensure!(*pos + len <= data.len(), "bytes field overflows buffer");
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(result)
}

fn pb_skip_field(data: &[u8], pos: &mut usize, wire_type: u32) -> anyhow::Result<()> {
    match wire_type {
        0 => { pb_read_varint(data, pos)?; }
        1 => *pos += 8,
        2 => {
            let len = pb_read_varint(data, pos)? as usize;
            anyhow::ensure!(*pos + len <= data.len(), "skip: overflow");
            *pos += len;
        }
        5 => *pos += 4,
        wt => anyhow::bail!("unknown wire type: {wt}"),
    }
    Ok(())
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
