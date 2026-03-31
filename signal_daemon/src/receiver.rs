//! Message receiver implementing the peek → classify → selective ACK → zkFetch flow.
//!
//! Manager flow:
//!   1. Peek: GET /v1/messages/ (non-destructive)
//!   2. Classify: decrypt_envelope() each message locally (no ACK, no WS)
//!      - Finds SKDM position (if any) and classifies all messages
//!   3. If no SKDM: open WS, consume all N messages (ACKs them), close
//!   4. If SKDM at position K:
//!      a. Open WS, consume K messages before SKDM (ACKs them), close
//!      b. zkFetch GET /v1/messages/ (SKDM now at front of queue)
//!      c. Open WS, consume remaining including SKDM (ACKs them), close
//!   5. Normal messages → relay. SKDM + zkFetch proof → new flow.
//!
//! WS decrypt will fail on already-classified messages (Double Ratchet advanced)
//! but ACK still happens — ACK is sent before decrypt in presage's message pipe.

use crate::api::{ReceivedMessage, SkdmEvent};
use crate::config::DaemonConfig;

use futures::StreamExt;
use presage::libsignal_service::content::{Content, ContentBody};
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::protocol::ServiceId;
use presage::model::identity::OnNewIdentity;
use presage::model::messages::{DecryptResult, Received};
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

/// Classified message from the peek-decrypt step.
enum Classified {
    /// Normal 1-to-1 or group message with decrypted content.
    Normal(Content),
    /// SenderKeyDistributionMessage — content was consumed by libsignal.
    Skdm,
    /// Empty envelope or decrypt error — skip.
    Skip,
}

/// Main receive loop: peek → classify → selective ACK → zkFetch when needed.
pub async fn run_receive_loop(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    message_queue: Arc<Mutex<Vec<ReceivedMessage>>>,
    config: &DaemonConfig,
    app_state: Arc<Mutex<crate::AppState>>,
) -> anyhow::Result<()> {
    tracing::info!("Starting peek-classify-ACK receive loop");

    let mut send_interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut peek_interval = tokio::time::interval(std::time::Duration::from_secs(3));

    loop {
        tokio::select! {
            _ = send_interval.tick() => {
                process_pending_sends(manager, &app_state).await;
            }

            _ = peek_interval.tick() => {
                if let Err(e) = peek_classify_ack(manager, config, &app_state).await {
                    tracing::warn!("Peek-classify-ACK error: {e:#}");
                }
            }
        }
    }
}

/// The main manager orchestration: peek, classify, selectively ACK, zkFetch if needed.
async fn peek_classify_ack(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    config: &DaemonConfig,
    app_state: &Arc<Mutex<crate::AppState>>,
) -> anyhow::Result<()> {
    // ── Step 1: Peek ──────────────────────────────────────────────────
    let peek_body = peek_message_queue(config).await?;
    let envelopes = crate::receiver_parse::parse_envelopes_from_json(&peek_body);

    if envelopes.is_empty() {
        return Ok(());
    }

    let count = envelopes.len();
    tracing::info!("Peek: {count} envelope(s) in queue");

    // ── Step 2: Classify via decrypt_envelope (no WS, no ACK) ─────────
    let our_uuid = manager.registration_data().service_ids.aci.to_string();
    let mut classified: Vec<Classified> = Vec::with_capacity(count);
    let mut skdm_position: Option<usize> = None;

    for (idx, env) in envelopes.iter().enumerate() {
        if env.content_b64.is_empty() || env.msg_type != 6 {
            classified.push(Classified::Skip);
            continue;
        }

        let content_bytes = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &env.content_b64,
        ) {
            Ok(b) => b,
            Err(_) => {
                classified.push(Classified::Skip);
                continue;
            }
        };

        let envelope = presage::libsignal_service::envelope::Envelope {
            r#type: Some(6), // UNIDENTIFIED_SENDER
            content: Some(content_bytes),
            timestamp: Some(env.timestamp),
            server_timestamp: Some(env.server_timestamp),
            destination_service_id: Some(our_uuid.clone()),
            ..Default::default()
        };

        match manager.decrypt_envelope(envelope).await {
            Ok(DecryptResult::Content(content, _mk, _pqr)) => {
                classified.push(Classified::Normal(content));
            }
            Ok(DecryptResult::Skdm) => {
                if skdm_position.is_none() {
                    skdm_position = Some(idx);
                }
                classified.push(Classified::Skdm);
                tracing::info!("SKDM detected at queue position {idx}");
            }
            Ok(DecryptResult::Empty) => {
                classified.push(Classified::Skip);
            }
            Err(e) => {
                tracing::debug!("Classify: envelope {idx} decrypt error: {e}");
                classified.push(Classified::Skip);
            }
        }
    }

    // ── Step 3: Selective ACK via WebSocket ────────────────────────────
    if let Some(k) = skdm_position {
        // 3a. ACK messages before the SKDM
        if k > 0 {
            tracing::info!("ACKing {k} messages before SKDM");
            consume_ws_messages(manager, k).await;
        }

        // 3b. zkFetch the GET (SKDM is now at front of queue)
        tracing::info!("Calling zkFetch sidecar (SKDM at front of queue)");
        let proof = call_zkfetch_sidecar(config).await;
        match &proof {
            Ok(p) => tracing::info!("zkFetch proof obtained ({} bytes)", p.to_string().len()),
            Err(e) => tracing::warn!("zkFetch failed: {e:#}"),
        }

        // 3c. ACK remaining messages including the SKDM
        let remaining = count - k;
        tracing::info!("ACKing remaining {remaining} messages (including SKDM)");
        consume_ws_messages(manager, remaining).await;

        // Store SKDM event
        {
            let mut s = app_state.lock().await;
            s.skdm_events.push(SkdmEvent {
                raw_envelope: String::new(), // TODO: capture from peek
                sender: String::new(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                zkfetch_proof: proof.ok(),
            });
        }
    } else {
        // No SKDM — ACK everything
        tracing::debug!("No SKDM, ACKing all {count} messages");
        consume_ws_messages(manager, count).await;
    }

    // ── Step 4: Forward classified messages ────────────────────────────
    let mut normal_count = 0u32;
    let mut group_count = 0u32;
    let mut skdm_count = 0u32;

    for msg in classified {
        match msg {
            Classified::Normal(content) => {
                let sender_uuid = content.metadata.sender.raw_uuid().to_string();
                let body = extract_body_text(&content);

                let is_group = matches!(&content.body,
                    ContentBody::DataMessage(dm) if dm.group_v2.is_some()
                );

                if is_group {
                    group_count += 1;
                    tracing::info!(
                        "Group message from {}: {} [null bin]",
                        sender_uuid,
                        body.as_deref().unwrap_or("<non-text>"),
                    );
                    // SenderKey group messages → null bin for now
                } else {
                    normal_count += 1;
                    tracing::info!(
                        "Message from {}: {}",
                        sender_uuid,
                        body.as_deref().unwrap_or("<non-text>"),
                    );

                    let msg = ReceivedMessage {
                        sender_uuid,
                        sender_phone: None,
                        sender_identity_key: None,
                        timestamp: content.metadata.timestamp,
                        sealed_envelope: Default::default(),
                        verified_envelope: None,
                        decrypted_body: body,
                    };

                    let mut s = app_state.lock().await;
                    s.message_queue.push(msg);
                    s.messages_received += 1;
                }
            }
            Classified::Skdm => {
                skdm_count += 1;
            }
            Classified::Skip => {}
        }
    }

    if normal_count + group_count + skdm_count > 0 {
        tracing::info!(
            "Processed: {normal_count} normal, {group_count} group (null bin), {skdm_count} SKDM"
        );
    }

    Ok(())
}

/// Open WebSocket, consume exactly `count` messages (ACKing each), then close.
/// The WS ACKs happen before decryption in presage's message pipe, so even if
/// decrypt fails (because we already decrypted in the classify step), ACK succeeds.
async fn consume_ws_messages(
    manager: &mut Manager<SqliteStore, presage::manager::Registered>,
    count: usize,
) {
    if count == 0 {
        return;
    }

    match manager.receive_messages().await {
        Ok(stream) => {
            futures::pin_mut!(stream);
            let timeout = tokio::time::sleep(std::time::Duration::from_secs(10));
            tokio::pin!(timeout);

            let mut consumed = 0usize;
            loop {
                if consumed >= count {
                    break;
                }
                tokio::select! {
                    item = stream.next() => {
                        match item {
                            Some(Received::QueueEmpty) | None => break,
                            Some(_) => { consumed += 1; }
                        }
                    }
                    _ = &mut timeout => {
                        tracing::debug!("WS consume timeout after {consumed}/{count}");
                        break;
                    }
                }
            }
            tracing::debug!("WS consumed {consumed}/{count} messages");
            // Stream dropped here — WS closes, remaining messages stay in queue
        }
        Err(e) => {
            tracing::warn!("WS consume failed: {e}");
        }
    }
}

/// Call the zkFetch sidecar to get a proof of Signal's GET /v1/messages/ response.
async fn call_zkfetch_sidecar(config: &DaemonConfig) -> anyhow::Result<serde_json::Value> {
    let sidecar_url = std::env::var("ZKFETCH_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:7585".to_string());

    let auth = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{}:{}", config.uuid, config.password),
    );

    let signal_url = format!("https://{}/v1/messages/", config.signal_host);

    let request_body = serde_json::json!({
        "url": signal_url,
        "publicOptions": {
            "method": "GET",
        },
        "privateOptions": {
            "headers": {
                "Authorization": format!("Basic {auth}")
            }
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{sidecar_url}/zkfetch"))
        .json(&request_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("zkFetch sidecar returned {status}: {body}");
    }

    let result: serde_json::Value = response.json().await?;
    Ok(result.get("proof").cloned().unwrap_or(result))
}

/// Peek Signal's message queue via plain HTTPS GET.
async fn peek_message_queue(config: &DaemonConfig) -> anyhow::Result<Vec<u8>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let der = include_bytes!("signal_root_ca.der");
    root_store
        .add(rustls::pki_types::CertificateDer::from(&der[..]))
        .expect("Signal root CA is valid");

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let host = &config.signal_host;
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())?;

    let tcp = tokio::net::TcpStream::connect(format!("{host}:443")).await?;
    let mut tls = connector.connect(server_name, tcp).await?;

    let auth = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{}:{}", config.uuid, config.password),
    );
    let request = format!(
        "GET /v1/messages/ HTTP/1.1\r\n\
         Host: {host}\r\n\
         Authorization: Basic {auth}\r\n\
         Connection: close\r\n\
         \r\n",
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;

    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(0);

    Ok(response[body_start..].to_vec())
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
