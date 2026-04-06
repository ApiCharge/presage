//! Signal Sealed Sender Daemon
//!
//! Replaces signal-cli for the ApiCharge relay. Connects to Signal servers,
//! receives sealed sender envelopes, extracts the s-layer cryptographic
//! material, and exposes it via HTTP for the .NET SignalRelayService.
//!
//! Architecture:
//!   Signal servers <-> presage (WebSocket) <-> This daemon <-> HTTP <-> .NET relay

mod api;
mod message_keys;
mod receiver;
mod sealed_sender;

use api::*;
use presage::store::ContentsStore;
use std::sync::Arc;
use tokio::sync::Mutex;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

use ed25519_dalek::SigningKey;

/// Outbound send request queued by the HTTP handler, processed by the receiver thread.
pub struct PendingSend {
    pub recipient: String,
    pub message: String,
}

/// Group creation request queued by the HTTP handler, processed by the receiver thread.
pub struct PendingGroupCreate {
    pub name: String,
    pub members: Vec<String>,
    pub response_tx: tokio::sync::oneshot::Sender<Result<String, String>>,
}

/// Outbound group send request queued by the HTTP handler, processed by the receiver thread.
pub struct PendingGroupSend {
    pub group_id: String,
    pub message: String,
}

/// Typing indicator request queued by the HTTP handler, processed by the receiver thread.
pub struct PendingTyping {
    pub recipient: Option<String>,
    pub group_id: Option<String>,
    pub started: bool,
}

/// Daemon operating mode
#[derive(Clone, PartialEq)]
pub enum DaemonMode {
    /// No Signal identity — waiting for operator to register via HTTP
    Registration,
    /// Signal identity exists — processing messages
    Normal,
}

pub struct AppState {
    pub mode: DaemonMode,
    pub message_queue: Vec<ReceivedMessage>,
    pub send_queue: Vec<PendingSend>,
    pub group_send_queue: Vec<PendingGroupSend>,
    pub group_create_queue: Vec<PendingGroupCreate>,
    pub typing_queue: Vec<PendingTyping>,
    pub messages_received: u64,
    pub connected: bool,
    pub phone_number: String,
    pub uuid: String,
    pub username: Option<String>,
    pub tee_signing_key: SigningKey,
    /// Group IDs the daemon has seen (populated from incoming messages + group creates).
    /// Used by /list-groups for fee change notifications.
    pub known_group_ids: std::collections::HashSet<String>,
    /// Presage DB path (needed for registration flow)
    pub db_path: String,
    /// Signal to the receiver thread that registration completed and it should start
    pub registration_complete_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

type SharedState = Arc<Mutex<AppState>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    async_main().await
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "signal_daemon=info".into()),
        )
        .init();

    let db_path = std::env::var("PRESAGE_DB_PATH")
        .unwrap_or_else(|_| "sqlite:///data/signal-cli/presage.sqlite".into());
    let listen_addr =
        std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:7584".into());

    tracing::info!("Using presage store at {db_path}");

    // Generate ephemeral TEE Ed25519 signing key (fresh every boot)
    let tee_signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    tracing::info!(
        "TEE ephemeral key generated, pubkey={}",
        hex::encode(tee_signing_key.verifying_key().as_bytes())
    );

    // Detect mode: does a registered identity exist?
    let has_identity = check_identity_exists(&db_path).await;
    let initial_mode = if has_identity {
        tracing::info!("Signal identity found — starting in NORMAL mode");
        DaemonMode::Normal
    } else {
        tracing::info!("No Signal identity — starting in REGISTRATION mode");
        tracing::info!("Complete registration via HTTP: POST /register-signal, then POST /register-signal/verify");
        DaemonMode::Registration
    };

    // Load persisted username (if set previously — auto-claimed on first normal boot)
    let persisted_username = load_persisted_username(&db_path);
    if let Some(ref u) = persisted_username {
        tracing::info!("Relay username: {u}");
    }

    let (reg_complete_tx, reg_complete_rx) = tokio::sync::oneshot::channel::<()>();

    let state: SharedState = Arc::new(Mutex::new(AppState {
        mode: initial_mode.clone(),
        message_queue: Vec::new(),
        send_queue: Vec::new(),
        group_send_queue: Vec::new(),
        group_create_queue: Vec::new(),
        typing_queue: Vec::new(),
        messages_received: 0,
        connected: false,
        phone_number: String::new(),
        uuid: String::new(),
        username: persisted_username,
        tee_signing_key,
        known_group_ids: std::collections::HashSet::new(),
        db_path: db_path.clone(),
        registration_complete_tx: if initial_mode == DaemonMode::Registration {
            Some(reg_complete_tx)
        } else {
            None
        },
    }));

    // Start receiver thread (only if identity exists; otherwise wait for registration)
    if initial_mode == DaemonMode::Normal {
        // Auto-claim username if not set yet
        if persisted_username.is_none() {
            tracing::info!("No username set — auto-claiming apicharge_XXXX...");
            let claim_state = state.clone();
            let claim_db = db_path.clone();
            tokio::spawn(async move {
                // Small delay to let receiver thread connect first
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                match auto_claim_username(&claim_db, &claim_state).await {
                    Ok(username) => {
                        tracing::info!("══════════════════════════════════════════════");
                        tracing::info!("  RELAY USERNAME CLAIMED: {username}");
                        tracing::info!("  Admin: authorize this on-chain with:");
                        tracing::info!("  authorize_relay --signal_username \"{username}\"");
                        tracing::info!("══════════════════════════════════════════════");
                        let mut s = claim_state.lock().await;
                        s.username = Some(username);
                    }
                    Err(e) => tracing::error!("Failed to auto-claim username: {e:#}"),
                }
            });
        }
        start_receiver_thread(state.clone(), db_path.clone());
    } else {
        // Spawn a task that waits for registration to complete, then starts the receiver
        let recv_state = state.clone();
        let recv_db = db_path.clone();
        tokio::spawn(async move {
            let _ = reg_complete_rx.await;
            tracing::info!("Registration complete — starting receiver thread");
            start_receiver_thread(recv_state, recv_db);
        });
    }

    // HTTP server — all routes available in all modes.
    // Registration endpoints return 403 in normal mode (identity is irreversible).
    // Normal-mode endpoints return 503 in registration mode.
    let app = Router::new()
        // Normal mode endpoints
        .route("/receive", get(handle_receive))
        .route("/send", post(handle_send))
        .route("/send-group", post(handle_send_group))
        .route("/create-group", post(handle_create_group))
        .route("/tee-pubkey", get(handle_tee_pubkey))
        .route("/typing", post(handle_typing))
        .route("/list-groups", get(handle_list_groups))
        .route("/tee-sign", post(handle_tee_sign))
        // Registration mode endpoints
        .route("/register-signal", post(handle_register_signal))
        .route("/register-signal/verify", post(handle_verify_code))
        // Status (both modes)
        .route("/status", get(handle_status))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("HTTP server listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Auto-claim a Signal username with format apicharge_XXXX where XXXX is random lowercase alphanumeric.
async fn auto_claim_username(db_path: &str, state: &SharedState) -> anyhow::Result<String> {
    use presage::model::identity::OnNewIdentity;
    use usernames::{Username, NicknameLimits};

    let store = presage_store_sqlite::SqliteStore::open_with_passphrase(
        db_path, None, OnNewIdentity::Trust,
    ).await?;
    let manager = presage::Manager::load_registered(store).await?;

    // Generate random 4-char suffix: lowercase alphanumeric
    let suffix: String = {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        bytes.iter().map(|b| {
            let idx = b % 36;
            if idx < 10 { (b'0' + idx) as char } else { (b'a' + idx - 10) as char }
        }).collect()
    };
    let nickname = format!("apicharge_{suffix}");
    tracing::info!("Generated nickname: {nickname}");

    // Generate candidates manually (avoid rand version mismatch with usernames crate)
    let limits = NicknameLimits::default();
    let mut candidates = Vec::new();
    for disc in 1..=99u32 {
        let candidate = format!("{nickname}.{disc:02}");
        if Username::new(&candidate).is_ok() {
            candidates.push(candidate);
        }
        if candidates.len() >= 20 { break; }
    }

    tracing::info!("Generated {} candidates", candidates.len());

    // Compute hashes
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut candidate_map: std::collections::HashMap<[u8; 32], String> = std::collections::HashMap::new();
    for candidate in &candidates {
        if let Ok(u) = Username::new(candidate) {
            let hash = u.hash();
            hashes.push(hash);
            candidate_map.insert(hash, candidate.clone());
        }
    }

    if hashes.is_empty() {
        return Err(anyhow::anyhow!("no valid candidates"));
    }

    // Reserve with Signal server
    let hashes_b64: Vec<String> = hashes.iter()
        .map(|h| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, h))
        .collect();
    let reserve_body = serde_json::json!({ "usernameHashes": hashes_b64 });

    let reg = manager.registration_data();
    let credentials = format!("{}:{}", reg.service_ids.aci, reg.password);
    let auth_header = format!("Basic {}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD, credentials.as_bytes()));

    let signal_host = std::env::var("SIGNAL_HOST").unwrap_or_else(|_| "chat.signal.org".into());
    let http_client = reqwest::Client::new();

    let reserve_url = format!("https://{signal_host}/v1/accounts/username_hash/reserve");
    tracing::info!("Reserving username at {reserve_url}...");

    let reserve_resp = http_client.put(&reserve_url)
        .header("Authorization", &auth_header)
        .json(&reserve_body)
        .send()
        .await?;

    if !reserve_resp.status().is_success() {
        let status = reserve_resp.status();
        let body = reserve_resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("reserve failed (HTTP {status}): {body}"));
    }

    let reserve_result: serde_json::Value = reserve_resp.json().await?;
    let selected_hash_b64 = reserve_result["usernameHash"].as_str()
        .ok_or_else(|| anyhow::anyhow!("reserve response missing usernameHash"))?
        .to_string();

    let selected_hash_bytes: [u8; 32] = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD, &selected_hash_b64
    )?.try_into().map_err(|_| anyhow::anyhow!("invalid hash length"))?;

    let selected_username = candidate_map.get(&selected_hash_bytes)
        .ok_or_else(|| anyhow::anyhow!("reserved hash doesn't match any candidate"))?
        .clone();

    tracing::info!("Reserved: {selected_username}");

    // Generate ZK proof and confirm
    let username_obj = Username::new(&selected_username).unwrap();
    let mut randomness = [0u8; 32];
    getrandom::getrandom(&mut randomness).expect("getrandom failed");
    let proof = username_obj.proof(&randomness)
        .map_err(|e| anyhow::anyhow!("ZK proof failed: {e:?}"))?;

    let confirm_body = serde_json::json!({
        "usernameHash": selected_hash_b64,
        "zkProof": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &proof),
    });

    let confirm_url = format!("https://{signal_host}/v1/accounts/username_hash/confirm");
    let confirm_resp = http_client.put(&confirm_url)
        .header("Authorization", &auth_header)
        .json(&confirm_body)
        .send()
        .await?;

    if !confirm_resp.status().is_success() {
        let status = confirm_resp.status();
        let body = confirm_resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("confirm failed (HTTP {status}): {body}"));
    }

    // Persist to disk
    persist_username(db_path, &selected_username)?;

    Ok(selected_username)
}

/// Path for the persisted username file (alongside the presage SQLite).
fn username_file_path(db_path: &str) -> String {
    // db_path is like "sqlite:///data/presage/presage.sqlite"
    // Extract the directory and put relay_username.txt next to it
    let stripped = db_path.strip_prefix("sqlite://").unwrap_or(db_path);
    let parent = std::path::Path::new(stripped)
        .parent()
        .unwrap_or(std::path::Path::new("/data/presage"));
    parent.join("relay_username.txt").to_string_lossy().to_string()
}

/// Load the persisted username from disk (returns None if not set).
fn load_persisted_username(db_path: &str) -> Option<String> {
    let path = username_file_path(db_path);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                tracing::info!("Loaded persisted username: {trimmed}");
                Some(trimmed)
            }
        }
        Err(_) => None,
    }
}

/// Save the username to disk (persistent across restarts).
fn persist_username(db_path: &str, username: &str) -> std::io::Result<()> {
    let path = username_file_path(db_path);
    std::fs::write(&path, username)?;
    tracing::info!("Username persisted to {path}");
    Ok(())
}

/// Check if a registered Signal identity exists in the presage store.
async fn check_identity_exists(db_path: &str) -> bool {
    use presage::model::identity::OnNewIdentity;
    match presage_store_sqlite::SqliteStore::open_with_passphrase(db_path, None, OnNewIdentity::Trust).await {
        Ok(store) => {
            match presage::Manager::load_registered(store).await {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Start the presage receiver on a dedicated OS thread.
fn start_receiver_thread(state: SharedState, db_path: String) {
    std::thread::Builder::new()
        .name("presage-receiver".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build receiver runtime");
            rt.block_on(async {
                let mut manager = match receiver::create_manager(&db_path).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!("Failed to create manager: {e:#}");
                        return;
                    }
                };
                {
                    let mut s = state.lock().await;
                    s.connected = true;
                    let reg = manager.registration_data();
                    s.phone_number = reg.phone_number.to_string();
                    s.uuid = reg.service_ids.aci.to_string();
                    tracing::info!("Connected as {} ({})", s.phone_number, s.uuid);

                    // Load all known groups from presage store into the cache
                    match manager.store().groups().await {
                        Ok(groups_iter) => {
                            let mut count = 0;
                            for group_result in groups_iter {
                                if let Ok((master_key, _group)) = group_result {
                                    s.known_group_ids.insert(hex::encode(master_key));
                                    count += 1;
                                }
                            }
                            tracing::info!("Loaded {count} known groups from store");
                        }
                        Err(e) => tracing::warn!("Failed to load groups from store: {e:#}"),
                    }
                }

                loop {
                    let queue = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
                    match receiver::run_receive_loop(&mut manager, queue.clone(), state.clone()).await {
                        Ok(()) => tracing::info!("Receiver ended, reconnecting in 10s..."),
                        Err(e) => tracing::error!("Receiver error: {e:#}, reconnecting in 10s..."),
                    }
                    {
                        let mut remaining = queue.lock().await;
                        if !remaining.is_empty() {
                            let mut s = state.lock().await;
                            s.message_queue.append(&mut remaining);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            });
        })
        .expect("failed to spawn receiver thread");
}

// ---- HTTP Handlers ----

async fn handle_receive(State(state): State<SharedState>) -> Json<ReceiveResponse> {
    let mut s = state.lock().await;
    let messages = std::mem::take(&mut s.message_queue);
    Json(ReceiveResponse { messages })
}

async fn handle_send(
    State(state): State<SharedState>,
    Json(req): Json<SendRequest>,
) -> Json<SendResponse> {
    tracing::info!("Queuing send to {}", req.recipient);
    let mut s = state.lock().await;
    s.send_queue.push(PendingSend {
        recipient: req.recipient,
        message: req.message,
    });
    Json(SendResponse {
        success: true,
        error: None,
    })
}

async fn handle_send_group(
    State(state): State<SharedState>,
    Json(req): Json<GroupSendRequest>,
) -> Json<SendResponse> {
    tracing::info!("Queuing group send to {}", req.group_id);
    let mut s = state.lock().await;
    s.group_send_queue.push(PendingGroupSend {
        group_id: req.group_id,
        message: req.message,
    });
    Json(SendResponse {
        success: true,
        error: None,
    })
}

async fn handle_status(State(state): State<SharedState>) -> Json<ExtendedStatusResponse> {
    let s = state.lock().await;
    Json(ExtendedStatusResponse {
        connected: s.connected,
        mode: match s.mode {
            DaemonMode::Registration => "registration".to_string(),
            DaemonMode::Normal => "normal".to_string(),
        },
        phone_number: s.phone_number.clone(),
        uuid: s.uuid.clone(),
        username: s.username.clone(),
        messages_received: s.messages_received,
    })
}

async fn handle_create_group(
    State(state): State<SharedState>,
    Json(req): Json<CreateGroupRequest>,
) -> Json<CreateGroupResponse> {
    tracing::info!(
        "create-group called for '{}' with {} members",
        req.name,
        req.members.len(),
    );

    let (tx, rx) = tokio::sync::oneshot::channel();

    {
        let mut s = state.lock().await;
        if !s.connected {
            return Json(CreateGroupResponse {
                success: false,
                group_id: None,
                error: Some("Not connected to Signal".into()),
            });
        }
        s.group_create_queue.push(PendingGroupCreate {
            name: req.name,
            members: req.members,
            response_tx: tx,
        });
    }

    // Wait for the receiver thread to process the group creation
    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(Ok(group_id))) => Json(CreateGroupResponse {
            success: true,
            group_id: Some(group_id),
            error: None,
        }),
        Ok(Ok(Err(err))) => Json(CreateGroupResponse {
            success: false,
            group_id: None,
            error: Some(err),
        }),
        Ok(Err(_)) => Json(CreateGroupResponse {
            success: false,
            group_id: None,
            error: Some("Internal error: response channel closed".into()),
        }),
        Err(_) => Json(CreateGroupResponse {
            success: false,
            group_id: None,
            error: Some("Timeout waiting for group creation (30s)".into()),
        }),
    }
}

async fn handle_tee_pubkey(State(state): State<SharedState>) -> Json<TeePubkeyResponse> {
    let s = state.lock().await;
    let pubkey_hex = hex::encode(s.tee_signing_key.verifying_key().as_bytes());
    Json(TeePubkeyResponse { pubkey_hex })
}

async fn handle_typing(
    State(state): State<SharedState>,
    Json(req): Json<TypingRequest>,
) -> Json<SendResponse> {
    let mut s = state.lock().await;
    s.typing_queue.push(PendingTyping {
        recipient: req.recipient,
        group_id: req.group_id,
        started: req.started,
    });
    Json(SendResponse { success: true, error: None })
}

async fn handle_list_groups(State(state): State<SharedState>) -> Json<ListGroupsResponse> {
    let s = state.lock().await;
    let group_ids: Vec<String> = s.known_group_ids.iter().cloned().collect();
    Json(ListGroupsResponse { group_ids })
}

async fn handle_tee_sign(
    State(state): State<SharedState>,
    Json(req): Json<TeeSignRequest>,
) -> Json<TeeSignResponse> {
    use ed25519_dalek::Signer;
    let payload = match hex::decode(&req.payload_hex) {
        Ok(p) => p,
        Err(e) => {
            return Json(TeeSignResponse {
                signature_hex: format!("error: invalid hex: {e}"),
            });
        }
    };
    let s = state.lock().await;
    let sig = s.tee_signing_key.sign(&payload);
    Json(TeeSignResponse {
        signature_hex: hex::encode(sig.to_bytes()),
    })
}

// ── Registration Mode HTTP Handlers ──────────────────────────────

/// POST /register-signal — Initiate Signal registration.
/// Takes phone + CAPTCHA, sends SMS. Returns immediately.
/// The operator then calls POST /register-signal/verify with the SMS code.
///
/// Registration runs on a dedicated thread (presage types are not Send).
/// The handler queues the request and returns; verify polls for completion.
async fn handle_register_signal(
    State(state): State<SharedState>,
    Json(req): Json<RegisterSignalRequest>,
) -> Json<RegisterSignalResponse> {
    {
        let s = state.lock().await;
        if s.mode != DaemonMode::Registration {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some("Identity already exists. Registration is irreversible.".into()),
            });
        }
    }

    let phone_number = match phonenumber::parse(None, &req.phone_number) {
        Ok(p) => p,
        Err(e) => {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some(format!("Invalid phone number: {e}")),
            });
        }
    };

    let db_path = {
        let s = state.lock().await;
        s.db_path.clone()
    };

    // Run the entire registration on a blocking thread (presage types are !Send)
    let captcha = req.captcha.clone();
    let phone_str = req.phone_number.clone();
    let reg_state = state.clone();

    let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<String, String>>();

    std::thread::Builder::new()
        .name("signal-register".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build registration runtime");
            rt.block_on(async move {
                use presage::libsignal_service::configuration::SignalServers;
                use presage::manager::RegistrationOptions;
                use presage::model::identity::OnNewIdentity;

                let store = match presage_store_sqlite::SqliteStore::open_with_passphrase(
                    &db_path, None, OnNewIdentity::Trust,
                ).await {
                    Ok(s) => s,
                    Err(e) => { let _ = result_tx.send(Err(format!("Store error: {e}"))); return; }
                };

                tracing::info!("Registering with Signal: {phone_str}...");
                let conf = match presage::Manager::register(
                    store,
                    RegistrationOptions {
                        signal_servers: SignalServers::Production,
                        phone_number,
                        use_voice_call: false,
                        captcha: Some(&captcha),
                        force: true,
                    },
                ).await {
                    Ok(c) => c,
                    Err(e) => { let _ = result_tx.send(Err(format!("Registration failed: {e}"))); return; }
                };

                tracing::info!("SMS sent. Waiting for verification code via /register-signal/verify...");
                let _ = result_tx.send(Ok("SMS sent".into()));

                // Now wait for the verify code — poll from a file
                let code_file = format!("{}/verify_code.txt",
                    std::path::Path::new(db_path.strip_prefix("sqlite://").unwrap_or(&db_path))
                        .parent().unwrap_or(std::path::Path::new("/data/presage"))
                        .to_string_lossy());

                loop {
                    if let Ok(code) = std::fs::read_to_string(&code_file) {
                        let code = code.trim().to_string();
                        if !code.is_empty() {
                            let _ = std::fs::remove_file(&code_file);
                            tracing::info!("Confirming verification code...");
                            match conf.confirm_verification_code(code).await {
                                Ok(registered) => {
                                    let reg = registered.registration_data();
                                    let phone = reg.phone_number.to_string();
                                    let uuid = reg.service_ids.aci.to_string();
                                    tracing::info!("Registration complete! {} ({})", phone, uuid);
                                    let mut s = reg_state.lock().await;
                                    s.mode = DaemonMode::Normal;
                                    s.phone_number = phone;
                                    s.uuid = uuid;
                                    if let Some(tx) = s.registration_complete_tx.take() {
                                        let _ = tx.send(());
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Verification failed: {e:#}");
                                }
                            }
                            break;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });
        })
        .expect("failed to spawn registration thread");

    // Wait for the SMS to be sent (or error)
    match tokio::time::timeout(std::time::Duration::from_secs(60), result_rx).await {
        Ok(Ok(Ok(msg))) => Json(RegisterSignalResponse {
            success: true,
            message: format!("{msg}. Submit code via POST /register-signal/verify"),
            error: None,
        }),
        Ok(Ok(Err(e))) => Json(RegisterSignalResponse {
            success: false,
            message: String::new(),
            error: Some(e),
        }),
        _ => Json(RegisterSignalResponse {
            success: false,
            message: String::new(),
            error: Some("Registration timeout or internal error".into()),
        }),
    }
}

/// POST /register-signal/verify — Submit the SMS verification code.
/// Writes the code to a file that the registration thread picks up.
async fn handle_verify_code(
    State(state): State<SharedState>,
    Json(req): Json<VerifyCodeRequest>,
) -> Json<RegisterSignalResponse> {
    {
        let s = state.lock().await;
        if s.mode != DaemonMode::Registration {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some("Not in registration mode.".into()),
            });
        }
    }

    let db_path = {
        let s = state.lock().await;
        s.db_path.clone()
    };

    // Write code to file for the registration thread to pick up
    let code_file = format!("{}/verify_code.txt",
        std::path::Path::new(db_path.strip_prefix("sqlite://").unwrap_or(&db_path))
            .parent().unwrap_or(std::path::Path::new("/data/presage"))
            .to_string_lossy());

    match std::fs::write(&code_file, req.code.trim()) {
        Ok(()) => {
            tracing::info!("Verification code written, registration thread will pick it up");
            Json(RegisterSignalResponse {
                success: true,
                message: "Code submitted. Watch /status for mode to change to 'normal'.".into(),
                error: None,
            })
        }
        Err(e) => Json(RegisterSignalResponse {
            success: false,
            message: String::new(),
            error: Some(format!("Failed to write code: {e}")),
        }),
    }
}

