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
    /// Pending confirmation manager (held between register step 1 and verify step 2)
    pub pending_confirmation: Option<Box<dyn std::any::Any + Send>>,
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
        username: None,
        tee_signing_key,
        known_group_ids: std::collections::HashSet::new(),
        db_path: db_path.clone(),
        pending_confirmation: None,
        registration_complete_tx: if initial_mode == DaemonMode::Registration {
            Some(reg_complete_tx)
        } else {
            None
        },
    }));

    // Start receiver thread (only if identity exists; otherwise wait for registration)
    if initial_mode == DaemonMode::Normal {
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
        .route("/set-username", post(handle_set_username))
        // Status (both modes)
        .route("/status", get(handle_status))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("HTTP server listening on {listen_addr}");
    axum::serve(listener, app).await?;

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

/// POST /register-signal — Step 1: Initiate Signal registration with phone + CAPTCHA.
/// Sends SMS to the provided phone number.
async fn handle_register_signal(
    State(state): State<SharedState>,
    Json(req): Json<RegisterSignalRequest>,
) -> Json<RegisterSignalResponse> {
    use presage::libsignal_service::configuration::SignalServers;
    use presage::manager::RegistrationOptions;
    use presage::model::identity::OnNewIdentity;

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

    let store = match presage_store_sqlite::SqliteStore::open_with_passphrase(
        &db_path, None, OnNewIdentity::Trust,
    ).await {
        Ok(s) => s,
        Err(e) => {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some(format!("Failed to open store: {e}")),
            });
        }
    };

    tracing::info!("Registering with Signal: {}...", req.phone_number);

    let captcha = req.captcha.clone();
    match presage::Manager::register(
        store,
        RegistrationOptions {
            signal_servers: SignalServers::Production,
            phone_number,
            use_voice_call: false,
            captcha: Some(&captcha),
            force: true,
        },
    ).await {
        Ok(confirmation_manager) => {
            // Store the confirmation manager for the verify step
            let mut s = state.lock().await;
            s.pending_confirmation = Some(Box::new(confirmation_manager));
            tracing::info!("SMS sent to {}. Awaiting verification code.", req.phone_number);
            Json(RegisterSignalResponse {
                success: true,
                message: "SMS sent. Submit the 6-digit code via POST /register-signal/verify".into(),
                error: None,
            })
        }
        Err(e) => {
            tracing::error!("Registration failed: {e:#}");
            Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some(format!("Registration failed: {e}")),
            })
        }
    }
}

/// POST /register-signal/verify — Step 2: Submit the SMS verification code.
/// Completes registration and transitions to normal mode.
async fn handle_verify_code(
    State(state): State<SharedState>,
    Json(req): Json<VerifyCodeRequest>,
) -> Json<RegisterSignalResponse> {
    let confirmation: Option<Box<dyn std::any::Any + Send>>;
    {
        let mut s = state.lock().await;
        if s.mode != DaemonMode::Registration {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some("Not in registration mode.".into()),
            });
        }
        confirmation = s.pending_confirmation.take();
    }

    let confirmation = match confirmation {
        Some(c) => c,
        None => {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some("No pending registration. Call POST /register-signal first.".into()),
            });
        }
    };

    // Downcast to the actual confirmation manager type
    type ConfManager = presage::Manager<presage_store_sqlite::SqliteStore, presage::manager::Confirmation>;
    let conf_manager = match confirmation.downcast::<ConfManager>() {
        Ok(m) => *m,
        Err(_) => {
            return Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some("Internal error: confirmation manager type mismatch.".into()),
            });
        }
    };

    tracing::info!("Confirming verification code...");

    match conf_manager.confirm_verification_code(req.code.trim().to_string()).await {
        Ok(registered_manager) => {
            let reg = registered_manager.registration_data();
            let phone = reg.phone_number.to_string();
            let uuid = reg.service_ids.aci.to_string();
            tracing::info!("Registration complete! {} ({})", phone, uuid);

            let mut s = state.lock().await;
            s.mode = DaemonMode::Normal;
            s.phone_number = phone.clone();
            s.uuid = uuid.clone();

            // Signal the receiver thread to start
            if let Some(tx) = s.registration_complete_tx.take() {
                let _ = tx.send(());
            }

            Json(RegisterSignalResponse {
                success: true,
                message: format!("Registered as {phone} ({uuid}). Now set a username via POST /set-username."),
                error: None,
            })
        }
        Err(e) => {
            tracing::error!("Verification failed: {e:#}");
            Json(RegisterSignalResponse {
                success: false,
                message: String::new(),
                error: Some(format!("Verification failed: {e}")),
            })
        }
    }
}

/// POST /set-username — Claim a Signal username (e.g. "apicharge_kx7m").
/// Signal assigns the discriminator (e.g. ".42"). Returns the full username.
///
/// This calls Signal's reserve + confirm API using the `usernames` crate for
/// hash computation and ZK proof generation.
async fn handle_set_username(
    State(state): State<SharedState>,
    Json(req): Json<SetUsernameRequest>,
) -> Json<SetUsernameResponse> {
    use presage::model::identity::OnNewIdentity;
    use usernames::{Username, NicknameLimits};

    // Validate nickname
    let nickname = req.nickname.trim();
    if nickname.is_empty() || nickname.len() > 32 {
        return Json(SetUsernameResponse {
            success: false,
            username: None,
            error: Some("Nickname must be 1-32 characters.".into()),
        });
    }

    let db_path = {
        let s = state.lock().await;
        s.db_path.clone()
    };

    // Load registered manager
    let store = match presage_store_sqlite::SqliteStore::open_with_passphrase(
        &db_path, None, OnNewIdentity::Trust,
    ).await {
        Ok(s) => s,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("Failed to open store: {e}")),
            });
        }
    };

    let manager = match presage::Manager::load_registered(store).await {
        Ok(m) => m,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("No registered identity: {e}")),
            });
        }
    };

    // Generate candidates using the usernames crate
    let limits = NicknameLimits::default();
    let mut rng = rand::rngs::OsRng;
    let candidates = match Username::candidates_from(&mut rng, nickname, limits) {
        Ok(c) => c,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("Invalid nickname: {e:?}")),
            });
        }
    };

    tracing::info!("Generated {} username candidates for '{}'", candidates.len(), nickname);

    // Compute hashes for all candidates
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut candidate_map: std::collections::HashMap<[u8; 32], String> = std::collections::HashMap::new();
    for candidate in &candidates {
        match Username::new(candidate) {
            Ok(u) => {
                let hash = u.hash();
                hashes.push(hash);
                candidate_map.insert(hash, candidate.clone());
            }
            Err(e) => tracing::warn!("Skipping invalid candidate '{}': {e:?}", candidate),
        }
    }

    if hashes.is_empty() {
        return Json(SetUsernameResponse {
            success: false, username: None,
            error: Some("No valid candidates generated.".into()),
        });
    }

    // Reserve: PUT /v1/accounts/username_hash/reserve
    let hashes_b64: Vec<String> = hashes.iter()
        .map(|h| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, h))
        .collect();

    let reserve_body = serde_json::json!({ "usernameHashes": hashes_b64 });

    // Use the manager's authenticated WebSocket to make the HTTP request
    // For now, use direct HTTP since presage doesn't expose reserve/confirm yet
    let reg = manager.registration_data();
    let credentials = format!("{}:{}", reg.service_ids.aci, reg.password());
    let auth_header = format!("Basic {}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD, credentials.as_bytes()));

    let signal_host = std::env::var("SIGNAL_HOST").unwrap_or_else(|_| "chat.signal.org".into());
    let http_client = reqwest::Client::new();

    let reserve_url = format!("https://{signal_host}/v1/accounts/username_hash/reserve");
    tracing::info!("Reserving username at {reserve_url}...");

    let reserve_resp = match http_client.put(&reserve_url)
        .header("Authorization", &auth_header)
        .json(&reserve_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("Reserve request failed: {e}")),
            });
        }
    };

    if !reserve_resp.status().is_success() {
        let status = reserve_resp.status();
        let body = reserve_resp.text().await.unwrap_or_default();
        return Json(SetUsernameResponse {
            success: false, username: None,
            error: Some(format!("Reserve failed (HTTP {status}): {body}")),
        });
    }

    let reserve_result: serde_json::Value = match reserve_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("Failed to parse reserve response: {e}")),
            });
        }
    };

    let selected_hash_b64 = match reserve_result["usernameHash"].as_str() {
        Some(h) => h.to_string(),
        None => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some("Reserve response missing usernameHash.".into()),
            });
        }
    };

    let selected_hash_bytes: [u8; 32] = match base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD, &selected_hash_b64
    ) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some("Invalid hash in reserve response.".into()),
            });
        }
    };

    // Find which candidate was selected
    let selected_username = match candidate_map.get(&selected_hash_bytes) {
        Some(u) => u.clone(),
        None => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some("Reserved hash doesn't match any candidate.".into()),
            });
        }
    };

    tracing::info!("Reserved username: {selected_username}");

    // Generate ZK proof
    let username_obj = Username::new(&selected_username).unwrap();
    let mut randomness = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut randomness);
    let proof = match username_obj.proof(&randomness) {
        Ok(p) => p,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("Failed to generate ZK proof: {e:?}")),
            });
        }
    };

    // Confirm: PUT /v1/accounts/username_hash/confirm
    let confirm_body = serde_json::json!({
        "usernameHash": selected_hash_b64,
        "zkProof": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &proof),
    });

    let confirm_url = format!("https://{signal_host}/v1/accounts/username_hash/confirm");
    tracing::info!("Confirming username...");

    let confirm_resp = match http_client.put(&confirm_url)
        .header("Authorization", &auth_header)
        .json(&confirm_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Json(SetUsernameResponse {
                success: false, username: None,
                error: Some(format!("Confirm request failed: {e}")),
            });
        }
    };

    if !confirm_resp.status().is_success() {
        let status = confirm_resp.status();
        let body = confirm_resp.text().await.unwrap_or_default();
        return Json(SetUsernameResponse {
            success: false, username: None,
            error: Some(format!("Confirm failed (HTTP {status}): {body}")),
        });
    }

    tracing::info!("Username confirmed: {selected_username}");

    // Store username in state
    {
        let mut s = state.lock().await;
        s.username = Some(selected_username.clone());
    }

    Json(SetUsernameResponse {
        success: true,
        username: Some(selected_username),
        error: None,
    })
}
