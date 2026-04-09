//! Companion Signal Daemon
//!
//! Minimal Signal identity that auto-joins groups created by the primary relay.
//! Its sole purpose is to meet Signal's SenderKey minimum threshold (>= 2 recipients).
//!
//! Architecture:
//!   Same TEE container as signal_daemon, separate identity, separate SQLite DB.
//!   Listens on port 7585, has no message processing, no TEE signing, no contract interaction.

use std::sync::Arc;
use tokio::sync::Mutex;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

/// Daemon operating mode
#[derive(Clone, PartialEq)]
pub enum DaemonMode {
    /// No Signal identity — waiting for operator to register via HTTP
    Registration,
    /// Signal identity exists — connected and accepting group invites
    Normal,
}

pub struct AppState {
    pub mode: DaemonMode,
    pub connected: bool,
    pub phone_number: String,
    pub uuid: String,
    pub username: Option<String>,
    pub db_path: String,
    pub registration_complete_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Queue of group master keys to accept invites for (pushed by HTTP, consumed by receiver)
    pub invite_accept_queue: Vec<PendingInviteAccept>,
}

pub struct PendingInviteAccept {
    pub master_key_hex: String,
    pub response_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
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
                .unwrap_or_else(|_| "companion_daemon=info".into()),
        )
        .init();

    let db_path = std::env::var("COMPANION_DB_PATH")
        .unwrap_or_else(|_| "sqlite:///data/presage/companion.sqlite".into());
    let listen_addr =
        std::env::var("COMPANION_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:7585".into());

    tracing::info!("Companion daemon starting (store: {db_path})");

    // Detect mode: does a registered identity exist?
    let has_identity = check_identity_exists(&db_path).await;
    let initial_mode = if has_identity {
        tracing::info!("Signal identity found — starting in NORMAL mode");
        DaemonMode::Normal
    } else {
        tracing::info!("No Signal identity — starting in REGISTRATION mode");
        tracing::info!("Register via HTTP: POST /register-signal, then POST /register-signal/verify");
        DaemonMode::Registration
    };

    let persisted_username = load_persisted_username(&db_path);
    if let Some(ref u) = persisted_username {
        tracing::info!("Companion username: {u}");
    }

    let (reg_complete_tx, reg_complete_rx) = tokio::sync::oneshot::channel::<()>();

    let state: SharedState = Arc::new(Mutex::new(AppState {
        mode: initial_mode.clone(),
        connected: false,
        phone_number: String::new(),
        uuid: String::new(),
        username: persisted_username.clone(),
        db_path: db_path.clone(),
        registration_complete_tx: if initial_mode == DaemonMode::Registration {
            Some(reg_complete_tx)
        } else {
            None
        },
        invite_accept_queue: Vec::new(),
    }));

    if initial_mode == DaemonMode::Normal {
        // Auto-claim username if not set yet
        if persisted_username.is_none() {
            tracing::info!("No username set — auto-claiming apicharge_XXXX...");
            let claim_state = state.clone();
            let claim_db = db_path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                match auto_claim_username(&claim_db).await {
                    Ok(username) => {
                        tracing::info!("Companion username claimed: {username}");
                        let mut s = claim_state.lock().await;
                        s.username = Some(username);
                    }
                    Err(e) => tracing::error!("Failed to auto-claim username: {e:#}"),
                }
            });
        }
        start_receiver_thread(state.clone(), db_path.clone());
    } else {
        let recv_state = state.clone();
        let recv_db = db_path.clone();
        tokio::spawn(async move {
            let _ = reg_complete_rx.await;
            tracing::info!("Registration complete — starting receiver thread");
            start_receiver_thread(recv_state, recv_db);
        });
    }

    // HTTP server — minimal: status, registration, and invite acceptance
    let app = Router::new()
        .route("/register-signal", post(handle_register_signal))
        .route("/register-signal/verify", post(handle_verify_code))
        .route("/status", get(handle_status))
        .route("/accept-invite", post(handle_accept_invite))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("Companion HTTP server listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}

// ── Receiver Thread ──────────────────────────────────────────────

/// Start the presage receiver on a dedicated OS thread.
/// The companion receive loop auto-accepts group invites and ignores everything else.
fn start_receiver_thread(state: SharedState, db_path: String) {
    std::thread::Builder::new()
        .name("companion-receiver".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build receiver runtime");
            rt.block_on(async {
                use presage::model::identity::OnNewIdentity;

                let store = match presage_store_sqlite::SqliteStore::open_with_passphrase(
                    &db_path, None, OnNewIdentity::Trust,
                ).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to open store: {e:#}");
                        return;
                    }
                };

                let mut manager = match presage::Manager::load_registered(store).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!("Failed to load registered manager: {e:#}");
                        return;
                    }
                };

                {
                    let mut s = state.lock().await;
                    s.connected = true;
                    let reg = manager.registration_data();
                    s.phone_number = reg.phone_number.to_string();
                    s.uuid = reg.service_ids.aci.to_string();
                    tracing::info!(
                        "Companion connected as {} ({})",
                        s.phone_number,
                        s.uuid
                    );
                }

                loop {
                    match run_companion_receive_loop(&mut manager, state.clone()).await {
                        Ok(()) => tracing::info!("Companion receiver ended, reconnecting in 10s..."),
                        Err(e) => tracing::error!("Companion receiver error: {e:#}, reconnecting in 10s..."),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            });
        })
        .expect("failed to spawn companion receiver thread");
}

/// Minimal receive loop: auto-accept group invites, process accept-invite queue.
async fn run_companion_receive_loop(
    manager: &mut presage::Manager<presage_store_sqlite::SqliteStore, presage::manager::Registered>,
    state: SharedState,
) -> anyhow::Result<()> {
    use futures::StreamExt;
    use presage::model::messages::Received;
    use presage::libsignal_service::content::ContentBody;

    let mut stream = Box::pin(manager.receive_messages().await?);

    tracing::info!("Companion receive loop started");

    loop {
        // Drain the invite accept queue before waiting for messages
        {
            let pending: Vec<PendingInviteAccept> = {
                let mut s = state.lock().await;
                std::mem::take(&mut s.invite_accept_queue)
            };
            for item in pending {
                tracing::info!("Processing queued invite accept: {}...", &item.master_key_hex[..16.min(item.master_key_hex.len())]);
                match hex::decode(&item.master_key_hex) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut master_key = [0u8; 32];
                        master_key.copy_from_slice(&bytes);

                        // Check if we're actually a pending member before accepting.
                        // Retry with backoff — the group state may not have propagated yet.
                        let delays = [2u64, 5, 10];
                        let mut result: Result<(), String> = Err("Not a pending member after 3 retries".into());
                        for (attempt, delay) in delays.iter().enumerate() {
                            match manager.check_pending_and_accept(&master_key).await {
                                Ok(true) => {
                                    tracing::info!("Accepted group invite (attempt {})", attempt + 1);
                                    result = Ok(());
                                    break;
                                }
                                Ok(false) => {
                                    tracing::info!("Not pending yet (attempt {}), retrying in {}s...", attempt + 1, delay);
                                    tokio::time::sleep(std::time::Duration::from_secs(*delay)).await;
                                }
                                Err(e) => {
                                    let err = format!("{e:#}");
                                    tracing::error!("Failed to accept invite (attempt {}): {err}", attempt + 1);
                                    result = Err(err);
                                    break;
                                }
                            }
                        }
                        let _ = item.response_tx.send(result);
                    }
                    _ => {
                        let _ = item.response_tx.send(Err("Invalid master_key_hex".into()));
                    }
                }
            }
        }

        // Wait for next message with timeout (so we periodically check the queue)
        let item = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.next(),
        ).await {
            Ok(Some(item)) => item,
            Ok(None) => break, // stream ended
            Err(_) => continue, // timeout — loop back to check queue
        };

        match item {
            Received::Content { content, .. } => {
                // Check for group invite: DataMessage with GroupContextV2 containing master_key
                if let ContentBody::DataMessage(ref dm) = content.body {
                    if let Some(ref gv2) = dm.group_v2 {
                        if let Some(ref mk) = gv2.master_key {
                            if mk.len() == 32 {
                                let mut master_key = [0u8; 32];
                                master_key.copy_from_slice(mk);
                                tracing::info!(
                                    "Companion: received group invite (master_key={}...)",
                                    hex::encode(&master_key[..8])
                                );
                                match manager.accept_group_invite(&master_key).await {
                                    Ok(()) => tracing::info!("Companion: accepted group invite"),
                                    Err(e) => tracing::error!("Companion: failed to accept invite: {e:#}"),
                                }
                            }
                        }
                    }
                }
                // All other content silently ignored
            }
            Received::SenderKeyDistribution { .. } => {
                // Presage processes SKDMs automatically in cipher.rs —
                // the SenderKey is stored in the SenderKeyStore.
                tracing::debug!("Companion: received SKDM (auto-processed by presage)");
            }
            Received::QueueEmpty => {}
            Received::Contacts => {}
        }
    } // loop

    Ok(())
}

// ── Username Claiming ────────────────────────────────────────────

async fn auto_claim_username(db_path: &str) -> anyhow::Result<String> {
    use presage::model::identity::OnNewIdentity;
    use usernames::{Username, NicknameLimits};

    let store = presage_store_sqlite::SqliteStore::open_with_passphrase(
        db_path, None, OnNewIdentity::Trust,
    ).await?;
    let mut manager = presage::Manager::load_registered(store).await?;

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
    tracing::info!("Companion: generated nickname: {nickname}");

    let _limits = NicknameLimits::default();
    let mut candidates = Vec::new();
    for disc in 1..=99u32 {
        let candidate = format!("{nickname}.{disc:02}");
        if Username::new(&candidate).is_ok() {
            candidates.push(candidate);
        }
        if candidates.len() >= 20 { break; }
    }

    // Compute hashes
    let mut hashes: Vec<Vec<u8>> = Vec::new();
    let mut candidate_map: std::collections::HashMap<Vec<u8>, String> = std::collections::HashMap::new();
    for candidate in &candidates {
        if let Ok(u) = Username::new(candidate) {
            let hash = u.hash().to_vec();
            candidate_map.insert(hash.clone(), candidate.clone());
            hashes.push(hash);
        }
    }

    if hashes.is_empty() {
        return Err(anyhow::anyhow!("no valid candidates"));
    }

    tracing::info!("Companion: reserving username...");
    let reserved_hash = manager.reserve_username(hashes).await
        .map_err(|e| anyhow::anyhow!("reserve failed: {e:?}"))?;

    let selected_username = candidate_map.get(&reserved_hash)
        .ok_or_else(|| anyhow::anyhow!("reserved hash doesn't match any candidate"))?
        .clone();

    tracing::info!("Companion: reserved {selected_username}");

    // Generate ZK proof and confirm
    let username_obj = Username::new(&selected_username).unwrap();
    let mut randomness = [0u8; 32];
    getrandom::getrandom(&mut randomness).expect("getrandom failed");
    let proof = username_obj.proof(&randomness)
        .map_err(|e| anyhow::anyhow!("ZK proof failed: {e:?}"))?;

    manager.confirm_username(&reserved_hash, &proof).await
        .map_err(|e| anyhow::anyhow!("confirm failed: {e:?}"))?;

    // Persist to disk
    persist_username(db_path, &selected_username)?;

    Ok(selected_username)
}

// ── Username Persistence ─────────────────────────────────────────

fn username_file_path(db_path: &str) -> String {
    let stripped = db_path.strip_prefix("sqlite://").unwrap_or(db_path);
    let parent = std::path::Path::new(stripped)
        .parent()
        .unwrap_or(std::path::Path::new("/data/presage"));
    parent.join("companion_username.txt").to_string_lossy().to_string()
}

fn load_persisted_username(db_path: &str) -> Option<String> {
    let path = username_file_path(db_path);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() { None } else { Some(trimmed) }
        }
        Err(_) => None,
    }
}

fn persist_username(db_path: &str, username: &str) -> std::io::Result<()> {
    let path = username_file_path(db_path);
    std::fs::write(&path, username)?;
    tracing::info!("Companion username persisted to {path}");
    Ok(())
}

// ── Identity Check ───────────────────────────────────────────────

async fn check_identity_exists(db_path: &str) -> bool {
    use presage::model::identity::OnNewIdentity;
    match presage_store_sqlite::SqliteStore::open_with_passphrase(db_path, None, OnNewIdentity::Trust).await {
        Ok(store) => presage::Manager::load_registered(store).await.is_ok(),
        Err(_) => false,
    }
}

// ── HTTP Types ───────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    connected: bool,
    mode: String,
    uuid: String,
    username: Option<String>,
}

#[derive(Deserialize)]
struct RegisterSignalRequest {
    phone_number: String,
    captcha: String,
}

#[derive(Serialize)]
struct RegisterSignalResponse {
    success: bool,
    message: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct VerifyCodeRequest {
    code: String,
}

#[derive(Deserialize)]
struct AcceptInviteRequest {
    master_key_hex: String,
}

#[derive(Serialize)]
struct AcceptInviteResponse {
    success: bool,
    error: Option<String>,
}

// ── HTTP Handlers ────────────────────────────────────────────────

async fn handle_status(State(state): State<SharedState>) -> Json<StatusResponse> {
    let s = state.lock().await;
    Json(StatusResponse {
        connected: s.connected,
        mode: match s.mode {
            DaemonMode::Registration => "registration".to_string(),
            DaemonMode::Normal => "normal".to_string(),
        },
        uuid: s.uuid.clone(),
        username: s.username.clone(),
    })
}

/// Accept a group invite by master key. The relay calls this after creating a group
/// with the companion as a pending member.
async fn handle_accept_invite(
    State(state): State<SharedState>,
    Json(req): Json<AcceptInviteRequest>,
) -> Json<AcceptInviteResponse> {
    tracing::info!("accept-invite called for master_key={}...", &req.master_key_hex[..16.min(req.master_key_hex.len())]);

    let (tx, rx) = tokio::sync::oneshot::channel();
    {
        let mut s = state.lock().await;
        if s.mode != DaemonMode::Normal {
            return Json(AcceptInviteResponse {
                success: false,
                error: Some("Companion not in normal mode".into()),
            });
        }
        s.invite_accept_queue.push(PendingInviteAccept {
            master_key_hex: req.master_key_hex,
            response_tx: tx,
        });
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(Ok(()))) => Json(AcceptInviteResponse { success: true, error: None }),
        Ok(Ok(Err(e))) => Json(AcceptInviteResponse { success: false, error: Some(e) }),
        Ok(Err(_)) => Json(AcceptInviteResponse { success: false, error: Some("Internal error".into()) }),
        Err(_) => Json(AcceptInviteResponse { success: false, error: Some("Timeout".into()) }),
    }
}

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

    let captcha = req.captcha.clone();
    let phone_str = req.phone_number.clone();
    let reg_state = state.clone();

    let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<String, String>>();

    std::thread::Builder::new()
        .name("companion-register".into())
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

                tracing::info!("Companion: registering with Signal: {phone_str}...");
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

                tracing::info!("SMS sent. Waiting for verification code...");
                let _ = result_tx.send(Ok("SMS sent".into()));

                let code_file = format!("{}/companion_verify_code.txt",
                    std::path::Path::new(db_path.strip_prefix("sqlite://").unwrap_or(&db_path))
                        .parent().unwrap_or(std::path::Path::new("/data/presage"))
                        .to_string_lossy());

                loop {
                    if let Ok(code) = std::fs::read_to_string(&code_file) {
                        let code = code.trim().to_string();
                        if !code.is_empty() {
                            let _ = std::fs::remove_file(&code_file);
                            tracing::info!("Companion: confirming verification code...");
                            match conf.confirm_verification_code(code).await {
                                Ok(registered) => {
                                    let reg = registered.registration_data();
                                    let phone = reg.phone_number.to_string();
                                    let uuid = reg.service_ids.aci.to_string();
                                    tracing::info!("Companion registered: {} ({})", phone, uuid);
                                    let mut s = reg_state.lock().await;
                                    s.mode = DaemonMode::Normal;
                                    s.phone_number = phone;
                                    s.uuid = uuid;
                                    if let Some(tx) = s.registration_complete_tx.take() {
                                        let _ = tx.send(());
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Companion verification failed: {e:#}");
                                }
                            }
                            break;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });
        })
        .expect("failed to spawn companion registration thread");

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

    let code_file = format!("{}/companion_verify_code.txt",
        std::path::Path::new(db_path.strip_prefix("sqlite://").unwrap_or(&db_path))
            .parent().unwrap_or(std::path::Path::new("/data/presage"))
            .to_string_lossy());

    match std::fs::write(&code_file, req.code.trim()) {
        Ok(()) => {
            tracing::info!("Companion: verification code written");
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
