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

pub struct AppState {
    pub message_queue: Vec<ReceivedMessage>,
    pub send_queue: Vec<PendingSend>,
    pub group_send_queue: Vec<PendingGroupSend>,
    pub group_create_queue: Vec<PendingGroupCreate>,
    pub typing_queue: Vec<PendingTyping>,
    pub messages_received: u64,
    pub connected: bool,
    pub phone_number: String,
    pub uuid: String,
    pub tee_signing_key: SigningKey,
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

    // Handle --register: fresh Signal registration via SMS
    if std::env::args().any(|a| a == "--register") {
        return register_account(&db_path).await;
    }

    tracing::info!("Using presage store at {db_path}");

    // Load or generate TEE Ed25519 signing key
    let tee_signing_key = match std::env::var("TEE_SIGNING_KEY") {
        Ok(hex_key) => {
            let bytes = hex::decode(&hex_key)
                .map_err(|e| anyhow::anyhow!("TEE_SIGNING_KEY invalid hex: {e}"))?;
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("TEE_SIGNING_KEY must be 32 bytes (64 hex chars), got {}", v.len()))?;
            let key = SigningKey::from_bytes(&secret);
            tracing::info!(
                "TEE signing key loaded from env, pubkey={}",
                hex::encode(key.verifying_key().as_bytes())
            );
            key
        }
        Err(_) => {
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            tracing::warn!(
                "TEE_SIGNING_KEY not set — using ephemeral key for development. pubkey={}",
                hex::encode(key.verifying_key().as_bytes())
            );
            key
        }
    };

    let state: SharedState = Arc::new(Mutex::new(AppState {
        message_queue: Vec::new(),
        send_queue: Vec::new(),
        group_send_queue: Vec::new(),
        group_create_queue: Vec::new(),
        typing_queue: Vec::new(),
        messages_received: 0,
        connected: false,
        phone_number: String::new(),
        uuid: String::new(),
        tee_signing_key,
    }));

    // Run the receiver on a dedicated OS thread (presage futures are huge in debug)
    let recv_state = state.clone();
    let recv_db = db_path.clone();
    std::thread::Builder::new()
        .name("presage-receiver".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build receiver runtime");
            rt.block_on(async {
                // Create manager ONCE — reuse across reconnects to avoid ghost WebSocket overlap
                let mut manager = match receiver::create_manager(&recv_db).await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!("Failed to create manager: {e:#}");
                        return;
                    }
                };
                {
                    let mut s = recv_state.lock().await;
                    s.connected = true;
                    let reg = manager.registration_data();
                    s.phone_number = reg.phone_number.to_string();
                    s.uuid = reg.service_ids.aci.to_string();
                    tracing::info!("Connected as {} ({})", s.phone_number, s.uuid);
                }

                loop {
                    let queue = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
                    match receiver::run_receive_loop(&mut manager, queue.clone(), recv_state.clone()).await {
                        Ok(()) => tracing::info!("Receiver ended, reconnecting in 10s..."),
                        Err(e) => tracing::error!("Receiver error: {e:#}, reconnecting in 10s..."),
                    }
                    // Move messages to main state
                    {
                        let mut remaining = queue.lock().await;
                        if !remaining.is_empty() {
                            let mut s = recv_state.lock().await;
                            s.message_queue.append(&mut remaining);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            });
        })?;

    // HTTP server on the main thread
    let app = Router::new()
        .route("/receive", get(handle_receive))
        .route("/send", post(handle_send))
        .route("/send-group", post(handle_send_group))
        .route("/status", get(handle_status))
        .route("/create-group", post(handle_create_group))
        .route("/tee-pubkey", get(handle_tee_pubkey))
        .route("/typing", post(handle_typing))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("HTTP server listening on {listen_addr}");
    axum::serve(listener, app).await?;

    Ok(())
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

async fn handle_status(State(state): State<SharedState>) -> Json<StatusResponse> {
    let s = state.lock().await;
    Json(StatusResponse {
        connected: s.connected,
        phone_number: s.phone_number.clone(),
        uuid: s.uuid.clone(),
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

/// Interactive registration via SMS verification code.
/// Usage: signal-daemon --register
/// Env vars: PRESAGE_DB_PATH (sqlite URL for the presage store)
async fn register_account(db_path: &str) -> anyhow::Result<()> {
    use presage::libsignal_service::configuration::SignalServers;
    use presage::manager::RegistrationOptions;
    use presage::model::identity::OnNewIdentity;

    println!("=== Signal Registration ===");
    println!();

    // Get phone number
    println!("Enter phone number (E.164 format, e.g. +420702843097):");
    let mut phone_input = String::new();
    std::io::stdin().read_line(&mut phone_input)?;
    let phone_number = phonenumber::parse(None, phone_input.trim())?;

    // Get captcha
    println!();
    println!("Go to: https://signalcaptchas.org/registration/generate.html");
    println!("Solve the captcha, copy the signalcaptcha:// URL, and paste it here:");
    let mut captcha_input = String::new();
    std::io::stdin().read_line(&mut captcha_input)?;
    let captcha = captcha_input.trim().to_string();

    // Open or create the store
    let store = presage_store_sqlite::SqliteStore::open_with_passphrase(
        db_path, None, OnNewIdentity::Trust,
    ).await?;

    println!();
    println!("Sending SMS to {}...", phone_number);

    let confirmation_manager = presage::Manager::register(
        store,
        RegistrationOptions {
            signal_servers: SignalServers::Production,
            phone_number,
            use_voice_call: false,
            captcha: Some(&captcha),
            force: true,
        },
    )
    .await?;

    println!("SMS sent! Enter the 6-digit verification code:");
    let mut code_input = String::new();
    std::io::stdin().read_line(&mut code_input)?;
    let code = code_input.trim().to_string();

    let registered = confirmation_manager
        .confirm_verification_code(code)
        .await?;

    println!();
    println!("Registration complete!");
    println!("Account: {}", registered.registration_data().service_ids);
    println!("Phone: {}", registered.registration_data().phone_number);
    println!();
    println!("Restart the daemon normally (without --register).");

    Ok(())
}
