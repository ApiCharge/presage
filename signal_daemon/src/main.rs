//! Signal Sealed Sender Daemon
//!
//! Replaces signal-cli for the ApiCharge relay. Connects to Signal servers,
//! receives sealed sender envelopes, extracts the s-layer cryptographic
//! material, and exposes it via HTTP for the .NET SignalRelayService.
//!
//! Phase 1: Uses presage's receive_messages() for decrypted content.
//!   The relay submits instructions via admin-auth. Works for testnet.
//!
//! Phase 2: Custom WebSocket receiver that captures raw sealed sender
//!   material for full on-chain verification. Required for MiCA production.
//!
//! Architecture:
//!   Signal servers ↔ presage (WebSocket) ↔ This daemon ↔ HTTP ↔ .NET relay

mod api;
mod config;
mod message_keys;
mod receiver;
mod sealed_sender;
mod tls_poll;

use api::*;
use std::sync::Arc;
use tokio::sync::Mutex;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

/// Outbound send request queued by the HTTP handler, processed by the receiver thread.
pub struct PendingSend {
    pub recipient: String,
    pub message: String,
}

pub struct AppState {
    pub message_queue: Vec<ReceivedMessage>,
    pub send_queue: Vec<PendingSend>,
    pub messages_received: u64,
    pub connected: bool,
    pub phone_number: String,
    pub uuid: String,
    /// TLS session setup for the relay to submit to the contract (once per TLS session)
    pub pending_tls_session: Option<api::TlsSessionSetupDto>,
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

    let signal_cli_dir = std::env::var("SIGNAL_CLI_DATA_DIR")
        .map_err(|_| anyhow::anyhow!("SIGNAL_CLI_DATA_DIR must be set"))?;

    // Load identity keys from signal-cli data
    let daemon_config = config::DaemonConfig::from_signal_cli_data(&signal_cli_dir, &listen_addr)?;
    tracing::info!("Loaded identity for {} ({})", daemon_config.phone_number, daemon_config.uuid);

    // One-shot migration: only create store if it doesn't exist
    let db_file = db_path
        .strip_prefix("sqlite://")
        .and_then(|s| s.split('?').next())
        .unwrap_or(&db_path);
    if !std::path::Path::new(db_file).exists() {
        tracing::info!("Creating presage store at {db_path} from signal-cli data...");
        init_presage_store(&db_path, &daemon_config).await?;
        tracing::info!("Presage store created.");
    } else {
        tracing::info!("Presage store exists at {db_file}, skipping migration.");
    }

    let state: SharedState = Arc::new(Mutex::new(AppState {
        message_queue: Vec::new(),
        send_queue: Vec::new(),
        messages_received: 0,
        connected: false,
        phone_number: daemon_config.phone_number.clone(),
        uuid: daemon_config.uuid.clone(),
        pending_tls_session: None,
    }));

    // Create TLS polling client if SIGNAL_HOST is set
    let tls_client = std::env::var("SIGNAL_HOST").ok().map(|host| {
        tracing::info!("TLS polling enabled for {host}");
        std::sync::Arc::new(tls_poll::TlsPollClient::new(
            &host,
            &daemon_config.uuid,
            &daemon_config.password,
        ))
    });

    // Run the receiver on a dedicated OS thread (presage futures are huge in debug)
    let recv_state = state.clone();
    let recv_db = db_path.clone();
    let recv_config = daemon_config.clone();
    let recv_tls = tls_client.clone();
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
                    match receiver::run_receive_loop(&mut manager, queue.clone(), &recv_config, recv_state.clone(), recv_tls.clone()).await {
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
        .route("/status", get(handle_status))
        .route("/tls-session", get(handle_tls_session))
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
    tracing::info!("Queuing send to {}: {}", req.recipient, req.message);
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

async fn handle_status(State(state): State<SharedState>) -> Json<StatusResponse> {
    let s = state.lock().await;
    Json(StatusResponse {
        connected: s.connected,
        phone_number: s.phone_number.clone(),
        uuid: s.uuid.clone(),
        messages_received: s.messages_received,
    })
}

/// GET /tls-session — retrieve the latest TLS session setup data.
/// The .NET relay calls this once per TLS session, then submits to the contract's verify_tls_session.
async fn handle_tls_session(State(state): State<SharedState>) -> Json<Option<api::TlsSessionSetupDto>> {
    let mut s = state.lock().await;
    Json(s.pending_tls_session.take())
}

/// Create a presage-compatible SQLite store from signal-cli credentials.
/// Opens SqliteStore (runs migrations), then writes registration + identity via the exposed pool.
async fn init_presage_store(db_path: &str, cfg: &config::DaemonConfig) -> anyhow::Result<()> {
    use base64::Engine;
    use presage::libsignal_service::protocol::{IdentityKeyPair, PrivateKey, PublicKey};
    use presage::model::identity::OnNewIdentity;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Open store with create_if_missing (open_with_passphrase sets it, open does not)
    let store = presage_store_sqlite::SqliteStore::open_with_passphrase(db_path, None, OnNewIdentity::Trust).await?;

    let phone = phonenumber::parse(None, &cfg.phone_number)?;
    let reg = serde_json::json!({
        "signal_servers": "Production",
        "device_name": null,
        "phone_number": serde_json::to_value(&phone)?,
        "uuid": cfg.uuid,
        "pni": cfg.pni_uuid.as_deref().unwrap_or("00000000-0000-0000-0000-000000000000"),
        "password": cfg.password,
        "signaling_key": b64.encode([0u8; 52]),
        "device_id": if cfg.device_id == 1 { serde_json::Value::Null } else { serde_json::json!(cfg.device_id) },
        "registration_id": cfg.registration_id,
        "pni_registration_id": cfg.pni_registration_id,
        "profile_key": cfg.profile_key.as_deref().unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    });

    sqlx::query("INSERT OR REPLACE INTO kv (key, value) VALUES ('registration', ?)")
        .bind(serde_json::to_string(&reg)?)
        .execute(&store.db)
        .await?;

    let kp = IdentityKeyPair::new(
        PublicKey::deserialize(&{
            let mut k = vec![0x05];
            k.extend_from_slice(&cfg.identity_public_key);
            k
        })?.into(),
        PrivateKey::deserialize(&cfg.identity_private_key)?,
    );
    // Key name must match presage's IdentityType::identity_key_pair_key() = "identity_keypair_aci"
    // Value is raw protobuf bytes (IdentityKeyPair::serialize()), NOT base64 or JSON
    let kp_bytes = kp.serialize();
    sqlx::query("INSERT OR REPLACE INTO kv (key, value) VALUES ('identity_keypair_aci', ?)")
        .bind(&*kp_bytes)
        .execute(&store.db)
        .await?;

    // PNI identity key pair (required for register_pre_keys which updates both ACI and PNI)
    if let Some(ref pni) = cfg.pni_identity_private_key {
        let pni_pub_bytes = cfg.pni_identity_public_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("PNI public key missing"))?;
        let mut pub_with_prefix = vec![0x05];
        pub_with_prefix.extend_from_slice(pni_pub_bytes);
        let pni_kp = IdentityKeyPair::new(
            PublicKey::deserialize(&pub_with_prefix)?.into(),
            PrivateKey::deserialize(pni)?,
        );
        sqlx::query("INSERT OR REPLACE INTO kv (key, value) VALUES ('identity_keypair_pni', ?)")
            .bind(&*pni_kp.serialize())
            .execute(&store.db)
            .await?;
        tracing::info!("PNI identity key pair written");
    }

    tracing::info!("Registration + identity key pairs written. Pre-keys will be generated by presage on connect.");

    Ok(())
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
