//! TLS-verified HTTP polling for Signal's GET /v1/messages endpoint.
//!
//! Polls Signal's REST API directly and captures raw TLS records + session keys.
//! The Soroban contract verifies these records to prove message bytes came from
//! Signal's server.
//!
//! Architecture:
//!   1. Connect to chat.signal.org over TLS 1.3 with custom CryptoProvider
//!   2. Capture ephemeral X25519 private key via x25519-dalek
//!   3. Capture raw encrypted bytes at the TCP level (both reads and writes)
//!   4. Send HTTP GET /v1/messages (protobuf format)
//!   5. Return: raw TLS record(s) + session setup data + decrypted response
//!   6. Acknowledge messages via DELETE /v1/messages/uuid/{guid}

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ============================================================================
// Custom CryptoProvider for ephemeral X25519 key capture
// ============================================================================

/// X25519 key exchange group that captures the ephemeral private key.
/// The contract needs this to recompute the ECDHE shared secret on-chain.
struct CapturingX25519 {
    captured_priv: Arc<Mutex<Option<[u8; 32]>>>,
}

impl std::fmt::Debug for CapturingX25519 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturingX25519").finish()
    }
}

impl rustls::crypto::SupportedKxGroup for CapturingX25519 {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        // Capture the raw 32-byte private key for the contract
        *self.captured_priv.lock().unwrap() = Some(secret.to_bytes());

        Ok(Box::new(CapturingKeyExchange {
            secret,
            public_key: public.to_bytes(),
        }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// Active key exchange that uses x25519-dalek for the DH computation.
struct CapturingKeyExchange {
    secret: x25519_dalek::StaticSecret,
    public_key: [u8; 32],
}

impl rustls::crypto::ActiveKeyExchange for CapturingKeyExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        if peer_pub_key.len() != 32 {
            return Err(rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare));
        }
        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_pub_key);
        let peer_public = x25519_dalek::PublicKey::from(peer_bytes);
        let shared = self.secret.diffie_hellman(&peer_public);
        Ok(rustls::crypto::SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// Build a CryptoProvider that captures the ephemeral X25519 private key.
/// Uses ring for everything except X25519 key exchange.
/// Restricts cipher suites to TLS13_AES_256_GCM_SHA384 (32-byte keys)
/// to match the contract's AES-256-GCM verification.
fn build_capturing_provider(
    captured_priv: Arc<Mutex<Option<[u8; 32]>>>,
) -> rustls::crypto::CryptoProvider {
    let ring_provider = rustls::crypto::ring::default_provider();

    // Only allow AES-256-GCM to guarantee 32-byte record keys
    let cipher_suites: Vec<_> = ring_provider
        .cipher_suites
        .into_iter()
        .filter(|cs| {
            cs.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
        })
        .collect();

    // Leak to get a &'static reference — one allocation per TLS connection, acceptable
    let kx_group: &'static dyn rustls::crypto::SupportedKxGroup =
        Box::leak(Box::new(CapturingX25519 { captured_priv }));

    rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups: vec![kx_group],
        signature_verification_algorithms: ring_provider.signature_verification_algorithms,
        secure_random: ring_provider.secure_random,
        key_provider: ring_provider.key_provider,
    }
}

// ============================================================================
// KeyLog for capturing SERVER_TRAFFIC_SECRET_0
// ============================================================================

#[derive(Debug)]
struct KeyCapture {
    server_traffic_secret: Mutex<Option<Vec<u8>>>,
}

impl KeyCapture {
    fn new() -> Self {
        KeyCapture {
            server_traffic_secret: Mutex::new(None),
        }
    }
}

impl rustls::KeyLog for KeyCapture {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == "SERVER_TRAFFIC_SECRET_0" {
            *self.server_traffic_secret.lock().unwrap() = Some(secret.to_vec());
        }
    }
}

// ============================================================================
// TCP stream wrapper that captures both reads AND writes
// ============================================================================

struct CapturingStream {
    inner: TcpStream,
    captured_reads: Arc<Mutex<Vec<u8>>>,
    captured_writes: Arc<Mutex<Vec<u8>>>,
}

impl CapturingStream {
    fn new(stream: TcpStream) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<Mutex<Vec<u8>>>) {
        let reads = Arc::new(Mutex::new(Vec::new()));
        let writes = Arc::new(Mutex::new(Vec::new()));
        (
            CapturingStream {
                inner: stream,
                captured_reads: reads.clone(),
                captured_writes: writes.clone(),
            },
            reads,
            writes,
        )
    }
}

impl tokio::io::AsyncRead for CapturingStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                let new_bytes = &buf.filled()[before..after];
                this.captured_reads.lock().unwrap().extend_from_slice(new_bytes);
            }
        }
        result
    }
}

impl tokio::io::AsyncWrite for CapturingStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            this.captured_writes.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ============================================================================
// TLS record parsing
// ============================================================================

/// Parse TLS record boundaries from raw captured bytes.
/// Returns (start_offset, total_length) for each complete record.
fn parse_tls_record_boundaries(data: &[u8]) -> Vec<(usize, usize)> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos + 5 <= data.len() {
        let content_type = data[pos];
        if content_type < 20 || content_type > 23 {
            break;
        }
        let length = ((data[pos + 3] as usize) << 8) | (data[pos + 4] as usize);
        let total = 5 + length;
        if pos + total > data.len() {
            break;
        }
        records.push((pos, total));
        pos += total;
    }
    records
}

/// Derive TLS 1.3 record key and IV from the server traffic secret.
fn derive_record_key_iv(server_traffic_secret: &[u8]) -> ([u8; 32], [u8; 12]) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, server_traffic_secret);

    // HKDF-Expand-Label(Secret, "key", "", 32) — AES-256-GCM = 32-byte keys
    let mut key_info = Vec::new();
    key_info.extend_from_slice(&(32u16).to_be_bytes());
    key_info.push(9); // "tls13 " (6) + "key" (3) = 9
    key_info.extend_from_slice(b"tls13 key");
    key_info.push(0);
    let mut key = [0u8; 32];
    hk.expand(&key_info, &mut key).expect("HKDF expand key");

    // HKDF-Expand-Label(Secret, "iv", "", 12)
    let mut iv_info = Vec::new();
    iv_info.extend_from_slice(&(12u16).to_be_bytes());
    iv_info.push(8); // "tls13 " (6) + "iv" (2) = 8
    iv_info.extend_from_slice(b"tls13 iv");
    iv_info.push(0);
    let mut iv = [0u8; 12];
    hk.expand(&iv_info, &mut iv).expect("HKDF expand iv");

    (key, iv)
}

// ============================================================================
// Public types
// ============================================================================

/// Captured TLS session keys derived from the handshake.
#[derive(Debug, Clone)]
pub struct TlsSessionKeys {
    pub record_key: [u8; 32],
    pub base_iv: [u8; 12],
    pub client_ephemeral_priv: [u8; 32],
}

/// A captured TLS record with its metadata.
#[derive(Debug, Clone)]
pub struct CapturedTlsRecord {
    pub raw_bytes: Vec<u8>,
    /// Sequence number (0-based, application data records only)
    pub sequence_no: u64,
}

/// Complete captured response from a TLS polling session.
#[derive(Debug, Clone)]
pub struct TlsCapturedResponse {
    pub session_keys: TlsSessionKeys,
    pub handshake_data: TlsHandshakeCapture,
    pub message_records: Vec<CapturedTlsRecord>,
    /// Decrypted HTTP response body (for local processing)
    pub response_body: Vec<u8>,
}

/// Captured TLS handshake messages for contract session verification.
#[derive(Debug, Clone)]
pub struct TlsHandshakeCapture {
    pub client_hello: Vec<u8>,
    pub server_hello: Vec<u8>,
    pub encrypted_handshake_records: Vec<u8>,
}

// ============================================================================
// TlsPollClient
// ============================================================================

/// Persistent TLS polling client for Signal's REST API.
pub struct TlsPollClient {
    signal_host: String,
    uuid: String,
    password: String,
    next_session_id: std::sync::atomic::AtomicU64,
}

impl TlsPollClient {
    pub fn new(signal_host: &str, uuid: &str, password: &str) -> Self {
        TlsPollClient {
            signal_host: signal_host.to_string(),
            uuid: uuid.to_string(),
            password: password.to_string(),
            next_session_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Poll Signal's GET /v1/messages endpoint with TLS record capture.
    /// Creates a fresh TLS connection each time for fresh handshake data.
    pub async fn poll_messages(&self) -> anyhow::Result<Option<TlsCapturedResponse>> {
        let _session_id = self.next_session_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Build capturing CryptoProvider
        let captured_priv: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));
        let provider = build_capturing_provider(captured_priv.clone());

        let key_capture = Arc::new(KeyCapture::new());

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Signal uses a self-signed CA, not a public CA. Add Signal's root cert.
        add_signal_root_ca(&mut root_store);

        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.key_log = key_capture.clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(self.signal_host.clone())?;

        // Connect TCP with bidirectional byte capturing
        let tcp = TcpStream::connect(format!("{}:443", self.signal_host)).await?;
        let (capturing_stream, captured_reads, captured_writes) = CapturingStream::new(tcp);

        // TLS handshake
        let mut tls = connector.connect(server_name, capturing_stream).await?;

        // Extract session keys
        let server_secret = key_capture
            .server_traffic_secret
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("SERVER_TRAFFIC_SECRET_0 not captured"))?;

        let (record_key, base_iv) = derive_record_key_iv(&server_secret);

        let client_ephemeral_priv = captured_priv
            .lock()
            .unwrap()
            .ok_or_else(|| anyhow::anyhow!("Ephemeral X25519 private key not captured"))?;

        // Parse handshake records:
        //   ClientHello = first type-22 record from WRITES
        //   ServerHello = first type-22 record from READS
        //   Encrypted HS = type-23 records from READS
        let writes = captured_writes.lock().unwrap().clone();
        let reads = captured_reads.lock().unwrap().clone();

        let write_records = parse_tls_record_boundaries(&writes);
        let read_records = parse_tls_record_boundaries(&reads);

        let mut client_hello = Vec::new();
        for &(offset, len) in &write_records {
            if writes[offset] == 22 && client_hello.is_empty() {
                client_hello = writes[offset + 5..offset + len].to_vec();
                break;
            }
        }

        let mut server_hello = Vec::new();
        let mut encrypted_hs = Vec::new();
        for &(offset, len) in &read_records {
            let record = &reads[offset..offset + len];
            match record[0] {
                22 if server_hello.is_empty() => {
                    server_hello = record[5..].to_vec();
                }
                23 => {
                    // Encrypted handshake records (TLS 1.3 wraps in application_data)
                    encrypted_hs.extend_from_slice(record);
                }
                20 => {} // ChangeCipherSpec compatibility record
                _ => {}
            }
        }

        if client_hello.is_empty() {
            return Err(anyhow::anyhow!("ClientHello not captured from writes"));
        }
        if server_hello.is_empty() {
            return Err(anyhow::anyhow!("ServerHello not captured from reads"));
        }

        // Record byte count before sending our HTTP request
        let pre_request_read_len = reads.len();

        // Send HTTP GET /v1/messages with protobuf Accept
        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", self.uuid, self.password),
        );
        let request = format!(
            "GET /v1/messages HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: Basic {auth}\r\n\
             X-Signal-Receive-Stories: false\r\n\
             Connection: close\r\n\
             \r\n",
            self.signal_host,
        );
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;

        // Read full response
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await?;

        // Extract response TLS records from captured reads (after handshake)
        let all_reads = captured_reads.lock().unwrap().clone();
        let response_raw = &all_reads[pre_request_read_len..];
        let response_records = parse_tls_record_boundaries(response_raw);

        if response_records.is_empty() {
            return Ok(None);
        }

        // Collect application data records — sequence counter starts at 0
        // (separate encryption context from handshake records)
        let mut message_records = Vec::new();
        let mut app_seq: u64 = 0;
        for &(rec_offset, rec_len) in &response_records {
            let record = &response_raw[rec_offset..rec_offset + rec_len];
            if record[0] == 0x17 {
                message_records.push(CapturedTlsRecord {
                    raw_bytes: record.to_vec(),
                    sequence_no: app_seq,
                });
                app_seq += 1;
            }
        }

        if message_records.is_empty() {
            return Ok(None);
        }

        Ok(Some(TlsCapturedResponse {
            session_keys: TlsSessionKeys {
                record_key,
                base_iv,
                client_ephemeral_priv,
            },
            handshake_data: TlsHandshakeCapture {
                client_hello,
                server_hello,
                encrypted_handshake_records: encrypted_hs,
            },
            message_records,
            response_body: response,
        }))
    }

    /// Acknowledge messages by sending DELETE requests.
    /// Uses a fresh (non-capturing) TLS connection.
    pub async fn acknowledge_messages(&self, guids: &[String]) -> anyhow::Result<()> {
        if guids.is_empty() {
            return Ok(());
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        add_signal_root_ca(&mut root_store);

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(self.signal_host.clone())?;
        let tcp = TcpStream::connect(format!("{}:443", self.signal_host)).await?;
        let mut tls = connector.connect(server_name, tcp).await?;

        let auth = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", self.uuid, self.password),
        );

        for guid in guids {
            let request = format!(
                "DELETE /v1/messages/uuid/{guid} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Authorization: Basic {auth}\r\n\
                 Content-Length: 0\r\n\
                 \r\n",
                self.signal_host,
            );
            tls.write_all(request.as_bytes()).await?;
            tls.flush().await?;

            // Read response (we don't need the body, just drain it)
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tls.read(&mut buf),
            )
            .await;
        }

        tracing::debug!("Acknowledged {} messages", guids.len());
        Ok(())
    }

    pub fn current_session_id(&self) -> u64 {
        self.next_session_id.load(std::sync::atomic::Ordering::SeqCst) - 1
    }

    pub fn signal_host(&self) -> &str {
        &self.signal_host
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Add Signal's self-signed root CA to the trust store.
/// Signal Messenger uses its own CA (not a public CA like Let's Encrypt).
/// Root cert: C=US, ST=California, L=Mountain View, O=Signal Messenger, LLC, CN=Signal Messenger
/// Valid: 2022-01-26 to 2032-01-24 (RSA 4096-bit, self-signed)
fn add_signal_root_ca(root_store: &mut rustls::RootCertStore) {
    let der = include_bytes!("signal_root_ca.der");
    root_store
        .add(rustls::pki_types::CertificateDer::from(&der[..]))
        .expect("Signal root CA is valid");
}
