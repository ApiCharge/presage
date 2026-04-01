//! HTTP API types for the signal daemon.
//!
//! The .NET SignalRelayService polls this API to receive messages.
//! Each message includes both the sealed sender material (for the contract)
//! and the decrypted text (for relay responses).

use serde::{Deserialize, Serialize};

/// A received message with sealed sender material.
/// The .NET relay uses the envelope fields to call execute_signal_instruction,
/// and the decrypted_body for user-facing responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Sender's Signal UUID
    pub sender_uuid: String,
    /// Sender's phone number (if known)
    pub sender_phone: Option<String>,
    /// Sender's Curve25519 identity public key (hex, 32 bytes, no 0x05 prefix)
    pub sender_identity_key: Option<String>,
    /// Unix timestamp (milliseconds)
    pub timestamp: u64,

    /// Legacy sealed sender material for the old contract flow
    pub sealed_envelope: SealedEnvelopeDto,

    /// TLS-verified envelope material for the new contract flow
    pub verified_envelope: Option<VerifiedEnvelopeDto>,

    /// TEE attestation signature (hex-encoded Ed25519 signature)
    pub tee_signature: Option<String>,

    /// Decrypted message body (for relay to display/respond)
    pub decrypted_body: Option<String>,
}

/// The fields needed by the Soroban contract's SealedEnvelope.
/// All byte arrays are hex-encoded for JSON transport.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SealedEnvelopeDto {
    pub s_cipher_key: String,  // hex, 32 bytes
    pub s_mac_key: String,     // hex, 32 bytes
    pub s_ciphertext: String,  // hex, variable
    pub s_mac: String,         // hex, 32 bytes
    pub message_key: String,   // hex, 32 bytes (Double Ratchet seed)
    pub pqr_salt: String,      // hex, 32 bytes (PQR HKDF salt, or empty if inactive)
}

/// TLS-verified envelope fields for the new contract flow.
/// The contract independently verifies the TLS record, then uses
/// the ECDH shared secrets (pinned by TLS-anchored MACs) to decrypt.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VerifiedEnvelopeDto {
    pub session_id: u64,
    pub tls_record: String,       // hex, raw TLS record
    pub tls_sequence_no: u64,
    pub e_shared: String,         // hex, 32 bytes
    pub s_shared: String,         // hex, 32 bytes
    pub message_key: String,      // hex, 32 bytes
    pub pqr_salt: String,         // hex, 32 bytes
}

/// Response to GET /receive
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiveResponse {
    pub messages: Vec<ReceivedMessage>,
}

/// Response to GET /status
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub connected: bool,
    pub phone_number: String,
    pub uuid: String,
    pub messages_received: u64,
}

/// Request for POST /send
#[derive(Debug, Serialize, Deserialize)]
pub struct SendRequest {
    pub recipient: String, // phone number or UUID
    pub message: String,
}

/// Response for POST /send
#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Request for POST /send-group
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupSendRequest {
    pub group_id: String, // hex-encoded group master key
    pub message: String,
}

/// Request for POST /create-group
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub members: Vec<String>, // UUIDs
}

/// Response for POST /create-group
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupResponse {
    pub success: bool,
    pub group_id: Option<String>,
    pub error: Option<String>,
}

/// Response for GET /tee-pubkey
#[derive(Debug, Serialize, Deserialize)]
pub struct TeePubkeyResponse {
    pub pubkey_hex: String,
}

/// A detected SenderKeyDistributionMessage event.
/// The daemon surfaces these so the relay can trigger TEE attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkdmEvent {
    /// Hex-encoded raw sealed sender envelope bytes
    pub raw_envelope: String,
    /// Sender's service ID (if known)
    pub sender: String,
    /// Detection timestamp (millis since epoch)
    pub timestamp: u64,
    /// TEE attestation signature (hex-encoded Ed25519 signature)
    pub tee_signature: Option<String>,
    /// Signal protocol pre-computed ECDH values (hex, 32 bytes each).
    /// Needed by the RISC Zero prover to verify the sealed sender envelope.
    pub e_shared: String,
    pub s_shared: String,
    pub message_key: String,
    pub pqr_salt: String,
}
