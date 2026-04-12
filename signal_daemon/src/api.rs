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

    /// Group ID (hex-encoded master key) if this is a group message
    pub group_id: Option<String>,

    /// True if this is a SenderKeyDistributionMessage event (not a regular message)
    #[serde(default)]
    pub is_skdm: bool,

    /// SKDM signing key (hex, 32 bytes Curve25519) — present only for SKDM events
    pub skdm_signing_key: Option<String>,

    /// True if this message represents a group member accepting an invite
    #[serde(default)]
    pub is_member_joined: bool,

    /// UUID of the member who joined (if is_member_joined is true)
    #[serde(default)]
    pub joined_member_uuid: Option<String>,

    /// Raw SenderKeyMessage wire bytes (hex). For group messages only.
    /// Contains version + protobuf(chain_id, iteration, ciphertext) + 64-byte signature.
    /// Used by the contract for on-chain signature verification + decryption.
    pub sender_key_msg: Option<String>,

    /// SenderMessageKey seed (hex, 32 bytes). For group messages only.
    /// Input to HKDF("WhisperGroup") → iv(16) + cipher_key(32) for on-chain decryption.
    pub sender_key_seed: Option<String>,

    /// Signing key (hex, 32 bytes, Curve25519 no prefix) used to verify the SenderKeyMessage.
    /// May differ from the SKDM signing key if the sender rotated after a membership change.
    /// The relay compares this to the on-chain key and re-registers if different.
    pub sender_key_signing_key: Option<String>,
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

/// Request for POST /typing
#[derive(Debug, Serialize, Deserialize)]
pub struct TypingRequest {
    pub recipient: Option<String>,  // UUID for DM typing
    pub group_id: Option<String>,   // hex group ID for group typing
    pub started: bool,
}

/// Response for GET /tee-pubkey
#[derive(Debug, Serialize, Deserialize)]
pub struct TeePubkeyResponse {
    pub pubkey_hex: String,
}

/// Group info with members for /list-groups
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: String,
    pub members: Vec<String>,
}

/// Response for GET /list-groups
#[derive(Debug, Serialize, Deserialize)]
pub struct ListGroupsResponse {
    pub groups: Vec<GroupInfo>,
}

/// Request for POST /tee-sign
#[derive(Debug, Serialize, Deserialize)]
pub struct TeeSignRequest {
    pub payload_hex: String,
}

/// Response for POST /tee-sign
#[derive(Debug, Serialize, Deserialize)]
pub struct TeeSignResponse {
    pub signature_hex: String,
}

// ── Registration Mode API ────────────────────────────────────────

/// Response for GET /status (extended with mode + username)
#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendedStatusResponse {
    pub connected: bool,
    pub mode: String,           // "registration" or "normal"
    pub phone_number: String,
    pub uuid: String,
    pub username: Option<String>,
    pub messages_received: u64,
}

/// Request for POST /register-signal (step 1: initiate registration)
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterSignalRequest {
    pub phone_number: String,   // E.164 format, e.g. "+420702843097"
    pub captcha: String,        // signalcaptcha:// token from https://signalcaptchas.org/registration/generate.html
}

/// Response for POST /register-signal
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterSignalResponse {
    pub success: bool,
    pub message: String,
    pub error: Option<String>,
}

/// Request for POST /register-signal/verify (step 2: submit SMS code)
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyCodeRequest {
    pub code: String,           // 6-digit SMS verification code
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
