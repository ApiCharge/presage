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

    /// Sealed sender material for the Soroban contract
    pub sealed_envelope: SealedEnvelopeDto,

    /// Decrypted message body (for relay to display/respond)
    pub decrypted_body: Option<String>,
}

/// The five fields needed by the Soroban contract's SealedEnvelope.
/// All byte arrays are hex-encoded for JSON transport.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SealedEnvelopeDto {
    pub s_cipher_key: String,  // hex, 32 bytes
    pub s_mac_key: String,     // hex, 32 bytes
    pub s_ciphertext: String,  // hex, variable
    pub s_mac: String,         // hex, 32 bytes
    pub message_key: String,   // hex, 32 bytes
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
