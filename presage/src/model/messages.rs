use libsignal_service::prelude::Content;

/// Result of decrypting a single envelope via decrypt_envelope().
#[derive(Debug)]
pub enum DecryptResult {
    /// Normal message with content.
    Content(Content, Option<Vec<u8>>, Option<Vec<u8>>),
    /// SenderKeyDistributionMessage — processed internally by libsignal, content filtered.
    Skdm,
    /// Genuinely empty envelope.
    Empty,
}

#[derive(Debug)]
pub enum Received {
    /// when the receive loop is empty, happens when opening the websocket for the first time
    /// once you're done synchronizing all pending messages for this registered client.
    QueueEmpty,

    /// Got contacts (only applies if linked to a primary device
    /// Contacts can be later queried in the store.
    Contacts,

    /// Incoming decrypted message with metadata, content, and raw envelope bytes.
    /// `raw_content` contains the original encrypted envelope content before
    /// decryption — the sealed sender wire format for on-chain verification.
    Content {
        content: Box<Content>,
        raw_content: Option<Vec<u8>>,
        /// Raw Double Ratchet message key seed (32 bytes) captured during open_envelope.
        message_key: Option<Vec<u8>>,
        /// PQR (post-quantum ratchet) salt for HKDF expansion of message_key.
        /// None if PQR is not active (use zero salt).
        pqr_salt: Option<Vec<u8>>,
    },

    /// A SenderKeyDistributionMessage was received and processed.
    /// libsignal processes SKDMs internally (stores the sender key) and returns Ok(None).
    /// We surface them here so the daemon can detect key distribution events for zkFetch.
    SenderKeyDistribution {
        /// Raw sealed sender envelope bytes (for zkFetch attestation)
        raw_content: Option<Vec<u8>>,
        /// Sender's service ID (extracted from sealed sender metadata)
        sender: String,
    },
}
