//! JSON parser for Signal's GET /v1/messages/ response.
//! Used by the peek step to inspect the queue without decrypting.

/// Envelope metadata from the peek response (not decrypted).
pub struct PeekedEnvelope {
    pub msg_type: u32,
    pub guid: String,
    pub timestamp: u64,
    pub server_timestamp: u64,
    /// Base64-encoded content (sealed sender bytes). Not decoded here.
    pub content_b64: String,
}

/// Parse envelope metadata from Signal's JSON response.
/// Does NOT decode content — just extracts metadata for classification.
pub fn parse_envelopes_from_json(body: &[u8]) -> Vec<PeekedEnvelope> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let value: serde_json::Value = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let messages = match value.get("messages").and_then(|m| m.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    let mut envelopes = Vec::new();
    for msg in messages {
        let msg_type = msg.get("type").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
        let guid = msg.get("guid").and_then(|g| g.as_str()).unwrap_or("").to_string();
        let timestamp = msg.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0);
        let server_timestamp = msg.get("serverTimestamp").and_then(|t| t.as_u64()).unwrap_or(0);
        let content_b64 = msg.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();

        envelopes.push(PeekedEnvelope {
            msg_type,
            guid,
            timestamp,
            server_timestamp,
            content_b64,
        });
    }

    envelopes
}
