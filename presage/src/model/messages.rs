use libsignal_service::prelude::Content;

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
    },
}
