#![warn(clippy::large_futures)]

use std::cell::RefCell;

mod errors;
pub mod manager;
pub mod model;
mod serde;
pub mod store;

pub use libsignal_service;

/// Thread-local capture of the last loaded session record (serialized bytes).
/// Written by the session store's load_session, read after open_envelope
/// to derive the Double Ratchet message_key before the ratchet advances.
thread_local! {
    pub static LAST_LOADED_SESSION: RefCell<Option<Vec<u8>>> = RefCell::new(None);
}
/// Protobufs used in Signal protocol and service communication
pub use libsignal_service::proto;

pub use errors::Error;
pub use manager::Manager;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

pub type AvatarBytes = Vec<u8>;
