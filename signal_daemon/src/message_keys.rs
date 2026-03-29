//! Double Ratchet message_key derivation.
//!
//! After the s-layer is decrypted, the plaintext contains a WhisperMessage.
//! The WhisperMessage's ciphertext is encrypted with a key derived from the
//! Double Ratchet chain. The relay needs to provide this message_key to the
//! contract so it can independently decrypt the inner message.
//!
//! Signal's Double Ratchet key derivation:
//!   chain_key[n+1] = HMAC-SHA256(chain_key[n], 0x02)
//!   message_key[n] = HMAC-SHA256(chain_key[n], 0x01)
//!
//! The relay advances the chain to the message's counter and extracts the key.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MESSAGE_KEY_SEED: u8 = 0x01;
const CHAIN_KEY_SEED: u8 = 0x02;

/// Derive the message_key for a specific counter from a chain_key.
///
/// `chain_key` — the current receiving chain key from the session store
/// `current_counter` — the counter stored in the session (next expected)
/// `message_counter` — the counter in the incoming WhisperMessage
///
/// Returns the 32-byte message_key for this specific message.
pub fn derive_message_key(
    chain_key: &[u8; 32],
    current_counter: u32,
    message_counter: u32,
) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        message_counter >= current_counter,
        "message counter {} < current {}: possible replay or out-of-order",
        message_counter,
        current_counter
    );

    // Advance chain to the target counter
    let mut ck = *chain_key;
    for _ in current_counter..message_counter {
        // Skip message keys for counters we're jumping over
        // (In a full implementation, these would be cached for out-of-order messages)
        ck = hmac_derive(&ck, CHAIN_KEY_SEED)?;
    }

    // Derive the message key at the target counter
    let mk = hmac_derive(&ck, MESSAGE_KEY_SEED)?;
    Ok(mk)
}

/// HMAC-SHA256(key, single_byte_input)
fn hmac_derive(key: &[u8; 32], seed: u8) -> anyhow::Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(&[seed]);
    let result = mac.finalize().into_bytes();
    Ok(result.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_message_key_same_counter() {
        let chain_key = [0x42u8; 32];
        let mk = derive_message_key(&chain_key, 0, 0).unwrap();
        // message_key = HMAC-SHA256(chain_key, 0x01)
        assert_eq!(mk.len(), 32);
        // Should be deterministic
        let mk2 = derive_message_key(&chain_key, 0, 0).unwrap();
        assert_eq!(mk, mk2);
    }

    #[test]
    fn test_derive_message_key_advanced() {
        let chain_key = [0x42u8; 32];
        // Counter 0 and counter 1 should produce different keys
        let mk0 = derive_message_key(&chain_key, 0, 0).unwrap();
        let mk1 = derive_message_key(&chain_key, 0, 1).unwrap();
        assert_ne!(mk0, mk1);
    }

    #[test]
    fn test_chain_advancement() {
        let chain_key = [0x42u8; 32];
        // derive_message_key(ck, 0, 5) should match
        // manually advancing chain 5 times then deriving
        let mut ck = chain_key;
        for _ in 0..5 {
            ck = hmac_derive(&ck, CHAIN_KEY_SEED).unwrap();
        }
        let expected = hmac_derive(&ck, MESSAGE_KEY_SEED).unwrap();
        let actual = derive_message_key(&chain_key, 0, 5).unwrap();
        assert_eq!(actual, expected);
    }
}
