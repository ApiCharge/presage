//! Sealed sender wire format parser + e-layer ECDH extraction.
//!
//! Signal sealed sender v1 wire format:
//!   version_byte(1) || protobuf(UnidentifiedSenderMessage)
//!
//! The UnidentifiedSenderMessage protobuf contains:
//!   field 1 (bytes): ephemeral_public — ephemeral Curve25519 key (33 bytes with 0x05 prefix)
//!   field 2 (bytes): encrypted_static — AES-CTR ciphertext + HMAC-SHA256 truncated to 10 bytes
//!   field 3 (bytes): encrypted_message — s-layer ciphertext (sender cert + whisper message)
//!
//! E-layer key derivation (receiving direction):
//!   salt = "UnidentifiedDelivery" || our_pub_serialized(33) || their_pub_serialized(33)
//!   HKDF-SHA256(salt, ECDH(our_priv, e_pub)) → chain_key(32) || cipher_key(32) || mac_key(32)
//!
//! encrypted_static = AES-256-CTR(cipher_key, sender_identity_pub) || HMAC-SHA256(mac_key, ctext)[0:10]
//!
//! S-layer key derivation:
//!   salt = chain_key || encrypted_static (full field including MAC)
//!   HKDF-SHA256(salt, ECDH(our_identity_priv, sender_identity_pub)) → _discard(32) || s_cipher_key(32) || s_mac_key(32)
//!
//! Reference: libsignal/rust/protocol/src/sealed_sender.rs

use aes::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

/// Curve25519 ECDH using presage's re-exported libsignal types.
fn curve25519_ecdh(private_key: &[u8; 32], public_key_raw: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    use presage::libsignal_service::protocol::{PrivateKey, PublicKey};
    let private = PrivateKey::deserialize(private_key)?;
    let mut pub_with_prefix = [0u8; 33];
    pub_with_prefix[0] = 0x05;
    pub_with_prefix[1..].copy_from_slice(public_key_raw);
    let public = PublicKey::deserialize(&pub_with_prefix)?;
    let shared = private.calculate_agreement(&public)?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&shared);
    Ok(result)
}

/// Serialize a 32-byte Curve25519 public key with 0x05 prefix (33 bytes).
fn serialize_pub(key: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x05;
    out[1..].copy_from_slice(key);
    out
}

/// The s-layer material extracted from a sealed sender envelope.
/// These fields are submitted directly to the Soroban contract.
#[derive(Debug, Clone)]
pub struct SealedEnvelopeFields {
    pub s_cipher_key: [u8; 32],
    pub s_mac_key: [u8; 32],
    pub s_ciphertext: Vec<u8>,
    pub s_mac: [u8; 32],
}

/// Raw ECDH shared secrets for TLS-verified flow.
/// The contract verifies these via TLS-anchored MAC comparison.
#[derive(Debug, Clone)]
pub struct EcdhSharedSecrets {
    pub e_shared: [u8; 32],
    pub s_shared: [u8; 32],
}

/// Full extraction result.
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub envelope: SealedEnvelopeFields,
    pub ecdh: EcdhSharedSecrets,
    pub s_plaintext: Vec<u8>,
    pub sender_identity_public: [u8; 32],
}

/// Parse sealed sender v1 envelope and perform e-layer ECDH extraction.
///
/// `raw` — the sealed sender envelope bytes (from Envelope.content)
/// `relay_identity_private` — relay's Curve25519 identity private key (32 bytes)
/// `relay_identity_public` — relay's Curve25519 identity public key (32 bytes, no prefix)
pub fn extract_sealed_sender(
    raw: &[u8],
    relay_identity_private: &[u8; 32],
    relay_identity_public: &[u8; 32],
) -> anyhow::Result<ExtractionResult> {
    // ---- Parse version byte ----
    anyhow::ensure!(raw.len() > 1, "envelope too short");
    let version_byte = raw[0];
    let version = version_byte >> 4;
    anyhow::ensure!(
        version >= 1,
        "unsupported sealed sender version: {version} (byte: {version_byte:#04x})"
    );

    let data = &raw[1..];
    let parsed = parse_unidentified_sender_message(data)?;

    // ---- E-layer ECDH ----
    let e_shared = curve25519_ecdh(relay_identity_private, &parsed.ephemeral_public)?;

    // Salt: "UnidentifiedDelivery" || our_pub_serialized || their_pub_serialized
    // Direction: Receiving → our = relay, their = ephemeral
    let our_pub_ser = serialize_pub(relay_identity_public);
    let their_pub_ser = serialize_pub(&parsed.ephemeral_public);
    let mut e_salt = Vec::with_capacity(20 + 33 + 33);
    e_salt.extend_from_slice(b"UnidentifiedDelivery");
    e_salt.extend_from_slice(&our_pub_ser);
    e_salt.extend_from_slice(&their_pub_ser);

    let hk = Hkdf::<Sha256>::new(Some(&e_salt), &e_shared);
    let mut e_keys = [0u8; 96]; // chain(32) + cipher(32) + mac(32)
    hk.expand(b"", &mut e_keys)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;

    let e_chain_key: [u8; 32] = e_keys[0..32].try_into().unwrap();
    let e_cipher_key: [u8; 32] = e_keys[32..64].try_into().unwrap();
    let e_mac_key: [u8; 32] = e_keys[64..96].try_into().unwrap();

    // ---- Verify + decrypt encrypted_static ----
    // Format: AES-CTR ciphertext || HMAC-SHA256(mac_key, ctext)[0:10]
    let enc_static = &parsed.encrypted_static;
    anyhow::ensure!(enc_static.len() > 10, "encrypted_static too short");

    let (e_ciphertext, their_mac) = enc_static.split_at(enc_static.len() - 10);

    let mut e_hmac = HmacSha256::new_from_slice(&e_mac_key)?;
    e_hmac.update(e_ciphertext);
    let our_mac = e_hmac.finalize().into_bytes();
    anyhow::ensure!(
        constant_time_eq(&our_mac[..10], their_mac),
        "e-layer MAC verification failed"
    );

    // AES-256-CTR decrypt → sender's identity public key
    let mut e_plaintext = e_ciphertext.to_vec();
    let zero_nonce = [0u8; 16];
    let mut cipher = Aes256Ctr::new(&e_cipher_key.into(), &zero_nonce.into());
    cipher.apply_keystream(&mut e_plaintext);

    // Extract sender identity (strip 0x05 prefix if present)
    let sender_identity_start = if !e_plaintext.is_empty() && e_plaintext[0] == 0x05 { 1 } else { 0 };
    anyhow::ensure!(
        e_plaintext.len() >= sender_identity_start + 32,
        "e_plaintext too short for sender identity"
    );
    let sender_identity_public: [u8; 32] = e_plaintext
        [sender_identity_start..sender_identity_start + 32]
        .try_into()?;

    // ---- S-layer key derivation ----
    // salt = chain_key || encrypted_static (full field, including MAC bytes)
    // shared_secret = ECDH(relay_identity_private, sender_identity_public)
    let s_shared = curve25519_ecdh(relay_identity_private, &sender_identity_public)?;

    let mut s_salt = Vec::new();
    s_salt.extend_from_slice(&e_chain_key);
    s_salt.extend_from_slice(enc_static); // full encrypted_static including MAC

    let hk = Hkdf::<Sha256>::new(Some(&s_salt), &s_shared);
    let mut s_keys = [0u8; 96]; // _discard(32) + cipher(32) + mac(32)
    hk.expand(b"", &mut s_keys)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;

    // First 32 bytes are discarded (mirrors EphemeralKeys derivation structure)
    let s_cipher_key: [u8; 32] = s_keys[32..64].try_into().unwrap();
    let s_mac_key: [u8; 32] = s_keys[64..96].try_into().unwrap();

    // ---- Extract s_ciphertext and s_mac ----
    // encrypted_message = s_ciphertext || s_mac(10 bytes, truncated HMAC)
    let enc_msg = &parsed.encrypted_message;
    anyhow::ensure!(enc_msg.len() > 10, "encrypted_message too short");

    let (s_ciphertext_bytes, s_mac_bytes) = enc_msg.split_at(enc_msg.len() - 10);

    // Verify s-layer MAC
    let mut s_hmac = HmacSha256::new_from_slice(&s_mac_key)?;
    s_hmac.update(s_ciphertext_bytes);
    let s_our_mac = s_hmac.finalize().into_bytes();
    anyhow::ensure!(
        constant_time_eq(&s_our_mac[..10], s_mac_bytes),
        "s-layer MAC verification failed"
    );

    // AES-CTR decrypt s_ciphertext
    let mut s_plaintext = s_ciphertext_bytes.to_vec();
    let mut cipher = Aes256Ctr::new(&s_cipher_key.into(), &zero_nonce.into());
    cipher.apply_keystream(&mut s_plaintext);

    // For the contract, we need the full 32-byte MAC keys and full s_mac.
    // The contract does its own verification with 32-byte MACs.
    // Recompute the full 32-byte s_mac for the contract.
    let mut s_hmac_full = HmacSha256::new_from_slice(&s_mac_key)?;
    s_hmac_full.update(s_ciphertext_bytes);
    let s_mac_full: [u8; 32] = s_hmac_full.finalize().into_bytes().into();

    Ok(ExtractionResult {
        envelope: SealedEnvelopeFields {
            s_cipher_key,
            s_mac_key,
            s_ciphertext: s_ciphertext_bytes.to_vec(),
            s_mac: s_mac_full,
        },
        ecdh: EcdhSharedSecrets { e_shared, s_shared },
        s_plaintext,
        sender_identity_public,
    })
}

/// Constant-time comparison of byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- Protobuf parsing for UnidentifiedSenderMessage ----

struct ParsedUsmEnvelope {
    ephemeral_public: [u8; 32],
    encrypted_static: Vec<u8>,
    encrypted_message: Vec<u8>,
}

fn parse_unidentified_sender_message(data: &[u8]) -> anyhow::Result<ParsedUsmEnvelope> {
    let mut pos = 0;
    let mut ephemeral: Option<Vec<u8>> = None;
    let mut enc_static: Option<Vec<u8>> = None;
    let mut enc_message: Option<Vec<u8>> = None;

    while pos < data.len() {
        let (field, wire_type) = read_tag(data, &mut pos)?;
        match (field, wire_type) {
            (1, 2) => ephemeral = Some(read_bytes(data, &mut pos)?),
            (2, 2) => enc_static = Some(read_bytes(data, &mut pos)?),
            (3, 2) => enc_message = Some(read_bytes(data, &mut pos)?),
            (_, wt) => skip_field(data, &mut pos, wt)?,
        }
    }

    let eph = ephemeral.ok_or_else(|| anyhow::anyhow!("missing ephemeral_public"))?;
    // Strip 0x05 prefix if present (33 → 32 bytes)
    let start = if eph.len() == 33 && eph[0] == 0x05 { 1 } else { 0 };
    anyhow::ensure!(
        eph.len() - start == 32,
        "bad ephemeral key length: {}",
        eph.len()
    );
    let ephemeral_public: [u8; 32] = eph[start..start + 32].try_into()?;

    Ok(ParsedUsmEnvelope {
        ephemeral_public,
        encrypted_static: enc_static
            .ok_or_else(|| anyhow::anyhow!("missing encrypted_static"))?,
        encrypted_message: enc_message
            .ok_or_else(|| anyhow::anyhow!("missing encrypted_message"))?,
    })
}

// ---- Minimal protobuf wire format helpers ----

fn read_varint(data: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        anyhow::ensure!(*pos < data.len(), "varint: unexpected end");
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        anyhow::ensure!(shift < 64, "varint overflow");
    }
}

fn read_tag(data: &[u8], pos: &mut usize) -> anyhow::Result<(u32, u32)> {
    let v = read_varint(data, pos)?;
    Ok(((v >> 3) as u32, (v & 0x07) as u32))
}

fn read_bytes(data: &[u8], pos: &mut usize) -> anyhow::Result<Vec<u8>> {
    let len = read_varint(data, pos)? as usize;
    anyhow::ensure!(*pos + len <= data.len(), "bytes field overflows buffer");
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(result)
}

fn skip_field(data: &[u8], pos: &mut usize, wire_type: u32) -> anyhow::Result<()> {
    match wire_type {
        0 => {
            read_varint(data, pos)?;
        }
        1 => *pos += 8,
        2 => {
            let len = read_varint(data, pos)? as usize;
            *pos += len;
        }
        5 => *pos += 4,
        wt => anyhow::bail!("unknown wire type: {wt}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint() {
        let data = [0xac, 0x02];
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos).unwrap(), 300);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_read_tag() {
        let data = [0x12];
        let mut pos = 0;
        let (field, wt) = read_tag(&data, &mut pos).unwrap();
        assert_eq!(field, 2);
        assert_eq!(wt, 2);
    }

    #[test]
    fn test_parse_unidentified_sender_message() {
        let mut data = Vec::new();
        // field 1 (LEN): 33 bytes ephemeral key (with 0x05 prefix)
        data.push(0x0a);
        data.push(33);
        data.push(0x05);
        data.extend_from_slice(&[0xAA; 32]);
        // field 2 (LEN): 48 bytes encrypted static
        data.push(0x12);
        data.push(48);
        data.extend_from_slice(&[0xBB; 48]);
        // field 3 (LEN): 64 bytes encrypted message
        data.push(0x1a);
        data.push(64);
        data.extend_from_slice(&[0xCC; 64]);

        let parsed = parse_unidentified_sender_message(&data).unwrap();
        assert_eq!(parsed.ephemeral_public, [0xAA; 32]);
        assert_eq!(parsed.encrypted_static.len(), 48);
        assert_eq!(parsed.encrypted_message.len(), 64);
    }
}
