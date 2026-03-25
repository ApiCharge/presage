//! Configuration and signal-cli data import.
//!
//! Reads the existing signal-cli registration data (identity keys, password,
//! registration ID, UUID) so we can connect to Signal without re-registering.

use base64::Engine;
use serde::Deserialize;
use std::path::Path;

/// Signal-cli account config (from the numbered file, e.g., "687634")
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalCliAccount {
    pub number: String,
    pub password: String,
    pub device_id: u32,
    pub aci_account_data: AccountData,
    #[serde(default)]
    pub pni_account_data: Option<AccountData>,
    pub profile_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountData {
    pub service_id: String,
    pub registration_id: u32,
    pub identity_private_key: String, // base64
    pub identity_public_key: String,  // base64
}

/// Signal-cli accounts.json
#[derive(Debug, Deserialize)]
pub struct AccountsJson {
    pub accounts: Vec<AccountEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AccountEntry {
    pub path: String,
    pub number: String,
    pub uuid: String,
}

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Phone number (E.164)
    pub phone_number: String,
    /// Signal UUID (ACI)
    pub uuid: String,
    /// Relay identity private key (32 bytes, Curve25519)
    pub identity_private_key: [u8; 32],
    /// Relay identity public key (32 bytes, Curve25519, no 0x05 prefix)
    pub identity_public_key: [u8; 32],
    /// Password for Signal server auth
    pub password: String,
    /// Registration ID
    pub registration_id: u32,
    /// Device ID
    pub device_id: u32,
    /// PNI identity keys (optional)
    pub pni_identity_private_key: Option<[u8; 32]>,
    pub pni_identity_public_key: Option<[u8; 32]>,
    pub pni_uuid: Option<String>,
    pub pni_registration_id: Option<u32>,
    /// Profile key (base64)
    pub profile_key: Option<String>,
    /// HTTP listen address
    pub listen_addr: String,
    /// signal-cli data directory (for session SQLite database)
    pub data_dir: String,
}

impl DaemonConfig {
    /// Load from signal-cli data directory.
    pub fn from_signal_cli_data(data_dir: &str, listen_addr: &str) -> anyhow::Result<Self> {
        let base = Path::new(data_dir).join("data");

        // Read accounts.json
        let accounts_json: AccountsJson =
            serde_json::from_str(&std::fs::read_to_string(base.join("accounts.json"))?)?;

        let entry = accounts_json
            .accounts
            .first()
            .ok_or_else(|| anyhow::anyhow!("no accounts in accounts.json"))?;

        // Read account config
        let account: SignalCliAccount =
            serde_json::from_str(&std::fs::read_to_string(base.join(&entry.path))?)?;

        let b64 = base64::engine::general_purpose::STANDARD;

        // Parse identity keys
        let priv_bytes = b64.decode(&account.aci_account_data.identity_private_key)?;
        let pub_bytes = b64.decode(&account.aci_account_data.identity_public_key)?;

        // Private key: first byte may be 0x00 type prefix, key is 32 bytes
        let priv_start = if priv_bytes.len() == 33 { 1 } else { 0 };
        let identity_private_key: [u8; 32] = priv_bytes
            [priv_start..priv_start + 32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad private key length: {}", priv_bytes.len()))?;

        // Public key: first byte is 0x05 Curve25519 prefix
        let pub_start = if pub_bytes.len() == 33 && pub_bytes[0] == 0x05 {
            1
        } else {
            0
        };
        let identity_public_key: [u8; 32] = pub_bytes[pub_start..pub_start + 32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad public key length: {}", pub_bytes.len()))?;

        // Parse PNI keys if available
        let (pni_priv, pni_pub, pni_uuid, pni_reg_id) = if let Some(ref pni) = account.pni_account_data {
            let pp = b64.decode(&pni.identity_private_key)?;
            let pb = b64.decode(&pni.identity_public_key)?;
            let pp_start = if pp.len() == 33 { 1 } else { 0 };
            let pb_start = if pb.len() == 33 && pb[0] == 0x05 { 1 } else { 0 };
            (
                Some(pp[pp_start..pp_start+32].try_into().map_err(|_| anyhow::anyhow!("bad PNI priv key"))?),
                Some(pb[pb_start..pb_start+32].try_into().map_err(|_| anyhow::anyhow!("bad PNI pub key"))?),
                pni.service_id.strip_prefix("PNI:").map(|s| s.to_string()),
                Some(pni.registration_id),
            )
        } else {
            (None, None, None, None)
        };

        Ok(DaemonConfig {
            phone_number: account.number,
            uuid: entry.uuid.clone(),
            identity_private_key,
            identity_public_key,
            password: account.password,
            registration_id: account.aci_account_data.registration_id,
            device_id: account.device_id,
            pni_identity_private_key: pni_priv,
            pni_identity_public_key: pni_pub,
            pni_uuid,
            pni_registration_id: pni_reg_id,
            profile_key: account.profile_key.clone(),
            listen_addr: listen_addr.to_string(),
            data_dir: data_dir.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accounts_json() {
        let json = r#"{
            "accounts": [{
                "path": "687634",
                "environment": "LIVE",
                "number": "+420702843097",
                "uuid": "4d25eecc-9544-4e32-8535-29af1f088c1c"
            }],
            "version": 2
        }"#;
        let parsed: AccountsJson = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.accounts.len(), 1);
        assert_eq!(parsed.accounts[0].number, "+420702843097");
    }

    #[test]
    fn test_parse_account_config() {
        let json = r#"{
            "version": 10,
            "serviceEnvironment": "LIVE",
            "registered": true,
            "number": "+420702843097",
            "username": null,
            "encryptedDeviceName": null,
            "deviceId": 1,
            "isMultiDevice": false,
            "password": "testpass",
            "aciAccountData": {
                "serviceId": "4d25eecc-9544-4e32-8535-29af1f088c1c",
                "registrationId": 15506,
                "identityPrivateKey": "ANzBjv53TgzF16exFik/NbzmWfMjEzid4d+p2unSwnQ=",
                "identityPublicKey": "BahRGNfikluUqr5O4sYOVxnwfTzbCWVHG9zib0NBZypz",
                "nextPreKeyId": 1,
                "nextSignedPreKeyId": 1,
                "activeSignedPreKeyId": 1,
                "nextKyberPreKeyId": 1,
                "activeLastResortKyberPreKeyId": 1
            },
            "pniAccountData": null,
            "registrationLockPin": null,
            "pinMasterKey": null,
            "storageKey": null,
            "accountEntropyPool": null,
            "mediaRootBackupKey": null,
            "profileKey": null,
            "usernameLinkEntropy": null,
            "usernameLinkServerId": null
        }"#;
        let parsed: SignalCliAccount = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.number, "+420702843097");
        assert_eq!(parsed.aci_account_data.registration_id, 15506);
    }
}
