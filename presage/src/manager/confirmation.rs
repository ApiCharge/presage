use std::sync::Arc;

use libsignal_service::configuration::SignalServers;
use libsignal_service::messagepipe::ServiceCredentials;
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::prelude::PushService;
use libsignal_service::protocol::{IdentityKeyPair, IdentityKeyStore};
use libsignal_service::provisioning::generate_registration_id;
use libsignal_service::push_service::ServiceIds;
use libsignal_service::utils::TryIntoE164;
use libsignal_service::websocket::account::{AccountAttributes, DeviceCapabilities};
use libsignal_service::websocket::registration::{
    DeviceActivationRequest, RegistrationMethod, VerifyAccountResponse,
};
use libsignal_service::zkgroup::profiles::ProfileKey;
use rand::{CryptoRng, RngCore};
use tracing::trace;

use crate::manager::registered::RegistrationData;
use crate::store::Store;
use crate::{Error, Manager};

use super::Registered;

/// Manager state after a successful registration of new main device
///
/// In this state, the user has to confirm the new registration via a validation code.
#[derive(Clone)]
pub struct Confirmation {
    pub(crate) signal_servers: SignalServers,
    pub(crate) phone_number: PhoneNumber,
    pub(crate) password: String,
    pub(crate) session_id: String,
}

impl<S: Store> Manager<S, Confirmation> {
    /// Confirm a newly registered account using the code you
    /// received by SMS or phone call.
    ///
    /// Returns a [registered manager](Manager::load_registered) that you can use
    /// to send and receive messages.
    pub async fn confirm_verification_code(
        self,
        confirmation_code: impl AsRef<str>,
    ) -> Result<Manager<S, Registered>, Error<S::Error>> {
        trace!("confirming verification code");

        let mut rng = rand::rng();

        let registration_id = generate_registration_id(&mut rng);
        let pni_registration_id = generate_registration_id(&mut rng);

        let Confirmation {
            signal_servers,
            phone_number,
            password,
            session_id,
        } = &*self.state;

        let credentials = ServiceCredentials {
            aci: None,
            pni: None,
            phonenumber: phone_number.try_into_e164().expect("valid phone number"),
            password: Some(password.clone()),
            device_id: None,
        };

        let identified_push_service = PushService::new(
            *signal_servers,
            Some(credentials),
            crate::USER_AGENT,
        );

        // Submit verification code via direct REST (not WebSocket).
        // Signal's /v1/websocket/ rejects credentials for unregistered accounts.
        // See: https://github.com/whisperfish/presage/issues/371
        let session = identified_push_service
            .submit_verification_code(session_id, confirmation_code.as_ref())
            .await?;

        trace!("verification code submitted");

        if !session.verified {
            return Err(Error::UnverifiedRegistrationSession);
        }

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        // generate a 32 bytes profile key
        let mut profile_key = [0u8; 32];
        rng.fill_bytes(&mut profile_key);
        let profile_key = ProfileKey::generate(profile_key);

        // generate new identity keys
        self.store
            .set_aci_identity_key_pair(IdentityKeyPair::generate(&mut rng))
            .await?;
        self.store
            .set_pni_identity_key_pair(IdentityKeyPair::generate(&mut rng))
            .await?;

        // Generate pre-keys (mirrors AccountManager::register_account)
        let aci_identity_key_pair = self.store.aci_protocol_store()
            .get_identity_key_pair().await?;
        let pni_identity_key_pair = self.store.pni_protocol_store()
            .get_identity_key_pair().await?;

        let (
            _aci_pre_keys,
            aci_signed_pre_key,
            _aci_kyber_pre_keys,
            aci_last_resort_kyber_prekey,
        ) = libsignal_service::pre_keys::replenish_pre_keys(
            &mut self.store.aci_protocol_store(),
            &mut rng,
            &aci_identity_key_pair,
            true,
            0,
            0,
        )
        .await?;

        let (
            _pni_pre_keys,
            pni_signed_pre_key,
            _pni_kyber_pre_keys,
            pni_last_resort_kyber_prekey,
        ) = libsignal_service::pre_keys::replenish_pre_keys(
            &mut self.store.pni_protocol_store(),
            &mut rng,
            &pni_identity_key_pair,
            true,
            0,
            0,
        )
        .await?;

        let device_activation_request = DeviceActivationRequest {
            aci_signed_pre_key: aci_signed_pre_key.try_into()?,
            pni_signed_pre_key: pni_signed_pre_key.try_into()?,
            aci_pq_last_resort_pre_key: aci_last_resort_kyber_prekey
                .expect("requested last resort prekey")
                .try_into()?,
            pni_pq_last_resort_pre_key: pni_last_resort_kyber_prekey
                .expect("requested last resort prekey")
                .try_into()?,
        };

        let account_attributes = AccountAttributes {
            fetches_messages: true,
            registration_id,
            pni_registration_id,
            name: None,
            registration_lock: None,
            unidentified_access_key: Some(
                profile_key.derive_access_key().to_vec(),
            ),
            unrestricted_unidentified_access: false,
            capabilities: DeviceCapabilities::default(),
            discoverable_by_phone_number: true,
            pin: None,
            recovery_password: None,
        };

        // Register via direct REST (not WebSocket).
        let VerifyAccountResponse {
            aci,
            pni,
            storage_capable: _,
            number: _,
        } = identified_push_service
            .submit_registration_request(
                RegistrationMethod::SessionId(&session.id),
                account_attributes,
                true, // skip_device_transfer
                aci_identity_key_pair.identity_key(),
                pni_identity_key_pair.identity_key(),
                device_activation_request,
            )
            .await?;

        let mut manager = Manager {
            store: self.store,
            state: Arc::new(Registered::with_data(RegistrationData {
                signal_servers: self.state.signal_servers,
                device_name: None,
                phone_number: phone_number.clone(),
                service_ids: ServiceIds { aci, pni },
                password: password.clone(),
                device_id: None,
                registration_id,
                pni_registration_id: Some(pni_registration_id),
                profile_key,
            })),
        };

        manager
            .store
            .save_registration_data(&manager.state.data)
            .await?;

        trace!("confirmed! (and registered)");

        Ok(manager)
    }
}
