pub mod utils;

mod authenticators;
mod admin;
mod types;
mod contract_state;
mod link_device;

mod verify_authentication_response;
mod verify_registration_response;

use near_sdk::{env, log, near};
use near_sdk::store::{LookupMap, IterableSet};

pub use types::{
    WebAuthnRegistrationCredential,
    WebAuthnAuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
};
use contract_state::WebAuthnContractExt;
pub use contract_state::{
    WebAuthnContract,
    VRFSettings,
    TldConfiguration,
    StoredAuthenticator,
    StorageKey,
    AuthenticatorTransport,
};
pub use verify_registration_response::{
    VerifyRegistrationResponse,
    VerifyCanRegisterResponse,
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////


#[near]
impl WebAuthnContract {

    #[init]
    pub fn init() -> Self {
        Self {
            greeting: "Hello".to_string(),
            vrf_settings: VRFSettings::default(),
            tld_config: None, // No complex TLD support by default - standard domains only
            admins: IterableSet::new(StorageKey::Admins),
            authenticators: LookupMap::new(StorageKey::Authenticators),
            registered_users: IterableSet::new(StorageKey::RegisteredUsers),
            credential_to_users: LookupMap::new(StorageKey::CredentialToUsers),
            device_numbers: LookupMap::new(StorageKey::AccountDeviceCounters),
            device_linking_map: LookupMap::new(StorageKey::DeviceLinkingMap),
        }
    }

    pub fn get_greeting(&self) -> String {
        self.greeting.clone()
    }

    pub fn set_greeting(&mut self, greeting: String) {
        log!("Saving greeting: {}", greeting);
        self.greeting = greeting;
    }
    /// Set VRF settings (only contract owner can call this)
    pub fn set_vrf_settings(&mut self, settings: VRFSettings) {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can update VRF settings");
        }

        self.vrf_settings = settings;
        log!("VRF settings updated");
    }

    /// Get current VRF settings
    pub fn get_vrf_settings(&self) -> VRFSettings {
        self.vrf_settings.clone()
    }

    ///////////////////////////////////////////////////
    // Main WebAuthn registration and verification functions are found in:
    // - webauthn-contract/src/verify_registration_response.rs
    // - webauthn-contract/src/verify_authentication_response.rs
    ///////////////////////////////////////////////////

    // Test vrf-wasm vs. vrf-contract-verifier compatibility (view-only verification)
    pub fn verify_vrf_1(
        &self,
        proof_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
        input: Vec<u8>,
    ) -> Option<Vec<u8>> {
        match vrf_contract_verifier::verify_vrf(&proof_bytes, &public_key_bytes, &input) {
            Ok(vrf_output) => Some(vrf_output.to_vec()),
            Err(_) => None,
        }
    }
}
