pub mod utils;

mod authenticators;
mod admin;
mod types;
mod contract_state;
mod link_device;

mod verify_authentication_response;
mod verify_registration_response;

// Choose one of the VRF verification methods
use crate::utils::vrf_verifier;
use crate::contract_state::WebAuthnContractExt;

pub use types::{
    WebAuthnRegistrationCredential,
    WebAuthnAuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
};
pub use contract_state::{
    WebAuthnContract,
    VRFSettings,
    StoredAuthenticator,
    StorageKey,
};
pub use verify_registration_response::{
    VerifyRegistrationResponse,
    VerifyCanRegisterResponse,
    VRFVerificationData,
};
pub use verify_authentication_response::{
    VerifiedAuthenticationResponse,
};
use near_sdk::{env, log, near};
use near_sdk::store::{LookupMap, IterableSet};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

/// VRF authentication response with output
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct VerifiedVRFAuthenticationResponse {
    pub verified: bool,
    pub vrf_output: Option<Vec<u8>>, // 64-byte VRF output if verification succeeds
    pub authentication_info: Option<String>,
}

#[near]
impl WebAuthnContract {

    #[init]
    pub fn init(contract_name: String) -> Self {
        Self {
            contract_name,
            greeting: "Hello".to_string(),
            vrf_settings: VRFSettings::default(),
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


    // vrf-contract-verifier (view-only verification)
    pub fn verify_vrf_1(
        &self,
        proof_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
        input: Vec<u8>,
    ) -> VerifiedVRFAuthenticationResponse {
        match vrf_verifier::verify_vrf_1(&proof_bytes, &public_key_bytes, &input) {
            Ok(vrf_output) => VerifiedVRFAuthenticationResponse {
                verified: true,
                vrf_output: Some(vrf_output.to_vec()),
                authentication_info: Some("VRF verification successful".to_string()),
            },
            Err(_) => VerifiedVRFAuthenticationResponse {
                verified: false,
                vrf_output: None,
                authentication_info: Some("VRF verification failed".to_string()),
            }
        }
    }

    // // vrf-wasm
    // pub fn verify_vrf_2(
    //     &mut self,
    //     proof_bytes: Vec<u8>,
    //     public_key_bytes: Vec<u8>,
    //     input: Vec<u8>,
    // ) -> VerifiedVRFAuthenticationResponse {
    //     match vrf_verifier::verify_vrf_2(&proof_bytes, &public_key_bytes, &input) {
    //         Ok(vrf_output) => VerifiedVRFAuthenticationResponse {
    //             verified: true,
    //             vrf_output: Some(vrf_output.to_vec()),
    //             authentication_info: Some("VRF-WASM verification successful".to_string()),
    //         },
    //         Err(_) => VerifiedVRFAuthenticationResponse {
    //             verified: false,
    //             vrf_output: None,
    //             authentication_info: Some("VRF-WASM verification failed".to_string()),
    //         }
    //     }
    // }

    /// Update VRF settings (only contract owner can call this)
    pub fn update_vrf_settings(&mut self, settings: VRFSettings) {
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

}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE};
    use std::collections::BTreeMap;
    use crate::utils::vrf_verifier::*;

    // === TEST HELPERS ===

    /// Helper to get a VMContext with predictable randomness for testing
    fn get_context_with_seed(random_byte_val: u8) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let seed: Vec<u8> = (0..32).map(|_| random_byte_val).collect();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(accounts(1))
            .predecessor_account_id(accounts(1))
            .is_view(false)
            .random_seed(seed.try_into().unwrap());
        builder
    }


    /// Create a valid mock WebAuthn registration response
    fn create_mock_webauthn_registration_response_with_challenge(challenge_b64: &str) -> WebAuthnRegistrationCredential {
        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://test-contract.testnet","crossOrigin":false}}"#,
            challenge_b64
        );
        let client_data_b64 = BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create valid attestation object for "none" format
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            serde_cbor::Value::Text("fmt".to_string()),
            serde_cbor::Value::Text("none".to_string()),
        );

        // Create valid authenticator data
        let mut auth_data = Vec::new();
        let rp_id_hash = env::sha256(b"test-contract.testnet");
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x45); // UP (0x01) + UV (0x04) + AT (0x40)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Counter = 1

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x00u8; 16]);

        // Credential ID
        let cred_id = b"test_vrf_credential";
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);

        // Create valid COSE Ed25519 public key
        let mock_ed25519_pubkey = [0x42u8; 32];
        let mut cose_map = BTreeMap::new();
        cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
        cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
        cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
        cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
        let cose_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();
        auth_data.extend_from_slice(&cose_key);

        attestation_map.insert(
            serde_cbor::Value::Text("authData".to_string()),
            serde_cbor::Value::Bytes(auth_data),
        );
        attestation_map.insert(
            serde_cbor::Value::Text("attStmt".to_string()),
            serde_cbor::Value::Map(BTreeMap::new()),
        );

        let attestation_object_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(attestation_map)).unwrap();
        let attestation_object_b64 = BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        WebAuthnRegistrationCredential {
            id: "test_vrf_credential".to_string(),
            raw_id: BASE64_URL_ENGINE.encode(b"test_vrf_credential"),
            response: AuthenticatorAttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
                transports: Some(vec!["internal".to_string()]),
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: None,
        }
    }

    /// Create a valid mock WebAuthn authentication response
    fn create_mock_webauthn_authentication_response_with_challenge(challenge_b64: &str) -> WebAuthnAuthenticationCredential {
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://test-contract.testnet","crossOrigin":false}}"#,
            challenge_b64
        );
        let client_data_b64 = BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create valid authenticator data
        let mut auth_data = Vec::new();
        let rp_id_hash = env::sha256(b"test-contract.testnet");
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x05); // UP (0x01) + UV (0x04)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // Counter = 2

        let auth_data_b64 = BASE64_URL_ENGINE.encode(&auth_data);

        WebAuthnAuthenticationCredential {
            id: "test_vrf_credential".to_string(),
            raw_id: BASE64_URL_ENGINE.encode(b"test_vrf_credential"),
            response: AuthenticatorAssertionResponse {
                client_data_json: client_data_b64,
                authenticator_data: auth_data_b64,
                signature: BASE64_URL_ENGINE.encode(&vec![0u8; 64]), // Mock signature
                user_handle: None,
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: None,
        }
    }


}
