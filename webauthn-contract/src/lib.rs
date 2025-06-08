pub mod utils;

mod generate_authentication_options;
mod generate_registration_options;
mod verify_authentication_response;
mod verify_registration_response;
mod contract_helpers;

pub mod test_yield_resume;


pub use generate_authentication_options::{
    AuthenticationOptionsJSON,
};
pub use generate_registration_options::{
    RegistrationOptionsJSON,
};
pub use verify_registration_response::{
    VerifiedRegistrationResponse,
    AuthenticatorSelectionCriteria,
};
use near_sdk::{log, near, CryptoHash};
use near_sdk::store::{LookupMap, IterableMap};
use crate::generate_registration_options::YieldedRegistrationData;

pub use crate::verify_authentication_response::{
    VerifiedAuthenticationResponse,
    YieldedAuthenticationData
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near(contract_state)]
pub struct WebAuthnContract {
    greeting: String,
    contract_name: String,
    pending_registrations: LookupMap<String, YieldedRegistrationData>,
    pending_authentications: LookupMap<String, YieldedAuthenticationData>,
    pending_prunes: LookupMap<String, Vec<u8>>, // Stores commitment_id -> yield_resume_id
}

impl Default for WebAuthnContract {
    fn default() -> Self {
        Self {
            greeting: "Hello".to_string(),
            contract_name: "webauthn-contract.testnet".to_string(),
            pending_registrations: LookupMap::new(b"r"),
            pending_authentications: LookupMap::new(b"a"),
            pending_prunes: LookupMap::new(b"p"),
        }
    }
}

#[near]
impl WebAuthnContract {

    #[init]
    pub fn init(contract_name: String) -> Self {
        Self {
            contract_name,
            greeting: "Hello".to_string(),
            pending_registrations: LookupMap::new(b"r"),
            pending_authentications: LookupMap::new(b"a"),
            pending_prunes: LookupMap::new(b"p"),
        }
    }

    pub fn get_greeting(&self) -> String {
        self.greeting.clone()
    }

    pub fn get_pending_prune_id(&self, commitment_id: String) -> Option<Vec<u8>> {
        self.pending_prunes.get(&commitment_id).cloned()
    }

    pub fn set_greeting(&mut self, greeting: String) {
        log!("Saving greeting: {}", greeting);
        self.greeting = greeting;
    }

    pub fn get_contract_name(&self) -> String {
        self.contract_name.clone()
    }

    pub fn set_contract_name(&mut self, contract_name: String) {
        log!("Saving contract name: {}", contract_name);
        self.contract_name = contract_name;
    }

    pub fn get_yield_id(&self, commitment_id: String) -> Option<CryptoHash> {
        match self.pending_prunes.get(&commitment_id) {
            None => None,
            Some(yield_resume_id_bytes) => {
                let yield_resume_id: CryptoHash = yield_resume_id_bytes.clone()
                    .try_into()
                    .expect("Invalid yield_resume_id format in pending_prunes");

                Some(yield_resume_id.clone())
            }
        }
    }

    // pub fn generate_registration_options(
    //     &mut self,
    //     rp_name: String,
    //     rp_id: String,
    //     user_name: String,
    //     user_id: String,
    // ) -> String {
    //     _generate_registration_options(
    //         rp_name,
    //         rp_id,
    //         user_name,
    //         user_id,
    //     )
    // }

    // pub fn verify_registration_response(
    //     &self,
    //     response: RegistrationResponseJSON,
    //     expected_challenge: String,
    //     expected_origin: String,
    //     expected_rp_id: String,
    // ) -> VerifiedRegistrationResponse {
    //     _verify_registration_response(
    //         response,
    //         expected_challenge,
    //         expected_origin,
    //         expected_rp_id,
    //     )
    // }

    // pub fn generate_authentication_options(
    //     &mut self,
    //     rp_id: Option<String>,
    //     allow_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
    //     challenge: Option<String>,
    //     timeout: Option<u64>,
    //     user_verification: Option<UserVerificationRequirement>,
    // ) -> String {
    //     _generate_authentication_options(
    //         rp_id,
    //         allow_credentials,
    //         challenge,
    //         timeout,
    //         user_verification,
    //     )
    // }

    // pub fn verify_authentication_response(
    //     &self,
    //     response: AuthenticationResponseJSON,
    //     expected_challenge: String,
    //     expected_origin: String,
    //     expected_rp_id: String,
    // ) -> VerifiedAuthenticationResponse {
    //     _verify_authentication_response(
    //         response,
    //         expected_challenge,
    //         expected_origin,
    //         expected_rp_id,
    //     )
    // }
}
