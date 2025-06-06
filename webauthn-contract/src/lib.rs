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
    VerifiedAuthenticationResponse,
    AuthenticatorSelectionCriteria,
};
use near_sdk::{log, near, BorshStorageKey, CryptoHash};
use near_sdk::store::{LookupMap, IterableMap};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near(contract_state)]
pub struct WebAuthnContract {
    greeting: String,
    contract_name: String,
}

impl Default for WebAuthnContract {
    fn default() -> Self {
        Self {
            greeting: "Hello".to_string(),
            contract_name: "webauthn-contract.testnet".to_string(),
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
        }
    }

    pub fn get_greeting(&self) -> String {
        self.greeting.clone()
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
