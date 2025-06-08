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
    AuthenticatorTransport,
};
pub use verify_registration_response::{
    VerifiedRegistrationResponse,
    AuthenticatorSelectionCriteria,
};
use near_sdk::{log, near, CryptoHash, AccountId, PanicOnDefault, BorshStorageKey};
use near_sdk::store::{LookupMap, IterableMap};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use crate::generate_registration_options::YieldedRegistrationData;

pub use crate::verify_authentication_response::{
    VerifiedAuthenticationResponse,
    YieldedAuthenticationData as AuthYieldData
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct UserIdYieldId {
    pub user_id: AccountId,
    pub yield_resume_id: Vec<u8>,
}

#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub counter: u32,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub client_managed_near_public_key: Option<String>,
    pub name: Option<String>,
    pub registered: String, // ISO date string
    pub last_used: Option<String>, // ISO date string
    pub backed_up: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct WebAuthnContract {
    greeting: String,
    pub contract_name: String,
    pub pending_registrations: LookupMap<String, YieldedRegistrationData>,
    pub pending_authentications: LookupMap<String, AuthYieldData>,
    pub pending_prunes: LookupMap<String, UserIdYieldId>,
    pub authenticators: IterableMap<(AccountId, String), StoredAuthenticator>,
}

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    PendingRegistrations,
    PendingAuthentications,
    PendingPrunes,
    Authenticators,
}

#[near]
impl WebAuthnContract {

    #[init]
    pub fn init(contract_name: String) -> Self {
        Self {
            contract_name,
            greeting: "Hello".to_string(),
            pending_registrations: LookupMap::new(StorageKey::PendingRegistrations),
            pending_authentications: LookupMap::new(StorageKey::PendingAuthentications),
            pending_prunes: LookupMap::new(StorageKey::PendingPrunes),
            authenticators: IterableMap::new(StorageKey::Authenticators),
        }
    }

    pub fn get_greeting(&self) -> String {
        self.greeting.clone()
    }

    pub fn get_pending_prune_id(&self, commitment_id: String) -> Option<UserIdYieldId> {
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
            Some(user_id_yield_id) => {
                let yield_resume_id_bytes = user_id_yield_id.yield_resume_id.clone();
                let yield_resume_id: CryptoHash = yield_resume_id_bytes
                    .try_into()
                    .expect("Invalid yield_resume_id format in pending_prunes");

                Some(yield_resume_id.clone())
            }
        }
    }

    // Authenticator management methods

    /// Get all authenticators for a specific user
    pub fn get_authenticators_by_user(&self, user_id: AccountId) -> Vec<(String, StoredAuthenticator)> {
        let mut result = Vec::new();
        for ((account_id, credential_id), authenticator) in self.authenticators.iter() {
            if *account_id == user_id {
                result.push((credential_id.clone(), authenticator.clone()));
            }
        }
        result
    }

    /// Get a specific authenticator by user and credential ID
    pub fn get_authenticator(&self, user_id: AccountId, credential_id: String) -> Option<StoredAuthenticator> {
        self.authenticators.get(&(user_id, credential_id)).cloned()
    }

    /// Store a new authenticator
    pub fn store_authenticator(
        &mut self,
        user_id: AccountId,
        credential_id: String,
        credential_public_key: Vec<u8>,
        counter: u32,
        transports: Option<Vec<AuthenticatorTransport>>,
        client_managed_near_public_key: Option<String>,
        name: Option<String>,
        registered: String,
        backed_up: bool,
    ) -> bool {
        let authenticator = StoredAuthenticator {
            credential_public_key,
            counter,
            transports,
            client_managed_near_public_key,
            name,
            registered,
            last_used: None,
            backed_up,
        };

        self.authenticators.insert((user_id, credential_id), authenticator);
        true
    }

    /// Update authenticator counter and last used timestamp
    pub fn update_authenticator_usage(
        &mut self,
        user_id: AccountId,
        credential_id: String,
        new_counter: u32,
        last_used: String,
    ) -> bool {
        let key = (user_id.clone(), credential_id.clone());
        if let Some(mut authenticator) = self.authenticators.get(&key).cloned() {
            authenticator.counter = new_counter;
            authenticator.last_used = Some(last_used);
            self.authenticators.insert(key, authenticator);
            true
        } else {
            false
        }
    }

    /// Update the client-managed NEAR public key for an authenticator
    pub fn update_authenticator_near_key(
        &mut self,
        user_id: AccountId,
        credential_id: String,
        client_managed_near_public_key: String,
    ) -> bool {
        let key = (user_id.clone(), credential_id.clone());
        if let Some(mut authenticator) = self.authenticators.get(&key).cloned() {
            authenticator.client_managed_near_public_key = Some(client_managed_near_public_key);
            self.authenticators.insert(key, authenticator);
            true
        } else {
            false
        }
    }

    /// Get the latest (first registered) authenticator for a user
    pub fn get_latest_authenticator_by_user(&self, user_id: AccountId) -> Option<String> {
        let mut earliest_date: Option<String> = None;
        let mut earliest_credential_id: Option<String> = None;

        for ((account_id, credential_id), authenticator) in self.authenticators.iter() {
            if *account_id == user_id {
                if let Some(ref current_earliest) = earliest_date {
                    if authenticator.registered < *current_earliest {
                        earliest_date = Some(authenticator.registered.clone());
                        earliest_credential_id = Some(credential_id.clone());
                    }
                } else {
                    earliest_date = Some(authenticator.registered.clone());
                    earliest_credential_id = Some(credential_id.clone());
                }
            }
        }

        earliest_credential_id
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
