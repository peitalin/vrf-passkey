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
use near_sdk::{log, near, CryptoHash, AccountId, PanicOnDefault, BorshStorageKey, env, NearToken};
use near_sdk::store::{LookupMap, IterableSet, IterableMap};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use std::str::FromStr;
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
    pub registered: String, // ISO date string
    pub last_used: Option<String>, // ISO date string
    pub backed_up: bool,
}

#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct UserProfile {
    pub account_id: AccountId,
    pub registered_at: u64, // Block timestamp
    pub last_activity: u64, // Block timestamp
    pub authenticator_count: u32,
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
    pub registered_users: IterableSet<AccountId>,
    pub user_profiles: LookupMap<AccountId, UserProfile>,
    pub admins: IterableSet<AccountId>,
}

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    PendingRegistrations,
    PendingAuthentications,
    PendingPrunes,
    Authenticators,
    RegisteredUsers,
    UserProfiles,
    Admins,
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
            registered_users: IterableSet::new(StorageKey::RegisteredUsers),
            user_profiles: LookupMap::new(StorageKey::UserProfiles),
            admins: IterableSet::new(StorageKey::Admins),
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

        /// Register a new user in the contract
    pub fn register_user(&mut self, user_id: AccountId) -> bool {
        // Allow the user themselves, contract owner, or any admin to register
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();
        let is_admin = self.admins.contains(&predecessor);

        if predecessor != user_id && predecessor != contract_account && !is_admin {
            env::panic_str("Only the user, contract owner, or admins can register users");
        }

        if self.registered_users.contains(&user_id) {
            log!("User {} already registered", user_id);
            return false;
        }

        let current_timestamp = env::block_timestamp_ms();

        // Add to registry
        self.registered_users.insert(user_id.clone());

        // Create user profile
        let profile = UserProfile {
            account_id: user_id.clone(),
            registered_at: current_timestamp,
            last_activity: current_timestamp,
            authenticator_count: 0,
        };

        self.user_profiles.insert(user_id.clone(), profile);

        log!("User {} registered successfully", user_id);
        true
    }

    /// Check if a user is registered
    pub fn is_user_registered(&self, user_id: AccountId) -> bool {
        self.registered_users.contains(&user_id)
    }

    /// Get user profile
    pub fn get_user_profile(&self, user_id: AccountId) -> Option<UserProfile> {
        self.user_profiles.get(&user_id).cloned()
    }

    /// Update user activity timestamp
    pub fn update_user_activity(&mut self, user_id: AccountId) -> bool {
        if let Some(mut profile) = self.user_profiles.get(&user_id).cloned() {
            profile.last_activity = env::block_timestamp_ms();
            self.user_profiles.insert(user_id, profile);
            true
        } else {
            false
        }
    }

    /// Update user's authenticator count
    pub fn update_user_authenticator_count(&mut self, user_id: AccountId) -> bool {
        if let Some(mut profile) = self.user_profiles.get(&user_id).cloned() {
            // Count authenticators for this user
            let count = self.authenticators
                .iter()
                .filter(|((account_id, _), _)| *account_id == user_id)
                .count() as u32;

            profile.authenticator_count = count;
            profile.last_activity = env::block_timestamp_ms();
            self.user_profiles.insert(user_id, profile);
            true
        } else {
            false
        }
    }

    /// Get total number of registered users
    pub fn get_total_users(&self) -> u32 {
        self.registered_users.len() as u32
    }

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
        registered: String,
        backed_up: bool,
    ) -> bool {
        let authenticator = StoredAuthenticator {
            credential_public_key,
            counter,
            transports,
            client_managed_near_public_key,
            registered,
            last_used: None,
            backed_up,
        };

        self.authenticators.insert((user_id.clone(), credential_id), authenticator);

        // Update user's authenticator count if user is registered
        if self.registered_users.contains(&user_id) {
            self.update_user_authenticator_count(user_id);
        }

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

            // Update user activity
            self.update_user_activity(user_id);
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

            // Update user activity
            self.update_user_activity(user_id);
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

    /// Add a new admin (only contract owner can call this)
    pub fn add_admin(&mut self, admin_id: AccountId) -> bool {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can add admins");
        }

        if self.admins.contains(&admin_id) {
            log!("Admin {} already exists", admin_id);
            return false;
        }

        self.admins.insert(admin_id.clone());
        log!("Admin {} added successfully", admin_id);
        true
    }

    /// Remove an admin (only contract owner can call this)
    pub fn remove_admin(&mut self, admin_id: AccountId) -> bool {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can remove admins");
        }

        if !self.admins.contains(&admin_id) {
            log!("Admin {} does not exist", admin_id);
            return false;
        }

        self.admins.remove(&admin_id);
        log!("Admin {} removed successfully", admin_id);
        true
    }

    /// Check if an account is an admin
    pub fn is_admin(&self, account_id: AccountId) -> bool {
        self.admins.contains(&account_id)
    }

    /// Get all admins
    pub fn get_admins(&self) -> Vec<AccountId> {
        self.admins.iter().cloned().collect()
    }

    /// Create a user account as a subaccount of this contract
    /// This allows for serverless registration by using the contract's funds
    #[payable]
    pub fn create_user_account(
        &mut self,
        username: String,
        public_key: String,
        initial_balance: Option<String>
    ) -> bool {
        // Sanitize username
        let sanitized_username = username.to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .take(32)
            .collect::<String>();

        if sanitized_username.is_empty() {
            return false;
        }

        // Create account ID as subaccount of this contract
        let account_id = format!("{}.{}", sanitized_username, env::current_account_id());

        // Parse the initial balance (default to 0.02 NEAR)
        let balance = if let Some(balance_str) = initial_balance {
            balance_str.parse::<u128>().unwrap_or(20_000_000_000_000_000_000_000) // 0.02 NEAR
        } else {
            20_000_000_000_000_000_000_000 // 0.02 NEAR
        };

        // Parse the public key
        let public_key_parsed = match near_sdk::PublicKey::from_str(&public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Create the account using a promise
        let promise = near_sdk::Promise::new(account_id.parse().unwrap())
            .create_account()
            .add_full_access_key(public_key_parsed)
            .transfer(NearToken::from_yoctonear(balance));

        // The promise will execute and we return true to indicate the call was made
        // The actual success/failure will be determined by the promise execution
        true
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
