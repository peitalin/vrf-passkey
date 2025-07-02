use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near, AccountId, env, NearToken};
use std::str::FromStr;

use crate::types::AuthenticatorTransport;

// Maximum number of VRF public keys per authenticator (FIFO queue)
pub const MAX_VRF_KEYS_PER_AUTHENTICATOR: usize = 5;


#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String, // ISO timestamp of registration
    pub vrf_public_keys: Vec<Vec<u8>>, // VRF public keys for stateless authentication (max 5, FIFO)
}

#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct UserProfile {
    pub account_id: AccountId,
    pub registered_at: u64, // Block timestamp
    pub last_activity: u64, // Block timestamp
    pub authenticator_count: u32,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    #[private]
    pub fn can_register_user(&self, user_id: &AccountId) -> bool {
        // Allow the user themselves, contract owner, or any admin to register
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();
        let is_admin = self.admins.contains(&predecessor);

        if predecessor != *user_id && predecessor != contract_account && !is_admin {
            false
        } else {
            true
        }
    }

    /// Register a new user in the contract
    pub fn register_user(&mut self, user_id: AccountId) -> bool {

        if !self.can_register_user(&user_id) {
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

    /// Store a new authenticator with VRF public key
    pub fn store_authenticator(
        &mut self,
        credential_id: String,
        credential_public_key: Vec<u8>,
        transports: Option<Vec<AuthenticatorTransport>>,
        registered: String,
        vrf_public_key: Vec<u8>,
    ) -> bool {

        let user_id = env::predecessor_account_id();

        let authenticator = StoredAuthenticator {
            credential_public_key,
            transports,
            registered,
            vrf_public_keys: vec![vrf_public_key], // Initialize with first VRF key
        };

        self.authenticators.insert((user_id.clone(), credential_id), authenticator);

        // Update user's authenticator count if user is registered
        if self.registered_users.contains(&user_id) {
            self.update_user_authenticator_count(user_id.clone());
        }

        log!("Stored authenticator for user {} with VRF support", user_id);
        true
    }

    /// Add a new VRF public key to an existing authenticator (FIFO queue with max 5 keys)
    pub fn add_vrf_key_to_authenticator(
        &mut self,
        credential_id: String,
        new_vrf_key: Vec<u8>,
    ) -> bool {
        let user_id = env::predecessor_account_id();
        let key = (user_id.clone(), credential_id.clone());
        if let Some(mut authenticator) = self.authenticators.get(&key).cloned() {
            // Check if key already exists to avoid duplicates
            if !authenticator.vrf_public_keys.contains(&new_vrf_key) {
                // Add new key
                authenticator.vrf_public_keys.push(new_vrf_key);

                // If exceeds max size, remove oldest (FIFO)
                if authenticator.vrf_public_keys.len() > MAX_VRF_KEYS_PER_AUTHENTICATOR {
                    authenticator.vrf_public_keys.remove(0); // Remove first (oldest)
                }

                // Store updated authenticator
                self.authenticators.insert(key, authenticator);
                let n_keys = self.authenticators.get(&(user_id.clone(), credential_id)).unwrap().vrf_public_keys.len();
                log!("Added VRF key to authenticator for user {} (total keys: {})", user_id, n_keys);
                true
            } else {
                log!("VRF key already exists for user {}, credential {}", user_id, credential_id);
                false
            }
        } else {
            log!("No authenticator found for user {}, credential {}", user_id, credential_id);
            false
        }
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
        near_sdk::Promise::new(account_id.parse().unwrap())
            .create_account()
            .add_full_access_key(public_key_parsed)
            .transfer(NearToken::from_yoctonear(balance));

        // The promise will execute and we return true to indicate the call was made
        // The actual success/failure will be determined by the promise execution
        true
    }
}
