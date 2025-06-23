use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near, AccountId, env, NearToken};
use std::str::FromStr;

use crate::types::AuthenticatorTransport;


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
    // VRF support
    pub vrf_public_key: Option<Vec<u8>>, // User's VRF public key for serverless mode
}

#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct UserProfile {
    pub account_id: AccountId,
    pub registered_at: u64, // Block timestamp
    pub last_activity: u64, // Block timestamp
    pub authenticator_count: u32,
    // VRF support
    pub primary_vrf_public_key: Option<Vec<u8>>, // Primary VRF key for this user
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    pub fn get_contract_name(&self) -> String {
        self.contract_name.clone()
    }

    pub fn set_contract_name(&mut self, contract_name: String) {
        log!("Saving contract name: {}", contract_name);
        self.contract_name = contract_name;
    }

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
            primary_vrf_public_key: None,
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

    /// Store a new authenticator with optional VRF public key (for VRF registration)
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
        vrf_public_key: Option<Vec<u8>>,
    ) -> bool {
                let vrf_enabled = vrf_public_key.is_some();

        let authenticator = StoredAuthenticator {
            credential_public_key,
            counter,
            transports,
            client_managed_near_public_key,
            registered,
            last_used: None,
            backed_up,
            vrf_public_key,
        };

        self.authenticators.insert((user_id.clone(), credential_id), authenticator);

        // Update user's authenticator count if user is registered
        if self.registered_users.contains(&user_id) {
            self.update_user_authenticator_count(user_id.clone());
        }

        log!("Stored authenticator for user {} with VRF support: {}",
             user_id,
             if vrf_enabled { "enabled" } else { "disabled" });

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
        near_sdk::Promise::new(account_id.parse().unwrap())
            .create_account()
            .add_full_access_key(public_key_parsed)
            .transfer(NearToken::from_yoctonear(balance));

        // The promise will execute and we return true to indicate the call was made
        // The actual success/failure will be determined by the promise execution
        true
    }
}
