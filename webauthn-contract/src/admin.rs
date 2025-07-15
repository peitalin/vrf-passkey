use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near,  env, require, AccountId, serde_json};

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

    /// Checks if msg.sender (env::predecessor_account_id()) has permission to register a new user
    /// Returns true if predecessor is the user themselves, contract owner, or an admin
    /// @non-view - uses env::predecessor_account_id()
    pub(crate) fn only_sender_or_admin(&self, user_id: &AccountId) -> bool {
        // Allow the user themselves, contract owner, or admins to register new users
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();
        let is_admin = self.admins.contains(&predecessor);

        if predecessor != *user_id && predecessor != contract_account && !is_admin {
            false
        } else {
            true
        }
    }

    pub(crate) fn only_admin(&self) {
        require!(self.admins.contains(&env::predecessor_account_id()),
            "Only admins can call this function");
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

    ///////////////////////////////////////////////////////////////////////////////////
    // TESTNET-ONLY FUNCTIONS: State Deletion
    // These functions are for testnet deployment only and should not be used in production
    // They allow the contract owner to clear state to avoid "large state" issues
    ///////////////////////////////////////////////////////////////////////////////////

    /// Clear all authenticators (only contract owner can call this)
    #[private]
    pub fn clear_authenticators(&mut self) {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can clear authenticators");
        }

        // Use registered_users to get all account IDs and clear their authenticators
        let users: Vec<AccountId> = self.registered_users.iter().cloned().collect();
        let count = users.len();

        // Remove all authenticator entries for each user
        for user_id in users {
            self.authenticators.remove(&user_id);
        }

        log!("Cleared {} authenticator entries", count);
    }

    /// Clear all credential to users mappings (only contract owner can call this)
    /// Note: This collects credential IDs from authenticators before clearing them
    #[private]
    pub fn clear_credential_to_users(&mut self) {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can clear credential to users mappings");
        }

        let mut credential_ids = Vec::new();

        // Collect all credential IDs from all users' authenticators
        for user_id in self.registered_users.iter() {
            if let Some(user_authenticators) = self.authenticators.get(user_id) {
                for credential_id in user_authenticators.keys() {
                    credential_ids.push(credential_id.clone());
                }
            }
        }

        let count = credential_ids.len();

        // Remove all credential to users mappings
        for credential_id in credential_ids {
            self.credential_to_users.remove(&credential_id);
        }

        log!("Cleared {} credential to users mappings", count);
    }

    /// Clear all registered users (only contract owner can call this)
    #[private]
    pub fn clear_registered_users(&mut self) {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can clear registered users");
        }

        let count = self.registered_users.len();
        self.registered_users.clear();
        log!("Cleared {} registered users", count);
    }

    /// Clear all contract state (only contract owner can call this)
    /// This is a nuclear option that clears all user data
    pub fn clear_all_state(&mut self) {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can clear all state");
        }

        // Step 1: Collect all credential IDs from authenticators before clearing them
        let mut credential_ids = Vec::new();
        for user_id in self.registered_users.iter() {
            if let Some(user_authenticators) = self.authenticators.get(user_id) {
                for credential_id in user_authenticators.keys() {
                    credential_ids.push(credential_id.clone());
                }
            }
        }

        // Step 2: Clear credential_to_users mappings using collected credential IDs
        let cred_count = credential_ids.len();
        for credential_id in credential_ids {
            self.credential_to_users.remove(&credential_id);
        }

        // Step 3: Clear authenticators for each registered user
        let users: Vec<AccountId> = self.registered_users.iter().cloned().collect();
        let auth_count = users.len();
        for user_id in users {
            self.authenticators.remove(&user_id);
        }

        // Step 4: Clear registered users
        let users_count = self.registered_users.len();
        self.registered_users.clear();

        log!("Cleared all state: {} authenticators, {} registered users, {} credential mappings",
             auth_count, users_count, cred_count);
    }

    /// Get state statistics (view function)
    pub fn get_state_stats(&self) -> serde_json::Value {
        // Count authenticators and credential IDs by iterating through registered users
        let mut total_authenticators = 0;
        let mut total_credential_ids = 0;

        for user_id in self.registered_users.iter() {
            if let Some(user_authenticators) = self.authenticators.get(user_id) {
                let user_auth_count = user_authenticators.keys().count();
                total_authenticators += 1; // One authenticator entry per user
                total_credential_ids += user_auth_count;
            }
        }
        let storage_usage = env::storage_usage();

        serde_json::json!({
            "registered_users_count": self.registered_users.len(),
            "authenticator_entries_count": total_authenticators,
            "total_credential_ids": total_credential_ids,
            "admins_count": self.admins.len(),
            "storage_usage": storage_usage,
        })
    }

}
