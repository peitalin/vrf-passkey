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
        self.contract_name = contract_name;
    }

    /// Checks if msg.sender (env::predecessor_account_id()) has permission to register a new user
    /// Returns true if predecessor is the user themselves, contract owner, or an admin
    /// @non-view - uses env::predecessor_account_id()
    pub(crate) fn only_sender_or_admin(&self, user_id: &AccountId) -> bool {
        // Allow the user themselves (msg.sender), contract owner, or admins to register new users
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
        require!(
            self.admins.contains(&env::predecessor_account_id()),
            "Only admins can call this function"
        );
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
