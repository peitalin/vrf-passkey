use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near, require, env, AccountId, NearToken};
use near_sdk::store::IterableMap;
use std::str::FromStr;
use crate::contract_state::{
    AccountCreationSettings,
    AuthenticatorTransport,
    StoredAuthenticator
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /////////////////////////////////////
    /// USER REGISTRATION
    /////////////////////////////////////

    /// Register a new user in the contract
    /// @payable - This function can be called with attached NEAR tokens
    pub fn register_user(&mut self, user_id: AccountId) -> bool {

        require!(self.only_sender_or_admin(&user_id),
            "Must be called by the user, owner, or admins");

        if self.registered_users.contains(&user_id) {
            log!("User {} already registered", user_id);
            return false;
        }

        // Add to registry
        self.registered_users.insert(user_id.clone());
        log!("User {} registered successfully", user_id);
        true
    }

    /// Check if a user is registered
    /// @view
    pub fn is_user_registered(&self, user_id: AccountId) -> bool {
        self.registered_users.contains(&user_id)
    }

    /////////////////////////////////////
    /// AUTHENTICATORS
    /////////////////////////////////////

    /// Get all authenticators for a specific user
    /// @view
    pub fn get_authenticators_by_user(&self, user_id: AccountId) -> Vec<(String, StoredAuthenticator)> {
        let mut result = Vec::new();
        // Get the user's authenticator map (O(1))
        if let Some(user_authenticators) = self.authenticators.get(&user_id) {
            // Iterate through the user's authenticators (O(k) where k = user's credentials)
            for (credential_id, authenticator) in user_authenticators.iter() {
                result.push((credential_id.clone(), authenticator.clone()));
            }
        }

        result
    }

    /// Get a specific authenticator by user and credential ID
    /// @view
    pub fn get_authenticator(&self, user_id: AccountId, credential_id: String) -> Option<StoredAuthenticator> {
        // First get user's map, then get specific authenticator
        self.authenticators.get(&user_id)
            .and_then(|user_authenticators| user_authenticators.get(&credential_id))
            .cloned()
    }

    /// Store a new authenticator with VRF public keys (supports single or multiple keys)
    pub fn store_authenticator(
        &mut self,
        user_id: AccountId,
        credential_id: String,
        credential_public_key: Vec<u8>,
        transports: Option<Vec<AuthenticatorTransport>>,
        registered: String,
        vrf_public_keys: Vec<Vec<u8>>, // Changed from single key to vector of keys
    ) -> bool {
        require!(env::predecessor_account_id() == user_id, "Only the user can call this function");

        let vrf_count = vrf_public_keys.len();
        let authenticator = StoredAuthenticator {
            credential_public_key,
            transports,
            registered,
            vrf_public_keys, // Store all VRF keys
        };

        // Check if user's authenticator map exists, if not create it
        if !self.authenticators.contains_key(&user_id) {
            // Create new IterableMap with a unique storage key based on user_id
            let storage_key_bytes = format!("auth_{}", user_id).into_bytes();
            let new_map = IterableMap::new(storage_key_bytes);
            self.authenticators.insert(user_id.clone(), new_map);
        }

        // Insert the authenticator into the user's map
        if let Some(user_authenticators) = self.authenticators.get_mut(&user_id) {
            user_authenticators.insert(credential_id.clone(), authenticator);
        }

        // Update credential->user mapping for account recovery
        self.add_credential_user_mapping(credential_id, user_id.clone());

        log!("Stored authenticator for user {} with {} VRF key(s)", user_id, vrf_count);
        true
    }

    /// Add a new VRF public key to an existing authenticator (FIFO queue with max 5 keys)
    pub fn add_vrf_key_to_authenticator(
        &mut self,
        credential_id: String,
        new_vrf_key: Vec<u8>,
    ) -> bool {
        let user_id = env::predecessor_account_id();

        // Get the user's authenticator map and find the specific authenticator
        if let Some(user_authenticators) = self.authenticators.get_mut(&user_id) {
            if let Some(authenticator) = user_authenticators.get_mut(&credential_id) {
                // Check if key already exists to avoid duplicates
                if !authenticator.vrf_public_keys.contains(&new_vrf_key) {
                    // Add new key
                    authenticator.vrf_public_keys.push(new_vrf_key);

                    // If exceeds max size, remove oldest (FIFO)
                    if authenticator.vrf_public_keys.len() > self.vrf_settings.max_authenticators_per_account {
                        authenticator.vrf_public_keys.remove(0); // Remove first (oldest)
                    }

                    let n_keys = authenticator.vrf_public_keys.len();
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
        } else {
            log!("No authenticators found for user {}", user_id);
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
    /// Update account creation settings (only contract owner can call this)
    pub fn update_account_creation_settings(&mut self, settings: AccountCreationSettings) {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        if predecessor != contract_account {
            env::panic_str("Only the contract owner can update account creation settings");
        }

        self.account_creation_settings = settings;
        log!("Account creation settings updated");
    }

    /// Get current account creation settings
    pub fn get_account_creation_settings(&self) -> AccountCreationSettings {
        self.account_creation_settings.clone()
    }

    /////////////////////////////////
    /// CREDENTIAL LOOKUP
    /////////////////////////////////

    /// Get all account IDs associated with a credential ID
    /// This enables efficient account discovery during recovery
    pub fn get_accounts_by_credential_id(&self, credential_id: String) -> Vec<AccountId> {
        self.credential_to_users.get(&credential_id).cloned().unwrap_or_default()
    }

    /// Get all credential IDs associated with an account ID
    /// This enables reverse lookup for account recovery (account -> credential IDs)
    pub fn get_credential_ids_by_account(&self, account_id: AccountId) -> Vec<String> {
        if let Some(user_authenticators) = self.authenticators.get(&account_id) {
            user_authenticators.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Helper method to add a credential->user mapping (used during registration)
    pub(crate) fn add_credential_user_mapping(&mut self, credential_id: String, user_id: AccountId) {
        let mut users = self.credential_to_users.get(&credential_id).cloned().unwrap_or_default();
        if !users.contains(&user_id) {
            users.push(user_id);
            self.credential_to_users.insert(credential_id.clone(), users);
        }
    }

    /// Helper method to remove a credential->user mapping (used during deregistration)
    pub(crate) fn remove_credential_user_mapping(&mut self, credential_id: String, user_id: AccountId) {
        if let Some(mut users) = self.credential_to_users.get(&credential_id).cloned() {
            users.retain(|u| u != &user_id);
            if users.is_empty() {
                self.credential_to_users.remove(&credential_id);
            } else {
                self.credential_to_users.insert(credential_id.clone(), users);
            }
        }
    }
}
