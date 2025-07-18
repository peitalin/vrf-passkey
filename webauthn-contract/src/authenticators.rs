use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near, require, env, AccountId, NearToken};
use near_sdk::store::IterableMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;

use crate::contract_state::{
    AuthenticatorTransport,
    StoredAuthenticator,
};
use crate::verify_registration_response::{
    RegistrationInfo,
    VerifyRegistrationResponse,
};
use crate::types::WebAuthnRegistrationCredential;

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
    #[payable]
    pub fn register_user(&mut self, user_id: AccountId) -> bool {

        require!(self.only_sender_or_admin(&user_id), "Must be called by the user, owner, or admins");

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
    #[private]
    pub fn store_authenticator(
        &mut self,
        user_id: AccountId,
        credential_id: String,
        credential_public_key: Vec<u8>,
        transports: Option<Vec<AuthenticatorTransport>>,
        registered: String,
        vrf_public_keys: Vec<Vec<u8>>, // Changed from single key to vector of keys
    ) -> bool {
        require!(self.only_sender_or_admin(&user_id), "Must be called by the msg.sender, owner, or admins");

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

    /// Stores the authenticator and user data after successful registration verification for a specific account
    ///
    /// # Arguments
    /// * `account_id` - The account ID to store the authenticator for
    /// * `registration_info` - Contains the verified credential ID, public key and optional VRF public key
    /// * `credential` - The original registration credential containing transport info and attestation data
    /// * `bootstrap_vrf_public_key` - Bootstrap VRF public key (WebAuthn-bound)
    /// * `deterministic_vrf_public_key` - Optional deterministic VRF public key for account recovery
    ///
    /// # Returns
    /// * `VerifyRegistrationResponse` - Contains verification status and registration info
    ///
    /// # Params
    /// * `self` - Mutable reference to contract state
    /// * `account_id` - The account ID to store the authenticator for
    /// * `registration_info` - RegistrationInfo struct containing credential data
    /// * `credential` - RegistrationCredential struct with transport and attestation data
    /// * `bootstrap_vrf_public_key` - Vec<u8> containing bootstrap VRF public key
    /// * `deterministic_vrf_public_key` - Optional Vec<u8> containing deterministic VRF public key
    /// * for key recovery purposes
    ///
    /// # Private
    /// This is a private non-view function that modifies contract state
    #[private]
    pub fn store_authenticator_and_user_for_account(
        &mut self,
        account_id: AccountId,
        registration_info: RegistrationInfo,
        credential: WebAuthnRegistrationCredential,
        bootstrap_vrf_public_key: Vec<u8>,
        deterministic_vrf_public_key: Option<Vec<u8>>,
    ) -> VerifyRegistrationResponse {

        log!("Storing new authenticator for account {}", account_id);
        let credential_id_b64url = BASE64_URL_ENGINE.encode(&registration_info.credential_id);

        // Parse transports from the response if available
        let transports = if let Some(transport_strings) = &credential.response.transports {
            Some(transport_strings.iter().filter_map(|t| {
                match t.as_str() {
                    "usb" => Some(AuthenticatorTransport::Usb),
                    "nfc" => Some(AuthenticatorTransport::Nfc),
                    "ble" => Some(AuthenticatorTransport::Ble),
                    "internal" => Some(AuthenticatorTransport::Internal),
                    "hybrid" => Some(AuthenticatorTransport::Hybrid),
                    _ => None,
                }
            }).collect())
        } else {
            None
        };

        // Get current timestamp as ISO string
        let current_timestamp = env::block_timestamp_ms().to_string();

        // Prepare VRF keys for storage
        let mut vrf_keys = vec![bootstrap_vrf_public_key.clone()];
        if let Some(det_key) = deterministic_vrf_public_key {
            vrf_keys.push(det_key);
            log!("Storing authenticator with dual VRF keys for account {}: bootstrap + deterministic", account_id);
        } else {
            log!("Storing authenticator with single VRF key for account {}: bootstrap only", account_id);
        }

        // Store the authenticator with multiple VRF public keys
        self.store_authenticator(
            account_id.clone(),
            credential_id_b64url.clone(),
            registration_info.credential_public_key.clone(),
            transports,
            current_timestamp,
            vrf_keys,
        );

        // 2. Register user in user registry if not already registered
        if !self.registered_users.contains(&account_id) {
            log!("Registering new user in user registry: {}", account_id);
            self.register_user(account_id.clone());
        } else {
            log!("User already registered in user registry: {}", account_id);
        }

        VerifyRegistrationResponse {
            verified: true,
            registration_info: Some(registration_info),
        }
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

    /////////////////////////////////
    /// CREDENTIAL LOOKUP
    /////////////////////////////////

    /// Get the account ID associated with a credential ID
    /// This enables efficient account discovery during recovery
    pub fn get_account_by_credential_id(&self, credential_id: String) -> Option<AccountId> {
        self.credential_to_users.get(&credential_id).cloned()
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
        self.credential_to_users.insert(credential_id, user_id);
    }

    /// Helper method to remove a credential->user mapping (used during deregistration)
    pub(crate) fn remove_credential_user_mapping(&mut self, credential_id: String, _user_id: AccountId) {
        self.credential_to_users.remove(&credential_id);
    }
}
