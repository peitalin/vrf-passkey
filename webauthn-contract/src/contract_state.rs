use near_sdk::{AccountId, PanicOnDefault, BorshStorageKey};
use near_sdk::store::{LookupMap, IterableSet, IterableMap};
use near_sdk::borsh::BorshSerialize;

/// VRF configuration settings
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct VRFSettings {
    pub max_input_age_ms: u64, // Maximum age for VRF input components (default: 5 minutes)
    pub max_block_age: u64,    // Maximum block age for block hash validation
    pub enabled: bool,         // Feature flag for VRF functionality
    pub max_authenticators_per_account: usize, // Maximum number of authenticators per account
}

impl Default for VRFSettings {
    fn default() -> Self {
        Self {
            max_input_age_ms: 300_000, // 5 minutes
            max_block_age: 100,        // 100 blocks (~60 seconds, accommodates TouchID delays)
            enabled: true,
            max_authenticators_per_account: 5,
        }
    }
}

/// Account creation configuration settings
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct AccountCreationSettings {
    pub initial_balance_near: f64,  // Initial balance to transfer to new accounts (in NEAR tokens)
    pub enabled: bool,              // Feature flag for account creation functionality
    pub max_accounts_per_day: u32,  // Rate limiting for account creation
}

impl Default for AccountCreationSettings {
    fn default() -> Self {
        Self {
            initial_balance_near: 0.1,  // 0.1 NEAR default
            enabled: true,
            max_accounts_per_day: 1000, // Reasonable default limit
        }
    }
}

/// Stored authenticator data (part of contract state)
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String, // ISO timestamp of registration
    pub vrf_public_keys: Vec<Vec<u8>>, // VRF public keys for stateless authentication (max 5, FIFO)
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticatorTransport {
    #[serde(rename = "usb")]
    Usb,
    #[serde(rename = "nfc")]
    Nfc,
    #[serde(rename = "ble")]
    Ble,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "hybrid")]
    Hybrid,
}

/// Storage keys for the contract's persistent collections
#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    Authenticators,
    RegisteredUsers,
    Admins,
    CredentialToUsers,
}

/// Main contract state
#[near_sdk::near(contract_state)]
#[derive(PanicOnDefault)]
pub struct WebAuthnContract {
    pub greeting: String,
    pub contract_name: String,
    pub admins: IterableSet<AccountId>,
    // Global VRF configuration
    pub vrf_settings: VRFSettings,
    // Account creation configuration - Comment out for now to maintain consistency with existing deployed state
    pub account_creation_settings: AccountCreationSettings,
    // Authenticators: 1-to-many: AccountId -> [{ CredentialID: AuthenticatorData }, ...]
    pub authenticators: LookupMap<AccountId, IterableMap<String, StoredAuthenticator>>,
    // Registered users
    pub registered_users: IterableSet<AccountId>,
    // Lookup accounts associated with a WebAuthn (TouchId) credential_id
    pub credential_to_users: LookupMap<String, Vec<AccountId>>,
}