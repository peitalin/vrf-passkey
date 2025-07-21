// === CONFIGURATION CONSTANTS ===
// Configuration values for the WASM signer worker

// === CRYPTOGRAPHIC CONSTANTS ===

/// AES-GCM nonce size in bytes (96 bits / 12 bytes as recommended)
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// AES-256 key size in bytes
pub const AES_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Info string for AES-GCM encryption key derivation using HKDF
pub const AES_ENCRYPTION_INFO: &str = "aes-gcm-encryption-key-v1";

/// Info string for Ed25519 signing key derivation from dual PRF
pub const ED25519_DUAL_PRF_INFO: &str = "ed25519-signing-key-dual-prf-v1";

// === GAS CONSTANTS ===

/// Standard gas amount for contract verification calls (30 TGas)
pub const VERIFY_REGISTRATION_GAS: &str = "30000000000000";

/// Higher gas amount for device linking registration calls (40 TGas)
pub const DEVICE_LINKING_REGISTRATION_GAS: &str = "40000000000000";

// === ERROR MESSAGES ===

/// Error message for empty PRF output
pub const ERROR_EMPTY_PRF_OUTPUT: &str = "PRF output cannot be empty";

/// Error message for invalid key size
pub const ERROR_INVALID_KEY_SIZE: &str = "Invalid key size for AES-256";

// === UTILITY FUNCTIONS ===

/// Generate account-specific AES salt
pub fn aes_salt_for_account(account_id: &str) -> String {
    format!("aes-gcm-salt:{}", account_id)
}

/// Generate account-specific NEAR key derivation salt
pub fn near_key_salt_for_account(account_id: &str) -> String {
    format!("near-key-derivation:{}", account_id)
}