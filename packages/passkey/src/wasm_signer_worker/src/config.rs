/// Cryptographic configuration constants for the WASM signer worker
///
/// This module centralizes all cryptographic constants to ensure consistency
/// and make updates easier. All salt, info, and domain separation strings
/// are defined here.

// === LOGGING CONFIGURATION ===

/// Log level for the signer worker
/// Change this constant and recompile to adjust logging verbosity
/// Levels: Error = 1, Warn = 2, Info = 3, Debug = 4, Trace = 5
pub const CURRENT_LOG_LEVEL: log::Level = log::Level::Debug;

// === AES-GCM ENCRYPTION CONSTANTS ===

/// Salt template for account-specific AES key derivation
/// Format: "aes-gcm-salt:{account_id}"
pub const AES_SALT_TEMPLATE: &str = "aes-gcm-salt:{}";

/// Info string for AES-GCM encryption key derivation using HKDF
pub const AES_ENCRYPTION_INFO: &str = "aes-gcm-encryption-key-v1";

// === ED25519 KEY DERIVATION CONSTANTS ===

/// Salt template for account-specific NEAR key derivation
/// Format: "near-key-derivation:{account_id}"
pub const NEAR_KEY_SALT_TEMPLATE: &str = "near-key-derivation:{}";

/// Info string for NEAR Ed25519 key derivation using HKDF
pub const NEAR_KEY_DERIVATION_INFO: &str = "near-key-derivation-info-v1";

/// Info string for Ed25519 signing key derivation from dual PRF
pub const ED25519_DUAL_PRF_INFO: &str = "ed25519-signing-key-dual-prf-v1";

// === CRYPTOGRAPHIC PARAMETERS ===

/// AES-256 key size in bytes
pub const AES_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// AES-GCM nonce size in bytes (standard is 12 bytes for AES-GCM)
pub const AES_GCM_NONCE_SIZE: usize = 12;

// === VALIDATION CONSTANTS ===

/// Minimum allowed account ID length
pub const MIN_ACCOUNT_ID_LENGTH: usize = 2;

/// Maximum allowed account ID length
pub const MAX_ACCOUNT_ID_LENGTH: usize = 64;

// === ERROR MESSAGES ===

/// Error message for empty PRF output
pub const ERROR_EMPTY_PRF_OUTPUT: &str = "PRF output cannot be empty";

/// Error message for invalid key size
pub const ERROR_INVALID_KEY_SIZE: &str = "Invalid key size for AES-256";

/// Error message for HKDF expansion failure
pub const ERROR_HKDF_EXPANSION: &str = "HKDF key expansion failed";

/// Error message for invalid account ID
pub const ERROR_INVALID_ACCOUNT_ID: &str = "Invalid NEAR account ID format";

// === UTILITY FUNCTIONS ===

/// Generate account-specific AES salt
pub fn aes_salt_for_account(account_id: &str) -> String {
    AES_SALT_TEMPLATE.replace("{}", account_id)
}

/// Generate account-specific NEAR key derivation salt
pub fn near_key_salt_for_account(account_id: &str) -> String {
    NEAR_KEY_SALT_TEMPLATE.replace("{}", account_id)
}

/// Validate account ID length
pub fn validate_account_id_length(account_id: &str) -> Result<(), String> {
    let len = account_id.len();
    if len < MIN_ACCOUNT_ID_LENGTH {
        return Err(format!("{}: too short (minimum {} chars)", ERROR_INVALID_ACCOUNT_ID, MIN_ACCOUNT_ID_LENGTH));
    }
    if len > MAX_ACCOUNT_ID_LENGTH {
        return Err(format!("{}: too long (maximum {} chars)", ERROR_INVALID_ACCOUNT_ID, MAX_ACCOUNT_ID_LENGTH));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation() {
        let account_id = "test.near";

        let aes_salt = aes_salt_for_account(account_id);
        assert_eq!(aes_salt, "aes-gcm-salt:test.near");

        let near_salt = near_key_salt_for_account(account_id);
        assert_eq!(near_salt, "near-key-derivation:test.near");
    }

    #[test]
    fn test_account_id_validation() {
        // Valid account IDs
        assert!(validate_account_id_length("test.near").is_ok());
        assert!(validate_account_id_length("ab").is_ok());

        // Invalid account IDs
        assert!(validate_account_id_length("a").is_err()); // Too short
        assert!(validate_account_id_length(&"a".repeat(65)).is_err()); // Too long
    }

    #[test]
    fn test_constants() {
        assert_eq!(AES_KEY_SIZE, 32);
        assert_eq!(ED25519_PRIVATE_KEY_SIZE, 32);
        assert_eq!(ED25519_PUBLIC_KEY_SIZE, 32);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
        assert_eq!(AES_GCM_NONCE_SIZE, 12);
    }
}