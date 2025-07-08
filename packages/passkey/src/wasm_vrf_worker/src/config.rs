/// VRF Worker Configuration Constants
///
/// This module contains all configuration constants used by the VRF worker,
/// including cryptographic parameters, domain separators, and other configurable values.

// === CRYPTOGRAPHIC CONSTANTS ===

/// Domain separator for VRF challenge generation
/// Used to ensure VRF challenges are domain-specific and cannot be replayed across different contexts
pub const VRF_DOMAIN_SEPARATOR: &[u8] = b"web3_authn_vrf_challenge_v1";

/// HKDF info string for AES key derivation from PRF output
/// Used for both VRF keypair encryption and general AES operations
pub const HKDF_AES_KEY_INFO: &[u8] = b"vrf-aes-key";

/// HKDF info string for VRF keypair derivation from PRF output
/// Used for deterministic VRF keypair generation during account recovery
pub const HKDF_VRF_KEYPAIR_INFO: &[u8] = b"vrf-keypair-derivation-v1";

// === ENCRYPTION PARAMETERS ===

/// AES-GCM key size in bytes (256 bits)
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM nonce/IV size in bytes (96 bits)
pub const AES_NONCE_SIZE: usize = 12;

/// VRF seed size in bytes for deterministic generation (256 bits)
pub const VRF_SEED_SIZE: usize = 32;

// === JSON FIELD NAMES ===

/// JSON field names for VRF challenge data serialization
pub mod vrf_challenge_fields {
    pub const VRF_INPUT: &str = "vrfInput";
    pub const VRF_OUTPUT: &str = "vrfOutput";
    pub const VRF_PROOF: &str = "vrfProof";
    pub const VRF_PUBLIC_KEY: &str = "vrfPublicKey";
    pub const USER_ID: &str = "userId";
    pub const RP_ID: &str = "rpId";
    pub const BLOCK_HEIGHT: &str = "blockHeight";
    pub const BLOCK_HASH: &str = "blockHash";
}

/// JSON field names for encrypted VRF keypair data
pub mod encrypted_keypair_fields {
    pub const ENCRYPTED_VRF_DATA: &str = "encrypted_vrf_data_b64u";
    pub const AES_GCM_NONCE: &str = "aes_gcm_nonce_b64u";
}

/// JSON field names for worker messages
pub mod worker_message_fields {
    pub const MESSAGE_TYPE: &str = "type";
    pub const NEAR_ACCOUNT_ID: &str = "nearAccountId";
    pub const ENCRYPTED_VRF_KEYPAIR: &str = "encryptedVrfKeypair";
    pub const PRF_KEY: &str = "prfKey";
    pub const VRF_INPUT_PARAMS: &str = "vrfInputParams";
    pub const EXPECTED_PUBLIC_KEY: &str = "expectedPublicKey";
    pub const PRF_OUTPUT: &str = "prfOutput";
}

/// JSON field names for status responses
pub mod status_fields {
    pub const ACTIVE: &str = "active";
    pub const SESSION_DURATION: &str = "sessionDuration";
    pub const STATUS: &str = "status";
    pub const TIMESTAMP: &str = "timestamp";
    pub const ALIVE: &str = "alive";
}

// === WORKER MESSAGE TYPES ===

/// VRF Worker message type constants
pub mod message_types {
    pub const PING: &str = "PING";
    pub const UNLOCK_VRF_KEYPAIR: &str = "UNLOCK_VRF_KEYPAIR";
    pub const GENERATE_VRF_CHALLENGE: &str = "GENERATE_VRF_CHALLENGE";
    pub const GENERATE_VRF_KEYPAIR_BOOTSTRAP: &str = "GENERATE_VRF_KEYPAIR_BOOTSTRAP";
    pub const ENCRYPT_VRF_KEYPAIR_WITH_PRF: &str = "ENCRYPT_VRF_KEYPAIR_WITH_PRF";
    pub const CHECK_VRF_STATUS: &str = "CHECK_VRF_STATUS";
    pub const LOGOUT: &str = "LOGOUT";
    pub const DERIVE_VRF_KEYPAIR_FROM_PRF: &str = "DERIVE_VRF_KEYPAIR_FROM_PRF";
}

// === ERROR MESSAGES ===

/// Common error message constants
pub mod error_messages {
    pub const NO_VRF_KEYPAIR: &str = "No VRF keypair in memory - please generate keypair first";
    pub const VRF_NOT_UNLOCKED: &str = "VRF keypair not unlocked - please login first";
    pub const PRF_OUTPUT_EMPTY: &str = "PRF output cannot be empty";
    pub const HKDF_KEY_DERIVATION_FAILED: &str = "HKDF key derivation failed";
    pub const HKDF_VRF_SEED_DERIVATION_FAILED: &str = "HKDF VRF seed derivation failed";
    pub const INVALID_IV_LENGTH: &str = "Invalid IV length for AES-GCM";
    pub const FAILED_TO_STRINGIFY: &str = "Failed to stringify message";
    pub const MESSAGE_NOT_STRING: &str = "Message is not a string";
    pub const FAILED_TO_SERIALIZE: &str = "failed to serialize";
}

// === LOG MESSAGES ===

/// Common log message constants for consistency
pub mod log_messages {
    pub const VRF_MANAGER_READY: &str = "VRF WASM Web Worker: VRFKeyManager ready (no user session active)";
    pub const GENERATING_BOOTSTRAP: &str = "VRF WASM Web Worker: Generating VRF keypair for bootstrapping";
    pub const KEYPAIR_IN_MEMORY: &str = "VRF keypair will be stored in memory unencrypted until PRF encryption";
    pub const KEYPAIR_GENERATED: &str = "VRF WASM Web Worker: VRF keypair generated and stored in memory";
    pub const BOOTSTRAP_COMPLETED: &str = "VRF WASM Web Worker: VRF keypair bootstrap completed";
    pub const ENCRYPTING_KEYPAIR: &str = "VRF WASM Web Worker: Encrypting VRF keypair with PRF output";
    pub const PUBLIC_KEY_VERIFIED: &str = "VRF WASM Web Worker: Public key verification successful";
    pub const KEYPAIR_ENCRYPTED: &str = "VRF WASM Web Worker: VRF keypair encrypted with PRF output";
    pub const READY_FOR_STORAGE: &str = "VRF keypair ready for persistent storage";
    pub const KEYPAIR_UNLOCKED: &str = "✅ VRF WASM Web Worker: VRF keypair unlocked successfully";
    pub const GENERATING_CHALLENGE: &str = "VRF WASM Web Worker: Generating VRF challenge";
    pub const CHALLENGE_GENERATED: &str = "VRF WASM Web Worker: VRF challenge generated successfully";
    pub const LOGGING_OUT: &str = "VRF WASM Web Worker: Logging out and securely clearing VRF keypair";
    pub const KEYPAIR_CLEARED: &str = "VRF WASM Web Worker: VRF keypair cleared with automatic zeroization";
    pub const SESSION_CLEARED: &str = "VRF WASM Web Worker: Session cleared securely with automatic zeroization";
    pub const DERIVING_AES_KEY: &str = "VRF WASM Web Worker: Deriving AES key using HKDF-SHA256";
    pub const KEYPAIR_RESTORED: &str = "VRF WASM Web Worker: VRF keypair successfully restored from bincode";
    pub const GENERATING_SECURE_KEYPAIR: &str = "VRF WASM Web Worker: Generating VRF keypair with secure randomness";
    pub const SECURE_KEYPAIR_GENERATED: &str = "VRF WASM Web Worker: VRF keypair generated successfully";
    pub const DETERMINISTIC_KEYPAIR_GENERATED: &str = "VRF WASM Web Worker: Deterministic VRF keypair generated successfully";
    pub const ENCRYPTING_KEYPAIR_DATA: &str = "VRF WASM Web Worker: Encrypting VRF keypair data";
    pub const KEYPAIR_DATA_ENCRYPTED: &str = "VRF WASM Web Worker: VRF keypair encrypted successfully";
    pub const DERIVING_AES_FOR_ENCRYPTION: &str = "VRF WASM Web Worker: Deriving AES key using HKDF-SHA256 for encryption";
}

// === DISPLAY TRUNCATION ===

/// Number of characters to show when displaying truncated keys/hashes in logs
pub const DISPLAY_TRUNCATE_LENGTH: usize = 20;
