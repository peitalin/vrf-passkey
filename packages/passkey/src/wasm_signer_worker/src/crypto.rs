use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey};
use getrandom::getrandom;
use hkdf::Hkdf;
use bs58;
use sha2::{Sha256, Digest};

use crate::error::KdfError;
use crate::types::EncryptedDataAesGcmResponse;

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

// === CONSTANTS ===
const HKDF_INFO: &str = "near-key-encryption-info-v1";
const HKDF_SALT: &str = "near-key-encryption-salt-v1";

// === UTILITY FUNCTIONS ===

/// Helper function for base64url decoding
fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| KdfError::Base64DecodeError(format!("{:?}", e)))
}

// === KEY DERIVATION ===

/// Function for deriving encryption key from PRF output
pub fn derive_encryption_key_from_prf_core(
    prf_output_base64: &str,  // Base64-encoded PRF output from WebAuthn
) -> Result<Vec<u8>, KdfError> {
    console_log!("RUST: Deriving encryption key from PRF output");

    // Decode PRF output from base64
    let prf_output = base64_url_decode(prf_output_base64)?;

    // Use PRF output directly as IKM
    let ikm = prf_output;

    // Convert info and salt to bytes
    let info_bytes = HKDF_INFO.as_bytes();
    let salt_bytes = HKDF_SALT.as_bytes();

    // Perform HKDF
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), &ikm);
    let mut okm = vec![0u8; 32]; // 32 bytes for AES-256
    hk.expand(info_bytes, &mut okm)
        .map_err(|_| KdfError::HkdfError)?;

    console_log!("RUST: Successfully derived 32-byte encryption key from PRF");
    Ok(okm)
}

// === AES-GCM ENCRYPTION/DECRYPTION ===

/// Encrypt data using AES-256-GCM
pub fn encrypt_data_aes_gcm_core(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<EncryptedDataAesGcmResponse, String> {
    if key_bytes.len() != 32 {
        return Err("Encryption key must be 32 bytes for AES-256-GCM.".to_string());
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let mut aes_gcm_nonce_bytes = [0u8; 12];
    getrandom(&mut aes_gcm_nonce_bytes)
        .map_err(|e| format!("Failed to generate IV: {}", e))?;
    let nonce = GenericArray::from_slice(&aes_gcm_nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plain_text_data_str.as_bytes())
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok(EncryptedDataAesGcmResponse {
        encrypted_near_key_data_b64u: Base64UrlUnpadded::encode_string(&ciphertext),
        aes_gcm_nonce_b64u: Base64UrlUnpadded::encode_string(&aes_gcm_nonce_bytes),
    })
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_data_aes_gcm_core(encrypted_data_b64u: &str, aes_gcm_nonce_b64u: &str, key_bytes: &[u8]) -> Result<String, String> {
    if key_bytes.len() != 32 {
        return Err("Decryption key must be 32 bytes for AES-256-GCM.".to_string());
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let aes_gcm_nonce_bytes = Base64UrlUnpadded::decode_vec(aes_gcm_nonce_b64u)
        .map_err(|e| format!("Base64UrlUnpadded decode error for AES-GCM nonce: {}", e))?;
    if aes_gcm_nonce_bytes.len() != 12 {
        return Err("Decryption AES-GCM nonce must be 12 bytes.".to_string());
    }
    let nonce = GenericArray::from_slice(&aes_gcm_nonce_bytes);

    let encrypted_data = Base64UrlUnpadded::decode_vec(encrypted_data_b64u)
        .map_err(|e| format!("Base64UrlUnpadded decode error for encrypted data: {}", e))?;

    let decrypted_bytes = cipher.decrypt(nonce, encrypted_data.as_slice())
        .map_err(|e| format!("Decryption error: {}", e))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("UTF-8 decoding error: {}", e))
}

// === KEY GENERATION ===

/// Generate a new NEAR key pair
pub fn generate_near_keypair_core() -> Result<(String, String), String> {
    console_log!("RUST: Generating new NEAR key pair");

    // Generate random bytes for the private key seed
    let mut private_key_seed = [0u8; 32];
    getrandom(&mut private_key_seed)
        .map_err(|e| format!("Failed to generate random bytes: {}", e))?;

    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&private_key_seed);

    // Get the public key bytes
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // NEAR Ed25519 private key format: 32-byte seed + 32-byte public key = 64 bytes total
    let mut full_private_key = [0u8; 64];
    full_private_key[0..32].copy_from_slice(&private_key_seed);
    full_private_key[32..64].copy_from_slice(&public_key_bytes);

    // Encode private key in NEAR format: "ed25519:BASE58_FULL_PRIVATE_KEY"
    let private_key_b58 = bs58::encode(&full_private_key).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    // Encode public key in NEAR format: "ed25519:BASE58_PUBLIC_KEY"
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();
    let public_key_near_format = format!("ed25519:{}", public_key_b58);

    console_log!("RUST: Generated NEAR key pair with public key: {}", public_key_near_format);
    console_log!("RUST: Private key is 64 bytes (seed + public key)");

    Ok((private_key_near_format, public_key_near_format))
}

/// Generate and encrypt NEAR keypair using PRF
pub fn generate_and_encrypt_near_keypair_with_prf_core(
    prf_output_base64: &str,
) -> Result<(String, EncryptedDataAesGcmResponse), String> {
    console_log!("RUST: Generating and encrypting NEAR key pair with PRF-derived key");

    // Generate the key pair
    let (private_key, public_key) = generate_near_keypair_core()?;

    // Derive encryption key from PRF output
    let encryption_key = derive_encryption_key_from_prf_core(prf_output_base64)
        .map_err(|e| format!("Key derivation failed: {:?}", e))?;

    // Encrypt the private key
    let encrypted_result = encrypt_data_aes_gcm_core(&private_key, &encryption_key)?;

    console_log!("RUST: Successfully generated and encrypted NEAR key pair with PRF");
    Ok((public_key, encrypted_result))
}

/// Derive NEAR Ed25519 key from WebAuthn COSE P-256 public key
pub fn derive_near_keypair_from_cose_p256_core(
    x_coordinate_bytes: &[u8],
    y_coordinate_bytes: &[u8],
) -> Result<(String, String), String> {
    console_log!("RUST: Deriving NEAR key pair from P-256 COSE coordinates (matching contract)");

    if x_coordinate_bytes.len() != 32 || y_coordinate_bytes.len() != 32 {
        return Err("P-256 coordinates must be 32 bytes each".to_string());
    }

    // Concatenate x and y coordinates (same as contract)
    let mut p256_material = Vec::new();
    p256_material.extend_from_slice(x_coordinate_bytes);
    p256_material.extend_from_slice(y_coordinate_bytes);

    // SHA-256 hash (same as contract)
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, &p256_material);
    let hash_bytes = Digest::finalize(hasher);

    // Use hash as Ed25519 seed (same as contract)
    let private_key_seed: [u8; 32] = hash_bytes.into();
    let signing_key = SigningKey::from_bytes(&private_key_seed);

    // Get the public key bytes
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // NEAR Ed25519 private key format: 32-byte seed + 32-byte public key = 64 bytes total
    let mut full_private_key = [0u8; 64];
    full_private_key[0..32].copy_from_slice(&private_key_seed);
    full_private_key[32..64].copy_from_slice(&public_key_bytes);

    // Encode private key in NEAR format: "ed25519:BASE58_FULL_PRIVATE_KEY"
    let private_key_b58 = bs58::encode(&full_private_key).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    // Encode public key in NEAR format: "ed25519:BASE58_PUBLIC_KEY"
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();
    let public_key_near_format = format!("ed25519:{}", public_key_b58);

    console_log!("RUST: Derived deterministic NEAR key with public key: {}", public_key_near_format);
    console_log!("RUST: Private key is 64 bytes (seed + public key)");

    Ok((private_key_near_format, public_key_near_format))
}

/// Decrypt private key from stored data and return as SigningKey
pub fn decrypt_private_key_with_prf_core(
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
) -> Result<SigningKey, String> {
    console_log!("RUST: Decrypting private key with PRF");

    // 1. Derive decryption key from PRF
    let decryption_key = derive_encryption_key_from_prf_core(prf_output_base64)
        .map_err(|e| format!("Key derivation failed: {:?}", e))?;

    // 2. Decrypt private key using AES-GCM
    let decrypted_private_key_str = decrypt_data_aes_gcm_core(
        encrypted_private_key_data,
        encrypted_private_key_iv,
        &decryption_key,
    )?;

    // 3. Parse private key (remove ed25519: prefix if present)
    let private_key_b58 = if decrypted_private_key_str.starts_with("ed25519:") {
        &decrypted_private_key_str[8..]
    } else {
        &decrypted_private_key_str
    };

    // 4. Decode private key from base58
    let private_key_bytes = bs58::decode(private_key_b58)
        .into_vec()
        .map_err(|e| format!("Failed to decode private key: {}", e))?;

    // 5. Handle both 32-byte (seed only) and 64-byte (seed + public key) formats
    let seed_bytes = if private_key_bytes.len() == 32 {
        // Legacy 32-byte format (seed only)
        console_log!("RUST: Using 32-byte private key format (seed only)");
        private_key_bytes
    } else if private_key_bytes.len() == 64 {
        // New 64-byte format (seed + public key) - extract first 32 bytes (seed)
        console_log!("RUST: Using 64-byte private key format (seed + public key)");
        private_key_bytes[0..32].to_vec()
    } else {
        return Err(format!("Invalid private key length: {} (expected 32 or 64)", private_key_bytes.len()));
    };

    // 6. Create SigningKey from the 32-byte seed
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    console_log!("RUST: Successfully decrypted private key");
    Ok(signing_key)
}