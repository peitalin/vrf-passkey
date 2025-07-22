use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey};
use getrandom::getrandom;
use hkdf::Hkdf;
use bs58;
use sha2::Sha256;
use log::{info, debug};

use crate::error::KdfError;
use crate::types::EncryptedDataAesGcmResponse;
use crate::config::{
    aes_salt_for_account,
    near_key_salt_for_account,
    AES_ENCRYPTION_INFO,
    ED25519_DUAL_PRF_INFO,
    AES_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    ED25519_PRIVATE_KEY_SIZE,
    ERROR_EMPTY_PRF_OUTPUT,
    ERROR_INVALID_KEY_SIZE,
};

// === UTILITY FUNCTIONS ===

/// Helper function for base64url decoding
pub(crate) fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| KdfError::Base64DecodeError(format!("{:?}", e)))
}

// === KEY DERIVATION ===

/// Derive account-specific AES-GCM encryption key from PRF output using HKDF
/// This provides domain separation for different accounts and is the ONLY AES derivation function
/// Used for both encryption during registration and decryption during operations
pub(crate) fn derive_aes_gcm_key_from_prf(
    prf_output_base64: &str,
    near_account_id: &str,
) -> Result<Vec<u8>, KdfError> {
    info!("Deriving account-specific AES key from PRF output using HKDF");

    // 1. Decode PRF output from base64
    let prf_output = base64_url_decode(prf_output_base64)?;

    if prf_output.is_empty() {
        return Err(KdfError::InvalidInput(ERROR_EMPTY_PRF_OUTPUT.to_string()));
    }

    // 2. Create account-specific salt for AES key derivation (different from Ed25519)
    let aes_salt = aes_salt_for_account(near_account_id);
    let salt_bytes = aes_salt.as_bytes();

    // 3. Use HKDF with account-specific domain separation
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), &prf_output);
    let mut aes_key = vec![0u8; AES_KEY_SIZE];

    let info = AES_ENCRYPTION_INFO.as_bytes();
    hk.expand(info, &mut aes_key)
        .map_err(|_| KdfError::HkdfError)?;

    info!("Successfully derived account-specific AES key ({} bytes) for {}", aes_key.len(), near_account_id);
    Ok(aes_key)
}

// === AES-GCM ENCRYPTION/DECRYPTION ===

/// Encrypt data using AES-256-GCM
pub(crate) fn encrypt_data_aes_gcm(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<EncryptedDataAesGcmResponse, String> {
    if key_bytes.len() != AES_KEY_SIZE {
        return Err(ERROR_INVALID_KEY_SIZE.to_string());
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
pub(crate) fn decrypt_data_aes_gcm(
    encrypted_data_b64u: &str,
    aes_gcm_nonce_b64u: &str,
    key_bytes: &[u8]
) -> Result<String, String> {
    if key_bytes.len() != AES_KEY_SIZE {
        return Err(ERROR_INVALID_KEY_SIZE.to_string());
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let aes_gcm_nonce_bytes = Base64UrlUnpadded::decode_vec(aes_gcm_nonce_b64u)
        .map_err(|e| format!("Base64UrlUnpadded decode error for AES-GCM nonce: {}", e))?;
    if aes_gcm_nonce_bytes.len() != AES_GCM_NONCE_SIZE {
        return Err(format!("Decryption AES-GCM nonce must be {} bytes.", AES_GCM_NONCE_SIZE));
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

/// NEW: Secure Ed25519 key derivation from PRF output (prf.results.second)
/// Pure PRF-based Ed25519 key derivation for signing purposes only
pub(crate) fn derive_ed25519_key_from_prf_output(
    prf_output_base64: &str,
    account_id: &str,
) -> Result<(String, String), KdfError> {
    info!("Deriving Ed25519 key from PRF output (dual PRF workflow)");

    // Decode PRF output from base64
    let prf_output = base64_url_decode(prf_output_base64)?;

    if prf_output.is_empty() {
        return Err(KdfError::InvalidInput(ERROR_EMPTY_PRF_OUTPUT.to_string()));
    }

    // Create account-specific salt for Ed25519 key derivation (different from AES)
    let ed25519_salt = near_key_salt_for_account(account_id);
    let salt_bytes = ed25519_salt.as_bytes();

    // Use HKDF with Ed25519-specific domain separation
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), &prf_output);
    let mut ed25519_key_material = [0u8; ED25519_PRIVATE_KEY_SIZE];

    let info = ED25519_DUAL_PRF_INFO.as_bytes();
    hk.expand(info, &mut ed25519_key_material)
        .map_err(|_| KdfError::HkdfError)?;

    // Create Ed25519 signing key from derived material
    let signing_key = SigningKey::from_bytes(&ed25519_key_material);
    let verifying_key = signing_key.verifying_key();

    // Convert to NEAR format (64 bytes: 32-byte seed + 32-byte public key)
    let seed_bytes = signing_key.to_bytes(); // 32 bytes
    let public_key_bytes = verifying_key.to_bytes(); // 32 bytes

    // NEAR private key format: concatenate seed + public key (64 bytes total)
    let mut near_private_key_bytes = Vec::with_capacity(64);
    near_private_key_bytes.extend_from_slice(&seed_bytes);
    near_private_key_bytes.extend_from_slice(&public_key_bytes);

    let private_key_b58 = bs58::encode(&near_private_key_bytes).into_string();
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();

    let near_private_key = format!("ed25519:{}", private_key_b58);
    let near_public_key = format!("ed25519:{}", public_key_b58);

    info!("Successfully derived Ed25519 key for account: {}", account_id);
    Ok((near_private_key, near_public_key))
}

/// Dual PRF workflow
/// Derives both AES and Ed25519 keys from separate PRF outputs and encrypts the Ed25519 key
pub(crate) fn derive_and_encrypt_keypair_from_dual_prf(
    dual_prf_outputs: &crate::types::DualPrfOutputs,
    account_id: &str,
) -> Result<(String, EncryptedDataAesGcmResponse), KdfError> {
    info!("Starting complete dual PRF workflow");

    // 1. Derive account-specific AES key from first PRF output (prf.results.first)
    // Use same account-specific method as decryption for consistency
    let aes_key = derive_aes_gcm_key_from_prf(&dual_prf_outputs.aes_prf_output_base64, account_id)?;
    info!("Derived account-specific AES key from first PRF output");

    // 2. Derive Ed25519 key from second PRF output (prf.results.second)
    let (near_private_key, near_public_key) = derive_ed25519_key_from_prf_output(
        &dual_prf_outputs.ed25519_prf_output_base64,
        account_id
    )?;
    info!("Derived Ed25519 key from second PRF output");

    // 3. Encrypt the Ed25519 private key using the account-specific AES key
    let encrypted_response = encrypt_data_aes_gcm(&near_private_key, &aes_key)
        .map_err(|e| KdfError::EncryptionError(e))?;

    info!("Dual PRF workflow completed successfully");
    Ok((near_public_key, encrypted_response))
}

/// Decrypt private key from stored data and return as SigningKey
/// Now uses account-specific HKDF for secure key derivation
pub fn decrypt_private_key_with_prf(
    near_account_id: &str,
    aes_prf_output: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
) -> Result<SigningKey, String> {
    info!("Decrypting private key with PRF using account-specific HKDF");

    let aes_key = derive_aes_gcm_key_from_prf(aes_prf_output, near_account_id)
        .map_err(|e| format!("Account-specific key derivation failed: {}", e))?;

    // 2. Decrypt private key using AES-GCM
    let decrypted_private_key_str = decrypt_data_aes_gcm(
        encrypted_private_key_data,
        encrypted_private_key_iv,
        &aes_key,
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
        debug!("Using 32-byte private key format (seed only)");
        private_key_bytes
    } else if private_key_bytes.len() == 64 {
        // New 64-byte format (seed + public key) - extract first 32 bytes (seed)
        debug!("Using 64-byte private key format (seed + public key)");
        private_key_bytes[0..32].to_vec()
    } else {
        return Err(format!("Invalid private key length: {} (expected 32 or 64)", private_key_bytes.len()));
    };

    // 6. Create SigningKey from the 32-byte seed
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    info!("Successfully decrypted private key");
    Ok(signing_key)
}

/// Encrypt private key with PRF output for storage
/// Returns both encrypted data and IV separately for IndexedDB storage
pub fn encrypt_private_key_with_prf(
    private_key_bytes: &str,
    prf_output_base64: &str,
    near_account_id: &str,
) -> Result<EncryptedDataAesGcmResponse, String> {
    info!("Encrypting private key with PRF output for account: {}", near_account_id);

    // Derive AES key from PRF output using account-specific HKDF
    let aes_key_bytes = derive_aes_gcm_key_from_prf(prf_output_base64, near_account_id)
        .map_err(|e| format!("Failed to derive AES key from PRF: {}", e))?;

    // Encrypt the private key
    let encrypted_result = encrypt_data_aes_gcm(private_key_bytes, &aes_key_bytes)
        .map_err(|e| format!("Failed to encrypt private key: {}", e))?;

    info!("Private key encrypted successfully");
    Ok(encrypted_result)
}



