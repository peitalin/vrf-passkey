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
fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
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

//////////////////////////
/// Tests
//////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DualPrfOutputs;

    #[test]
    fn test_account_specific_aes_key_edge_cases() {
        // Test with empty PRF output
        let empty_prf = "";
        let account_id = "test.testnet";
        let result = derive_aes_gcm_key_from_prf(empty_prf, account_id);
        assert!(result.is_err());

        // Test with invalid base64
        let invalid_b64 = "not_valid_base64!!!";
        let result = derive_aes_gcm_key_from_prf(invalid_b64, account_id);
        assert!(result.is_err());

        // Test with short PRF output
        let short_prf = "YQ"; // base64 for "a"
        let result = derive_aes_gcm_key_from_prf(short_prf, account_id);
        assert!(result.is_ok()); // Should work with HKDF expansion

        // Test with different accounts producing different keys
        let test_prf = "dGVzdC1wcmYtb3V0cHV0";
        let key1 = derive_aes_gcm_key_from_prf(test_prf, "account1.testnet").unwrap();
        let key2 = derive_aes_gcm_key_from_prf(test_prf, "account2.testnet").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_edge_cases() {
        let key = vec![0u8; 32];

        // Test empty string
        let encrypted = encrypt_data_aes_gcm("", &key).unwrap();
        let decrypted = decrypt_data_aes_gcm(
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
            &key
        ).unwrap();
        assert_eq!(decrypted, "");

        // Test large string
        let large_data = "x".repeat(10000);
        let encrypted = encrypt_data_aes_gcm(&large_data, &key).unwrap();
        let decrypted = decrypt_data_aes_gcm(
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
            &key
        ).unwrap();
        assert_eq!(decrypted, large_data);

        // Test Unicode data
        let unicode_data = "Hello 世界 🌍 مرحبا עולם";
        let encrypted = encrypt_data_aes_gcm(unicode_data, &key).unwrap();
        let decrypted = decrypt_data_aes_gcm(
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
            &key
        ).unwrap();
        assert_eq!(decrypted, unicode_data);
    }

    #[test]
    fn test_decrypt_aes_gcm_invalid_data() {
        let key = vec![0u8; 32];

        // Test with invalid base64url data
        let result = decrypt_data_aes_gcm("invalid_base64!!!", "dmFsaWRfbm9uY2U", &key);
                assert!(result.is_err());

        // Test with invalid nonce
        let result = decrypt_data_aes_gcm("dGVzdA", "invalid_nonce!!!", &key);
        assert!(result.is_err());

        // Test with wrong key
        let encrypted = encrypt_data_aes_gcm("test", &key).unwrap();
        let wrong_key = vec![1u8; 32];
        let result = decrypt_data_aes_gcm(
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
            &wrong_key
        );
        assert!(result.is_err());

        // Test with corrupted ciphertext
        let encrypted = encrypt_data_aes_gcm("test", &key).unwrap();
        let mut corrupted_data = encrypted.encrypted_near_key_data_b64u;
        corrupted_data.push('x'); // Corrupt the data
        let result = decrypt_data_aes_gcm(&corrupted_data, &encrypted.aes_gcm_nonce_b64u, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_private_key_with_prf_invalid_formats() {
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0";
        let account_id = "test.testnet";

        // Test with empty encrypted data
        let result = decrypt_private_key_with_prf(account_id, prf_output_b64, "", "dGVzdA");
        assert!(result.is_err());

        // Test with empty IV
        let result = decrypt_private_key_with_prf(account_id, prf_output_b64, "dGVzdA", "");
        assert!(result.is_err());

        // Test with invalid base64
        let result = decrypt_private_key_with_prf(account_id, prf_output_b64, "invalid!!!", "dGVzdA");
        assert!(result.is_err());

        // Test with empty PRF output
        let result = decrypt_private_key_with_prf(account_id, "", "dGVzdA", "dGVzdA");
        assert!(result.is_err());

        // Test with empty account ID
        let result = decrypt_private_key_with_prf("", prf_output_b64, "dGVzdA", "dGVzdA");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_url_decode_edge_cases() {
        // Test valid base64url
        let result = base64_url_decode("SGVsbG8");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");

        // Test with valid base64url (unpadded) - base64url doesn't use padding
        let result = base64_url_decode("SGVsbG8");
        assert!(result.is_ok());

        // Test empty string
        let result = base64_url_decode("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());

        // Test invalid characters
        let result = base64_url_decode("invalid!");
        assert!(result.is_err());

        // Test URL-safe characters (- and _ instead of + and /)
        let result = base64_url_decode("SGVsbG8_LQ");
        assert!(result.is_ok());

        // Test that padded strings fail (base64url should be unpadded)
        let result = base64_url_decode("SGVsbG8=");
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_key_consistency() {
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0";
        let account_id = "test.testnet";

        // Test that the same inputs always produce the same key
        for _ in 0..10 {
            let key1 = derive_aes_gcm_key_from_prf(prf_output_b64, account_id).unwrap();
            let key2 = derive_aes_gcm_key_from_prf(prf_output_b64, account_id).unwrap();
            assert_eq!(key1, key2);
        }
    }

    #[test]
    fn test_near_key_format_validation() {
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0";
        let account_id = "test.testnet";

        let (private_key, public_key) = derive_ed25519_key_from_prf_output(prf_output_b64, account_id).unwrap();

        // Validate format
        assert!(private_key.starts_with("ed25519:"));
        assert!(public_key.starts_with("ed25519:"));

        // Validate base58 encoding
        let private_b58 = &private_key[8..];
        let public_b58 = &public_key[8..];

        let private_bytes = bs58::decode(private_b58).into_vec().unwrap();
        let public_bytes = bs58::decode(public_b58).into_vec().unwrap();

        // Private key should be 64 bytes (32-byte seed + 32-byte public key)
        assert_eq!(private_bytes.len(), 64);
        // Public key should be 32 bytes
        assert_eq!(public_bytes.len(), 32);

        // Last 32 bytes of private key should match public key
        assert_eq!(&private_bytes[32..], &public_bytes[..]);
    }

    #[test]
    fn test_derive_account_specific_aes_key() {
        let prf_output = "dGVzdC1wcmYtb3V0cHV0LWFhYWFhYWFhYWFhYQ";
        let account_id = "test.testnet";

        // Test normal operation
        let key = derive_aes_gcm_key_from_prf(prf_output, account_id).unwrap();
        assert_eq!(key.len(), 32);

        // Test deterministic behavior
        let key2 = derive_aes_gcm_key_from_prf(prf_output, account_id).unwrap();
        assert_eq!(key, key2);

        // Test different accounts produce different keys
        let key3 = derive_aes_gcm_key_from_prf(prf_output, "different.testnet").unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_derive_ed25519_key_from_prf_output() {
        let prf_output = "dGVzdC1wcmYtb3V0cHV0LWFhYWFhYWFhYWFhYQ";
        let account_id = "test.testnet";

        // Test normal operation
        let (private_key, public_key) = derive_ed25519_key_from_prf_output(prf_output, account_id).unwrap();
        assert!(private_key.starts_with("ed25519:"));
        assert!(public_key.starts_with("ed25519:"));

        // Test deterministic behavior
        let (private_key2, public_key2) = derive_ed25519_key_from_prf_output(prf_output, account_id).unwrap();
        assert_eq!(private_key, private_key2);
        assert_eq!(public_key, public_key2);

        // Test different account produces different keys
        let (private_key3, public_key3) = derive_ed25519_key_from_prf_output(prf_output, "different.testnet").unwrap();
        assert_ne!(private_key, private_key3);
        assert_ne!(public_key, public_key3);
    }

    #[test]
    fn test_derive_and_encrypt_keypair_from_dual_prf() {
        let dual_prf = DualPrfOutputs {
            aes_prf_output_base64: "dGVzdC1hZXMtcHJmLW91dHB1dA".to_string(),
            ed25519_prf_output_base64: "dGVzdC1lZDI1NTE5LXByZi1vdXRwdXQ".to_string(),
        };
        let account_id = "test.testnet";

        // Test normal operation
        let (public_key, encrypted_data) = derive_and_encrypt_keypair_from_dual_prf(&dual_prf, account_id).unwrap();
        assert!(public_key.starts_with("ed25519:"));
        assert!(!encrypted_data.encrypted_near_key_data_b64u.is_empty());
        assert!(!encrypted_data.aes_gcm_nonce_b64u.is_empty());

        // Test deterministic behavior
        let (public_key2, _encrypted_data2) = derive_and_encrypt_keypair_from_dual_prf(&dual_prf, account_id).unwrap();
        assert_eq!(public_key, public_key2);

        // Test different account produces different keys
        let (public_key3, _) = derive_and_encrypt_keypair_from_dual_prf(&dual_prf, "different.testnet").unwrap();
        assert_ne!(public_key, public_key3);
    }

    #[test]
    fn test_dual_prf_key_isolation() {
        let dual_prf = DualPrfOutputs {
            aes_prf_output_base64: "dGVzdC1hZXMtcHJmLW91dHB1dA".to_string(),
            ed25519_prf_output_base64: "dGVzdC1lZDI1NTE5LXByZi1vdXRwdXQ".to_string(),
        };
        let account_id = "test.testnet";

        // Derive AES key separately
        let _aes_key = derive_aes_gcm_key_from_prf(&dual_prf.aes_prf_output_base64, account_id).unwrap();

        // Derive Ed25519 key separately
        let (_ed25519_private, _ed25519_public) = derive_ed25519_key_from_prf_output(&dual_prf.ed25519_prf_output_base64, account_id).unwrap();

        // Test that changing AES PRF doesn't affect Ed25519 derivation
        let modified_dual_prf = DualPrfOutputs {
            aes_prf_output_base64: "ZGlmZmVyZW50LWFlcy1wcmYtb3V0cHV0".to_string(),
            ed25519_prf_output_base64: dual_prf.ed25519_prf_output_base64.clone(),
        };

        let (ed25519_private2, ed25519_public2) = derive_ed25519_key_from_prf_output(&modified_dual_prf.ed25519_prf_output_base64, account_id).unwrap();

        // Ed25519 keys should be the same since we didn't change the Ed25519 PRF
        assert_eq!(_ed25519_private, ed25519_private2);
        assert_eq!(_ed25519_public, ed25519_public2);
    }

    #[test]
    fn test_dual_prf_edge_cases() {
        let account_id = "test.testnet";

        // Test with minimal PRF outputs
        let minimal_dual_prf = DualPrfOutputs {
            aes_prf_output_base64: "YQ".to_string(), // base64 for "a"
            ed25519_prf_output_base64: "YQ".to_string(),
        };

        let result = derive_and_encrypt_keypair_from_dual_prf(&minimal_dual_prf, account_id);
        assert!(result.is_ok());

        // Test with empty PRF outputs (should fail)
        let empty_dual_prf = DualPrfOutputs {
            aes_prf_output_base64: "".to_string(),
            ed25519_prf_output_base64: "".to_string(),
        };

        let result = derive_and_encrypt_keypair_from_dual_prf(&empty_dual_prf, account_id);
        assert!(result.is_err());

        // Test with invalid base64 (should fail)
        let invalid_dual_prf = DualPrfOutputs {
            aes_prf_output_base64: "invalid!!!".to_string(),
            ed25519_prf_output_base64: "dGVzdA".to_string(),
        };

        let result = derive_and_encrypt_keypair_from_dual_prf(&invalid_dual_prf, account_id);
        assert!(result.is_err());
    }
}