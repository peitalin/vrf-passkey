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

/// Function for deriving AES-GCM encryption key from PRF output
pub(crate) fn derive_aes_gcm_encryption_key_from_prf_core(
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
pub(crate) fn encrypt_data_aes_gcm_core(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<EncryptedDataAesGcmResponse, String> {
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
pub(crate) fn decrypt_data_aes_gcm_core(encrypted_data_b64u: &str, aes_gcm_nonce_b64u: &str, key_bytes: &[u8]) -> Result<String, String> {
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

/// Derive and encrypt NEAR keypair from COSE P-256 credential (RECOMMENDED)
pub(crate) fn internal_derive_near_keypair_from_cose_and_encrypt_with_prf(
    attestation_object_b64u: &str,
    prf_output_base64: &str,
) -> Result<(String, EncryptedDataAesGcmResponse), String> {
    console_log!("RUST: Deriving deterministic NEAR key pair from COSE P-256 credential");

    // 1. Extract COSE P-256 public key from WebAuthn attestation
    let cose_key_bytes = crate::cose::extract_cose_public_key_from_attestation_core(attestation_object_b64u)
        .map_err(|e| format!("Failed to extract COSE key: {}", e))?;

    // 2. Extract P-256 coordinates from COSE key
    let (x_coord, y_coord) = crate::cose::extract_p256_coordinates_from_cose(&cose_key_bytes)
        .map_err(|e| format!("Failed to extract P-256 coordinates: {}", e))?;

    // 3. Derive deterministic NEAR keypair from P-256 coordinates
    let (private_key, public_key) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord)?;

    // 4. Derive encryption key from PRF output
    let encryption_key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_base64)
        .map_err(|e| format!("Key derivation failed: {:?}", e))?;

    // 5. Encrypt the deterministic private key
    let encrypted_result = encrypt_data_aes_gcm_core(&private_key, &encryption_key)?;

    console_log!("RUST: Successfully derived and encrypted deterministic NEAR key pair");
    console_log!("RUST: NEAR keypair cryptographically bound to WebAuthn P-256 credential");
    Ok((public_key, encrypted_result))
}

/// Derive NEAR Ed25519 key from WebAuthn COSE P-256 public key
pub(crate) fn internal_derive_near_keypair_from_cose_p256(
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
    let decryption_key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_base64)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_aes_gcm_encryption_key_edge_cases() {
        // Test with empty PRF output (should still work as valid base64)
        let empty_prf = ""; // Empty string is valid base64
        let result = derive_aes_gcm_encryption_key_from_prf_core(empty_prf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);

        // Test with invalid base64
        let invalid_b64 = "Invalid@Base64!";
        let result = derive_aes_gcm_encryption_key_from_prf_core(invalid_b64);
        assert!(result.is_err());

        // Test with very short PRF output
        let short_prf = "YQ"; // "a" in base64
        let result = derive_aes_gcm_encryption_key_from_prf_core(short_prf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);

        // Test deterministic behavior
        let test_prf = "dGVzdCBwcmYgb3V0cHV0";
        let key1 = derive_aes_gcm_encryption_key_from_prf_core(test_prf).unwrap();
        let key2 = derive_aes_gcm_encryption_key_from_prf_core(test_prf).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_edge_cases() {
        let key = vec![0xAAu8; 32]; // Valid 32-byte key

        // Test with empty plaintext
        let empty_text = "";
        let encrypted = encrypt_data_aes_gcm_core(empty_text, &key).unwrap();
        let decrypted = decrypt_data_aes_gcm_core(
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
            &key
        ).unwrap();
        assert_eq!(decrypted, empty_text);

        // Test with very long plaintext
        let long_text = "A".repeat(10000);
        let encrypted = encrypt_data_aes_gcm_core(&long_text, &key).unwrap();
        let decrypted = decrypt_data_aes_gcm_core(
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
            &key
        ).unwrap();
        assert_eq!(decrypted, long_text);

        // Test with invalid key length
        let wrong_key = vec![0xAAu8; 16]; // Wrong length
        let result = encrypt_data_aes_gcm_core("test", &wrong_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Encryption key must be 32 bytes"));

        // Test decryption with wrong key length
        let valid_encrypted = encrypt_data_aes_gcm_core("test", &key).unwrap();
        let decrypt_result = decrypt_data_aes_gcm_core(
            &valid_encrypted.encrypted_near_key_data_b64u,
            &valid_encrypted.aes_gcm_nonce_b64u,
            &wrong_key
        );
        assert!(decrypt_result.is_err());
        assert!(decrypt_result.unwrap_err().contains("Decryption key must be 32 bytes"));
    }

    #[test]
    fn test_decrypt_aes_gcm_invalid_data() {
        // Test decryption with invalid data
        let key = [0u8; 32];

        // Invalid base64 encoded data should fail
        let result = decrypt_data_aes_gcm_core(
            "Invalid@Base64!!!",  // Contains invalid base64 characters
            "QUJDREVGRzEyMzQ1Ngo", // Valid 12-byte IV in base64
            &key,
        );
                assert!(result.is_err());
        let error_msg = result.unwrap_err();
        // Check for any kind of decryption-related error
        assert!(error_msg.contains("decode error") || error_msg.contains("Base64") || error_msg.contains("decode") || error_msg.contains("Decryption") || error_msg.contains("nonce") || error_msg.contains("bytes"));

        // Invalid base64 IV should fail
        let result = decrypt_data_aes_gcm_core(
            "SGVsbG8xMjM", // Valid data
            "Invalid@Base64!!!", // Contains invalid base64 characters
            &key,
        );
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        // Check for any kind of decryption-related error
        assert!(error_msg.contains("decode error") || error_msg.contains("Base64") || error_msg.contains("decode") || error_msg.contains("Decryption") || error_msg.contains("nonce") || error_msg.contains("bytes"));

        // Valid base64 but wrong nonce length should fail
        let result = decrypt_data_aes_gcm_core(
            "SGVsbG8", // Valid data
            "SGVsbG8", // Valid base64 but wrong length (5 bytes, not 12)
            &key,
        );
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Decryption AES-GCM nonce must be 12 bytes"));
    }

    #[test]
    fn test_internal_derive_near_keypair_from_cose_p256_edge_cases() {
        // Test with invalid coordinate lengths
        let wrong_x = vec![0x42u8; 31]; // Wrong length
        let wrong_y = vec![0x84u8; 33]; // Wrong length

        let result = internal_derive_near_keypair_from_cose_p256(&wrong_x, &[0x84u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("P-256 coordinates must be 32 bytes each"));

        let result = internal_derive_near_keypair_from_cose_p256(&[0x42u8; 32], &wrong_y);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("P-256 coordinates must be 32 bytes each"));

        // Test with zero coordinates (edge case)
        let zero_coord = vec![0x00u8; 32];
        let result = internal_derive_near_keypair_from_cose_p256(&zero_coord, &zero_coord);
        assert!(result.is_ok());
        let (private_key, public_key) = result.unwrap();
        assert!(private_key.starts_with("ed25519:"));
        assert!(public_key.starts_with("ed25519:"));

        // Test with maximum value coordinates (edge case)
        let max_coord = vec![0xFFu8; 32];
        let result = internal_derive_near_keypair_from_cose_p256(&max_coord, &max_coord);
        assert!(result.is_ok());
        let (private_key, public_key) = result.unwrap();
        assert!(private_key.starts_with("ed25519:"));
        assert!(public_key.starts_with("ed25519:"));
    }

    #[test]
    fn test_decrypt_private_key_with_prf_invalid_formats() {
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0";
        let encryption_key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_b64).unwrap();

        // Test with invalid private key format (not ed25519:)
        let invalid_key = "invalid_key_format";
        let encrypted = encrypt_data_aes_gcm_core(invalid_key, &encryption_key).unwrap();
        let result = decrypt_private_key_with_prf_core(
            prf_output_b64,
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode private key"));

        // Test with wrong private key length (not 32 or 64 bytes)
        let wrong_length_key = bs58::encode(&[0x42u8; 20]).into_string(); // 20 bytes
        let wrong_length_with_prefix = format!("ed25519:{}", wrong_length_key);
        let encrypted = encrypt_data_aes_gcm_core(&wrong_length_with_prefix, &encryption_key).unwrap();
        let result = decrypt_private_key_with_prf_core(
            prf_output_b64,
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key length: 20"));

        // Test with invalid base58 in private key
        let invalid_b58_key = "ed25519:Invalid0IL"; // Contains invalid base58 characters
        let encrypted = encrypt_data_aes_gcm_core(invalid_b58_key, &encryption_key).unwrap();
        let result = decrypt_private_key_with_prf_core(
            prf_output_b64,
            &encrypted.encrypted_near_key_data_b64u,
            &encrypted.aes_gcm_nonce_b64u,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode private key"));
    }

    #[test]
    fn test_internal_derive_near_keypair_from_cose_and_encrypt_with_prf_edge_cases() {
        // This would test the full integration but requires valid COSE attestation objects
        // For now, we test the individual components which are already covered above

        // Test with invalid PRF output
        let result = derive_aes_gcm_encryption_key_from_prf_core("Invalid@PRF!");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_url_decode_edge_cases() {
        // Test various edge cases for base64url decoding

        // Standard base64url (no padding needed)
        let result = base64_url_decode("SGVsbG8").unwrap();
        assert_eq!(result, b"Hello");

        // With URL-safe characters
        let result = base64_url_decode("aGVsbG8_d29ybGQ").unwrap(); // "hello?world" in base64url
        assert_eq!(result, b"hello?world");

        // Empty string
        let result = base64_url_decode("").unwrap();
        assert_eq!(result, b"");

        // Single character
        let result = base64_url_decode("YQ").unwrap(); // "a" in base64url
        assert_eq!(result, b"a");

        // Invalid characters should fail gracefully
        let result = base64_url_decode("Invalid@Base64");
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_key_consistency() {
        // Test that the same PRF output always produces the same encryption key
        let prf_outputs = vec![
            "dGVzdA", // "test"
            "VGVzdFN0cmluZw", // "TestString"
            "TG9uZ2VyVGVzdFN0cmluZ1dpdGhOdW1iZXJzMTIz", // "LongerTestStringWithNumbers123"
        ];

        for prf_output in prf_outputs {
            let key1 = derive_aes_gcm_encryption_key_from_prf_core(prf_output).unwrap();
            let key2 = derive_aes_gcm_encryption_key_from_prf_core(prf_output).unwrap();
            assert_eq!(key1, key2, "Keys should be deterministic for PRF output: {}", prf_output);
            assert_eq!(key1.len(), 32, "Key should always be 32 bytes");
        }
    }

    #[test]
    fn test_near_key_format_validation() {
        // Test that generated keys have the correct NEAR format
        let x_coord = vec![0x12u8; 32];
        let y_coord = vec![0x34u8; 32];

        let (private_key, public_key) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

        // Check format
        assert!(private_key.starts_with("ed25519:"));
        assert!(public_key.starts_with("ed25519:"));

        // Check that the base58 parts are valid
        let private_b58 = &private_key[8..];
        let public_b58 = &public_key[8..];

        assert!(bs58::decode(private_b58).into_vec().is_ok());
        assert!(bs58::decode(public_b58).into_vec().is_ok());

        // Check lengths after decoding
        let private_bytes = bs58::decode(private_b58).into_vec().unwrap();
        let public_bytes = bs58::decode(public_b58).into_vec().unwrap();

        assert_eq!(private_bytes.len(), 64, "Private key should be 64 bytes (seed + public)");
        assert_eq!(public_bytes.len(), 32, "Public key should be 32 bytes");

        // Verify the last 32 bytes of private key match the public key
        assert_eq!(&private_bytes[32..], &public_bytes[..]);
    }
}