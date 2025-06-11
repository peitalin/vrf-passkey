mod error;
use error::KdfError;

use wasm_bindgen::prelude::*;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey};
use getrandom::getrandom;
use bs58;


#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn warn(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn error(s: &str);
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// Helper function for base64url decoding
fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| KdfError::Base64DecodeError(format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn encrypt_data_aes_gcm(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Encryption key must be 32 bytes for AES-256-GCM."));
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| JsValue::from_str(&format!("Failed to generate IV: {}", e)))?;
    let nonce = GenericArray::from_slice(&iv_bytes);

    let ciphertext = cipher.encrypt(nonce, plain_text_data_str.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    let result = format!(
        r#"{{"encrypted_data_b64u": "{}", "iv_b64u": "{}"}}"#,
        Base64UrlUnpadded::encode_string(&ciphertext),
        Base64UrlUnpadded::encode_string(&iv_bytes)
    );
    Ok(result)
}

#[wasm_bindgen]
pub fn decrypt_data_aes_gcm(encrypted_data_b64u: &str, iv_b64u: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Decryption key must be 32 bytes for AES-256-GCM."));
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let iv_bytes = Base64UrlUnpadded::decode_vec(iv_b64u)
        .map_err(|e| JsValue::from_str(&format!("Base64UrlUnpadded decode error for IV: {}", e)))?;
    if iv_bytes.len() != 12 {
        return Err(JsValue::from_str("Decryption IV must be 12 bytes."));
    }
    let nonce = GenericArray::from_slice(&iv_bytes);

    // Check if the data has the "ed25519:" prefix and strip it
    let data_to_decode = if encrypted_data_b64u.starts_with("ed25519:") {
        &encrypted_data_b64u[8..]
    } else {
        encrypted_data_b64u
    };

    let encrypted_data = Base64UrlUnpadded::decode_vec(data_to_decode)
        .map_err(|e| JsValue::from_str(&format!("Base64UrlUnpadded decode error for encrypted data: {}", e)))?;

    let decrypted_bytes = cipher.decrypt(nonce, encrypted_data.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {}", e)))?;

    String::from_utf8(decrypted_bytes).map_err(|e| JsValue::from_str(&format!("UTF-8 decoding error: {}", e)))
}

// Generate a new NEAR key pair
#[wasm_bindgen]
pub fn generate_near_keypair() -> Result<String, JsValue> {
    console_log!("RUST: Generating new NEAR key pair");

    // Generate random bytes for the private key seed
    let mut seed_bytes = [0u8; 32];
    getrandom(&mut seed_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate random bytes: {}", e)))?;

    // Create signing key from the seed
    let signing_key = SigningKey::from_bytes(&seed_bytes);

    // Get the corresponding public key
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // A full NEAR private key is the 64-byte concatenation of the seed and the public key
    let mut full_private_key_bytes = Vec::with_capacity(64);
    full_private_key_bytes.extend_from_slice(&seed_bytes);
    full_private_key_bytes.extend_from_slice(&public_key_bytes);

    // Encode the full 64-byte private key in NEAR format
    let private_key_b58 = bs58::encode(&full_private_key_bytes).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    // Encode public key in NEAR format
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();
    let public_key_near_format = format!("ed25519:{}", public_key_b58);

    // Return as JSON
    let result = format!(
        r#"{{"privateKey": "{}", "publicKey": "{}"}}"#,
        private_key_near_format,
        public_key_near_format
    );

    console_log!("RUST: Generated NEAR key pair with public key: {}", public_key_near_format);
    Ok(result)
}

// Function for deriving encryption key from PRF output
pub fn derive_encryption_key_from_prf_core(
    prf_output_base64: &str,  // Base64-encoded PRF output from WebAuthn
    info: &str,               // Fixed info string (e.g., "near-key-encryption")
    hkdf_salt: &str,          // Fixed salt (can be empty string)
) -> Result<Vec<u8>, KdfError> {
    console_log!("RUST: Deriving encryption key from PRF output");

    // Decode PRF output from base64
    let prf_output = base64_url_decode(prf_output_base64)?;

    // Use PRF output directly as IKM
    let ikm = prf_output;

    // Convert info and salt to bytes
    let info_bytes = info.as_bytes();
    let salt_bytes = hkdf_salt.as_bytes();

    // Perform HKDF
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), &ikm);
    let mut okm = vec![0u8; 32]; // 32 bytes for AES-256
    hk.expand(info_bytes, &mut okm)
        .map_err(|_| KdfError::HkdfError)?;

    console_log!("RUST: Successfully derived 32-byte encryption key from PRF");
    Ok(okm)
}

// WASM binding
#[wasm_bindgen]
pub fn derive_encryption_key_from_prf(
    prf_output_base64: &str,
    info: &str,
    hkdf_salt: &str,
) -> Result<Vec<u8>, JsValue> {
    derive_encryption_key_from_prf_core(prf_output_base64, info, hkdf_salt)
        .map_err(|e| JsValue::from(e))
}

// Combined function for generating and encrypting with PRF
#[wasm_bindgen]
pub fn generate_and_encrypt_near_keypair_with_prf(
    prf_output_base64: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Generating and encrypting NEAR key pair with PRF-derived key");

    // Fixed parameters for consistency
    const INFO: &str = "near-key-encryption";
    const HKDF_SALT: &str = "";

    // Generate the key pair
    let keypair_json = generate_near_keypair()?;

    // Remove ed25519: prefix before encryption
    let keypair_data: serde_json::Value = serde_json::from_str(&keypair_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse keypair: {}", e)))?;

    let private_key_full = keypair_data["privateKey"].as_str()
        .ok_or_else(|| JsValue::from_str("Failed to extract private key"))?;

    let private_key_seed = if private_key_full.starts_with("ed25519:") {
        &private_key_full[8..]
    } else {
        private_key_full
    };

    let public_key = keypair_data["publicKey"].as_str()
        .ok_or_else(|| JsValue::from_str("Failed to extract public key"))?;

    // Derive encryption key from PRF output
    let encryption_key = derive_encryption_key_from_prf_core(prf_output_base64, INFO, HKDF_SALT)
        .map_err(|e| JsValue::from(e))?;

    // Encrypt the raw seed
    let encrypted_result = encrypt_data_aes_gcm(private_key_seed, &encryption_key)?;

    // Return combined result
    let result = format!(
        r#"{{"publicKey": "{}", "encryptedPrivateKey": {}}}"#,
        public_key,
        encrypted_result
    );

    console_log!("RUST: Successfully generated and encrypted NEAR key pair with PRF");
    Ok(result)
}

// Derive NEAR Ed25519 key from WebAuthn COSE P-256 public key
#[wasm_bindgen]
pub fn derive_near_keypair_from_cose_p256(
    x_coordinate_bytes: &[u8],
    y_coordinate_bytes: &[u8],
) -> Result<String, JsValue> {
    console_log!("RUST: Deriving NEAR key pair from P-256 COSE coordinates (matching contract)");

    if x_coordinate_bytes.len() != 32 || y_coordinate_bytes.len() != 32 {
        return Err(JsValue::from_str("P-256 coordinates must be 32 bytes each"));
    }

    // Concatenate x and y coordinates (same as contract)
    let mut p256_material = Vec::new();
    p256_material.extend_from_slice(x_coordinate_bytes);
    p256_material.extend_from_slice(y_coordinate_bytes);

    // SHA-256 hash (same as contract)
    let mut hasher = Sha256::new();
    hasher.update(&p256_material);
    let hash_bytes = hasher.finalize();

    // Use hash as Ed25519 seed (same as contract)
    let signing_key = SigningKey::from_bytes(&hash_bytes.into());

    // Encode in NEAR format
    let private_key_b58 = bs58::encode(&hash_bytes).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_b58 = bs58::encode(&public_key_bytes).into_string();
    let public_key_near_format = format!("ed25519:{}", public_key_b58);

    let result = format!(
        r#"{{"privateKey": "{}", "publicKey": "{}"}}"#,
        private_key_near_format,
        public_key_near_format
    );

    console_log!("RUST: Derived deterministic NEAR key with public key: {}", public_key_near_format);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_kdf() {
        // Test PRF-based key derivation
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"
        let key = derive_encryption_key_from_prf_core(prf_output_b64, "near-key-encryption", "").unwrap();
        assert_eq!(key.len(), 32);

        // Should be deterministic
        let key2 = derive_encryption_key_from_prf_core(prf_output_b64, "near-key-encryption", "").unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let key = vec![0u8; 32]; // Test key
        let plaintext = "Hello, WebAuthn PRF!";

        let encrypted = encrypt_data_aes_gcm(plaintext, &key).unwrap();

        // Parse the JSON result
        let encrypted_obj: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        let encrypted_data = encrypted_obj["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_obj["iv_b64u"].as_str().unwrap();

        let decrypted = decrypt_data_aes_gcm(encrypted_data, iv, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_deterministic_near_key_derivation() {
        // Test P-256 coordinates (example values)
        let x_coord = vec![
            0x22, 0xc6, 0xb5, 0xbe, 0x9a, 0xa8, 0x08, 0x35,
            0x8c, 0xa9, 0x33, 0x52, 0xf9, 0x5a, 0x55, 0x09,
            0x25, 0xf3, 0xaf, 0xc2, 0xf9, 0xa6, 0x03, 0x65,
            0x85, 0xb1, 0x18, 0x73, 0x1c, 0x23, 0x0b, 0x75,
        ];
        let y_coord = vec![
            0x33, 0x1b, 0x60, 0x66, 0xae, 0xa9, 0x34, 0x5d,
            0x7a, 0x30, 0x31, 0x5e, 0x26, 0x6e, 0x53, 0x63,
            0x69, 0xbc, 0x8d, 0xa7, 0xe1, 0x80, 0x78, 0x1a,
            0xe8, 0x9f, 0x71, 0x74, 0xfb, 0x0d, 0xde, 0xc0,
        ];

        let result = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

        // Parse the result
        let keypair: serde_json::Value = serde_json::from_str(&result).unwrap();
        let public_key = keypair["publicKey"].as_str().unwrap();
        let private_key = keypair["privateKey"].as_str().unwrap();

        // Should be deterministic
        let result2 = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();
        assert_eq!(result, result2);

        println!("Generated keypair from P-256 coordinates:");
        println!("X: {}", Base64UrlUnpadded::encode_string(&x_coord));
        println!("Y: {}", Base64UrlUnpadded::encode_string(&y_coord));

        // Keys should start with ed25519:
        assert!(public_key.starts_with("ed25519:"));
        assert!(private_key.starts_with("ed25519:"));

        // Should match the expected key from server logs
        // Contract derived: ed25519:Dax81obDiyu9eDMfP9vtSCdpX3skSRjopKYUKPGeucmV
        assert_eq!(public_key, "ed25519:Dax81obDiyu9eDMfP9vtSCdpX3skSRjopKYUKPGeucmV");

        println!("Deterministic public key: {}", public_key);
        println!("Deterministic private key: {}", private_key);
    }

    #[test]
    fn test_p256_coordinate_extraction() {
        // Test with known good P-256 coordinates
        let x_coord = vec![1u8; 32];
        let y_coord = vec![2u8; 32];

        let keypair1 = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();
        let keypair2 = derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

        // Should be identical (deterministic)
        assert_eq!(keypair1, keypair2);
    }

    #[test]
    fn test_key_length_and_format() {
        // Generate a new keypair
        let keypair_json = generate_near_keypair().unwrap();
        let keypair: serde_json::Value = serde_json::from_str(&keypair_json).unwrap();

        let private_key_full = keypair["privateKey"].as_str().unwrap();
        let public_key = keypair["publicKey"].as_str().unwrap();

        // 1. Test original key lengths
        let private_key_b58_part = &private_key_full[8..];
        let private_key_bytes = bs58::decode(private_key_b58_part).into_vec().unwrap();
        assert_eq!(private_key_bytes.len(), 64, "Full private key should be 64 bytes");

        let public_key_b58_part = &public_key[8..];
        let public_key_bytes = bs58::decode(public_key_b58_part).into_vec().unwrap();
        assert_eq!(public_key_bytes.len(), 32, "Public key should be 32 bytes");

        // 2. Test encryption/decryption roundtrip and length of decrypted key
        let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"
        let encryption_key = derive_encryption_key_from_prf_core(prf_output_b64, "near-key-encryption", "").unwrap();

        // Encrypt the raw seed (first 32 bytes of the full private key)
        let seed_bytes = &private_key_bytes[0..32];
        let seed_b58 = bs58::encode(seed_bytes).into_string();
        let encrypted_json = encrypt_data_aes_gcm(&seed_b58, &encryption_key).unwrap();
        let encrypted_obj: serde_json::Value = serde_json::from_str(&encrypted_json).unwrap();
        let encrypted_data = encrypted_obj["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_obj["iv_b64u"].as_str().unwrap();

        // Decrypt and check length
        let decrypted_seed_b58 = decrypt_data_aes_gcm(encrypted_data, iv, &encryption_key).unwrap();
        let decrypted_seed_bytes = bs58::decode(&decrypted_seed_b58).into_vec().unwrap();
        assert_eq!(decrypted_seed_bytes.len(), 32, "Decrypted seed should be 32 bytes");
        assert_eq!(decrypted_seed_bytes, seed_bytes, "Decrypted seed should match original seed");
    }
}
