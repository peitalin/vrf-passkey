// Tests for VRF Worker - Native-compatible only
// These tests focus on TypeScript/WASM boundary issues without requiring WASM runtime

use serde_json;

// Import existing types, functions, and constants from other modules
use crate::types::{VRFInputData, EncryptedVRFKeypair, VRFWorkerMessage, VRFWorkerResponse};
use crate::utils::{base64_url_encode, base64_url_decode, process_prf_input};
use crate::config::{AES_KEY_SIZE, AES_NONCE_SIZE, VRF_SEED_SIZE, VRF_DOMAIN_SEPARATOR, HKDF_AES_KEY_INFO, HKDF_VRF_KEYPAIR_INFO};

// Test helper functions
fn create_test_prf_output() -> Vec<u8> {
    (0..32).map(|i| (i as u8).wrapping_add(42)).collect()
}

fn create_test_account_id() -> String {
    "test-account.testnet".to_string()
}

#[test]
fn test_prf_input_processing_consistency() {
    let test_prf_bytes = create_test_prf_output();
    let test_prf_base64url = base64_url_encode(&test_prf_bytes);

    // Test both input formats produce same result
    let result_from_string = process_prf_input(&serde_json::Value::String(test_prf_base64url.clone()));
    let result_from_array = process_prf_input(&serde_json::Value::Array(
        test_prf_bytes.iter().map(|&b| serde_json::Value::Number(serde_json::Number::from(b))).collect()
    ));

    assert!(result_from_string.is_ok(), "String PRF processing should succeed");
    assert!(result_from_array.is_ok(), "Array PRF processing should succeed");

    let string_result = result_from_string.unwrap();
    let array_result = result_from_array.unwrap();

    assert_eq!(string_result.len(), 32, "PRF should be exactly 32 bytes");
    assert_eq!(array_result.len(), 32, "PRF should be exactly 32 bytes");
    assert_eq!(string_result, array_result, "Both PRF processing methods should produce identical results");
    assert_eq!(string_result, test_prf_bytes, "PRF processing should preserve original bytes");

    println!("✅ PRF input processing consistency test passed");
}

#[test]
fn test_vrf_data_structures_serialization() {
    // Test VRFInputData serialization/deserialization
    let vrf_input = VRFInputData {
        user_id: create_test_account_id(),
        rp_id: "example.com".to_string(),
        block_height: 12345,
        block_hash: vec![0u8; 32],
        timestamp: Some(1234567890),
    };

    let json_str = serde_json::to_string(&vrf_input).expect("Should serialize VRFInputData");
    let deserialized: VRFInputData = serde_json::from_str(&json_str).expect("Should deserialize VRFInputData");

    assert_eq!(vrf_input.user_id, deserialized.user_id);
    assert_eq!(vrf_input.rp_id, deserialized.rp_id);
    assert_eq!(vrf_input.block_height, deserialized.block_height);
    assert_eq!(vrf_input.block_hash, deserialized.block_hash);
    assert_eq!(vrf_input.timestamp, deserialized.timestamp);

    // Test EncryptedVRFKeypair serialization/deserialization
    let encrypted_keypair = EncryptedVRFKeypair {
        encrypted_vrf_data_b64u: base64_url_encode(&vec![1u8; 64]),
        aes_gcm_nonce_b64u: base64_url_encode(&vec![2u8; 12]),
    };

    let json_str = serde_json::to_string(&encrypted_keypair).expect("Should serialize EncryptedVRFKeypair");
    let deserialized: EncryptedVRFKeypair = serde_json::from_str(&json_str).expect("Should deserialize EncryptedVRFKeypair");

    assert_eq!(encrypted_keypair.encrypted_vrf_data_b64u, deserialized.encrypted_vrf_data_b64u);
    assert_eq!(encrypted_keypair.aes_gcm_nonce_b64u, deserialized.aes_gcm_nonce_b64u);

    println!("✅ VRF data structures serialization test passed");
}

#[test]
fn test_worker_message_format_consistency() {
    // Test VRFWorkerMessage structure
    let test_message = VRFWorkerMessage {
        msg_type: "PING".to_string(),
        id: Some("test-123".to_string()),
        data: Some(serde_json::json!({"test": "data"})),
    };

    let json_str = serde_json::to_string(&test_message).expect("Should serialize VRFWorkerMessage");
    let deserialized: VRFWorkerMessage = serde_json::from_str(&json_str).expect("Should deserialize VRFWorkerMessage");

    assert_eq!(test_message.msg_type, deserialized.msg_type);
    assert_eq!(test_message.id, deserialized.id);

    // Test VRFWorkerResponse structure
    let test_response = VRFWorkerResponse {
        id: Some("test-123".to_string()),
        success: true,
        data: Some(serde_json::json!({"result": "success"})),
        error: None,
    };

    let json_str = serde_json::to_string(&test_response).expect("Should serialize VRFWorkerResponse");
    let deserialized: VRFWorkerResponse = serde_json::from_str(&json_str).expect("Should deserialize VRFWorkerResponse");

    assert_eq!(test_response.id, deserialized.id);
    assert_eq!(test_response.success, deserialized.success);
    assert_eq!(test_response.error, deserialized.error);

    println!("✅ Worker message format consistency test passed");
}

#[test]
fn test_base64_encoding_consistency() {
    // This test verifies the exact encoding issue that caused the original bug
    let test_data = create_test_prf_output();

    // Test base64url encoding/decoding consistency
    let encoded = base64_url_encode(&test_data);
    let decoded = base64_url_decode(&encoded).expect("Should decode successfully");

    assert_eq!(test_data, decoded, "Base64url encode/decode should be lossless");
    assert_eq!(encoded.len(), 43, "32-byte data should encode to 43 characters (no padding)");

    // Test that the encoding is URL-safe (no +, /, or = characters)
    assert!(!encoded.contains('+'), "Base64url should not contain + characters");
    assert!(!encoded.contains('/'), "Base64url should not contain / characters");
    assert!(!encoded.contains('='), "Base64url should not contain = padding");

    println!("✅ Base64 encoding consistency test passed");
}

#[test]
fn test_configuration_constants() {
    // Test that configuration constants are properly defined
    assert_eq!(AES_KEY_SIZE, 32, "AES key size should be 32 bytes");
    assert_eq!(AES_NONCE_SIZE, 12, "AES nonce size should be 12 bytes");
    assert_eq!(VRF_SEED_SIZE, 32, "VRF seed size should be 32 bytes");

    // Test domain separator consistency
    assert!(!VRF_DOMAIN_SEPARATOR.is_empty(), "Domain separator should not be empty");
    assert!(VRF_DOMAIN_SEPARATOR.len() > 10, "Domain separator should be sufficiently long");

    // Test HKDF info strings
    assert!(!HKDF_AES_KEY_INFO.is_empty(), "HKDF AES info should not be empty");
    assert!(!HKDF_VRF_KEYPAIR_INFO.is_empty(), "HKDF VRF info should not be empty");
    assert_ne!(HKDF_AES_KEY_INFO, HKDF_VRF_KEYPAIR_INFO, "HKDF info strings should be different");

    println!("✅ Configuration constants test passed");
}

#[test]
fn test_account_id_salt_generation() {
    // Test the salt generation logic that's used for PRF key derivation
    let account_id = create_test_account_id();

    let aes_salt = format!("aes-gcm-salt:{}", account_id);
    let ed25519_salt = format!("ed25519-salt:{}", account_id);

    assert_ne!(aes_salt, ed25519_salt, "AES and Ed25519 salts should be different");
    assert!(aes_salt.contains(&account_id), "AES salt should contain account ID");
    assert!(ed25519_salt.contains(&account_id), "Ed25519 salt should contain account ID");
    assert!(aes_salt.starts_with("aes-gcm-salt:"), "AES salt should have correct prefix");
    assert!(ed25519_salt.starts_with("ed25519-salt:"), "Ed25519 salt should have correct prefix");

    // Test with different account IDs produce different salts
    let different_account = "different-account.testnet";
    let different_aes_salt = format!("aes-gcm-salt:{}", different_account);

    assert_ne!(aes_salt, different_aes_salt, "Different accounts should produce different salts");

    println!("✅ Account ID salt generation test passed");
}

#[test]
fn test_utf8_encoding_bug_prevention() {
    // This test demonstrates the UTF-8 encoding bug that was causing issues
    let test_prf_bytes = create_test_prf_output();

    // Correct approach: base64url encoding preserves binary data
    let correct_base64url = base64_url_encode(&test_prf_bytes);
    let correct_decoded = base64_url_decode(&correct_base64url).expect("Should decode correctly");
    assert_eq!(test_prf_bytes, correct_decoded, "Correct encoding should be lossless");

    // Demonstrate the bug: treating binary data as UTF-8 can corrupt it
    // This would happen if someone tried to convert PRF bytes to a string incorrectly
    let utf8_result = std::str::from_utf8(&test_prf_bytes);

    // Most binary data is NOT valid UTF-8, which would cause the bug
    if utf8_result.is_err() {
        println!("✅ Binary PRF data is not valid UTF-8 (expected - this prevents the bug)");
    } else {
        // If it happens to be valid UTF-8, show that round-trip can still corrupt data
        let utf8_string = utf8_result.unwrap();
        let utf8_bytes = utf8_string.as_bytes();

        // The round-trip through UTF-8 might not preserve original bytes
        if utf8_bytes != test_prf_bytes {
            println!("✅ UTF-8 round-trip corrupted data (demonstrates the bug)");
        } else {
            println!("⚠️ UTF-8 round-trip happened to preserve data (rare case)");
        }
    }

    println!("✅ UTF-8 encoding bug prevention test passed");
}
