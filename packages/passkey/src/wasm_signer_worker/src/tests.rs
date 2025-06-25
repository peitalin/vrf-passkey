use crate::types::*;
use crate::actions::*;
use crate::crypto::*;
use crate::transaction::*;

// Helper function for tests - creates deterministic keypair for testing
fn create_test_keypair_with_prf(prf_output_b64: &str) -> (String, EncryptedDataAesGcmResponse) {
    // Use deterministic function with mock coordinates
    let x_coord = vec![0x42u8; 32]; // Mock P-256 x coordinate
    let y_coord = vec![0x84u8; 32]; // Mock P-256 y coordinate
    let (private_key, public_key) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

    // Encrypt the key manually for testing
    let encryption_key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_b64).unwrap();
    let encrypted_result = encrypt_data_aes_gcm_core(&private_key, &encryption_key).unwrap();

    (public_key, encrypted_result)
}

#[test]
fn test_prf_kdf() {
    // Test PRF-based key derivation
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";
    let key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_b64).unwrap();
    assert_eq!(key.len(), 32);

    // Should be deterministic
    let key2 = derive_aes_gcm_encryption_key_from_prf_core(prf_output_b64).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn test_encryption_decryption_roundtrip() {
    let key = vec![0u8; 32]; // Test key
    let plaintext = "Hello, WebAuthn PRF!";

    let encrypted = encrypt_data_aes_gcm_core(plaintext, &key).unwrap();

    let decrypted = decrypt_data_aes_gcm_core(
        &encrypted.encrypted_near_key_data_b64u,
        &encrypted.aes_gcm_nonce_b64u,
        &key
    ).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_deterministic_near_key_generation() {
    // Test that deterministic key generation produces correct format
    let x_coord = vec![0x42u8; 32]; // Mock P-256 x coordinate
    let y_coord = vec![0x84u8; 32]; // Mock P-256 y coordinate
    let (private_key, public_key) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

    // Remove ed25519: prefix and decode
    let private_key_b58 = &private_key[8..]; // Remove "ed25519:"
    let public_key_b58 = &public_key[8..];   // Remove "ed25519:"

    let private_key_bytes = bs58::decode(private_key_b58).into_vec().unwrap();
    let public_key_bytes = bs58::decode(public_key_b58).into_vec().unwrap();

    // Private key should be 64 bytes (32-byte seed + 32-byte public key)
    assert_eq!(private_key_bytes.len(), 64, "Private key should be 64 bytes");

    // Public key should be 32 bytes
    assert_eq!(public_key_bytes.len(), 32, "Public key should be 32 bytes");

    // The last 32 bytes of private key should match the public key
    assert_eq!(&private_key_bytes[32..64], &public_key_bytes[..],
              "Last 32 bytes of private key should match public key");

    // First 32 bytes should be the seed - verify it generates the same public key
    let seed_bytes: [u8; 32] = private_key_bytes[0..32].try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let derived_public_key = signing_key.verifying_key().to_bytes();

    assert_eq!(derived_public_key, public_key_bytes.as_slice(),
              "Seed should generate the same public key");

    // Test deterministic behavior - same inputs should produce same outputs
    let (private_key2, public_key2) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();
    assert_eq!(private_key, private_key2, "Should be deterministic");
    assert_eq!(public_key, public_key2, "Should be deterministic");
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

    let (private_key1, public_key1) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();
    let (private_key2, public_key2) = internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

    // Should be deterministic
    assert_eq!(private_key1, private_key2);
    assert_eq!(public_key1, public_key2);

    // Keys should start with ed25519:
    assert!(public_key1.starts_with("ed25519:"));
    assert!(private_key1.starts_with("ed25519:"));
}

#[test]
fn test_private_key_decryption_with_prf() {
    // Test PRF-based private key decryption using deterministic derivation
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4"; // "test-prf-output-from-webauthn"

        // Use test helper to create deterministic keypair
    let (_public_key, encrypted_result) = create_test_keypair_with_prf(prf_output_b64);

    // Test decryption
    let decrypted_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &encrypted_result.encrypted_near_key_data_b64u,
        &encrypted_result.aes_gcm_nonce_b64u,
    ).unwrap();

    // Verify the decrypted key works (can generate public key)
    let public_key_bytes = decrypted_key.verifying_key().to_bytes();
    assert_eq!(public_key_bytes.len(), 32);
}

#[test]
fn test_deterministic_key_derivation_from_cose() {
    // Test deterministic key derivation from COSE P-256 coordinates
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

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

    // Derive deterministic NEAR keypair from P-256 coordinates
    let (deterministic_private_key, deterministic_public_key) =
        internal_derive_near_keypair_from_cose_p256(&x_coord, &y_coord).unwrap();

    // Encrypt the deterministic private key
    let encryption_key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_b64).unwrap();
    let encrypted_result = encrypt_data_aes_gcm_core(&deterministic_private_key, &encryption_key).unwrap();

    // Test decryption
    let decrypted_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &encrypted_result.encrypted_near_key_data_b64u,
        &encrypted_result.aes_gcm_nonce_b64u,
    ).unwrap();

    // Verify that the decrypted key produces the same public key
    let recovered_public_key_bytes = decrypted_key.verifying_key().to_bytes();
    let expected_public_key_b58 = &deterministic_public_key[8..]; // Remove "ed25519:" prefix
    let expected_public_key_bytes = bs58::decode(expected_public_key_b58).into_vec().unwrap();

    assert_eq!(recovered_public_key_bytes.to_vec(), expected_public_key_bytes);

    println!("✅ Deterministic key derivation test passed");
    println!("   - P-256 coordinates → deterministic NEAR keypair");
    println!("   - Encryption → decryption preserves keypair");
    println!("   - Provides cryptographic binding between WebAuthn and NEAR identities");
}

#[test]
fn test_private_key_format_compatibility() {
    // Test that the decryption function handles both 32-byte and 64-byte formats
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

    // Generate a 64-byte format key using deterministic function
    let (_public_key, encrypted_result) = create_test_keypair_with_prf(prf_output_b64);

    // Decrypt and verify it works
    let decrypted_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &encrypted_result.encrypted_near_key_data_b64u,
        &encrypted_result.aes_gcm_nonce_b64u,
    ).unwrap();

    let public_key_from_64byte = decrypted_key.verifying_key().to_bytes();

    // Now test with a legacy 32-byte format key
    let test_seed = [42u8; 32];
    let test_signing_key = ed25519_dalek::SigningKey::from_bytes(&test_seed);
    let legacy_private_key_b58 = bs58::encode(&test_seed).into_string();
    let legacy_private_key_near_format = format!("ed25519:{}", legacy_private_key_b58);

    // Derive encryption key and encrypt the legacy format
    let encryption_key = derive_aes_gcm_encryption_key_from_prf_core(prf_output_b64).unwrap();

    let legacy_encrypted = encrypt_data_aes_gcm_core(&legacy_private_key_near_format, &encryption_key).unwrap();

    // Decrypt the legacy format
    let decrypted_legacy_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &legacy_encrypted.encrypted_near_key_data_b64u,
        &legacy_encrypted.aes_gcm_nonce_b64u,
    ).unwrap();

    let public_key_from_32byte = decrypted_legacy_key.verifying_key().to_bytes();

    // Both should work and generate the expected public key
    assert_eq!(public_key_from_32byte, test_signing_key.verifying_key().to_bytes());

    println!("✅ Both 32-byte and 64-byte private key formats work correctly");
    println!("64-byte format public key: {}", bs58::encode(&public_key_from_64byte).into_string());
    println!("32-byte format public key: {}", bs58::encode(&public_key_from_32byte).into_string());
}

// === ACTION HANDLER TESTS ===

#[test]
fn test_transfer_action_handler() {
    let handler = TransferActionHandler;
    let params = ActionParams::Transfer {
        deposit: "1000000000000000000000000".to_string(),
    };

    assert!(handler.validate_params(&params).is_ok());
    let action = handler.build_action(&params).unwrap();

    match action {
        Action::Transfer { deposit } => {
            assert_eq!(deposit, 1000000000000000000000000u128);
        }
        _ => panic!("Expected Transfer action"),
    }

    assert_eq!(handler.get_action_type(), ActionType::Transfer);
}

#[test]
fn test_function_call_action_handler() {
    let handler = FunctionCallActionHandler;
    let params = ActionParams::FunctionCall {
        method_name: "set_greeting".to_string(),
        args: r#"{"greeting": "Hello World"}"#.to_string(),
        gas: "30000000000000".to_string(),
        deposit: "0".to_string(),
    };

    assert!(handler.validate_params(&params).is_ok());
    let action = handler.build_action(&params).unwrap();

    match action {
        Action::FunctionCall(function_call) => {
            assert_eq!(function_call.method_name, "set_greeting");
            assert_eq!(function_call.gas, 30000000000000u64);
            assert_eq!(function_call.deposit, 0u128);
            // Validate args are correctly serialized
            let args_str = String::from_utf8(function_call.args).unwrap();
            assert_eq!(args_str, r#"{"greeting": "Hello World"}"#);
        }
        _ => panic!("Expected FunctionCall action"),
    }

    assert_eq!(handler.get_action_type(), ActionType::FunctionCall);
}

#[test]
fn test_create_account_action_handler() {
    let handler = CreateAccountActionHandler;
    let params = ActionParams::CreateAccount;

    assert!(handler.validate_params(&params).is_ok());
    let action = handler.build_action(&params).unwrap();

    match action {
        Action::CreateAccount => {
            // Success - CreateAccount has no additional data
        }
        _ => panic!("Expected CreateAccount action"),
    }

    assert_eq!(handler.get_action_type(), ActionType::CreateAccount);
}

#[test]
fn test_action_handler_validation_errors() {
    // Test Transfer with empty deposit
    let transfer_handler = TransferActionHandler;
    let invalid_transfer = ActionParams::Transfer {
        deposit: "".to_string(),
    };
    assert!(transfer_handler.validate_params(&invalid_transfer).is_err());

    // Test Transfer with invalid deposit amount
    let invalid_transfer2 = ActionParams::Transfer {
        deposit: "not_a_number".to_string(),
    };
    assert!(transfer_handler.validate_params(&invalid_transfer2).is_err());

    // Test FunctionCall with empty method name
    let function_handler = FunctionCallActionHandler;
    let invalid_function = ActionParams::FunctionCall {
        method_name: "".to_string(),
        args: "{}".to_string(),
        gas: "30000000000000".to_string(),
        deposit: "0".to_string(),
    };
    assert!(function_handler.validate_params(&invalid_function).is_err());

    // Test FunctionCall with invalid JSON args
    let invalid_function2 = ActionParams::FunctionCall {
        method_name: "test_method".to_string(),
        args: "invalid json".to_string(),
        gas: "30000000000000".to_string(),
        deposit: "0".to_string(),
    };
    assert!(function_handler.validate_params(&invalid_function2).is_err());
}

#[test]
fn test_multi_action_parsing() {
    // Test that we can serialize and deserialize multiple actions
    let actions = vec![
        ActionParams::Transfer {
            deposit: "1000000000000000000000000".to_string(),
        },
        ActionParams::FunctionCall {
            method_name: "set_greeting".to_string(),
            args: r#"{"greeting": "Hello"}"#.to_string(),
            gas: "30000000000000".to_string(),
            deposit: "0".to_string(),
        },
        ActionParams::CreateAccount,
    ];

    let actions_json = serde_json::to_string(&actions).unwrap();
    let parsed_actions: Vec<ActionParams> = serde_json::from_str(&actions_json).unwrap();

    assert_eq!(actions.len(), parsed_actions.len());
    assert_eq!(actions, parsed_actions);
}

#[test]
fn test_get_action_handler() {
    // Test that we get the correct handler for each action type
    let transfer_params = ActionParams::Transfer {
        deposit: "1000000000000000000000000".to_string(),
    };
    let transfer_handler = get_action_handler(&transfer_params).unwrap();
    assert_eq!(transfer_handler.get_action_type(), ActionType::Transfer);

    let function_params = ActionParams::FunctionCall {
        method_name: "test".to_string(),
        args: "{}".to_string(),
        gas: "30000000000000".to_string(),
        deposit: "0".to_string(),
    };
    let function_handler = get_action_handler(&function_params).unwrap();
    assert_eq!(function_handler.get_action_type(), ActionType::FunctionCall);

    let create_params = ActionParams::CreateAccount;
    let create_handler = get_action_handler(&create_params).unwrap();
    assert_eq!(create_handler.get_action_type(), ActionType::CreateAccount);
}

// === TRANSACTION TESTS ===

#[test]
fn test_transaction_building() {
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

    // Generate and encrypt a key pair using deterministic function
    let (_public_key, encrypted_result) = create_test_keypair_with_prf(prf_output_b64);

    let private_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &encrypted_result.encrypted_near_key_data_b64u,
        &encrypted_result.aes_gcm_nonce_b64u,
    ).unwrap();

    // Create multiple actions
    let action_params = vec![
        ActionParams::Transfer {
            deposit: "1000000000000000000000000".to_string(),
        },
        ActionParams::FunctionCall {
            method_name: "set_greeting".to_string(),
            args: r#"{"greeting": "Hello Multi-Action"}"#.to_string(),
            gas: "30000000000000".to_string(),
            deposit: "0".to_string(),
        },
    ];

    let actions = build_actions_from_params(action_params).unwrap();
    let block_hash_bytes = [2u8; 32];

    // Test transaction building
    let transaction = build_transaction_with_actions(
        "test.testnet",
        "receiver.testnet",
        100,
        &block_hash_bytes,
        &private_key,
        actions,
    ).unwrap();

    assert_eq!(transaction.nonce, 100);
    assert_eq!(transaction.signer_id.0, "test.testnet");
    assert_eq!(transaction.receiver_id.0, "receiver.testnet");
    assert_eq!(transaction.actions.len(), 2);

    // Verify actions
    match &transaction.actions[0] {
        Action::Transfer { deposit } => {
            assert_eq!(*deposit, 1000000000000000000000000u128);
        }
        _ => panic!("Expected Transfer action"),
    }

    match &transaction.actions[1] {
        Action::FunctionCall(function_call) => {
            assert_eq!(function_call.method_name, "set_greeting");
            assert_eq!(function_call.gas, 30000000000000u64);
            assert_eq!(function_call.deposit, 0u128);
        }
        _ => panic!("Expected FunctionCall action"),
    }
}

#[test]
fn test_transaction_signing() {
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

    // Generate and encrypt a key pair using deterministic function
    let (_public_key, encrypted_result) = create_test_keypair_with_prf(prf_output_b64);

    let private_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &encrypted_result.encrypted_near_key_data_b64u,
        &encrypted_result.aes_gcm_nonce_b64u,
    ).unwrap();

    // Create a simple transfer action
    let actions = vec![Action::Transfer { deposit: 1000000000000000000000000u128 }];
    let block_hash_bytes = [1u8; 32];

    // Build transaction
    let transaction = build_transaction_with_actions(
        "test.testnet",
        "receiver.testnet",
        42,
        &block_hash_bytes,
        &private_key,
        actions,
    ).unwrap();

    // Sign transaction
    let signed_tx_bytes = sign_transaction(transaction, &private_key).unwrap();

    // Verify the signed transaction is not empty and is valid Borsh
    assert!(!signed_tx_bytes.is_empty());
    assert!(signed_tx_bytes.len() > 100); // Should be a substantial serialized transaction

    // Try to deserialize it back to verify structure
    let deserialized: Result<SignedTransaction, _> = borsh::from_slice(&signed_tx_bytes);
    assert!(deserialized.is_ok(), "Should be able to deserialize SignedTransaction");

    let signed_transaction = deserialized.unwrap();
    assert_eq!(signed_transaction.transaction.nonce, 42);
    assert_eq!(signed_transaction.transaction.signer_id.0, "test.testnet");
    assert_eq!(signed_transaction.transaction.receiver_id.0, "receiver.testnet");
}

#[test]
fn test_deterministic_transaction_signing() {
    // Test that transaction signing is deterministic for the same inputs
    let prf_output_b64 = "dGVzdC1wcmYtb3V0cHV0LWZyb20td2ViYXV0aG4";

    // Generate and encrypt a key pair using deterministic function
    let (_public_key, encrypted_result) = create_test_keypair_with_prf(prf_output_b64);

    let private_key = decrypt_private_key_with_prf_core(
        prf_output_b64,
        &encrypted_result.encrypted_near_key_data_b64u,
        &encrypted_result.aes_gcm_nonce_b64u,
    ).unwrap();

    let actions = vec![Action::Transfer { deposit: 1000000000000000000000000u128 }];
    let block_hash_bytes = [1u8; 32];

    // Build same transaction twice
    let transaction1 = build_transaction_with_actions(
        "test.testnet",
        "receiver.testnet",
        42,
        &block_hash_bytes,
        &private_key,
        actions.clone(),
    ).unwrap();

    let transaction2 = build_transaction_with_actions(
        "test.testnet",
        "receiver.testnet",
        42,
        &block_hash_bytes,
        &private_key,
        actions,
    ).unwrap();

    // Sign both transactions
    let signed_tx_bytes1 = sign_transaction(transaction1, &private_key).unwrap();
    let signed_tx_bytes2 = sign_transaction(transaction2, &private_key).unwrap();

    // Should be identical (deterministic signing)
    assert_eq!(signed_tx_bytes1, signed_tx_bytes2);

    // Verify both are valid SignedTransactions
    let deserialized1: SignedTransaction = borsh::from_slice(&signed_tx_bytes1).unwrap();
    let deserialized2: SignedTransaction = borsh::from_slice(&signed_tx_bytes2).unwrap();
    assert_eq!(deserialized1, deserialized2);
}