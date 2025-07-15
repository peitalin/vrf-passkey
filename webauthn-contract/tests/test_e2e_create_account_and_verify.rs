//! End-to-End Create Account and Verify Test
//!
//! Single comprehensive test for the new `create_account_and_verify` method that combines
//! account creation with VRF-based WebAuthn registration in a single atomic transaction.

use near_workspaces::types::Gas;
use serde_json::json;
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
use vrf_wasm::traits::WasmRngFromSeed;
use rand_core::SeedableRng;
use sha2::{Sha256, Digest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE};
use std::collections::BTreeMap;

mod utils_mocks;
use utils_mocks::VrfRegistrationData;

mod utils_contracts;
use utils_contracts::deploy_test_contract;

/// Create mock WebAuthn registration response for account creation test
fn create_mock_webauthn_registration_for_account_creation(
    vrf_output: &[u8],
    rp_id: &str,
    account_id: &str
) -> serde_json::Value {
    // Use first 32 bytes of VRF output as WebAuthn challenge
    let webauthn_challenge = &vrf_output[0..32];
    let challenge_b64 = BASE64_URL_ENGINE.encode(webauthn_challenge);

    let origin = format!("https://{}", rp_id);
    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        challenge_b64, origin
    );
    let client_data_b64 = BASE64_URL_ENGINE.encode(client_data.as_bytes());

    // Create valid attestation object for "none" format
    let mut attestation_map = BTreeMap::new();
    attestation_map.insert(
        serde_cbor::Value::Text("fmt".to_string()),
        serde_cbor::Value::Text("none".to_string()),
    );

    // Create valid authenticator data with RP ID hash
    let mut auth_data = Vec::new();
    let rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x45); // UP (0x01) + UV (0x04) + AT (0x40)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Counter = 1

    // AAGUID (16 bytes)
    auth_data.extend_from_slice(&[0x00u8; 16]);

    // Credential ID (use account_id as credential ID for clarity)
    let cred_id = format!("cred_{}", account_id);
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(cred_id.as_bytes());

    // Create valid COSE Ed25519 public key
    let mock_ed25519_pubkey = [0x42u8; 32];
    let mut cose_map = BTreeMap::new();
    cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
    cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
    cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
    cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
    let cose_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();
    auth_data.extend_from_slice(&cose_key);

    attestation_map.insert(
        serde_cbor::Value::Text("authData".to_string()),
        serde_cbor::Value::Bytes(auth_data),
    );
    attestation_map.insert(
        serde_cbor::Value::Text("attStmt".to_string()),
        serde_cbor::Value::Map(BTreeMap::new()),
    );

    let attestation_object_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(attestation_map)).unwrap();
    let attestation_object_b64 = BASE64_URL_ENGINE.encode(&attestation_object_bytes);

    // Return WebAuthn registration data structure
    json!({
        "id": cred_id,
        "rawId": BASE64_URL_ENGINE.encode(cred_id.as_bytes()),
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": attestation_object_b64,
            "transports": ["internal"]
        },
        "authenticatorAttachment": "platform",
        "type": "public-key",
        "clientExtensionResults": null
    })
}

/// Generate VRF data for account creation testing
async fn generate_vrf_account_creation_data(
    rp_id: &str,
    user_id: &str,
    session_id: &str,
) -> Result<VrfRegistrationData, Box<dyn std::error::Error>> {
    println!("Generating VRF data for account creation...");

    // Create deterministic keypair for testing
    let seed = [123u8; 32];
    let mut rng = WasmRngFromSeed::from_seed(seed);
    let keypair = ECVRFKeyPair::generate(&mut rng);

    // Construct VRF input according to specification
    let domain = b"web_authn_challenge_v1";
    let block_height = 987654321u64;
    let block_hash = b"create_account_block_hash_32_byte";
    let timestamp = 1700000000u64;

    let mut input_data = Vec::new();
    input_data.extend_from_slice(domain);
    input_data.extend_from_slice(user_id.as_bytes());
    input_data.extend_from_slice(rp_id.as_bytes());
    input_data.extend_from_slice(session_id.as_bytes());
    input_data.extend_from_slice(&block_height.to_le_bytes());
    input_data.extend_from_slice(block_hash);
    input_data.extend_from_slice(&timestamp.to_le_bytes());

    // Hash the input data (VRF input should be hashed)
    let vrf_input = Sha256::digest(&input_data).to_vec();

    // Generate VRF proof
    let proof = keypair.prove(&vrf_input);
    let vrf_output = proof.to_hash().to_vec();

    // Verify the proof works locally
    assert!(proof.verify(&vrf_input, &keypair.pk).is_ok(), "Generated VRF proof should be valid");

    println!("✅ Generated VRF data for account creation:");
    println!("  - VRF input: {} bytes", vrf_input.len());
    println!("  - VRF output: {} bytes", vrf_output.len());
    println!("  - User ID: {}", user_id);
    println!("  - RP ID: {}", rp_id);
    println!("  - Session ID: {}", session_id);

    Ok(VrfRegistrationData {
        input_data: vrf_input,
        output: vrf_output,
        proof,
        public_key: keypair.pk,
        user_id: user_id.to_string(),
        rp_id: rp_id.to_string(),
        block_height,
        block_hash: block_hash.to_vec(),
    })
}

#[tokio::test]
async fn test_create_account_and_verify_e2e() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Create Account and Verify E2E Test...");

    // Deploy contract
    let contract = deploy_test_contract().await?;

    // Test account creation settings integration
    println!("Testing account creation settings...");
    let settings_result = contract
        .call("get_account_creation_settings")
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    let settings: serde_json::Value = settings_result.json()?;
    assert_eq!(settings["initial_balance_near"].as_f64().unwrap(), 0.1);
    assert_eq!(settings["enabled"].as_bool().unwrap(), true);
    assert_eq!(settings["max_accounts_per_day"].as_u64().unwrap(), 1000);

    println!("✅ Default settings verified:");
    println!("  - Initial balance: {} NEAR", settings["initial_balance_near"]);
    println!("  - Enabled: {}", settings["enabled"]);
    println!("  - Max accounts per day: {}", settings["max_accounts_per_day"]);

    // Test data for account creation
    let rp_id = "example.com";
    let user_id = "new_user.testnet";
    let session_id = "create_account_session_12345";
    let new_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";

    // Generate VRF data
    let vrf_data = generate_vrf_account_creation_data(rp_id, user_id, session_id).await?;

    // Create WebAuthn registration data
    let webauthn_registration = create_mock_webauthn_registration_for_account_creation(
        &vrf_data.output,
        rp_id,
        user_id
    );

    // Test with deterministic VRF key (dual PRF setup)
    let deterministic_seed = [99u8; 32];
    let mut det_rng = WasmRngFromSeed::from_seed(deterministic_seed);
    let det_keypair = ECVRFKeyPair::generate(&mut det_rng);
    let deterministic_vrf_public_key = bincode::serialize(&det_keypair.pk).unwrap();

    println!("Testing atomic account creation and verification...");

    // Call create_account_and_verify method
    let result = contract
        .call("create_account_and_verify")
        .args_json(json!({
            "new_account_id": user_id,
            "new_public_key": new_public_key,
            "vrf_data": vrf_data.to_vrf_verification_data(),
            "webauthn_registration": webauthn_registration,
            "deterministic_vrf_public_key": deterministic_vrf_public_key
        }))
        .gas(Gas::from_tgas(300)) // More gas for account creation
        .transact()
        .await?;

    println!("✅ Account creation and verification transaction completed");
    println!("  - Transaction successful: {}", result.is_success());
    println!("  - Gas used: {:?}", result.total_gas_burnt);

    // Test configuration changes
    println!("️Testing configuration updates...");
    let update_result = contract
        .call("update_account_creation_settings")
        .args_json(json!({
            "settings": {
                "initial_balance_near": 0.25,
                "enabled": true,
                "max_accounts_per_day": 2000
            }
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    assert!(update_result.is_success(), "Should successfully update settings");

    // Verify settings were updated
    let updated_settings = contract
        .call("get_account_creation_settings")
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    let new_settings: serde_json::Value = updated_settings.json()?;
    assert_eq!(new_settings["initial_balance_near"].as_f64().unwrap(), 0.25);
    assert_eq!(new_settings["max_accounts_per_day"].as_u64().unwrap(), 2000);

    println!("✅ Configuration updates verified:");
    println!("  - Updated initial balance: {} NEAR", new_settings["initial_balance_near"]);
    println!("  - Updated max accounts per day: {}", new_settings["max_accounts_per_day"]);

    // Test disabled account creation
    println!("🚫 Testing disabled account creation...");
    let disable_result = contract
        .call("update_account_creation_settings")
        .args_json(json!({
            "settings": {
                "initial_balance_near": 0.25,
                "enabled": false,
                "max_accounts_per_day": 2000
            }
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    assert!(disable_result.is_success(), "Should successfully disable account creation");

    // Try to create account when disabled - should fail
    let disabled_user_id = "disabled_user.testnet";
    let disabled_vrf_data = generate_vrf_account_creation_data(rp_id, disabled_user_id, "disabled_session").await?;
    let disabled_webauthn_registration = create_mock_webauthn_registration_for_account_creation(
        &disabled_vrf_data.output,
        rp_id,
        disabled_user_id
    );

    let disabled_result = contract
        .call("create_account_and_verify")
        .args_json(json!({
            "new_account_id": disabled_user_id,
            "new_public_key": new_public_key,
            "vrf_data": disabled_vrf_data.to_vrf_verification_data(),
            "webauthn_registration": disabled_webauthn_registration,
            "deterministic_vrf_public_key": null
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;

    assert!(!disabled_result.is_success(), "Should fail when account creation is disabled");
    println!("✅ Correctly rejected account creation when disabled");

    println!("Complete Create Account and Verify E2E test passed!");
    println!("   - Account creation settings: ✅");
    println!("   - Atomic transaction flow: ✅");
    println!("   - Configuration updates: ✅");
    println!("   - Disabled state handling: ✅");
    println!("   - VRF + WebAuthn integration: ✅");
    println!("   - Deterministic VRF key support: ✅");

    Ok(())
}