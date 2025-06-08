use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
use base64::Engine as TestEngine;
use serde_json::json;
use near_workspaces::types::Gas;
use sha2::{Sha256, Digest};
use webauthn_contract::{AuthenticationOptionsJSON, VerifiedAuthenticationResponse, UserIdYieldId};

#[tokio::test]
async fn test_contract_authentication_on_chain_commitment_flow() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let user_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "webauthn-contract.testnet"}))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    // Step 1: Call generate_authentication_options
    let (
        rp_id,
        credential_id,
        auth_options_args
    ) = create_mock_auth_options();

    println!("\n\n1) Calling generate_authentication_options (async) with args:\n\t{}\n", auth_options_args);
    let gen_auth_options_request = user_account
        .call(contract.id(), "generate_authentication_options")
        .args_json(json!({
            "rp_id": auth_options_args["rp_id"],
            "allow_credentials": auth_options_args["allow_credentials"],
            "challenge": auth_options_args["challenge"],
            "timeout": auth_options_args["timeout"],
            "user_verification": auth_options_args["user_verification"],
            "extensions": auth_options_args["extensions"],
            "authenticator": auth_options_args["authenticator"]
        }))
        .gas(Gas::from_tgas(50))
        .transact_async()
        .await?;

    let gen_auth_options_outcome = gen_auth_options_request.await?;

    assert!(gen_auth_options_outcome.is_success(),
        "generate_authentication_options transaction failed: {:?}",
        gen_auth_options_outcome.outcome());

    let gen_auth_options_result: AuthenticationOptionsJSON = gen_auth_options_outcome.json()?;
    let commitment_id = gen_auth_options_result.commitment_id
        .expect("commitmentId should be in authentication options response");
    let challenge_from_options = gen_auth_options_result.options.challenge;

    println!("generate_authentication_options succeeded, got commitmentId: {}", commitment_id);

    // Check that the user_id associated with the commitment is the caller
    let pending_data: Option<UserIdYieldId> = user_account
        .view(contract.id(), "get_pending_prune_id")
        .args_json(json!({"commitment_id": commitment_id.clone()}))
        .await?
        .json()?;

    let pending_user_id = pending_data.expect("Pending data should exist").user_id;
    assert_eq!(pending_user_id, user_account.id().to_string(), "Pending user ID should match the caller");
    println!("Successfully verified that pending user_id matches caller");

    // Step 2: Prepare mock AuthenticationResponseJSON for verify_authentication_response
    let mock_authentication_response = create_mock_authentication_response_for_test(
        &rp_id,
        &challenge_from_options,
        credential_id.as_bytes(),
        false // user_verification not required for this test
    );

    // Step 3: Call verify_authentication_response
    println!("\n\n2) Calling verify_authentication_response with commitment_id: {}", commitment_id);
    let verify_auth_outcome = user_account
        .call(contract.id(), "verify_authentication_response")
        .args_json(json!({
            "authentication_response": mock_authentication_response,
            "commitment_id": commitment_id
        }))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;

    assert!(verify_auth_outcome.is_success(), "verify_authentication_response transaction failed");

    let verification_result: VerifiedAuthenticationResponse = verify_auth_outcome.json()?;

    println!("\nverification_result: {:?}", verification_result);
    // This will be false because we are using a mock signature, but it proves the flow works
    assert!(!verification_result.verified, "Verification should fail with mock signature, but flow is successful");

    sandbox.fast_forward(1).await?;

    // Check that the data has been cleaned up
    let data_after_verify: Option<UserIdYieldId> = user_account
        .view(contract.id(), "get_pending_prune_id")
        .args_json(json!({"commitment_id": commitment_id }))
        .await?
        .json()?;
    assert!(data_after_verify.is_none(), "Pending data should be cleaned up after verification");

    println!("\n\nOn-chain commitment authentication flow test completed successfully.");

    Ok(())
}


fn create_mock_auth_options() -> (String, &'static str, serde_json::Value) {
    // Test data setup for authentication
    let rp_id_str = "auth.test.localhost".to_string();
    let credential_id_str = "test_auth_credential_id_12345";
    let credential_id_b64 = TEST_BASE64_URL_ENGINE.encode(credential_id_str);

    // Create mock authenticator device for generate_authentication_options
    let credential_id_vec = credential_id_str.as_bytes().to_vec();
    let credential_public_key_vec = vec![0u8; 32]; // Mock 32-byte public key
    let mock_authenticator_device = json!({
        "credential_id": credential_id_vec,
        "credential_public_key": credential_public_key_vec,
        "counter": 5,
        "transports": ["internal", "hybrid"]
    });

    // Prepare values for auth options
    let rp_id_clone = rp_id_str.clone();
    let allow_credentials_array = json!([{
        "id": credential_id_b64,
        "type": "public-key",
        "transports": ["internal", "hybrid"]
    }]);

    // Step 1: Call generate_authentication_options with yield-resume
    let auth_options_args = json!({
        "rp_id": rp_id_clone,
        "allow_credentials": allow_credentials_array,
        "challenge": null,
        "timeout": 60000u64,
        "user_verification": "preferred",
        "extensions": null,
        "authenticator": mock_authenticator_device
    });

    (rp_id_str, credential_id_str, auth_options_args)
}

// Helper function to create mock AuthenticationResponseJSON for testing
fn create_mock_authentication_response_for_test(
    rp_id_str: &str,
    input_challenge_b64url: &str, // The challenge that clientDataJSON should contain
    credential_id_bytes: &[u8],
    require_user_verification: bool
) -> serde_json::Value {
    let mock_client_data_json_str = serde_json::to_string(&json!({
        "type": "webauthn.get", // Note: "webauthn.get" for authentication (vs "webauthn.create" for registration)
        "challenge": input_challenge_b64url,
        "origin": format!("https://{}", rp_id_str),
        "crossOrigin": false
    })).unwrap();
    let mock_client_data_b64 = TEST_BASE64_URL_ENGINE.encode(&mock_client_data_json_str);

    // Create mock authenticator data for authentication
    let mut test_auth_data = Vec::new();
    let sha256_rp_id = { let mut h = Sha256::new(); h.update(rp_id_str.as_bytes()); h.finalize().to_vec() };
    test_auth_data.extend_from_slice(&sha256_rp_id); // RP ID hash (32 bytes)

    let mut flags = 0x01; // User Present (UP) - required for authentication
    if require_user_verification {
        flags |= 0x04; // User Verified (UV)
    }
    // Note: No Attested credential data flag for authentication
    test_auth_data.push(flags);
    test_auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x06]); // Counter = 6 (incremented from mock device counter of 5)

    let test_authenticator_data_b64 = TEST_BASE64_URL_ENGINE.encode(&test_auth_data);

    // Create mock signature (in real scenario, this would be generated by the authenticator)
    let mock_signature = vec![0u8; 64]; // Mock 64-byte signature
    let mock_signature_b64 = TEST_BASE64_URL_ENGINE.encode(&mock_signature);

    json!({
        "id": TEST_BASE64_URL_ENGINE.encode(credential_id_bytes),
        "rawId": TEST_BASE64_URL_ENGINE.encode(credential_id_bytes),
        "type": "public-key",
        "response": {
            "clientDataJSON": mock_client_data_b64,
            "authenticatorData": test_authenticator_data_b64,
            "signature": mock_signature_b64,
            "userHandle": TEST_BASE64_URL_ENGINE.encode(b"test_user_handle")
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {}
    })
}

