use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
use base64::Engine as TestEngine;
use serde_json::json;
use near_workspaces::types::Gas;
use sha2::{Sha256, Digest};


#[tokio::test]
async fn test_contract_authentication_yield_resume_flow() -> Result<(), Box<dyn std::error::Error>> {
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

    // Test data setup for authentication
    let rp_id_str = "auth.test.localhost".to_string();
    let credential_id_bytes = b"test_auth_credential_id_12345";
    let credential_id_b64 = TEST_BASE64_URL_ENGINE.encode(credential_id_bytes);

    // Create mock authenticator device for generate_authentication_options
    let credential_id_vec = credential_id_bytes.to_vec();
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

    println!("Calling generate_authentication_options (async) with args:\n{:?}", auth_options_args);
    let auth_options_request_handle = user_account
        .call(contract.id(), "generate_authentication_options")
        .args_json(auth_options_args.clone())
        .gas(Gas::from_tgas(150))
        .transact_async()
        .await?;

    let initial_auth_options_outcome = auth_options_request_handle.await?;
    assert!(initial_auth_options_outcome.is_success(),
        "Initial generate_authentication_options transaction failed: {:?}",
        initial_auth_options_outcome.outcome());

    let auth_options_response_json_str: String = initial_auth_options_outcome.json()?;
    let parsed_auth_options_response: serde_json::Value = serde_json::from_str(&auth_options_response_json_str)?;
    let yield_resume_id_from_server = parsed_auth_options_response["yieldResumeId"]
        .as_str()
        .expect("yieldResumeId should be in authentication options response")
        .to_string();
    let challenge_from_options = parsed_auth_options_response["options"]["challenge"]
        .as_str()
        .expect("challenge should be in authentication options")
        .to_string();

    println!("generate_authentication_options (initial tx) succeeded, got yieldResumeId: {}", yield_resume_id_from_server);
    println!("Generated challenge: {}", challenge_from_options);

    // Step 2: Advance blockchain state for yield-resume
    sandbox.fast_forward(2).await?;

    // Step 3: Prepare mock AuthenticationResponseJSON for verify_authentication_response
    let mock_authentication_response = create_mock_authentication_response_for_test(
        &rp_id_str,
        &challenge_from_options,
        credential_id_bytes,
        false // user_verification not required for this test
    );

    // Step 4: Call verify_authentication_response
    let verify_auth_args = json!({
        "authentication_response": mock_authentication_response,
        "yield_resume_id": yield_resume_id_from_server
    });
    println!("Calling verify_authentication_response with yield_resume_id: {}", yield_resume_id_from_server);
    let verify_auth_transaction_outcome = user_account
        .call(contract.id(), "verify_authentication_response")
        .args_json(verify_auth_args)
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;

    // Step 5: Assert response fields
    let outcome_clone_for_asserts = verify_auth_transaction_outcome.clone();
    let logs_for_assertion = outcome_clone_for_asserts.logs().to_vec();
    let outcome_details_for_assertion = outcome_clone_for_asserts.outcome().clone();
    let final_success_status = outcome_clone_for_asserts.is_success();

    let resume_call_succeeded: bool = if !final_success_status {
        false
    } else {
        match verify_auth_transaction_outcome.json() {
            Ok(value) => value,
            Err(parse_err) => {
                panic!(
                    "verify_authentication_response transaction succeeded but failed to parse JSON result: {:?}. Outcome: {:?}. Logs: {:?}",
                    parse_err, outcome_details_for_assertion, logs_for_assertion
                );
            }
        }
    };

    assert!(final_success_status,
            "verify_authentication_response call itself failed: {:?}. Logs: {:?}",
            outcome_details_for_assertion, logs_for_assertion);

    assert!(resume_call_succeeded,
            "verify_authentication_response method returned false (expected true). Logs: {:?}",
            logs_for_assertion);

    // Check for expected log messages
    let found_resume_log = logs_for_assertion.iter().any(|log|
        log.contains("Resuming authentication with user's WebAuthn response")
    );
    assert!(found_resume_log,
            "Expected log 'Resuming authentication with user\'s WebAuthn response' not found. Logs: {:?}",
            logs_for_assertion);

    // Verify that the authentication options response has the expected structure
    assert!(parsed_auth_options_response["options"]["challenge"].is_string(),
        "Challenge should be present in authentication options");
    assert!(parsed_auth_options_response["options"]["rpId"].is_string(),
        "rpId should be present in authentication options");
    assert!(parsed_auth_options_response["options"]["allowCredentials"].is_array(),
        "allowCredentials should be present in authentication options");
    assert!(parsed_auth_options_response["yieldResumeId"].is_string(),
        "yieldResumeId should be present in authentication options");

    println!("Authentication yield-resume flow completed successfully!");
    println!("✅ Step 1: generate_authentication_options with yield created");
    println!("✅ Step 2: Blockchain state advanced");
    println!("✅ Step 3: Mock authentication response prepared");
    println!("✅ Step 4: verify_authentication_response called successfully");
    println!("✅ Step 5: All response fields verified");

    Ok(())
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
    // Note: No AT (Attested credential data) flag for authentication
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