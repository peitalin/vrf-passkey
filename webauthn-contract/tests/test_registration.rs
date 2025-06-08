use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
use base64::Engine as TestEngine;
use serde_json::json;
use near_workspaces::types::Gas;
use sha2::{Sha256, Digest};
use serde_cbor;
use webauthn_contract::{RegistrationOptionsJSON, AuthenticatorSelectionCriteria};


#[tokio::test]
async fn test_contract_basic_functionality() -> Result<(), Box<dyn std::error::Error>> {
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
    assert!(
        init_outcome.is_success(),
        "Initialization failed: {:#?}",
        init_outcome.into_result().unwrap_err()
    );

    // Test greeting functionality (doesn't use yield-resume)
    let outcome_set_greeting = user_account
        .call(contract.id(), "set_greeting")
        .args_json(json!({"greeting": "Hello World!"}))
        .transact()
        .await?;
    assert!(
        outcome_set_greeting.is_success(),
        "set_greeting failed: {:?}",
        outcome_set_greeting.into_result().unwrap_err()
    );

    let user_message_outcome = contract.view("get_greeting").args_json(json!({})).await?;
    assert_eq!(user_message_outcome.json::<String>()?, "Hello World!");

    // Test contract name functionality
    let outcome_set_name = user_account
        .call(contract.id(), "set_contract_name")
        .args_json(json!({"contract_name": "new-name.testnet"}))
        .transact()
        .await?;
    assert!(
        outcome_set_name.is_success(),
        "set_contract_name failed: {:?}",
        outcome_set_name.into_result().unwrap_err()
    );

    let contract_name_outcome = contract.view("get_contract_name").args_json(json!({})).await?;
    assert_eq!(contract_name_outcome.json::<String>()?, "new-name.testnet");

    println!("Basic contract functionality tests passed!");
    Ok(())
}

#[tokio::test]
async fn test_registration_on_chain_commitment_flow_invocations() -> Result<(), Box<dyn std::error::Error>> {
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
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", if init_outcome.is_failure() { Some(init_outcome.into_result().unwrap_err()) } else { None });

    // Test data
    let rp_name = "My Passkey App".to_string();
    let rp_id = "example.localhost".to_string();
    let user_name_for_entity = "testuser".to_string();
    let user_id_bytes = vec![1u8; 16];
    let challenge_bytes = vec![10u8; 16];
    let user_id_b64 = TEST_BASE64_URL_ENGINE.encode(&user_id_bytes);
    let challenge_b64url_from_input = TEST_BASE64_URL_ENGINE.encode(&challenge_bytes);

    // Step 1: Call generate_registration_options
    let options_args = json!({
        "rp_name": rp_name.clone(),
        "rp_id": rp_id.clone(),
        "user_name": user_name_for_entity.clone(),
        "user_id": user_id_b64.clone(),
        "challenge": challenge_b64url_from_input.clone(),
        "user_display_name": "Test User Display",
        "authenticator_selection": {"user_verification": "required"}, // Fixed field name
        "timeout": 60000u64,
        "attestation_type": "none",
        "exclude_credentials": null,
        "extensions": {"cred_props": true}, // Fixed field name
        "supported_algorithm_ids": [-7, -257],
        "preferred_authenticator_type": null,
    });

    println!("Calling generate_registration_options with args:\n{:?}", options_args);
    let initial_options_outcome = user_account
        .call(contract.id(), "generate_registration_options")
        .args_json(options_args.clone())
        .gas(Gas::from_tgas(300))
        .transact_async()
        .await?;

    let options_outcome = initial_options_outcome.await?;
    assert!(options_outcome.is_success(),
        "generate_registration_options call failed: {:?}", options_outcome.into_result());

    sandbox.fast_forward(2).await?;

    let options_response_json_str: String = options_outcome.json()?;
    let parsed_options_response: RegistrationOptionsJSON = serde_json::from_str(&options_response_json_str)?;
    let commitment_id = parsed_options_response.commitment_id.expect("commitment_id should be in response").to_string();
    println!("generate_registration_options succeeded, got commitmentId: {}", commitment_id);

    // Step 2: Prepare mock RegistrationResponseJSON for verify_registration_response
    let mock_client_data_json_str_for_test = serde_json::to_string(&json!({
        "type": "webauthn.create",
        "challenge": challenge_b64url_from_input, // Use the same challenge as input
        "origin": format!("https://{}", rp_id.clone()),
        "crossOrigin": false
    })).unwrap();
    let mock_client_data_b64_for_test = TEST_BASE64_URL_ENGINE.encode(&mock_client_data_json_str_for_test);
    let test_cred_id_bytes = b"test_integration_cred_id";

    let mock_registration_response_for_complete = json!({
        "id": TEST_BASE64_URL_ENGINE.encode(test_cred_id_bytes),
        "rawId": TEST_BASE64_URL_ENGINE.encode(test_cred_id_bytes),
        "type": "public-key",
        "response": {
            "clientDataJSON": mock_client_data_b64_for_test,
            "attestationObject": TEST_BASE64_URL_ENGINE.encode(b"mock_attestation_object_bytes"),
            "transports": ["internal"]
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {}
    });

    // Step 3: Call verify_registration_response
    let complete_args = json!({
        "registration_response": mock_registration_response_for_complete,
        "commitment_id": commitment_id
    });
    println!("Calling verify_registration_response with commitment_id: {}", commitment_id);
    let complete_outcome = user_account
        .call(contract.id(), "verify_registration_response")
        .args_json(complete_args)
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(complete_outcome.is_success(), "verify_registration_response call failed: {:?}", if complete_outcome.is_failure() { Some(complete_outcome.into_result().unwrap_err()) } else { None });

    let verification_result: webauthn_contract::VerifiedRegistrationResponse = complete_outcome.json()?;
    // This will fail verification because the attestation object is mock, but it proves the deserialization and flow works.
    assert!(!verification_result.verified, "Verification should fail with mock attestation, but flow is successful");

    println!("On-chain commitment flow (generate_options and verify_registration_response calls) succeeded.");

    Ok(())
}

#[tokio::test]
async fn test_contract_yield_resume_full_flow() -> Result<(), Box<dyn std::error::Error>> {
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

    // Test data setup
    let rp_name = "My Test App".to_string();
    let rp_id_str = "test.rp.id".to_string();
    let user_name_for_entity = "yielduser".to_string();
    let user_id_bytes = b"yield_user_id_0123456789ABCDEF".to_vec();
    let challenge_bytes = b"initial_challenge_bytes_for_yield".to_vec();

    let user_id_b64 = TEST_BASE64_URL_ENGINE.encode(&user_id_bytes);
    let challenge_b64url_from_input = TEST_BASE64_URL_ENGINE.encode(&challenge_bytes);

    let authenticator_selection_for_test = AuthenticatorSelectionCriteria {
        user_verification: Some("required".to_string()),
        resident_key: Some("required".to_string()),
        require_resident_key: Some(true),
        authenticator_attachment: Some("platform".to_string()),
    };

    let options_args = json!({
        "rp_name": rp_name.clone(),
        "rp_id": rp_id_str.clone(),
        "user_name": user_name_for_entity.clone(),
        "user_id": user_id_b64.clone(),
        "challenge": challenge_b64url_from_input.clone(),
        "user_display_name": "Yield Test User",
        "authenticator_selection": authenticator_selection_for_test.clone(),
        "timeout": 60000u64,
        "attestation_type": "none",
        "exclude_credentials": null,
        "extensions": {"cred_props": true},
        "supported_algorithm_ids": [-7, -257],
        "preferred_authenticator_type": "platform",
    });

    // Step 1: Call generate_registration_options
    println!("Calling generate_registration_options (async) with args:\n{:?}", options_args);
    let options_request_handle = user_account
        .call(contract.id(), "generate_registration_options")
        .args_json(options_args.clone())
        .gas(Gas::from_tgas(150))
        .transact_async()
        .await?;

    let options_outcome = options_request_handle.await?;
    assert!(options_outcome.is_success(), "generate_registration_options transaction failed: {:?}", options_outcome.outcome());

    let options_response_json_str: String = options_outcome.json()?;
    let parsed_options_response: RegistrationOptionsJSON = serde_json::from_str(&options_response_json_str)?;
    let commitment_id = parsed_options_response.commitment_id.expect("commitment_id should be in response");
    let yielded_challenge_in_options = parsed_options_response.options.challenge.clone();

    println!("generate_registration_options succeeded, got commitmentId: {}", commitment_id);

    // Check that the prune ID exists after generation
    let prune_id_after_generate: Option<webauthn_contract::UserIdYieldId> = user_account
        .view(contract.id(), "get_pending_prune_id")
        .args_json(json!({"commitment_id": commitment_id }))
        .await?
        .json()?;

    assert!(prune_id_after_generate.is_some(), "Prune ID should exist after generation");
    let yield_resume_id_bytes = prune_id_after_generate.unwrap().yield_resume_id;
    let yield_resume_id = TEST_BASE64_URL_ENGINE.encode(&yield_resume_id_bytes);
    println!("generate_registration_options also yielded a prune callback with yieldResumeId: {:?}", yield_resume_id);

    // Step 2: Advance blockchain state for yield-resume
    sandbox.fast_forward(2).await?;

    // Step 3: Prepare mock RegistrationResponseJSON using the helper
    let test_cred_id_bytes = b"yield_resume_test_cred_id_0123";
    let require_uv_flag = authenticator_selection_for_test.user_verification == Some("required".to_string());
    let mock_registration_response_val = create_mock_registration_response_for_test(
        &rp_id_str,
        &yielded_challenge_in_options,
        test_cred_id_bytes,
        require_uv_flag
    );

    // Step 4: Call verify_registration_response
    let complete_args = json!({
        "registration_response": mock_registration_response_val,
        "commitment_id": commitment_id
    });
    println!("Calling verify_registration_response with commitment_id: {}", commitment_id);
    let complete_transaction_outcome = user_account
        .call(contract.id(), "verify_registration_response")
        .args_json(complete_args)
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;

    assert!(complete_transaction_outcome.is_success(), "verify_registration_response call failed: {:?}", complete_transaction_outcome.outcome());

    let verification_result: webauthn_contract::VerifiedRegistrationResponse = complete_transaction_outcome.json()?;

    assert!(verification_result.verified, "Verification should be successful");
    let registration_info = verification_result.registration_info.expect("Should have registration info");
    assert_eq!(registration_info.credential_id, test_cred_id_bytes);

    // Check that the prune ID has been cleaned up
    let prune_id_after_verify: Option<webauthn_contract::UserIdYieldId> = user_account
        .view(contract.id(), "get_pending_prune_id")
        .args_json(json!({"commitment_id": commitment_id}))
        .await?
        .json()?;
    assert!(prune_id_after_verify.is_none(), "Prune ID should be cleaned up after verification");

    println!("On-chain commitment flow test successful.");

    Ok(())
}


// Helper function to create mock RegistrationResponseJSON for testing
fn create_mock_registration_response_for_test(
    rp_id_str: &str,
    input_challenge_b64url: &str, // The challenge that clientDataJSON should contain
    credential_id_bytes: &[u8],
    require_user_verification: bool
) -> serde_json::Value {
    let mock_client_data_json_str = serde_json::to_string(&json!({
        "type": "webauthn.create",
        "challenge": input_challenge_b64url,
        "origin": format!("https://{}", rp_id_str),
        "crossOrigin": false
    })).unwrap();
    let mock_client_data_b64 = TEST_BASE64_URL_ENGINE.encode(&mock_client_data_json_str);

    let mut test_auth_data = Vec::new();
    let sha256_rp_id = { let mut h = Sha256::new(); h.update(rp_id_str.as_bytes()); h.finalize().to_vec() };
    test_auth_data.extend_from_slice(&sha256_rp_id);

    let mut flags = 0x01 | 0x40; // User Present (UP) + Attested Credential Data (AT)
    if require_user_verification {
        flags |= 0x04; // User Verified (UV)
    }
    test_auth_data.push(flags);
    test_auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Counter
    test_auth_data.extend_from_slice(&[0u8; 16]); // AAGUID (zeroed for simplicity)
    test_auth_data.extend_from_slice(&(credential_id_bytes.len() as u16).to_be_bytes());
    test_auth_data.extend_from_slice(credential_id_bytes);

    let mut test_cose_key = std::collections::BTreeMap::new();
    test_cose_key.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
    test_cose_key.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
    test_cose_key.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(vec![0u8; 32])); // x-coordinate (mock)
    test_auth_data.extend_from_slice(&serde_cbor::to_vec(&test_cose_key).unwrap());

    let mut test_attestation_map = std::collections::BTreeMap::new();
    test_attestation_map.insert(serde_cbor::Value::Text("fmt".to_string()), serde_cbor::Value::Text("none".to_string()));
    test_attestation_map.insert(serde_cbor::Value::Text("attStmt".to_string()), serde_cbor::Value::Map(Default::default()));
    test_attestation_map.insert(serde_cbor::Value::Text("authData".to_string()), serde_cbor::Value::Bytes(test_auth_data));
    let test_attestation_object_b64 = TEST_BASE64_URL_ENGINE.encode(&serde_cbor::to_vec(&test_attestation_map).unwrap());

    json!({
        "id": TEST_BASE64_URL_ENGINE.encode(credential_id_bytes),
        "rawId": TEST_BASE64_URL_ENGINE.encode(credential_id_bytes),
        "type": "public-key",
        "response": {
            "clientDataJSON": mock_client_data_b64,
            "attestationObject": test_attestation_object_b64,
            "transports": ["internal"]
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {}
    })
}
