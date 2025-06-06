use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
use base64::Engine as TestEngine;
use serde_json::json;
use near_workspaces::types::Gas;
use sha2::{Sha256, Digest};
use near_primitives::hash::CryptoHash as CryptoHash2;
use near_jsonrpc_primitives::types::receipts::ReceiptReference;
use near_primitives::views::{ReceiptEnumView, ActionView};

use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_primitives::views::TxExecutionStatus;

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

    let mut tx_hashes = Vec::new();
    let mut receipt_ids = Vec::new();

    // Step 1: Call generate_authentication_options with yield-resume
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
        "Initial generate_authentication_options transaction failed: {:?}",
        gen_auth_options_outcome.outcome());

    for outcome in gen_auth_options_outcome.outcomes() {
        println!("generate_authentication_options ReceiptIDs: {:?}", outcome.receipt_ids);
        tx_hashes.push(outcome.transaction_hash);
        receipt_ids.extend(outcome.receipt_ids.iter().map(|id| id.clone()));
    }

    let auth_options_response_json_str: String = gen_auth_options_outcome.json()?;
    let parsed_auth_options_response: serde_json::Value = serde_json::from_str(&auth_options_response_json_str)?;
    let yield_resume_id_from_server = parsed_auth_options_response["yieldResumeId"]
        .as_str()
        .expect("yieldResumeId should be in authentication options response")
        .to_string();
    let challenge_from_options = parsed_auth_options_response["options"]["challenge"]
        .as_str()
        .expect("challenge should be in authentication options")
        .to_string();

    println!("generate_authentication_options succeeded, got yieldResumeId: {}", yield_resume_id_from_server);
    println!("generated challenge: {}", challenge_from_options);

    // Step 2: Advance blockchain state for yield-resume
    sandbox.fast_forward(1).await?;

    // Step 3: Prepare mock AuthenticationResponseJSON for verify_authentication_response
    let mock_authentication_response = create_mock_authentication_response_for_test(
        &rp_id,
        &challenge_from_options,
        credential_id.as_bytes(),
        false // user_verification not required for this test
    );

    // Step 4: Call verify_authentication_response
    println!("\n\n2) Calling verify_authentication_response with yield_resume_id: {}", yield_resume_id_from_server);
    let verify_auth_outcome = user_account
        .call(contract.id(), "verify_authentication_response")
        .args_json(json!({
            "authentication_response": mock_authentication_response,
            "yield_resume_id": yield_resume_id_from_server
        }))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;

    // Step 5: Assert response fields
    for outcome in verify_auth_outcome.outcomes() {
        println!("verify_authentication_response ReceiptIDs: {:?}", outcome.receipt_ids);
        tx_hashes.push(outcome.transaction_hash);
        receipt_ids.extend(outcome.receipt_ids.iter().map(|id| id.clone()));
    }

    for receipt_id in receipt_ids {
        // Convert the receipt_id CryptoHash to a near_primitives::CryptoHash
        let receipt_id2 = CryptoHash2::try_from(receipt_id.0.as_slice()).unwrap();
        assert_eq!(receipt_id2.to_string(), receipt_id.to_string());

        println!("\nquerying receipt_id: {:?}", receipt_id2);
        let receipt = sandbox.receipt(ReceiptReference { receipt_id: receipt_id2, }).await?;

        match receipt.receipt {
            ReceiptEnumView::Action {
                is_promise_yield,
                actions,
                ..
            } => {
                if let Some(action) = actions.iter().next() {
                    match action {
                        ActionView::FunctionCall {
                            method_name,
                            args,
                            ..
                        } => {
                            println!("method_name: {:?}", method_name);
                            println!("is_promise_yield: {:?}", is_promise_yield);
                            println!("args: {:?}", args);
                            if method_name == "resume_authentication_callback" {
                                assert!(is_promise_yield, "is_promise_yield for resume_authentication_callback should be true");
                            }
                        }
                        _ => {
                            println!("action: {:?}", action);
                        }
                    }
                }
            }
            ReceiptEnumView::Data { data, data_id, is_promise_resume, } => {
                println!("data: {:?}", data);
            }
            _ => {}
        }
    };

    // println!("\n\n=========================================");
    // println!("Total tx_hashes: {:?}", tx_hashes);
    // println!("=========================================\n\n");
    // for tx_hash in tx_hashes {
    //     let tx_hash2 = CryptoHash2::try_from(tx_hash.0.as_slice()).unwrap();
    //     assert_eq!(tx_hash2.to_string(), tx_hash.to_string());
    //     println!("\nquerying tx_hash: {:?}", tx_hash2);
    //     let tx_response = sandbox.tx_status(
    //         TransactionInfo::TransactionId {
    //             tx_hash: tx_hash2,
    //             sender_account_id: user_account.id().clone(),
    //         },
    //         TxExecutionStatus::Final,
    //     ).await?;
    //     println!("tx_response: {:?}", tx_response);
    // }

    // resumed callback should set the greeting to rp_id and challenge (for test purposes only)
    let greeting = user_account.call(contract.id(), "get_greeting").transact().await?;
    let actual_result = greeting.json::<String>()?;
    println!("\n\nget_greeting: {}", actual_result);

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

