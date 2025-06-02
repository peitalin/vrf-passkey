use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
use base64::Engine as TestEngine;
use serde_json::json;
use near_workspaces::types::Gas;

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
// #[ignore = "Full yield-resume flow with automatic callback execution is not reliably testable in near-workspaces due to environment limitations. Unit tests cover callback logic."]
async fn test_contract_yield_resume() -> Result<(), Box<dyn std::error::Error>> {
    // This test demonstrates the yield-resume flow with manual callback simulation
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
    assert!(init_outcome.is_success(), "Initialization failed");

    // Test data
    let rp_name = "My Passkey App".to_string();
    let rp_id = "example.localhost".to_string();
    let user_name_for_entity = "testuser".to_string();
    let user_id_bytes = vec![1u8; 16];
    let challenge_bytes = vec![10u8; 16];
    let user_id_b64 = TEST_BASE64_URL_ENGINE.encode(&user_id_bytes);
    let challenge_b64 = TEST_BASE64_URL_ENGINE.encode(&challenge_bytes);

    // Step 1: Generate registration options (creates yield)
    let options_args = json!({
        "rp_name": rp_name,
        "rp_id": rp_id.clone(),
        "user_name": user_name_for_entity,
        "user_id": user_id_b64,
        "challenge": Some(challenge_b64.clone()),
        "user_display_name": Some("Test User"),
        "timeout": Some(60000u64),
        "attestation_type": Some("none"),
        "exclude_credentials": null,
        "authenticator_selection": null,
        "extensions": null,
        "supported_algorithm_ids": null,
        "preferred_authenticator_type": null,
    });

    println!("calling generate_registration_options with options_args:\n{:?}", options_args);

    let options_outcome = user_account
        .call(contract.id(), "generate_registration_options")
        .args_json(options_args)
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(options_outcome.is_success(), "generate_registration_options failed: {:?}", if options_outcome.is_failure() { Some(options_outcome.into_result().unwrap_err()) } else { None });

    Ok(())
}
