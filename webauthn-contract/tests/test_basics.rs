use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
use base64::Engine as TestEngine;
use serde_json::json;
use webauthn_contract::{
    AuthenticationExtensionsClientInputsJSON, AuthenticatorSelectionCriteria,
    AuthenticatorTransport, PublicKeyCredentialDescriptorJSON, RegistrationOptionsWithDerpIdJSON,
};

#[tokio::test]
async fn test_contract_is_operational() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;

    test_basics_on(&contract_wasm).await?;
    Ok(())
}

async fn test_basics_on(contract_wasm: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(contract_wasm).await?;

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

    // WebAuthn Registration Options
    let rp_name = "My Passkey App".to_string();
    let rp_id = "example.localhost".to_string();
    let user_name_for_entity = "testuser".to_string();

    let user_id_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let challenge_bytes = vec![
        10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
    ];

    let user_id_b64_for_json = TEST_BASE64_URL_ENGINE.encode(&user_id_bytes);
    let challenge_b64_for_json = TEST_BASE64_URL_ENGINE.encode(&challenge_bytes);

    let user_display_name = "Custom Name".to_string();
    let custom_timeout = 120000u64;
    let custom_attestation = "direct".to_string();
    let custom_exclude = vec![PublicKeyCredentialDescriptorJSON {
        id: TEST_BASE64_URL_ENGINE.encode(b"cred-id-123"),
        type_: "public-key".to_string(),
        transports: Some(vec![AuthenticatorTransport::Usb]),
    }];
    let custom_auth_selection = AuthenticatorSelectionCriteria {
        authenticator_attachment: Some("platform".to_string()),
        resident_key: Some("required".to_string()),
        require_resident_key: Some(true),
        user_verification: Some("required".to_string()),
    };
    let custom_extensions_json = AuthenticationExtensionsClientInputsJSON {
        cred_props: Some(false), // Contract logic should override this to Some(true)
    };
    let custom_alg_ids_vec = vec![-7, -36];
    let custom_pref_auth_type_str = "securityKey".to_string();

    let args = json!({
        "rp_name": rp_name.clone(),
        "rp_id": rp_id.clone(),
        "user_name": user_name_for_entity.clone(),
        "user_id": user_id_b64_for_json.clone(),
        "challenge": Some(challenge_b64_for_json.clone()),
        "user_display_name": Some(user_display_name.clone()),
        "timeout": Some(custom_timeout),
        "attestation_type": Some(custom_attestation.clone()),
        "exclude_credentials": Some(custom_exclude.clone()),
        "authenticator_selection": Some(custom_auth_selection.clone()),
        "extensions": Some(custom_extensions_json.clone()),
        "supported_algorithm_ids": Some(custom_alg_ids_vec.clone()),
        "preferred_authenticator_type": Some(custom_pref_auth_type_str.clone()),
    });

    println!(
        "Sending registration options args (test_basics.rs): {}\n",
        args.to_string()
    );

    let registration_options_outcome = user_account
        .call(contract.id(), "generate_registration_options")
        .args_json(args)
        .transact()
        .await?;

    // Deserialize the full response if the struct is imported and implements Deserialize
    // For now, just checking parts of the JSON value to confirm success and key fields.
    let response_json: serde_json::Value = registration_options_outcome.json()?;
    println!(
        "Received registration options response: {}\n",
        serde_json::to_string_pretty(&response_json).unwrap_or_default()
    );

    // Assert key fields from the response
    assert_eq!(response_json["rp"]["name"].as_str(), Some("My Passkey App"));
    assert_eq!(
        response_json["user"]["id"].as_str(),
        Some(user_id_b64_for_json.as_str())
    );
    assert_eq!(
        response_json["challenge"].as_str(),
        Some(challenge_b64_for_json.as_str())
    );
    assert_eq!(
        response_json["authenticatorSelection"]["requireResidentKey"].as_bool(),
        Some(true)
    );
    assert_eq!(
        response_json["extensions"]["credProps"].as_bool(),
        Some(true)
    );
    assert_eq!(
        response_json["derpAccountId"].as_str(),
        Some(format!("{}.{}", user_name_for_entity, "webauthn-contract.testnet").as_str())
    );

    Ok(())
}
