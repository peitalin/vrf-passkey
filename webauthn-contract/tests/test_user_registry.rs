use near_workspaces::types::Gas;
use serde_json::json;

// Define UserProfile locally to match the contract's structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UserProfile {
    pub account_id: String,
    pub registered_at: u64,
    pub last_activity: u64,
    pub authenticator_count: u32,
    pub username: Option<String>,
}

#[tokio::test]
async fn test_user_registry_functionality() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let user1_account = sandbox.dev_create_account().await?;
    let user2_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "webauthn-contract.testnet"}))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    println!("✅ Contract initialized successfully");

    // Test 1: Register first user
    println!("\n🧪 Test 1: Register first user");
    let register_outcome = user1_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user1_account.id(),
            "username": "alice"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(register_outcome.is_success(), "User registration failed: {:?}", register_outcome.outcome());
    let registration_result: bool = register_outcome.json()?;
    assert!(registration_result, "Registration should return true");
    println!("✅ User1 registered successfully");

    // Test 2: Check user is registered
    println!("\n🧪 Test 2: Check user is registered");
    let is_registered: bool = user1_account
        .view(contract.id(), "is_user_registered")
        .args_json(json!({"user_id": user1_account.id()}))
        .await?
        .json()?;
    assert!(is_registered, "User should be registered");
    println!("✅ User registration confirmed");

    // Test 3: Get user profile
    println!("\n🧪 Test 3: Get user profile");
    let profile: Option<UserProfile> = user1_account
        .view(contract.id(), "get_user_profile")
        .args_json(json!({"user_id": user1_account.id()}))
        .await?
        .json()?;

    assert!(profile.is_some(), "Profile should exist");
    let profile = profile.unwrap();
    assert_eq!(profile.account_id, user1_account.id().to_string());
    assert_eq!(profile.username, Some("alice".to_string()));
    assert_eq!(profile.authenticator_count, 0);
    assert!(profile.registered_at > 0);
    assert!(profile.last_activity > 0);
    println!("✅ User profile retrieved successfully: {:?}", profile);

    // Test 4: Register second user with no username
    println!("\n🧪 Test 4: Register second user without username");
    let register_outcome2 = user2_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user2_account.id(),
            "username": null
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(register_outcome2.is_success(), "User2 registration failed");
    let registration_result2: bool = register_outcome2.json()?;
    assert!(registration_result2, "Registration should return true");
    println!("✅ User2 registered successfully without username");

    // Test 5: Check total users count
    println!("\n🧪 Test 5: Check total users count");
    let total_users: u32 = user1_account
        .view(contract.id(), "get_total_users")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(total_users, 2, "Should have 2 registered users");
    println!("✅ Total users count: {}", total_users);

    // Test 6: Try to register same user again (should fail)
    println!("\n🧪 Test 6: Try duplicate registration");
    let register_duplicate = user1_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user1_account.id(),
            "username": "alice_duplicate"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(register_duplicate.is_success(), "Transaction should succeed");
    let duplicate_result: bool = register_duplicate.json()?;
    assert!(!duplicate_result, "Duplicate registration should return false");
    println!("✅ Duplicate registration correctly rejected");

    // Test 7: Update username
    println!("\n🧪 Test 7: Update username");
    let update_outcome = user1_account
        .call(contract.id(), "update_username")
        .args_json(json!({
            "user_id": user1_account.id(),
            "username": "alice_updated"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(update_outcome.is_success(), "Username update failed");
    let update_result: bool = update_outcome.json()?;
    assert!(update_result, "Username update should return true");
    println!("✅ Username updated successfully");

    // Test 8: Verify username was updated
    println!("\n🧪 Test 8: Verify username update");
    let updated_profile: Option<UserProfile> = user1_account
        .view(contract.id(), "get_user_profile")
        .args_json(json!({"user_id": user1_account.id()}))
        .await?
        .json()?;

    let updated_profile = updated_profile.unwrap();
    assert_eq!(updated_profile.username, Some("alice_updated".to_string()));
    println!("✅ Username update verified: {:?}", updated_profile.username);

    // Test 9: Update user activity
    println!("\n🧪 Test 9: Update user activity");
    let original_activity = updated_profile.last_activity;

    // Wait a bit to ensure timestamp difference
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let activity_outcome = user1_account
        .call(contract.id(), "update_user_activity")
        .args_json(json!({"user_id": user1_account.id()}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(activity_outcome.is_success(), "Activity update failed");
    let activity_result: bool = activity_outcome.json()?;
    assert!(activity_result, "Activity update should return true");

    // Verify activity timestamp changed
    let activity_profile: Option<UserProfile> = user1_account
        .view(contract.id(), "get_user_profile")
        .args_json(json!({"user_id": user1_account.id()}))
        .await?
        .json()?;

    let activity_profile = activity_profile.unwrap();
    assert!(activity_profile.last_activity >= original_activity);
    println!("✅ User activity updated: {} -> {}", original_activity, activity_profile.last_activity);

    // Test 10: Try to update another user's username (should fail)
    println!("\n🧪 Test 10: Try unauthorized username update");
    let unauthorized_update = user1_account
        .call(contract.id(), "update_username")
        .args_json(json!({
            "user_id": user2_account.id(),  // Different user
            "username": "hacked"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!unauthorized_update.is_success(), "Unauthorized update should fail");
    println!("✅ Unauthorized username update correctly rejected");

    println!("\n🎉 All user registry tests passed successfully!");

    Ok(())
}

#[tokio::test]
async fn test_user_registry_with_authenticators() -> Result<(), Box<dyn std::error::Error>> {
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

    // Register user
    let register_outcome = user_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user_account.id(),
            "username": "bob"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert!(register_outcome.is_success() && register_outcome.json::<bool>()?, "User registration failed");

    // Store an authenticator
    let store_outcome = user_account
        .call(contract.id(), "store_authenticator")
        .args_json(json!({
            "user_id": user_account.id(),
            "credential_id": "test_credential_123",
            "credential_public_key": [1, 2, 3, 4, 5],
            "counter": 1,
            "transports": ["internal", "hybrid"],
            "client_managed_near_public_key": "ed25519:test_key",
            "name": "Test Authenticator",
            "registered": "2024-01-01T00:00:00Z",
            "backed_up": false
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(store_outcome.is_success(), "Authenticator storage failed");
    let store_result: bool = store_outcome.json()?;
    assert!(store_result, "Store authenticator should return true");

    // Check that authenticator count was updated
    let profile: Option<UserProfile> = user_account
        .view(contract.id(), "get_user_profile")
        .args_json(json!({"user_id": user_account.id()}))
        .await?
        .json()?;

    let profile = profile.unwrap();
    assert_eq!(profile.authenticator_count, 1, "Authenticator count should be 1");
    println!("✅ Authenticator count updated correctly: {}", profile.authenticator_count);

    // Store a second authenticator
    let store_outcome2 = user_account
        .call(contract.id(), "store_authenticator")
        .args_json(json!({
            "user_id": user_account.id(),
            "credential_id": "test_credential_456",
            "credential_public_key": [6, 7, 8, 9, 10],
            "counter": 1,
            "transports": ["usb"],
            "client_managed_near_public_key": "ed25519:test_key_2",
            "name": "Test Authenticator 2",
            "registered": "2024-01-02T00:00:00Z",
            "backed_up": true
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(store_outcome2.is_success(), "Second authenticator storage failed");

    // Check updated count
    let updated_profile: Option<UserProfile> = user_account
        .view(contract.id(), "get_user_profile")
        .args_json(json!({"user_id": user_account.id()}))
        .await?
        .json()?;

    let updated_profile = updated_profile.unwrap();
    assert_eq!(updated_profile.authenticator_count, 2, "Authenticator count should be 2");
    println!("✅ Authenticator count updated correctly after second store: {}", updated_profile.authenticator_count);

    println!("\n🎉 User registry + authenticator integration tests passed!");

    Ok(())
}