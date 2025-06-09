use near_workspaces::types::Gas;
use serde_json::json;

#[tokio::test]
async fn test_admin_functionality() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let admin1_account = sandbox.dev_create_account().await?;
    let admin2_account = sandbox.dev_create_account().await?;
    let user_account = sandbox.dev_create_account().await?;
    let non_admin_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "webauthn-contract.testnet"}))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    println!("✅ Contract initialized successfully");

    // Test 1: Initial state - no admins
    println!("\n🧪 Test 1: Check initial admin state");
    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert!(admins.is_empty(), "Admin list should be empty initially");
    println!("✅ Initial state verified: no admins");

    // Test 2: Contract owner adds first admin
    println!("\n🧪 Test 2: Contract owner adds first admin");
    let add_admin_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin1_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(add_admin_outcome.is_success(), "Add admin failed: {:?}", add_admin_outcome.outcome());
    let add_result: bool = add_admin_outcome.json()?;
    assert!(add_result, "Add admin should return true");
    println!("✅ First admin added successfully");

    // Test 3: Verify admin was added
    println!("\n🧪 Test 3: Verify admin was added");
    let is_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin1_account.id()}))
        .await?
        .json()?;
    assert!(is_admin, "Account should be an admin");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 1);
    assert!(admins.contains(&admin1_account.id().to_string()));
    println!("✅ Admin addition verified");

    // Test 4: Contract owner adds second admin
    println!("\n🧪 Test 4: Contract owner adds second admin");
    let add_admin2_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin2_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(add_admin2_outcome.is_success(), "Add second admin failed");
    let add_result2: bool = add_admin2_outcome.json()?;
    assert!(add_result2, "Add second admin should return true");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 2, "Should have 2 admins");
    println!("✅ Second admin added successfully");

    // Test 5: Try to add duplicate admin (should return false but not fail)
    println!("\n🧪 Test 5: Try to add duplicate admin");
    let add_duplicate_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin1_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(add_duplicate_outcome.is_success(), "Duplicate add should succeed");
    let duplicate_result: bool = add_duplicate_outcome.json()?;
    assert!(!duplicate_result, "Duplicate admin add should return false");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 2, "Should still have 2 admins");
    println!("✅ Duplicate admin correctly rejected");

    // Test 6: Non-owner tries to add admin (should fail)
    println!("\n🧪 Test 6: Non-owner tries to add admin");
    let unauthorized_add = admin1_account
        .call(contract.id(), "add_admin")
        .args_json(json!({
            "admin_id": user_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!unauthorized_add.is_success(), "Non-owner should not be able to add admin");
    println!("✅ Non-owner admin addition correctly rejected");

    // Test 7: Admin can register users
    println!("\n🧪 Test 7: Admin can register users");
    let admin_register_outcome = admin1_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user_account.id(),
            "username": "test_user"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(admin_register_outcome.is_success(), "Admin should be able to register users");
    let register_result: bool = admin_register_outcome.json()?;
    assert!(register_result, "User registration by admin should succeed");

    // Verify user was registered
    let is_registered: bool = contract
        .view("is_user_registered")
        .args_json(json!({"user_id": user_account.id()}))
        .await?
        .json()?;
    assert!(is_registered, "User should be registered");
    println!("✅ Admin successfully registered user");

    // Test 8: Non-admin tries to register another user (should fail)
    println!("\n🧪 Test 8: Non-admin tries to register another user");
    let non_admin_register = non_admin_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": admin2_account.id(),
            "username": "should_fail"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!non_admin_register.is_success(), "Non-admin should not be able to register other users");
    println!("✅ Non-admin user registration correctly rejected");

    // Test 9: Contract owner removes admin
    println!("\n🧪 Test 9: Contract owner removes admin");
    let remove_admin_outcome = contract
        .call("remove_admin")
        .args_json(json!({
            "admin_id": admin2_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(remove_admin_outcome.is_success(), "Remove admin failed");
    let remove_result: bool = remove_admin_outcome.json()?;
    assert!(remove_result, "Remove admin should return true");

    // Verify admin was removed
    let is_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin2_account.id()}))
        .await?
        .json()?;
    assert!(!is_admin, "Account should no longer be an admin");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 1, "Should have 1 admin after removal");
    println!("✅ Admin removed successfully");

    // Test 10: Try to remove non-existent admin (should return false but not fail)
    println!("\n🧪 Test 10: Try to remove non-existent admin");
    let remove_nonexistent_outcome = contract
        .call("remove_admin")
        .args_json(json!({
            "admin_id": user_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(remove_nonexistent_outcome.is_success(), "Remove non-existent should succeed");
    let remove_nonexistent_result: bool = remove_nonexistent_outcome.json()?;
    assert!(!remove_nonexistent_result, "Remove non-existent admin should return false");
    println!("✅ Non-existent admin removal correctly handled");

    // Test 11: Non-owner tries to remove admin (should fail)
    println!("\n🧪 Test 11: Non-owner tries to remove admin");
    let unauthorized_remove = admin1_account
        .call(contract.id(), "remove_admin")
        .args_json(json!({
            "admin_id": admin1_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!unauthorized_remove.is_success(), "Non-owner should not be able to remove admin");
    println!("✅ Non-owner admin removal correctly rejected");

    // Test 12: Removed admin can no longer register users for others
    println!("\n🧪 Test 12: Removed admin can no longer register users for others");
    let ex_admin_register = admin2_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": non_admin_account.id(),
            "username": "should_fail"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!ex_admin_register.is_success(), "Removed admin should not be able to register other users");
    println!("✅ Removed admin correctly loses privileges");

    // Test 13: Remaining admin still works
    println!("\n🧪 Test 13: Remaining admin still works");
    let remaining_admin_register = admin1_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": non_admin_account.id(),
            "username": "remaining_admin_test"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(remaining_admin_register.is_success(), "Remaining admin should still work");
    let remaining_register_result: bool = remaining_admin_register.json()?;
    assert!(remaining_register_result, "Remaining admin registration should succeed");
    println!("✅ Remaining admin still functional");

    println!("\n🎉 All admin functionality tests passed successfully!");

    Ok(())
}

#[tokio::test]
async fn test_admin_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let admin_account = sandbox.dev_create_account().await?;
    let user1_account = sandbox.dev_create_account().await?;
    let user2_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "webauthn-contract.testnet"}))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed");

    println!("✅ Contract initialized for edge case tests");

    // Test 1: Check non-existent account admin status
    println!("\n🧪 Test 1: Check non-existent account admin status");
    let is_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": "non-existent.testnet"}))
        .await?
        .json()?;
    assert!(!is_admin, "Non-existent account should not be admin");
    println!("✅ Non-existent account correctly not admin");

    // Test 2: User can still register themselves even if not admin
    println!("\n🧪 Test 2: User can register themselves");
    let self_register_outcome = user1_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user1_account.id(),
            "username": "self_registered"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(self_register_outcome.is_success(), "Users should be able to register themselves");
    let self_register_result: bool = self_register_outcome.json()?;
    assert!(self_register_result, "Self registration should succeed");
    println!("✅ User self-registration works");

    // Test 3: Add admin and verify they can register others
    println!("\n🧪 Test 3: Add admin and verify cross-registration");
    let add_admin_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(add_admin_outcome.is_success(), "Add admin should succeed");

    // Admin registers another user
    let admin_register_outcome = admin_account
        .call(contract.id(), "register_user")
        .args_json(json!({
            "user_id": user2_account.id(),
            "username": "admin_registered"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(admin_register_outcome.is_success(), "Admin should be able to register other users");
    let admin_register_result: bool = admin_register_outcome.json()?;
    assert!(admin_register_result, "Admin registration should succeed");

    // Verify both users are registered
    let user1_registered: bool = contract
        .view("is_user_registered")
        .args_json(json!({"user_id": user1_account.id()}))
        .await?
        .json()?;
    assert!(user1_registered, "User1 should be registered");

    let user2_registered: bool = contract
        .view("is_user_registered")
        .args_json(json!({"user_id": user2_account.id()}))
        .await?
        .json()?;
    assert!(user2_registered, "User2 should be registered");

    let total_users: u32 = contract
        .view("get_total_users")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(total_users, 2, "Should have 2 registered users");

    println!("✅ Admin cross-registration verified: {} total users", total_users);

    // Test 4: Contract owner (relayer) can also register users
    println!("\n🧪 Test 4: Contract owner can register users");
    let owner_user_account = sandbox.dev_create_account().await?;
    let owner_register_outcome = contract
        .call("register_user")
        .args_json(json!({
            "user_id": owner_user_account.id(),
            "username": "owner_registered"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(owner_register_outcome.is_success(), "Contract owner should be able to register users");
    let owner_register_result: bool = owner_register_outcome.json()?;
    assert!(owner_register_result, "Owner registration should succeed");

    let total_users_after_owner: u32 = contract
        .view("get_total_users")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(total_users_after_owner, 3, "Should have 3 registered users");
    println!("✅ Contract owner registration verified");

    println!("\n🎉 All admin edge case tests passed successfully!");

    Ok(())
}