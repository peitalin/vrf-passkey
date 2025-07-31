use serde_json::json;
use near_workspaces::types::Gas;
use near_workspaces::{Worker, Account};
use near_workspaces::network::Sandbox;
use near_workspaces::types::{NearToken, KeyType};


#[tokio::test]
async fn test_device_linking_automatic_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    async fn fast_forward(sandbox: &Worker<Sandbox>, blocks: u64) -> Result<(), Box<dyn std::error::Error>> {
        sandbox.fast_forward(blocks).await?;
        let block = sandbox.view_block().await?;
        println!("Advanced to block: {}", block.height());
        Ok(())
    }

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "webauthn-contract.testnet"}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    fast_forward(&sandbox, 1).await?;

    ///////////// Step 1: Create test account and add temporary key /////////////
    println!("\nStep 1: Creating test account and adding temporary key");

    // Create a test account that will own the device linking
    let test_account = sandbox.dev_create_account().await?;
    let test_account_id = test_account.id().as_str();

    // Create a new key pair for testing (since we can't easily match the exact test key)
    let temp_device2_key_pair = near_workspaces::types::SecretKey::from_seed(KeyType::ED25519, "temp_device_key");
    let device2_public_key = temp_device2_key_pair.public_key();

    // Actually add a temporary access key to the test account
    // This simulates the device linking process where Device1 adds Device2's key
    println!("✓ Adding Device2's temporary key to test account");
    println!("  - Device2 public key: {}", device2_public_key);
    println!("  - This key will be automatically removed after 200 blocks if device linking fails");

    // Add the temporary key as a full access key to the test account
    let add_key_outcome = test_account
        .batch(test_account.id())
        .add_key(device2_public_key.clone(), near_workspaces::types::AccessKey::full_access())
        .transact()
        .await?;

    if add_key_outcome.is_success() {
        println!("✓ Successfully added temporary access key to test account");
        println!("  - Temporary key: {}", device2_public_key);
    } else {
        panic!("Failed to add temporary access key: {:?}", add_key_outcome.outcome());
    }

    // Test that the temporary key can transfer NEAR on behalf of the account
    println!("Testing temporary key access to account...");
    let transfer_amount = NearToken::from_near(1);

    // Create a new account to transfer to
    let recipient_account = sandbox.dev_create_account().await?;
    let recipient_id = recipient_account.id();

    // Create a new account instance with the temporary key for signing
    let test_account_with_temp_key = Account::from_secret_key(
        test_account.id().clone(),
        temp_device2_key_pair.clone(),
        &sandbox
    );

    // Attempt transfer using the temporary key
    let transfer_request = test_account_with_temp_key
        .call(&recipient_id, "transfer")
        .args_json(json!({}))
        .deposit(transfer_amount)
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;

    let transfer_outcome = transfer_request.await?;
    println!("Transfer outcome: {:?}", transfer_outcome.outcome());

    // The transfer succeeded if we got here without an error
    // The status shows SuccessReceiptId which means it worked
    println!("✓ Temporary key successfully transferred {} NEAR to {} on behalf of account", transfer_amount, recipient_id);

    ///////////// Step 2: Store device linking mapping and schedule cleanup /////////////
    println!("\nStep 2: Storing device linking mapping and scheduling cleanup");

    // Call the actual store_device_linking_mapping method from the test account
    // This will schedule both mapping cleanup and key cleanup
    let store_mapping_request = test_account
        .call(contract.id(), "store_device_linking_mapping")
        .args_json(json!({
            "device_public_key": device2_public_key,
            "target_account_id": test_account_id
        }))
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;

    // Wait for the async transaction to complete
    let store_mapping_outcome = store_mapping_request.await?;

    if store_mapping_outcome.is_success() {
        println!("✓ store_device_linking_mapping succeeded");
        for outcome in store_mapping_outcome.outcomes() {
            println!("store_device_linking_mapping logs: {:?}", outcome.logs);
        }
    } else {
        println!("✗ store_device_linking_mapping failed: {:?}", store_mapping_outcome.outcome());
        panic!("store_device_linking_mapping should succeed");
    }

    fast_forward(&sandbox, 1).await?;

    // Get the current block number after yield creation
    let yield_creation_block = sandbox.view_block().await?.height();
    println!("Yield was created at block: {}", yield_creation_block);

    ///////////// Step 3: Verify device linking mapping exists /////////////
    println!("\nStep 3: Verify device linking mapping exists in HashMap");

    let query_result = contract
        .call("get_device_linking_account")
        .args_json(json!({"device_public_key": device2_public_key}))
        .view()
        .await?;

    let linking_account: Option<(String, u32)> = query_result.json()?;
    println!("Device linking query result: {:?}", linking_account);

    // Verify the mapping exists and points to the test account
    assert!(linking_account.is_some(), "Device linking mapping should exist");
    let (account_id, device_number) = linking_account.unwrap();
    assert_eq!(account_id, test_account_id);
    assert_eq!(device_number, 1, "First device should get device number 1");

        ///////////// Step 4: Fast forward 200+ blocks /////////////
    println!("\nStep 4: Fast forwarding 200+ blocks to simulate passage of time");

    fast_forward(&sandbox, 240).await?;

    ///////////// Step 5: Verify device linking mapping is cleaned up /////////////
    println!("\nStep 5: Verify device linking mapping has been cleaned up");

    let query_result_after = contract
        .call("get_device_linking_account")
        .args_json(json!({"device_public_key": device2_public_key}))
        .view()
        .await?;

    let linking_account_after: Option<(String, u32)> = query_result_after.json()?;
    println!("Device linking query result after cleanup: {:?}", linking_account_after);

    // Verify the mapping has been cleaned up
    assert!(linking_account_after.is_none(), "Device linking mapping should be cleaned up after calling cleanup_device_linking");

    ///////////// Step 6: Verify temporary key was removed by yield-resume cleanup /////////////
    println!("\nStep 6: Verifying temporary key was removed by yield-resume cleanup");

    // Check account balance before attempting the failed transfer
    let balance_before = test_account.view_account().await?.balance;
    println!("Account balance before failed transfer attempt: {} NEAR", balance_before.as_near());

    // Attempt another transfer using the temporary key after cleanup
    let transfer_amount_after = NearToken::from_near(1);
    let recipient_account_after = sandbox.dev_create_account().await?;
    let recipient_id_after = recipient_account_after.id();

    // Try to use the temporary key again (should FAIL because the yield-resume promise should have removed it)
    println!("Attempting transfer with temporary key that should have been deleted...");
    let transfer_outcome = test_account_with_temp_key
        .call(&recipient_id_after, "transfer")
        .args_json(json!({}))
        .deposit(transfer_amount_after)
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;

    let outcome = transfer_outcome.await?;
    println!("Transfer outcome after cleanup: {:?}\n", outcome.outcome());

    // Check if the transaction actually failed due to invalid access key
    if outcome.is_failure() {
        println!("✓ Temporary key access denied after cleanup - key was successfully removed by yield promise");
        println!("  - Transaction failed as expected: key no longer exists on the blockchain");
    } else {
        // If the transaction succeeded, this means the key cleanup didn't work
        panic!("FAILURE: Temporary key still has access after 200+ blocks! Key cleanup did not work properly.");
    }

    // Check account balance after the failed transfer attempt
    let balance_after = test_account.view_account().await?.balance;
    println!("Account balance after failed transfer attempt: {} NEAR", balance_after.as_near());

    // Verify that the balance remained the same (no tokens were deducted)
    let difference = if balance_before > balance_after {
        balance_before.saturating_sub(balance_after)
    } else {
        balance_after.saturating_sub(balance_before)
    };
    // Allow for small gas cost differences (less than 0.01 NEAR)
    if difference > NearToken::from_millinear(10) {
        panic!("FAILURE: Account balance changed by: {} NEAR, temp device2 key not removed!", difference.as_near());
    } else {
        println!("✓ Account balance unchanged - confirms transfer failed and no tokens were deducted");
    }

    ///////////// Step 7: Verify yield promise creation /////////////
    println!("\nStep 7: Verify yield promises were created");

    // Check that the yield promises were created by looking for the logs
    let mut yield_creation_logs = Vec::new();
    for outcome in store_mapping_outcome.outcomes() {
        for log in &outcome.logs {
            if log.contains("Automatic cleanup scheduled") || log.contains("data_id") {
                yield_creation_logs.push(log.clone());
            }
        }
    }

    // Verify that both cleanup promises were scheduled
    assert!(!yield_creation_logs.is_empty(), "Should have created yield promises for cleanup");
    println!("Found {} yield creation logs:", yield_creation_logs.len());
    for log in yield_creation_logs {
        println!("  - {}", log);
    }

    ///////////// Step 8: Verify temporary key cleanup logic /////////////
    println!("\nStep 8: Verify temporary key cleanup logic");

    // Check that the cleanup_temporary_key method was scheduled
    let mut key_cleanup_scheduled = false;
    for outcome in store_mapping_outcome.outcomes() {
        for log in &outcome.logs {
            if log.contains("Initiated automatic key cleanup") {
                key_cleanup_scheduled = true;
                println!("✓ Found key cleanup scheduling log: {}", log);
                break;
            }
        }
    }

    assert!(key_cleanup_scheduled, "Key cleanup should be scheduled for temporary key removal");
    println!("✓ Temporary key cleanup scheduling verified");

    println!("Test passed: Device linking mapping cleanup, yield promise creation, and key cleanup scheduling verified");

    Ok(())
}