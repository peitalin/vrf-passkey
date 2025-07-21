use serde_json::json;
use near_workspaces::types::Gas;
use near_workspaces::{Worker};
use near_workspaces::network::Sandbox;

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

    // Test device public key (valid ed25519 format)
    let device2_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";

    ///////////// Step 1: Manually add device linking entry /////////////
    println!("\nStep 1: Manually adding device linking entry for testing");

    let test_account_id = "test.testnet";
    let add_entry_request = contract
        .call("test_add_device_linking_entry")
        .args_json(json!({
            "device_public_key": device2_public_key,
            "account_id": test_account_id
        }))
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;

    // Wait for the async transaction to complete
    let add_entry_outcome = add_entry_request.await?;

    if add_entry_outcome.is_success() {
        println!("✓ test_add_device_linking_entry succeeded");
        for outcome in add_entry_outcome.outcomes() {
            println!("test_add_device_linking_entry logs: {:?}", outcome.logs);
        }
    } else {
        println!("✗ test_add_device_linking_entry failed: {:?}", add_entry_outcome.outcome());
        panic!("test_add_device_linking_entry should succeed");
    }

    fast_forward(&sandbox, 1).await?;

    // Get the current block number after yield creation
    let yield_creation_block = sandbox.view_block().await?.height();
    println!("Yield was created at block: {}", yield_creation_block);

    ///////////// Step 2: Verify device linking mapping exists /////////////
    println!("\nStep 2: Verify device linking mapping exists in HashMap");

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
    assert_eq!(device_number, 2, "Second device should get device number 2");

        ///////////// Step 3: Fast forward 200+ blocks /////////////
    println!("\nStep 3: Fast forwarding 200+ blocks to simulate passage of time");

    fast_forward(&sandbox, 240).await?;

    ///////////// Step 4: Verify device linking mapping is cleaned up /////////////
    println!("\nStep 4: Verify device linking mapping has been cleaned up");

    let query_result_after = contract
        .call("get_device_linking_account")
        .args_json(json!({"device_public_key": device2_public_key}))
        .view()
        .await?;

    let linking_account_after: Option<(String, u32)> = query_result_after.json()?;
    println!("Device linking query result after cleanup: {:?}", linking_account_after);

    // Verify the mapping has been cleaned up
    assert!(linking_account_after.is_none(), "Device linking mapping should be cleaned up after calling cleanup_device_linking");

    println!("Test passed: Device linking HashMap was cleaned up successfully");

    Ok(())
}