use near_workspaces::types::Gas;
use serde_json::json;

#[tokio::test]
async fn test_basic_contract_init() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    println!("\n\n✅ Contract deployed successfully: {:?}", contract.id());

    // Try a simple init with minimal parameters
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "test"}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    println!("init_outcome: {:?}", init_outcome.outcome());

    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    println!("Init call completed");

    // Instead of checking is_success(), let's verify the contract works by calling a view method
    let contract_name: String = contract
        .view("get_contract_name")
        .args_json(json!({}))
        .await?
        .json()?;

    println!("Contract name from view call: {}", contract_name);
    assert_eq!(contract_name, "test", "Contract name should match what we set during init");

    println!("✅ Contract initialization and view call successful!");

    Ok(())
}