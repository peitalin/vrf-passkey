use near_workspaces::types::Gas;
use serde_json::json;

#[tokio::test]
async fn test_basic_contract_init() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    println!("\nContract deployed successfully: {:?}", contract.id());

    // Try a simple init with minimal parameters
    let init_outcome = contract
        .call("init")
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    println!("init_outcome: {:?}", init_outcome.outcome());
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());
    Ok(())
}