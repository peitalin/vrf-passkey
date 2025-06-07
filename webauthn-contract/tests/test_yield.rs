use serde_json::json;
use near_workspaces::types::Gas;
use near_workspaces::{sandbox, Worker, CryptoHash};
use near_workspaces::network::Sandbox;
use near_jsonrpc_primitives::types::transactions::TransactionInfo;
use near_jsonrpc_primitives::types::receipts::ReceiptReference;
use near_primitives::types::FunctionArgs;
use near_primitives::views::{TxExecutionStatus, ReceiptView, ReceiptEnumView, ActionView};
use near_primitives::hash::CryptoHash as CryptoHash2;



#[tokio::test]
async fn test_yield_resume_flow() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let user_account = sandbox.dev_create_account().await?;

    async fn fast_forward(sandbox: &Worker<Sandbox>, blocks: u64) -> Result<(), Box<dyn std::error::Error>> {
        sandbox.fast_forward(blocks).await?;
        // let block = sandbox.view_block().await?;
        // println!("block: {:?}", block.height());
        Ok(())
    }

    let mut tx_hashes = Vec::new();
    let mut receipt_ids = Vec::new();

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({"contract_name": "webauthn-contract.testnet"}))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    fast_forward(&sandbox, 1).await?;

    ///////////// Step 1: Yield /////////////
    println!("\n\nStep 1: Calling yield_test (async)");
    let yield_request = user_account
        .call(contract.id(), "yield_test")
        .gas(Gas::from_tgas(150))
        .transact_async()
        .await?;

    // Step 2: Advance blockchain state for yield-resume
    fast_forward(&sandbox, 1).await?;
    println!("\n\nStep 2: Blockchain state advanced 1 block");

    let yield_outcome = yield_request.await?;
    println!("yield_test TX Outcomes:");
    for (i, outcome) in yield_outcome.outcomes().iter().enumerate() {
        println!("yield_test({}) tx_hash:\t{:?}", i, outcome.transaction_hash);
        println!("yield_test({}) logs:\t{:?}", i, outcome.logs);
        println!("yield_test({}) receipt_ids:\t{:?}", i, outcome.receipt_ids);
        tx_hashes.push(outcome.transaction_hash);
        receipt_ids.extend(outcome.receipt_ids.iter().map(|id| id.clone()));
        println!("\n")
    }
    // Get the yield_resume_id from the response
    let yield_resume_id: String = yield_outcome.json()?;
    println!("yield_test result: {}", yield_resume_id);

    fast_forward(&sandbox, 1).await?;

    // Step 3: Call resume_test with the yield_resume_id
    println!("\n\nStep 3: Resuming by calling resume_test with yield_resume_id");
    let resume_result = user_account
        .call(contract.id(), "resume_test")
        .args_json(json!({"yield_resume_id": yield_resume_id}))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;

    fast_forward(&sandbox, 1).await?;

    println!("resume_test Outcomes:");
    for (i, outcome) in resume_result.outcomes().iter().enumerate() {
        println!("resume_test({}) txhash:\t{:?}", i, outcome.transaction_hash);
        println!("resume_test({}) logs:\t{:?}", i, outcome.logs);
        println!("resume_test({}) receipt_ids:\t{:?}", i, outcome.receipt_ids);
        tx_hashes.push(outcome.transaction_hash);
        receipt_ids.extend(outcome.receipt_ids.iter().map(|id| id.clone()));
        println!("\n")
    }

    if resume_result.is_success() {
        let resume_response: bool = resume_result.json()?;
        // let resume_response: serde_json::Value = serde_json::from_str(&resume_response_json_str)?;
        println!("\nresume_test result: {:?}", resume_response);
    } else {
        println!("\nresume_test failed: {:?}", resume_result.outcomes());
    }

    fast_forward(&sandbox, 1).await?;

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

    println!("\n\n=========================================");
    println!("Total receipt_ids: {:?}", receipt_ids);
    println!("=========================================\n\n");

    for receipt_id in receipt_ids {
        // Convert the receipt_id CryptoHash to a near_primitives::CryptoHash
        let receipt_id2 = CryptoHash2::try_from(receipt_id.0.as_slice()).unwrap();
        assert_eq!(receipt_id2.to_string(), receipt_id.to_string());

        println!("\nQuerying receipt_id: {:?}", receipt_id2);
        let receipt = sandbox.receipt(
            ReceiptReference {
                receipt_id: receipt_id2,
            }
        ).await?;

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
                            if method_name == "callback_test" {
                                assert!(is_promise_yield, "is_promise_yield for resume_authentication_callback should be true");
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let greeting = user_account.call(contract.id(), "get_greeting").transact().await?;
    let expected_result =
        "finally_log_result(arg=\"callback_test(raw_data1=RAWDATA1, raw_data2=RAWDATA2)\")";
    let actual_result = greeting.json::<String>()?;
    println!("\n\nget_greeting: {}", actual_result);

    assert_eq!(actual_result, expected_result);

    Ok(())
}



