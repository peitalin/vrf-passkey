use ed25519_dalek::{SigningKey, Signer};
use borsh;

use crate::types::*;
use crate::actions::{ActionParams, get_action_handler};

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (crate::log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

/// Build a transaction with multiple actions
pub fn build_transaction_with_actions(
    signer_account_id: &str,
    receiver_account_id: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
    private_key: &SigningKey,
    actions: Vec<Action>,
) -> Result<Transaction, String> {
    // Parse account IDs
    let signer_id: AccountId = signer_account_id.parse()
        .map_err(|e| format!("Invalid signer account: {}", e))?;
    let receiver_id: AccountId = receiver_account_id.parse()
        .map_err(|e| format!("Invalid receiver account: {}", e))?;

    // Parse block hash
    if block_hash_bytes.len() != 32 {
        return Err("Block hash must be 32 bytes".to_string());
    }
    let mut block_hash_array = [0u8; 32];
    block_hash_array.copy_from_slice(block_hash_bytes);
    let block_hash = CryptoHash::from_bytes(block_hash_array);

    // Create PublicKey from ed25519 verifying key
    let public_key_bytes = private_key.verifying_key().to_bytes();
    let public_key = PublicKey::from_ed25519_bytes(&public_key_bytes);

    // Build transaction
    Ok(Transaction {
        signer_id,
        public_key,
        nonce,
        receiver_id,
        block_hash,
        actions,
    })
}

/// Build actions from action parameters
pub fn build_actions_from_params(action_params: Vec<ActionParams>) -> Result<Vec<Action>, String> {
    let mut actions = Vec::new();
    for (i, params) in action_params.iter().enumerate() {
        console_log!("RUST: Processing action {}: {:?}", i, params.clone());

        let handler = get_action_handler(params)
            .map_err(|e| format!("Action {} handler error: {}", i, e))?;

        handler.validate_params(params)
            .map_err(|e| format!("Action {} validation failed: {}", i, e))?;

        let action = handler.build_action(params)
            .map_err(|e| format!("Action {} build failed: {}", i, e))?;

        actions.push(action);
    }
    Ok(actions)
}

/// Sign a transaction and return the serialized SignedTransaction
pub fn sign_transaction(transaction: Transaction, private_key: &SigningKey) -> Result<Vec<u8>, String> {
    // Get transaction hash for signing
    let (transaction_hash, _size) = transaction.get_hash_and_size();

    // Sign the hash
    let signature_bytes = private_key.sign(&transaction_hash.0);
    let signature = Signature::from_ed25519_bytes(&signature_bytes.to_bytes());

    // Create SignedTransaction
    let signed_transaction = SignedTransaction::new(signature, transaction);

    // Serialize to Borsh
    borsh::to_vec(&signed_transaction)
        .map_err(|e| format!("Signed transaction serialization failed: {}", e))
}

/// Create a NEAR transaction from legacy parameters (for backward compatibility)
pub fn create_near_transaction_legacy(
    near_account_id: &str,
    key_pair: &SigningKey,
    receiver_id: &str,
    contract_method_name: &str,
    contract_args: &str,
    gas_amount: &str,
    deposit_amount: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
) -> Result<Transaction, String> {
    console_log!("RUST: Creating legacy NEAR transaction");

    // Parse parameters
    let signer_id: AccountId = near_account_id.parse()
        .map_err(|e| format!("Invalid signer account: {}", e))?;

    let receiver_account_id: AccountId = receiver_id.parse()
        .map_err(|e| format!("Invalid receiver account: {}", e))?;

    let gas: Gas = gas_amount.parse()
        .map_err(|e| format!("Invalid gas amount: {}", e))?;

    let deposit: Balance = deposit_amount.parse()
        .map_err(|e| format!("Invalid deposit amount: {}", e))?;

    // Parse block hash
    if block_hash_bytes.len() != 32 {
        return Err("Block hash must be 32 bytes".to_string());
    }

    let mut block_hash_array = [0u8; 32];
    block_hash_array.copy_from_slice(block_hash_bytes);
    let block_hash = CryptoHash::from_bytes(block_hash_array);

    // Create PublicKey from ed25519 verifying key
    let public_key_bytes = key_pair.verifying_key().to_bytes();
    let public_key = PublicKey::from_ed25519_bytes(&public_key_bytes);

    // Build legacy FunctionCall action
    let actions = vec![Action::FunctionCall(Box::new(FunctionCallAction {
        method_name: contract_method_name.to_string(),
        args: contract_args.as_bytes().to_vec(),
        gas,
        deposit,
    }))];

    // Build transaction following Transaction::new_v0() structure
    Ok(Transaction {
        signer_id,
        public_key,
        nonce,
        receiver_id: receiver_account_id,
        block_hash,
        actions,
    })
}