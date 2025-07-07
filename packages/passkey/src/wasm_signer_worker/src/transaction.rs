use ed25519_dalek::{SigningKey, Signer};
use borsh;

use crate::types::*;
use crate::actions::{ActionParams, get_action_handler};


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

