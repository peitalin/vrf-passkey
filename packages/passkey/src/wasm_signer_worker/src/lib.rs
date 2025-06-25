mod error;
mod types;
mod actions;
mod crypto;
mod transaction;
mod cose;

#[cfg(test)]
mod tests;

use wasm_bindgen::prelude::*;
use serde_json;
use bs58;

// Import from modules
use crate::actions::ActionParams;
use crate::crypto::{
    decrypt_private_key_with_prf_core,
    internal_derive_near_keypair_from_cose_and_encrypt_with_prf,
};
use crate::transaction::{
    sign_transaction,
    build_actions_from_params,
    build_transaction_with_actions,
};
use crate::cose::{
    extract_cose_public_key_from_attestation_core,
    validate_cose_key_format_core,
};

// === CONSOLE LOGGING ===

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn warn(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn error(s: &str);
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

// === WASM INITIALIZATION ===

#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// === WASM BINDINGS FOR KEY GENERATION ===

#[wasm_bindgen]
pub fn derive_near_keypair_from_cose_and_encrypt_with_prf(
    attestation_object_b64u: &str,
    prf_output_base64: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: WASM binding - deriving deterministic NEAR keypair from COSE credential");

    let (public_key, encrypted_result) = internal_derive_near_keypair_from_cose_and_encrypt_with_prf(
        attestation_object_b64u,
        prf_output_base64
    ).map_err(|e| JsValue::from_str(&e))?;

    let result = format!(
        r#"{{"publicKey": "{}", "encryptedPrivateKey": {}}}"#,
        public_key,
        serde_json::to_string(&encrypted_result)
            .map_err(|e| JsValue::from_str(&format!("JSON serialization failed: {}", e)))?
    );

    console_log!("RUST: WASM binding - deterministic keypair generation successful");
    Ok(result)
}

#[wasm_bindgen]
pub fn decrypt_private_key_with_prf_as_string(
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Decrypting private key with PRF and returning as string");

    // Use the core function to decrypt and get SigningKey
    let signing_key = decrypt_private_key_with_prf_core(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    ).map_err(|e| JsValue::from_str(&e))?;

    // Convert SigningKey back to NEAR string format
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    // Get the private key seed (first 32 bytes)
    let private_key_seed = signing_key.to_bytes();

    // NEAR Ed25519 private key format: 32-byte seed + 32-byte public key = 64 bytes total
    let mut full_private_key = [0u8; 64];
    full_private_key[0..32].copy_from_slice(&private_key_seed);
    full_private_key[32..64].copy_from_slice(&public_key_bytes);

    // Encode private key in NEAR format: "ed25519:BASE58_FULL_PRIVATE_KEY"
    let private_key_b58 = bs58::encode(&full_private_key).into_string();
    let private_key_near_format = format!("ed25519:{}", private_key_b58);

    console_log!("RUST: Successfully decrypted private key and formatted as string");
    Ok(private_key_near_format)
}

// === WASM BINDINGS FOR TRANSACTION SIGNING ===

#[wasm_bindgen]
pub fn sign_near_transaction_with_actions(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
    actions_json: &str, // JSON array of ActionParams
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting NEAR transaction signing with multiple actions");

    // 1. Decrypt private key using PRF
    let private_key = decrypt_private_key_with_prf_core(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    ).map_err(|e| JsValue::from_str(&e))?;

    // 2. Parse actions
    let action_params: Vec<ActionParams> = serde_json::from_str(actions_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse actions: {}", e)))?;

    console_log!("RUST: Parsed {} actions", action_params.len());

    // 3. Build actions using handlers
    let actions = build_actions_from_params(action_params)
        .map_err(|e| JsValue::from_str(&e))?;

    console_log!("RUST: Built {} actions successfully", actions.len());

    // 4. Build transaction
    let transaction = build_transaction_with_actions(
        signer_account_id,
        receiver_account_id,
        nonce,
        block_hash_bytes,
        &private_key,
        actions,
    ).map_err(|e| JsValue::from_str(&e))?;

    // 5. Sign transaction
    let signed_tx_bytes = sign_transaction(transaction, &private_key)
        .map_err(|e| JsValue::from_str(&e))?;

    console_log!("RUST: Successfully signed multi-action transaction, {} bytes", signed_tx_bytes.len());
    Ok(signed_tx_bytes)
}

#[wasm_bindgen]
pub fn sign_near_transfer_transaction(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    deposit_amount: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Signing Transfer transaction with PRF");

    // Build single transfer action
    let actions = vec![ActionParams::Transfer {
        deposit: deposit_amount.to_string(),
    }];

    let actions_json = serde_json::to_string(&actions)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize transfer action: {}", e)))?;

    // Use the multi-action function
    sign_near_transaction_with_actions(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
        signer_account_id,
        receiver_account_id,
        nonce,
        block_hash_bytes,
        &actions_json,
    )
}

// === WASM BINDINGS FOR COSE OPERATIONS ===

#[wasm_bindgen]
pub fn extract_cose_public_key_from_attestation(attestation_object_b64u: &str) -> Result<Vec<u8>, JsValue> {
    extract_cose_public_key_from_attestation_core(attestation_object_b64u)
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn validate_cose_key_format(cose_key_bytes: &[u8]) -> Result<String, JsValue> {
    validate_cose_key_format_core(cose_key_bytes)
        .map_err(|e| JsValue::from_str(&e))
}
