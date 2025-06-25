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
use crate::types::{
    EncryptedDataAesGcmResponse,
};
use crate::actions::ActionParams;
use crate::crypto::{
    encrypt_data_aes_gcm_core,
    decrypt_data_aes_gcm_core,
    derive_encryption_key_from_prf_core,
    decrypt_private_key_with_prf_core,
    generate_near_keypair_core,
    generate_and_encrypt_near_keypair_with_prf_core,
    derive_near_keypair_from_cose_p256_core,
};
use crate::transaction::{
    create_near_transaction_legacy,
    sign_transaction,
    build_actions_from_params,
    build_transaction_with_actions,
};
use crate::cose::{
    extract_cose_public_key_from_attestation_core,
    validate_cose_key_format_core,
};

// Buffer polyfill for Web Workers is handled by the JavaScript side

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

// === WASM BINDINGS FOR CRYPTO OPERATIONS ===

#[wasm_bindgen]
pub fn encrypt_data_aes_gcm(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    let result = encrypt_data_aes_gcm_core(plain_text_data_str, key_bytes)
        .map_err(|e| JsValue::from_str(&e))?;

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {}", e)))
}

#[wasm_bindgen]
pub fn decrypt_data_aes_gcm(encrypted_data_b64u: &str, aes_gcm_nonce_b64u: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    decrypt_data_aes_gcm_core(encrypted_data_b64u, aes_gcm_nonce_b64u, key_bytes)
        .map_err(|e| JsValue::from_str(&e))
}

#[wasm_bindgen]
pub fn derive_encryption_key_from_prf(
    prf_output_base64: &str,
) -> Result<Vec<u8>, JsValue> {
    derive_encryption_key_from_prf_core(prf_output_base64)
        .map_err(|e| JsValue::from(e))
}

// === WASM BINDINGS FOR KEY GENERATION ===

#[wasm_bindgen]
pub fn generate_near_keypair() -> Result<String, JsValue> {
    let (private_key, public_key) = generate_near_keypair_core()
        .map_err(|e| JsValue::from_str(&e))?;

    let result = format!(
        r#"{{"privateKey": "{}", "publicKey": "{}"}}"#,
        private_key,
        public_key
    );

    Ok(result)
}

#[wasm_bindgen]
pub fn generate_and_encrypt_near_keypair_with_prf(
    prf_output_base64: &str,
) -> Result<String, JsValue> {
    let (public_key, encrypted_result) = generate_and_encrypt_near_keypair_with_prf_core(prf_output_base64)
        .map_err(|e| JsValue::from_str(&e))?;

    let result = format!(
        r#"{{"publicKey": "{}", "encryptedPrivateKey": {}}}"#,
        public_key,
        serde_json::to_string(&encrypted_result)
            .map_err(|e| JsValue::from_str(&format!("JSON serialization failed: {}", e)))?
    );

    Ok(result)
}

#[wasm_bindgen]
pub fn derive_near_keypair_from_cose_p256(
    x_coordinate_bytes: &[u8],
    y_coordinate_bytes: &[u8],
) -> Result<String, JsValue> {
    let (private_key, public_key) = derive_near_keypair_from_cose_p256_core(x_coordinate_bytes, y_coordinate_bytes)
        .map_err(|e| JsValue::from_str(&e))?;

    let result = format!(
        r#"{{"privateKey": "{}", "publicKey": "{}"}}"#,
        private_key,
        public_key
    );

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
pub fn sign_near_transaction_with_prf(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    method_name: &str,
    args_json: &str,
    gas: &str,
    deposit: &str,
    nonce: u64,
    block_hash_base58: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting NEAR transaction signing with PRF");

    // 1. Decrypt private key using PRF
    let private_key = decrypt_private_key_with_prf_core(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    ).map_err(|e| JsValue::from_str(&e))?;

    // 2. Parse block hash
    let block_hash_bytes = bs58::decode(block_hash_base58)
        .into_vec()
        .map_err(|e| JsValue::from_str(&format!("Invalid block hash: {}", e)))?;

    // 3. Create legacy transaction
    let transaction = create_near_transaction_legacy(
        signer_account_id,
        &private_key,
        receiver_account_id,
        method_name,
        args_json,
        gas,
        deposit,
        nonce,
        &block_hash_bytes,
    ).map_err(|e| JsValue::from_str(&e))?;

    // 4. Sign transaction
    let signed_tx_bytes = sign_transaction(transaction, &private_key)
        .map_err(|e| JsValue::from_str(&e))?;

    console_log!("RUST: Successfully signed NEAR transaction, {} bytes", signed_tx_bytes.len());
    Ok(signed_tx_bytes)
}

#[wasm_bindgen]
pub fn decrypt_and_sign_transaction_with_prf(
    // Authentication and storage
    prf_output_base64: &str,
    encrypted_private_key_json: &str, // JSON with encrypted_near_key_data_b64u and aes_gcm_nonce_b64u

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    method_name: &str,
    args_json: &str,
    gas: &str,
    deposit: &str,
    nonce: u64,
    block_hash_base58: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Decrypt and sign transaction with PRF");

    // Parse encrypted private key JSON directly into typed struct
    let encrypted_key_data: EncryptedDataAesGcmResponse = serde_json::from_str(encrypted_private_key_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted key data: {}", e)))?;

    let encrypted_data = &encrypted_key_data.encrypted_near_key_data_b64u;
    let iv = &encrypted_key_data.aes_gcm_nonce_b64u;

    // Call the main signing function - returns Borsh-serialized SignedTransaction
    sign_near_transaction_with_prf(
        prf_output_base64,
        encrypted_data,
        iv,
        signer_account_id,
        receiver_account_id,
        method_name,
        args_json,
        gas,
        deposit,
        nonce,
        block_hash_base58,
    )
}

#[wasm_bindgen]
pub fn sign_transaction_with_encrypted_key(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_json: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_id: &str,
    contract_method_name: &str,
    contract_args: &str,
    gas_amount: &str,
    deposit_amount: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Signing transaction with encrypted key");

    // Convert block hash bytes to base58
    let block_hash_base58 = bs58::encode(block_hash_bytes).into_string();

    // Call the signing function - returns Borsh-serialized SignedTransaction
    decrypt_and_sign_transaction_with_prf(
        prf_output_base64,
        encrypted_private_key_json,
        signer_account_id,
        receiver_id,
        contract_method_name,
        contract_args,
        gas_amount,
        deposit_amount,
        nonce,
        &block_hash_base58,
    )
}

// === MULTI-ACTION SIGNING FUNCTIONS ===

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
pub fn sign_transfer_transaction_with_prf(
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
