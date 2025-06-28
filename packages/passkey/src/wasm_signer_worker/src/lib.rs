mod error;
mod types;
mod actions;
mod crypto;
mod transaction;
mod cose;
mod http;

#[cfg(test)]
mod tests;

use wasm_bindgen::prelude::*;
use serde_json;
use bs58;

// Import from modules
use crate::actions::ActionParams;
use crate::actions::validate_delete_account_context;
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
use crate::http::{
    perform_contract_verification_wasm,
    base64url_decode,
    VrfData,
    WebAuthnAuthenticationCredential,
    WebAuthnAuthenticationResponse,
    WebAuthnRegistrationCredential,
    WebAuthnRegistrationResponse,
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
    // Import JavaScript function for sending progress messages
    #[wasm_bindgen(js_name = "sendProgressMessage")]
    fn send_progress_message(message_type: &str, step: &str, message: &str, data: &str);
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

#[cfg(not(target_arch = "wasm32"))]
fn send_progress_message(_message_type: &str, _step: &str, _message: &str, _data: &str) {
    // No-op for non-WASM builds
    eprintln!("[PROGRESS] {}: {} - {}", _message_type, _step, _message);
}

// Helper function to send progress with optional logs
fn send_progress_with_logs(message_type: &str, step: &str, message: &str, data: &str, logs: Option<&[String]>) {
    // Create enhanced data payload that includes logs
    let enhanced_data = if let Some(log_array) = logs {
        if !log_array.is_empty() {
            // Parse existing data and add logs
            let mut data_obj: serde_json::Value = serde_json::from_str(data)
                .unwrap_or_else(|_| serde_json::json!({}));

            // Add logs to the data object
            if let serde_json::Value::Object(ref mut map) = data_obj {
                map.insert("logs".to_string(), serde_json::json!(log_array));
            }

            serde_json::to_string(&data_obj).unwrap_or_else(|_| data.to_string())
        } else {
            data.to_string()
        }
    } else {
        data.to_string()
    };

    send_progress_message(message_type, step, message, &enhanced_data);
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

// === WASM BINDINGS FOR TRANSACTION SIGNING ===
// COMBINED VERIFICATION + SIGNING WITH PROGRESS

#[wasm_bindgen]
pub async fn verify_and_sign_near_transaction_with_actions(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
    actions_json: &str,

    // Verification parameters
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_credential_json: &str,
    near_rpc_url: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting combined verification + signing with progress");

    // Step 1: Send verification progress with enhanced logging
    let verification_logs = vec![
        format!("Starting contract verification for {}", contract_id),
        "Parsing VRF challenge data...".to_string(),
        "Preparing WebAuthn credential for verification...".to_string()
    ];

    send_progress_with_logs(
        "VERIFICATION_PROGRESS",
        "contract_verification",
        "Verifying authentication with contract...",
        &format!(r#"{{"contractId": "{}"}}"#, contract_id),
        Some(&verification_logs)
    );

    // Step 2: Perform contract verification via WASM HTTP
    let verification_result = {

        // Parse VRF challenge data
        let vrf_data = parse_vrf_challenge(vrf_challenge_data_json)?;

        // Parse WebAuthn credential
        let webauthn_credential: serde_json::Value = serde_json::from_str(webauthn_credential_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse WebAuthn credential: {}", e)))?;

        // Extract WebAuthn authentication fields
        let auth_id = webauthn_credential["id"].as_str().ok_or("Missing WebAuthn id")?;
        let raw_id = webauthn_credential["rawId"].as_str().ok_or("Missing WebAuthn rawId")?;
        let response = &webauthn_credential["response"];
        let client_data_json = response["clientDataJSON"].as_str().ok_or("Missing clientDataJSON")?;
        let authenticator_data = response["authenticatorData"].as_str().ok_or("Missing authenticatorData")?;
        let signature = response["signature"].as_str().ok_or("Missing signature")?;
        let user_handle = response["userHandle"].as_str();
        // NOTE: do not send PRF outputs, should be kept private

        // Construct WebAuthnAuthentication struct
        let webauthn_auth = WebAuthnAuthenticationCredential {
            id: auth_id.to_string(),
            raw_id: raw_id.to_string(),
            response: WebAuthnAuthenticationResponse {
                client_data_json: client_data_json.to_string(),
                authenticator_data: authenticator_data.to_string(),
                signature: signature.to_string(),
                user_handle: user_handle.map(|s| s.to_string()),
            },
            authenticator_attachment: webauthn_credential["authenticatorAttachment"].as_str().map(|s| s.to_string()),
            auth_type: "public-key".to_string(),
        };

        // Perform verification using pure WASM HTTP
        perform_contract_verification_wasm(contract_id, vrf_data, webauthn_auth, near_rpc_url)
            .await
            .map_err(|e| JsValue::from_str(&format!("Contract verification failed: {}", e)))?
    };

    // Parse verification result
    let verification_success = verification_result.verified;

    // Step 3: Send verification complete with logs
    send_progress_message(
        "VERIFICATION_COMPLETE",
        "verification_complete",
        if verification_success { "Contract verification successful" } else { "Contract verification failed" },
        &format!(r#"{{"success": {}, "logs": {:?}}}"#, verification_success, verification_result.logs)
    );

    if !verification_success {
        let error_msg = verification_result.error.unwrap_or_else(|| "Contract verification failed".to_string());
        return Err(JsValue::from_str(&error_msg));
    }

    // Step 4: Send signing progress
    send_progress_message(
        "SIGNING_PROGRESS",
        "transaction_signing",
        "Signing transaction in secure WASM context...",
        &format!(r#"{{"signerAccountId": "{}", "receiverId": "{}"}}"#, signer_account_id, receiver_account_id)
    );

    // Step 5: Perform transaction signing (existing logic)
    let private_key = match decrypt_private_key_with_prf_core(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    ) {
        Ok(key) => key,
        Err(e) => {
            let error_msg = format!("Failed to decrypt private key: {:?}", e);
            send_progress_message(
                "SIGNING_COMPLETE",
                "signing_failed",
                &error_msg,
                r#"{"success": false}"#
            );
            return Err(JsValue::from_str(&error_msg));
        }
    };

    // Parse and build actions
    let action_params: Vec<ActionParams> = serde_json::from_str(actions_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse actions: {}", e)))?;

    let actions = build_actions_from_params(action_params)
        .map_err(|e| JsValue::from_str(&e))?;

    // Build and sign transaction
    let transaction = build_transaction_with_actions(
        signer_account_id,
        receiver_account_id,
        nonce,
        block_hash_bytes,
        &private_key,
        actions,
    ).map_err(|e| JsValue::from_str(&e))?;

    let signed_tx_bytes = sign_transaction(transaction, &private_key)
        .map_err(|e| JsValue::from_str(&e))?;

    // Step 6: Send signing complete with final result
    send_progress_message(
        "SIGNING_COMPLETE",
        "signing_complete",
        "Transaction signed successfully",
        &format!(r#"{{"signedTransactionBorsh": {:?}, "verificationLogs": {:?}}}"#,
            signed_tx_bytes,
            verification_result.logs
        )
    );

    console_log!("RUST: Combined verification + signing completed successfully");
    Ok(signed_tx_bytes)
}

#[wasm_bindgen]
pub async fn verify_and_sign_near_transfer_transaction(
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

    // Verification parameters
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_credential_json: &str,
    near_rpc_url: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting transfer transaction verification + signing with progress");

    // Convert transfer parameters to action-based format
    let transfer_actions = vec![ActionParams::Transfer {
        deposit: deposit_amount.to_string(),
    }];

    let actions_json = serde_json::to_string(&transfer_actions)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize transfer action: {}", e)))?;

    // Delegate to the main verification + signing function
    verify_and_sign_near_transaction_with_actions(
        // Authentication
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,

        // Transaction details
        signer_account_id,
        receiver_account_id,
        nonce,
        block_hash_bytes,
        &actions_json,

        // Verification parameters
        contract_id,
        vrf_challenge_data_json,
        webauthn_credential_json,
        near_rpc_url,
    ).await
}


/// Check if user can register (VIEW FUNCTION - uses query RPC)
#[wasm_bindgen]
pub async fn check_can_register_user(
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_registration_json: &str,
    near_rpc_url: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Checking if user can register (view function)");

    // Parse VRF challenge data
    let vrf_data = parse_vrf_challenge(vrf_challenge_data_json)?;

    // Parse WebAuthn registration credential
    let webauthn_registration_data: serde_json::Value = serde_json::from_str(webauthn_registration_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse WebAuthn registration: {}", e)))?;

    // Extract WebAuthn registration fields
    let reg_id = webauthn_registration_data["id"].as_str().ok_or("Missing WebAuthn id")?;
    let raw_id = webauthn_registration_data["rawId"].as_str().ok_or("Missing WebAuthn rawId")?;
    let response = &webauthn_registration_data["response"];
    let client_data_json = response["clientDataJSON"].as_str().ok_or("Missing clientDataJSON")?;
    let attestation_object = response["attestationObject"].as_str().ok_or("Missing attestationObject")?;
    let transports = response["transports"].as_array().map(|arr| {
        arr.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect()
    });

    // Construct WebAuthnRegistration struct
    let webauthn_registration = WebAuthnRegistrationCredential {
        id: reg_id.to_string(),
        raw_id: raw_id.to_string(),
        response: WebAuthnRegistrationResponse {
            client_data_json: client_data_json.to_string(),
            attestation_object: attestation_object.to_string(),
            transports,
        },
        authenticator_attachment: webauthn_registration_data["authenticatorAttachment"].as_str().map(|s| s.to_string()),
        reg_type: "public-key".to_string(),
    };

    // Call the http module function
    let registration_result = crate::http::check_can_register_user_wasm(contract_id, vrf_data, webauthn_registration, near_rpc_url)
            .await
    .map_err(|e| JsValue::from_str(&format!("Registration check failed: {}", e)))?;

    // Return result as JSON
    let result = serde_json::json!({
        "verified": registration_result.verified,
        "registration_info": registration_result.registration_info,
        "logs": registration_result.logs,
        "signed_transaction_borsh": registration_result.signed_transaction_borsh
    });

    Ok(result.to_string())
}

/// Actually register user (STATE-CHANGING FUNCTION - uses send_tx RPC)
#[wasm_bindgen]
pub async fn sign_verify_and_register_user(
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_registration_json: &str,
    signer_account_id: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
    prf_output_base64: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
) -> Result<String, JsValue> {
    console_log!("RUST: Performing actual user registration (state-changing function)");

    // Parse VRF challenge data
    let vrf_data = parse_vrf_challenge(vrf_challenge_data_json)?;

    // Parse WebAuthn registration credential
    let webauthn_registration_data: serde_json::Value = serde_json::from_str(webauthn_registration_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse WebAuthn registration: {}", e)))?;

    // Extract WebAuthn registration fields
    let reg_id = webauthn_registration_data["id"].as_str().ok_or("Missing WebAuthn id")?;
    let raw_id = webauthn_registration_data["rawId"].as_str().ok_or("Missing WebAuthn rawId")?;
    let response = &webauthn_registration_data["response"];
    let client_data_json = response["clientDataJSON"].as_str().ok_or("Missing clientDataJSON")?;
    let attestation_object = response["attestationObject"].as_str().ok_or("Missing attestationObject")?;
    let transports = response["transports"].as_array().map(|arr| {
        arr.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect()
    });

    // Construct WebAuthnRegistration struct
    let webauthn_registration = WebAuthnRegistrationCredential {
        id: reg_id.to_string(),
        raw_id: raw_id.to_string(),
        response: WebAuthnRegistrationResponse {
            client_data_json: client_data_json.to_string(),
            attestation_object: attestation_object.to_string(),
            transports,
        },
        authenticator_attachment: webauthn_registration_data["authenticatorAttachment"].as_str().map(|s| s.to_string()),
        reg_type: "public-key".to_string(),
    };

    // Call the http module function with transaction metadata
    let registration_result = crate::http::sign_registration_tx_wasm(
        contract_id,
        vrf_data,
        webauthn_registration,
        signer_account_id,
        encrypted_private_key_data,
        encrypted_private_key_iv,
        prf_output_base64,
        nonce,
        block_hash_bytes,
    )
    .await
    .map_err(|e| JsValue::from_str(&format!("Actual registration failed: {}", e)))?;

    // Return result as JSON
    let result = serde_json::json!({
        "verified": registration_result.verified,
        "registration_info": registration_result.registration_info,
        "logs": registration_result.logs,
        "signed_transaction_borsh": registration_result.signed_transaction_borsh
    });

    Ok(result.to_string())
}

pub fn parse_vrf_challenge(vrf_challenge_data_json: &str) -> Result<VrfData, JsValue> {

    let vrf_challenge_data: serde_json::Value = serde_json::from_str(vrf_challenge_data_json)
    .map_err(|e| JsValue::from_str(&format!("Failed to parse VRF Challenge data: {}", e)))?;

    let vrf_input = vrf_challenge_data["vrfInput"].as_str().ok_or("Missing vrfInput")?;
    let vrf_output = vrf_challenge_data["vrfOutput"].as_str().ok_or("Missing vrfOutput")?;
    let vrf_proof = vrf_challenge_data["vrfProof"].as_str().ok_or("Missing vrfProof")?;
    let vrf_public_key = vrf_challenge_data["vrfPublicKey"].as_str().ok_or("Missing vrfPublicKey")?;
    let user_id = vrf_challenge_data["userId"].as_str().ok_or("Missing userId")?;
    let rp_id = vrf_challenge_data["rpId"].as_str().ok_or("Missing rpId")?;
    let block_height = vrf_challenge_data["blockHeight"].as_u64().ok_or("Missing blockHeight")?;
    let block_hash = vrf_challenge_data["blockHash"].as_str().ok_or("Missing blockHash")?;

    // Construct VrfData struct
    let vrf_data = VrfData {
        vrf_input_data: base64url_decode(vrf_input)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF input: {}", e)))?,
        vrf_output: base64url_decode(vrf_output)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF output: {}", e)))?,
        vrf_proof: base64url_decode(vrf_proof)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF proof: {}", e)))?,
        public_key: base64url_decode(vrf_public_key)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF public key: {}", e)))?,
        user_id: user_id.to_string(),
        rp_id: rp_id.to_string(),
        block_height,
        block_hash: base64url_decode(block_hash)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode block hash: {}", e)))?,
    };

    Ok(vrf_data)
}

/// Special function for rolling back failed registration by deleting the account
/// This is the ONLY way to use DeleteAccount - it's context-restricted to registration rollback
#[wasm_bindgen]
pub async fn rollback_failed_registration_with_prf(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    beneficiary_account_id: &str, // Where any remaining balance goes
    nonce: u64,
    block_hash_bytes: &[u8],

    // Verification parameters (to prove this is a legitimate rollback)
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_credential_json: &str,
    near_rpc_url: &str,

    // SECURITY: Actual calling function name for validation
    caller_function: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting registration rollback with DeleteAccount (context-restricted)");

    // Step 1: Validate context with ACTUAL caller function - this is the key security check
    validate_delete_account_context("registration_rollback", caller_function)
        .map_err(|e| JsValue::from_str(&e))?;

    console_log!("RUST: Delete account context validation passed for caller '{}' - proceeding with rollback", caller_function);

    // Step 2: Create DeleteAccount action
    let delete_action = ActionParams::DeleteAccount {
        beneficiary_id: beneficiary_account_id.to_string(),
    };

    let actions_json = serde_json::to_string(&vec![delete_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize delete action: {}", e)))?;

    // Step 3: Use the main verification + signing function
    // This ensures the same security standards as other transactions
    verify_and_sign_near_transaction_with_actions(
        // Authentication
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,

        // Transaction details - delete the signer account
        signer_account_id,
        signer_account_id, // receiver_id is same as signer for delete account
        nonce,
        block_hash_bytes,
        &actions_json,

        // Verification parameters
        contract_id,
        vrf_challenge_data_json,
        webauthn_credential_json,
        near_rpc_url,
    ).await
}

/// Convenience function for adding keys with PRF authentication
#[wasm_bindgen]
pub async fn add_key_with_prf(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    new_public_key: &str,  // The public key to add (in "ed25519:..." format)
    access_key_json: &str, // JSON-serialized AccessKey
    nonce: u64,
    block_hash_bytes: &[u8],

    // Verification parameters
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_credential_json: &str,
    near_rpc_url: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting AddKey transaction with PRF authentication");

    let add_key_action = ActionParams::AddKey {
        public_key: new_public_key.to_string(),
        access_key: access_key_json.to_string(),
    };

    let actions_json = serde_json::to_string(&vec![add_key_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize add key action: {}", e)))?;

    verify_and_sign_near_transaction_with_actions(
        // Authentication
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,

        // Transaction details
        signer_account_id,
        signer_account_id, // receiver_id is same as signer for add key
        nonce,
        block_hash_bytes,
        &actions_json,

        // Verification parameters
        contract_id,
        vrf_challenge_data_json,
        webauthn_credential_json,
        near_rpc_url,
    ).await
}

/// Convenience function for deleting keys with PRF authentication
#[wasm_bindgen]
pub async fn delete_key_with_prf(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    public_key_to_delete: &str, // The public key to delete (in "ed25519:..." format)
    nonce: u64,
    block_hash_bytes: &[u8],

    // Verification parameters
    contract_id: &str,
    vrf_challenge_data_json: &str,
    webauthn_credential_json: &str,
    near_rpc_url: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting DeleteKey transaction with PRF authentication");

    let delete_key_action = ActionParams::DeleteKey {
        public_key: public_key_to_delete.to_string(),
    };

    let actions_json = serde_json::to_string(&vec![delete_key_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize delete key action: {}", e)))?;

    verify_and_sign_near_transaction_with_actions(
        // Authentication
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,

        // Transaction details
        signer_account_id,
        signer_account_id, // receiver_id is same as signer for delete key
        nonce,
        block_hash_bytes,
        &actions_json,

        // Verification parameters
        contract_id,
        vrf_challenge_data_json,
        webauthn_credential_json,
        near_rpc_url,
    ).await
}