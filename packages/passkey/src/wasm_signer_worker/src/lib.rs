mod actions;
mod config;
mod crypto;
mod cose;
mod error;
mod http;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use serde_json;
use bs58;
use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;

// Import from modules
use crate::transaction::{
    sign_transaction,
    build_actions_from_params,
    build_transaction_with_actions,
};
use crate::http::{
    perform_contract_verification_wasm,
    base64url_decode,
    VrfData,
    WebAuthnAuthenticationCredential,
    WebAuthnAuthenticationResponse,
    WebAuthnRegistrationCredential,
    WebAuthnRegistrationResponse,
    check_can_register_user_wasm,
    sign_registration_tx_wasm,
};
use crate::types::*;
use crate::actions::*;

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

// Set up panic hook for better debugging
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// === WASM BINDINGS FOR KEY GENERATION ===

/// Extract COSE public key from WebAuthn attestation object
#[wasm_bindgen]
pub fn extract_cose_public_key_from_attestation(
    attestation_object_b64u: &str,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: WASM binding - extracting COSE public key from attestation object");

    let cose_public_key_bytes = crate::cose::extract_cose_public_key_from_attestation(attestation_object_b64u)
        .map_err(|e| JsValue::from_str(&format!("Failed to extract COSE public key: {}", e)))?;

    console_log!("RUST: WASM binding - COSE public key extraction successful ({} bytes)", cose_public_key_bytes.len());
    Ok(cose_public_key_bytes)
}

/// Dual PRF key derivation for WASM

#[wasm_bindgen]
pub fn recover_keypair_from_passkey(
    credential: &WebAuthnAuthenticationCredentialRecoveryStruct,
    account_id_hint: Option<String>,
) -> Result<RecoverKeypairResult, JsValue> {
    console_log!("RUST: WASM binding - deriving deterministic keypair from passkey using dual PRF outputs");
    console_log!("RUST: Parsed authentication credential with ID: {}", credential.id);

    // Extract both PRF outputs from the recovery credential
    let aes_prf_output = &credential.aes_prf_output;
    let ed25519_prf_output = &credential.ed25519_prf_output;

    console_log!("RUST: Extracted dual PRF outputs for recovery - AES for encryption, Ed25519 for key derivation");

    // Use account hint if provided, otherwise generate placeholder
    let account_id = account_id_hint
        .as_deref()
        .unwrap_or("recovery-account.testnet");

    // Derive Ed25519 keypair from Ed25519 PRF output using account-specific HKDF
    // public_key already contains the ed25519: prefix from the crypto function
    let (private_key, public_key) = crate::crypto::derive_ed25519_key_from_prf_output(ed25519_prf_output, account_id)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Ed25519 key from PRF: {}", e)))?;

    // Encrypt the private key with the AES PRF output (correct usage)
    let encryption_result = crate::crypto::encrypt_private_key_with_prf(
        &private_key,
        aes_prf_output,
        account_id,
    ).map_err(|e| JsValue::from_str(&format!("Failed to encrypt private key with AES PRF: {}", e)))?;

    console_log!("RUST: Successfully derived NEAR keypair from Ed25519 PRF and encrypted with AES PRF");
    console_log!("RUST: PRF-based keypair recovery from authentication credential successful");

    Ok(RecoverKeypairResult::new(
        public_key,
        encryption_result.encrypted_near_key_data_b64u,
        encryption_result.aes_gcm_nonce_b64u, // IV
        account_id_hint
    ))
}


#[wasm_bindgen]
pub fn decrypt_private_key_with_prf(
    request: &DecryptPrivateKeyRequest,
) -> Result<DecryptPrivateKeyResult, JsValue> {
    console_log!("RUST: Decrypting private key with PRF using structured types");

    // Use the core function to decrypt and get SigningKey
    let signing_key = crate::crypto::decrypt_private_key_with_prf(
        &request.near_account_id,
        &request.aes_prf_output,
        &request.encrypted_private_key_data,
        &request.encrypted_private_key_iv,
    ).map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))?;

    // Convert SigningKey to NEAR format (64 bytes: 32-byte seed + 32-byte public key)
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let private_key_seed = signing_key.to_bytes();

    // NEAR Ed25519 format: 32-byte private key seed + 32-byte public key = 64 bytes total
    let mut full_private_key = Vec::with_capacity(64);
    full_private_key.extend_from_slice(&private_key_seed);
    full_private_key.extend_from_slice(&public_key_bytes);

    let private_key_near_format = format!("ed25519:{}", bs58::encode(&full_private_key).into_string());

    console_log!("RUST: Private key decrypted successfully with structured types");

    Ok(DecryptPrivateKeyResult::new(
        private_key_near_format,
        request.near_account_id.clone()
    ))
}

// === WASM BINDINGS FOR TRANSACTION SIGNING ===
// COMBINED VERIFICATION + SIGNING WITH PROGRESS

#[wasm_bindgen]
pub async fn verify_and_sign_near_transaction_with_actions(
    vrf_challenge: &VrfChallengeStruct,
    credential: &WebAuthnAuthenticationCredentialStruct,
    request: &TransactionSigningRequest,
) -> Result<TransactionSignResult, JsValue> {
    console_log!("RUST: Verify and sign NEAR transaction with actions using structured types");

    let mut logs: Vec<String> = Vec::new();

    // Send initial progress message
    send_progress_message(
        "SIGNING_PROGRESS",
        "preparation",
        "Starting transaction verification and signing...",
        &serde_json::json!({"step": 1, "total": 4}).to_string()
    );

    // Step 1: Contract verification
    logs.push(format!("Starting contract verification for {}", request.verification.contract_id));
    logs.push("Parsing VRF challenge data...".to_string());
    logs.push("Preparing WebAuthn credential for verification...".to_string());

    // Send verification progress
    send_progress_message(
        "VERIFICATION_PROGRESS",
        "contract_verification",
        "Verifying credentials with contract...",
        &serde_json::json!({"step": 2, "total": 4}).to_string()
    );

    // Convert structured types using From implementations
    let vrf_data = VrfData::try_from(vrf_challenge)?;
    let webauthn_auth = WebAuthnAuthenticationCredential::from(credential);

    // Perform contract verification
    let verification_result = match perform_contract_verification_wasm(
        &request.verification.contract_id,
        &request.verification.near_rpc_url,
        vrf_data,
        webauthn_auth,
    ).await {
        Ok(result) => {
            logs.extend(result.logs.clone());

            // Send verification complete progress
            send_progress_message(
                "VERIFICATION_COMPLETE",
                "verification_complete",
                "Contract verification completed successfully",
                &serde_json::json!({
                    "step": 2,
                    "total": 4,
                    "verified": result.verified,
                    "logs": result.logs
                }).to_string()
            );

            result
        }
        Err(e) => {
            let error_msg = format!("Contract verification failed: {}", e);
            logs.push(error_msg.clone());

            // Send error progress message
            send_progress_message(
                "VERIFICATION_PROGRESS",
                "error",
                &error_msg,
                &serde_json::json!({"error": e.to_string()}).to_string()
            );

            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    if !verification_result.verified {
        let error_msg = verification_result.error.unwrap_or_else(|| "Contract verification failed".to_string());
        logs.push(error_msg.clone());

        send_progress_message(
            "VERIFICATION_PROGRESS",
            "error",
            &error_msg,
            &serde_json::json!({"verified": false}).to_string()
        );

        return Ok(TransactionSignResult::failed(logs, error_msg));
    }

    logs.push("Contract verification successful".to_string());

    // Step 2: Transaction signing
    logs.push("Signing transaction in secure WASM context...".to_string());

    // Send signing progress
    send_progress_message(
        "SIGNING_PROGRESS",
        "transaction_signing",
        "Decrypting private key and signing transaction...",
        &serde_json::json!({"step": 3, "total": 4}).to_string()
    );

    // Decrypt private key using structured types
    let decrypt_request = DecryptPrivateKeyRequest::new(
        request.transaction.signer_account_id.clone(),
        request.decryption.aes_prf_output.clone(),
        request.decryption.encrypted_private_key_data.clone(),
        request.decryption.encrypted_private_key_iv.clone(),
    );
    let private_key_result = decrypt_private_key_with_prf(&decrypt_request)
        .map_err(|e| JsValue::from_str(&format!("Private key decryption failed: {:?}", e)))?;

    logs.push("Private key decrypted successfully".to_string());

    // Convert NEAR format private key back to SigningKey for transaction signing
    let private_key_str = &private_key_result.private_key;

    let private_key_without_prefix = private_key_str.strip_prefix("ed25519:")
        .ok_or_else(|| JsValue::from_str("Invalid private key format: missing ed25519 prefix"))?;

    let private_key_bytes = bs58::decode(private_key_without_prefix).into_vec()
        .map_err(|e| JsValue::from_str(&format!("Failed to decode private key: {}", e)))?;

    let signing_key = SigningKey::from_bytes(&private_key_bytes[0..32].try_into()
        .map_err(|_| JsValue::from_str("Invalid private key length"))?);

    // Parse and build actions
    let action_params: Vec<ActionParams> = match serde_json::from_str::<Vec<ActionParams>>(&request.transaction.actions_json) {
        Ok(params) => {
            logs.push(format!("Parsed {} actions", params.len()));
            params
        }
        Err(e) => {
            let error_msg = format!("Failed to parse actions: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    let actions = match build_actions_from_params(action_params) {
        Ok(actions) => {
            logs.push("Actions built successfully".to_string());
            actions
        }
        Err(e) => {
            let error_msg = format!("Failed to build actions: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    // Build and sign transaction
    let transaction = match build_transaction_with_actions(
        &request.transaction.signer_account_id,
        &request.transaction.receiver_account_id,
        request.transaction.nonce,
        &request.transaction.block_hash_bytes,
        &signing_key,
        actions,
    ) {
        Ok(tx) => {
            logs.push("Transaction built successfully".to_string());
            tx
        }
        Err(e) => {
            let error_msg = format!("Failed to build transaction: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    let signed_tx_bytes = match sign_transaction(transaction, &signing_key) {
        Ok(bytes) => {
            logs.push("Transaction signed successfully".to_string());
            bytes
        }
        Err(e) => {
            let error_msg = format!("Failed to sign transaction: {}", e);
            logs.push(error_msg.clone());
            return Ok(TransactionSignResult::failed(logs, error_msg));
        }
    };

    // Create structured transaction result
    let signed_tx_struct = match JsonSignedTransaction::from_borsh_bytes(&signed_tx_bytes) {
        Ok(json_tx) => Some(JsonSignedTransactionStruct::new(
            serde_json::to_string(&json_tx.transaction).unwrap_or_default(),
            serde_json::to_string(&json_tx.signature).unwrap_or_default(),
            Some(signed_tx_bytes),
        )),
        Err(e) => {
            console_log!("RUST: Warning - Failed to decode signed transaction for structured response: {}", e);
            None
        }
    };

    logs.push("Transaction verification and signing completed successfully".to_string());
    console_log!("RUST: Combined verification + signing completed successfully");

    // Send completion progress message
    send_progress_message(
        "SIGNING_COMPLETE",
        "signing_complete",
        "Transaction signed successfully",
        &serde_json::json!({
            "step": 4,
            "total": 4,
            "success": true,
            "logs": logs
        }).to_string()
    );

    Ok(TransactionSignResult::new(
        true,
        None, // Transaction hash will be available after sending
        signed_tx_struct,
        logs,
        None,
    ))
}

#[wasm_bindgen]
pub async fn verify_and_sign_near_transfer_transaction(
    vrf_challenge: &VrfChallengeStruct,
    credential: &WebAuthnAuthenticationCredentialStruct,
    request: &TransferTransactionRequest,
) -> Result<TransactionSignResult, JsValue> {
    console_log!("RUST: Starting transfer transaction verification + signing using structured types");

    // Convert transfer parameters to action-based format
    let transfer_actions = vec![ActionParams::Transfer {
        deposit: request.transaction.deposit_amount.clone(),
    }];

    let actions_json = serde_json::to_string(&transfer_actions)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize transfer action: {}", e)))?;

    // Create request for the main verification + signing function using grouped parameters
    let transaction = TxData::new(
        request.transaction.signer_account_id.clone(),
        request.transaction.receiver_account_id.clone(),
        request.transaction.nonce,
        request.transaction.block_hash_bytes.clone(),
        actions_json,
    );
    let main_request = TransactionSigningRequest::new(
        request.verification.clone(),
        request.decryption.clone(),
        transaction,
    );

    // Delegate to the main verification + signing function
    verify_and_sign_near_transaction_with_actions(vrf_challenge, credential, &main_request).await
}


/// Check if user can register (view function)
#[wasm_bindgen]
pub async fn check_can_register_user(
    vrf_challenge: &VrfChallengeStruct,
    credential: &WebAuthnRegistrationCredentialStruct,
    request: &RegistrationCheckRequest,
) -> Result<RegistrationCheckResult, JsValue> {
    console_log!("RUST: Checking if user can register (view function) using structured types");

    // Convert structured types using From implementations
    let vrf_data = VrfData::try_from(vrf_challenge)?;
    let webauthn_registration = WebAuthnRegistrationCredential::from(credential);

    // Call the http module function
    let registration_result = check_can_register_user_wasm(
        &request.contract_id,
        vrf_data,
        webauthn_registration,
        &request.near_rpc_url
    ).await
    .map_err(|e| JsValue::from_str(&format!("Registration check failed: {}", e)))?;

    // Create structured response
    let signed_transaction = if let Some(ref signed_tx_bytes) = registration_result.signed_transaction_borsh {
        if let Ok(json_signed_tx) = JsonSignedTransaction::from_borsh_bytes(signed_tx_bytes) {
            Some(JsonSignedTransactionStruct::new(
                serde_json::to_string(&json_signed_tx.transaction).unwrap_or_default(),
                serde_json::to_string(&json_signed_tx.signature).unwrap_or_default(),
                json_signed_tx.borsh_bytes
            ))
        } else {
            None
        }
    } else {
        None
    };

    let registration_info = registration_result.registration_info
        .map(|info| RegistrationInfoStruct::new(
            info.credential_id,
            info.credential_public_key,
            "".to_string(), // Not available from contract response
            None, // Not available from contract response
        ));

    Ok(RegistrationCheckResult::new(
        registration_result.verified,
        registration_info,
        registration_result.logs,
        signed_transaction,
        registration_result.error,
    ))
}

/// Actually register user (state-changing function: uses send_tx RPC)
#[wasm_bindgen]
pub async fn sign_verify_and_register_user(
    vrf_challenge: &VrfChallengeStruct,
    credential: &WebAuthnRegistrationCredentialStruct,
    request: &RegistrationRequest,
    deterministic_vrf_public_key: Option<String>, // Change to Option<String> for wasm-bindgen compatibility
) -> Result<RegistrationResult, JsValue> {
    console_log!("RUST: Performing dual VRF user registration (state-changing function) using structured types");

    // Send initial progress message
    send_progress_message(
        "REGISTRATION_PROGRESS",
        "preparation",
        "Starting dual VRF user registration process...",
        &serde_json::json!({"step": 1, "total": 4}).to_string()
    );

    // Convert structured types using From implementations
    let vrf_data = VrfData::try_from(vrf_challenge)?;
    let webauthn_registration = WebAuthnRegistrationCredential::from(credential);

    // Access grouped parameters
    let contract_id = &request.verification.contract_id;
    let signer_account_id = &request.transaction.signer_account_id;
    let encrypted_private_key_data = &request.decryption.encrypted_private_key_data;
    let encrypted_private_key_iv = &request.decryption.encrypted_private_key_iv;
    let aes_prf_output = &request.decryption.aes_prf_output;
    let nonce = request.transaction.nonce;
    let block_hash_bytes = &request.transaction.block_hash_bytes;

    // Send contract verification progress
    send_progress_message(
        "REGISTRATION_PROGRESS",
        "contract_verification",
        "Verifying credentials with contract...",
        &serde_json::json!({"step": 2, "total": 4}).to_string()
    );

    // Call the http module function with transaction metadata
    let registration_result = sign_registration_tx_wasm(
        contract_id,
        vrf_data,
        deterministic_vrf_public_key.as_deref(), // Convert Option<String> to Option<&str>
        webauthn_registration,
        signer_account_id,
        encrypted_private_key_data,
        encrypted_private_key_iv,
        aes_prf_output,
        nonce,
        block_hash_bytes,
    )
    .await
    .map_err(|e| {
        // Send error progress message
        send_progress_message(
            "REGISTRATION_PROGRESS",
            "error",
            &format!("Registration failed: {}", e),
            &serde_json::json!({"error": e.to_string()}).to_string()
        );
        JsValue::from_str(&format!("Actual registration failed: {}", e))
    })?;

    // Send transaction signing progress
    send_progress_message(
        "REGISTRATION_PROGRESS",
        "transaction_signing",
        "Signing registration transaction...",
        &serde_json::json!({"step": 3, "total": 4}).to_string()
    );

    // Create structured response with embedded borsh bytes
    let signed_transaction = if let Some(ref signed_tx_bytes) = registration_result.signed_transaction_borsh {
        if let Ok(json_signed_tx) = JsonSignedTransaction::from_borsh_bytes(signed_tx_bytes) {
            Some(JsonSignedTransactionStruct::new(
                serde_json::to_string(&json_signed_tx.transaction).unwrap_or_default(),
                serde_json::to_string(&json_signed_tx.signature).unwrap_or_default(),
                json_signed_tx.borsh_bytes
            ))
        } else {
            None
        }
    } else {
        None
    };

    let pre_signed_delete_transaction = if let Some(ref delete_tx_bytes) = registration_result.pre_signed_delete_transaction {
        if let Ok(json_signed_tx) = JsonSignedTransaction::from_borsh_bytes(delete_tx_bytes) {
            Some(JsonSignedTransactionStruct::new(
                serde_json::to_string(&json_signed_tx.transaction).unwrap_or_default(),
                serde_json::to_string(&json_signed_tx.signature).unwrap_or_default(),
                json_signed_tx.borsh_bytes
            ))
        } else {
            None
        }
    } else {
        None
    };

    let registration_info = registration_result.registration_info
        .map(|info| RegistrationInfoStruct::new(
            info.credential_id,
            info.credential_public_key,
            "".to_string(), // Not available from contract response
            None, // Not available from contract response
        ));

    // Send completion progress message
    if registration_result.verified {
        send_progress_message(
            "REGISTRATION_COMPLETE",
            "verification_complete",
            "User registration completed successfully",
            &serde_json::json!({
                "step": 4,
                "total": 4,
                "verified": true,
                "logs": registration_result.logs
            }).to_string()
        );
    } else {
        send_progress_message(
            "REGISTRATION_PROGRESS",
            "error",
            "Registration verification failed",
            &serde_json::json!({
                "verified": false,
                "error": registration_result.error.as_ref().unwrap_or(&"Unknown verification error".to_string())
            }).to_string()
        );
    }

    Ok(RegistrationResult::new(
        registration_result.verified,
        registration_info,
        registration_result.logs,
        signed_transaction,
        pre_signed_delete_transaction,
        registration_result.error,
    ))
}

/// Convenience function for adding keys with PRF authentication using structured types
#[wasm_bindgen]
pub async fn add_key_with_prf(
    vrf_challenge: &VrfChallengeStruct,
    credential: &WebAuthnAuthenticationCredentialStruct,
    request: &AddKeyRequest,
) -> Result<KeyActionResult, JsValue> {
    console_log!("RUST: Starting AddKey transaction with PRF authentication using structured types");

    let add_key_action = ActionParams::AddKey {
        public_key: request.transaction.new_public_key.clone(),
        access_key: request.transaction.access_key_json.clone(),
    };

    let actions_json = serde_json::to_string(&vec![add_key_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize add key action: {}", e)))?;

    let main_request = TransactionSigningRequest::new(
        request.verification.clone(),
        request.decryption.clone(),
        TxData::new(
            request.transaction.signer_account_id.clone(),
            request.transaction.signer_account_id.clone(), // receiver_id is same as signer for add key
            request.transaction.nonce,
            request.transaction.block_hash_bytes.clone(),
        actions_json,
        ),
    );

    let tx_result = verify_and_sign_near_transaction_with_actions(vrf_challenge, credential, &main_request).await?;

    // Convert TransactionSignResult to KeyActionResult
    Ok(KeyActionResult::new(
        tx_result.success,
        tx_result.transaction_hash,
        tx_result.signed_transaction,
        tx_result.logs,
        tx_result.error,
    ))
}

/// Convenience function for deleting keys with PRF authentication
#[wasm_bindgen]
pub async fn delete_key_with_prf(
    vrf_challenge: &VrfChallengeStruct,
    credential: &WebAuthnAuthenticationCredentialStruct,
    request: &DeleteKeyRequest,
) -> Result<KeyActionResult, JsValue> {
    console_log!("RUST: Starting DeleteKey transaction with PRF authentication using structured types");

    let delete_key_action = ActionParams::DeleteKey {
        public_key: request.transaction.public_key_to_delete.clone(),
    };

    let actions_json = serde_json::to_string(&vec![delete_key_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize delete key action: {}", e)))?;

    let main_request = TransactionSigningRequest::new(
        request.verification.clone(),
        request.decryption.clone(),
        TxData::new(
            request.transaction.signer_account_id.clone(),
            request.transaction.signer_account_id.clone(), // receiver_id is same as signer for delete key
            request.transaction.nonce,
            request.transaction.block_hash_bytes.clone(),
        actions_json,
        ),
    );

    let tx_result = verify_and_sign_near_transaction_with_actions(vrf_challenge, credential, &main_request).await?;

    // Convert TransactionSignResult to KeyActionResult
    Ok(KeyActionResult::new(
        tx_result.success,
        tx_result.transaction_hash,
        tx_result.signed_transaction,
        tx_result.logs,
        tx_result.error,
    ))
}

#[wasm_bindgen]
pub fn derive_and_encrypt_keypair(
    dual_prf_outputs: &DualPrfOutputs,
    near_account_id: &str,
) -> Result<EncryptionResult, JsValue> {
    console_log!("RUST: WASM binding - starting structured dual PRF keypair derivation");

    // Convert wasm-bindgen types to internal types
    let internal_dual_prf_outputs = crate::types::DualPrfOutputs {
        aes_prf_output_base64: dual_prf_outputs.aes_prf_output.clone(),
        ed25519_prf_output_base64: dual_prf_outputs.ed25519_prf_output.clone(),
    };

    // Call the dual PRF derivation function (same as JSON version)
    let (public_key, encrypted_result) = crate::crypto::derive_and_encrypt_keypair_from_dual_prf(
        &internal_dual_prf_outputs,
        near_account_id
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    console_log!("RUST: Structured dual PRF keypair derivation successful");

    // Return structured result (no JSON serialization)
    Ok(EncryptionResult::new(
        near_account_id.to_string(),
        public_key,
        encrypted_result.encrypted_near_key_data_b64u,
        encrypted_result.aes_gcm_nonce_b64u,
        true // Assuming storage success for consistency with JSON version
    ))
}

// === GROUPED PARAMETER STRUCTURES FOR CLEANER API ===

// Decryption-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Decryption {
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_iv: String,
}

#[wasm_bindgen]
impl Decryption {
    #[wasm_bindgen(constructor)]
    pub fn new(
        aes_prf_output: String,
        encrypted_private_key_data: String,
        encrypted_private_key_iv: String,
    ) -> Decryption {
        Decryption {
            aes_prf_output,
            encrypted_private_key_data,
            encrypted_private_key_iv,
        }
    }
}

// Transaction-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub receiver_account_id: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
    #[wasm_bindgen(getter_with_clone)]
    pub actions_json: String,
}

#[wasm_bindgen]
impl TxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        receiver_account_id: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
        actions_json: String,
    ) -> TxData {
        TxData {
            signer_account_id,
            receiver_account_id,
            nonce,
            block_hash_bytes,
            actions_json,
        }
    }
}

// Contract verification parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Verification {
    #[wasm_bindgen(getter_with_clone)]
    pub contract_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub near_rpc_url: String,
}

#[wasm_bindgen]
impl Verification {
    #[wasm_bindgen(constructor)]
    pub fn new(contract_id: String, near_rpc_url: String) -> Verification {
        Verification {
            contract_id,
            near_rpc_url,
        }
    }
}

// Improved transaction signing request with grouped parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TransactionSigningRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub verification: Verification,
    #[wasm_bindgen(getter_with_clone)]
    pub decryption: Decryption,
    #[wasm_bindgen(getter_with_clone)]
    pub transaction: TxData,
}

#[wasm_bindgen]
impl TransactionSigningRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verification: Verification,
        decryption: Decryption,
        transaction: TxData,
    ) -> TransactionSigningRequest {
        TransactionSigningRequest {
            verification,
            decryption,
            transaction,
        }
    }
}

// === STRUCTURED WASM-BINDGEN TYPES FOR ALL FUNCTIONS ===

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualPrfOutputs {
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: String,
}

#[wasm_bindgen]
impl DualPrfOutputs {
    #[wasm_bindgen(constructor)]
    pub fn new(aes_prf_output: String, ed25519_prf_output: String) -> DualPrfOutputs {
        DualPrfOutputs {
            aes_prf_output,
            ed25519_prf_output,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionResult {
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "publicKey")]
    pub public_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "encryptedData")]
    pub encrypted_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub iv: String,
    pub stored: bool,
}

#[wasm_bindgen]
impl EncryptionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(near_account_id: String, public_key: String, encrypted_data: String, iv: String, stored: bool) -> EncryptionResult {
        EncryptionResult {
            near_account_id,
            public_key,
            encrypted_data,
            iv,
            stored,
        }
    }
}

// WebAuthn credential types for structured input
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WebAuthnRegistrationCredentialStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub raw_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub credential_type: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_attachment: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub client_data_json: String,
    #[wasm_bindgen(getter_with_clone)]
    pub attestation_object: String,
    #[wasm_bindgen(getter_with_clone)]
    pub transports: Option<Vec<String>>,
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: Option<String>, // For recovery
}

#[wasm_bindgen]
impl WebAuthnRegistrationCredentialStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: String,
        raw_id: String,
        credential_type: String,
        authenticator_attachment: Option<String>,
        client_data_json: String,
        attestation_object: String,
        transports: Option<Vec<String>>,
        ed25519_prf_output: Option<String>,
    ) -> WebAuthnRegistrationCredentialStruct {
        WebAuthnRegistrationCredentialStruct {
            id,
            raw_id,
            credential_type,
            authenticator_attachment,
            client_data_json,
            attestation_object,
            transports,
            ed25519_prf_output,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WebAuthnAuthenticationCredentialStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub raw_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub credential_type: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_attachment: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub client_data_json: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub signature: String,
    #[wasm_bindgen(getter_with_clone)]
    pub user_handle: Option<String>,
}

#[wasm_bindgen]
impl WebAuthnAuthenticationCredentialStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: String,
        raw_id: String,
        credential_type: String,
        authenticator_attachment: Option<String>,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: Option<String>,
    ) -> WebAuthnAuthenticationCredentialStruct {
        WebAuthnAuthenticationCredentialStruct {
            id,
            raw_id,
            credential_type,
            authenticator_attachment,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        }
    }
}

/// Authentication credential struct specifically for account recovery with dual PRF outputs
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct WebAuthnAuthenticationCredentialRecoveryStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub raw_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub credential_type: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_attachment: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub client_data_json: String,
    #[wasm_bindgen(getter_with_clone)]
    pub authenticator_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub signature: String,
    #[wasm_bindgen(getter_with_clone)]
    pub user_handle: Option<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,      // For encryption/decryption
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: String,  // For key derivation
}

#[wasm_bindgen]
impl WebAuthnAuthenticationCredentialRecoveryStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        id: String,
        raw_id: String,
        credential_type: String,
        authenticator_attachment: Option<String>,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: Option<String>,
        aes_prf_output: String,
        ed25519_prf_output: String,
    ) -> WebAuthnAuthenticationCredentialRecoveryStruct {
        WebAuthnAuthenticationCredentialRecoveryStruct {
            id,
            raw_id,
            credential_type,
            authenticator_attachment,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            aes_prf_output,
            ed25519_prf_output,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct VrfChallengeStruct {
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_input: String,
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_proof: String,
    #[wasm_bindgen(getter_with_clone)]
    pub vrf_public_key: String,
    #[wasm_bindgen(getter_with_clone)]
    pub user_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub rp_id: String,
    pub block_height: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash: String,
}

#[wasm_bindgen]
impl VrfChallengeStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        vrf_input: String,
        vrf_output: String,
        vrf_proof: String,
        vrf_public_key: String,
        user_id: String,
        rp_id: String,
        block_height: u64,
        block_hash: String,
    ) -> VrfChallengeStruct {
        VrfChallengeStruct {
            vrf_input,
            vrf_output,
            vrf_proof,
            vrf_public_key,
            user_id,
            rp_id,
            block_height,
            block_hash,
        }
    }
}

// Recovery types
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverKeypairResult {
    #[wasm_bindgen(getter_with_clone, js_name = "publicKey")]
    pub public_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "encryptedData")]
    pub encrypted_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub iv: String,
    #[wasm_bindgen(getter_with_clone, js_name = "accountIdHint")]
    pub account_id_hint: Option<String>,
}

#[wasm_bindgen]
impl RecoverKeypairResult {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: String, encrypted_data: String, iv: String, account_id_hint: Option<String>) -> RecoverKeypairResult {
        RecoverKeypairResult {
            public_key,
            encrypted_data,
            iv,
            account_id_hint,
        }
    }
}

// Decryption types
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DecryptPrivateKeyRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_data: String,
    #[wasm_bindgen(getter_with_clone)]
    pub encrypted_private_key_iv: String,
}

#[wasm_bindgen]
impl DecryptPrivateKeyRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        near_account_id: String,
        aes_prf_output: String,
        encrypted_private_key_data: String,
        encrypted_private_key_iv: String,
    ) -> DecryptPrivateKeyRequest {
        DecryptPrivateKeyRequest {
            near_account_id,
            aes_prf_output,
            encrypted_private_key_data,
            encrypted_private_key_iv,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptPrivateKeyResult {
    #[wasm_bindgen(getter_with_clone, js_name = "privateKey")]
    pub private_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
}

#[wasm_bindgen]
impl DecryptPrivateKeyResult {
    #[wasm_bindgen(constructor)]
    pub fn new(private_key: String, near_account_id: String) -> DecryptPrivateKeyResult {
        DecryptPrivateKeyResult {
            private_key,
            near_account_id,
        }
    }
}

// Transfer-specific transaction data
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TransferTxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub receiver_account_id: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
    #[wasm_bindgen(getter_with_clone)]
    pub deposit_amount: String,
}

#[wasm_bindgen]
impl TransferTxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        receiver_account_id: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
        deposit_amount: String,
    ) -> TransferTxData {
        TransferTxData {
            signer_account_id,
            receiver_account_id,
            nonce,
            block_hash_bytes,
            deposit_amount,
        }
    }
}

// Improved transfer transaction request with grouped parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct TransferTransactionRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub verification: Verification,
    #[wasm_bindgen(getter_with_clone)]
    pub decryption: Decryption,
    #[wasm_bindgen(getter_with_clone)]
    pub transaction: TransferTxData,
}

#[wasm_bindgen]
impl TransferTransactionRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verification: Verification,
        decryption: Decryption,
        transaction: TransferTxData,
    ) -> TransferTransactionRequest {
        TransferTransactionRequest {
            verification,
            decryption,
            transaction,
        }
    }
}

// Registration types
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RegistrationCheckRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub contract_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub near_rpc_url: String,
}

#[wasm_bindgen]
impl RegistrationCheckRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(contract_id: String, near_rpc_url: String) -> RegistrationCheckRequest {
        RegistrationCheckRequest {
            contract_id,
            near_rpc_url,
        }
    }
}

// Registration transaction-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RegistrationTxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl RegistrationTxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
    ) -> RegistrationTxData {
        RegistrationTxData {
            signer_account_id,
            nonce,
            block_hash_bytes,
        }
    }
}

// Improved registration request with grouped parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RegistrationRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub verification: Verification,
    #[wasm_bindgen(getter_with_clone)]
    pub decryption: Decryption,
    #[wasm_bindgen(getter_with_clone)]
    pub transaction: RegistrationTxData,
}

#[wasm_bindgen]
impl RegistrationRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verification: Verification,
        decryption: Decryption,
        transaction: RegistrationTxData,
    ) -> RegistrationRequest {
        RegistrationRequest {
            verification,
            decryption,
            transaction,
        }
    }
}

// === STRUCTURED FUNCTION IMPLEMENTATIONS ===

// Transaction result types
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHash")]
    pub transaction_hash: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl TransactionSignResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        success: bool,
        transaction_hash: Option<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        logs: Vec<String>,
        error: Option<String>,
    ) -> TransactionSignResult {
        TransactionSignResult {
            success,
            transaction_hash,
            signed_transaction,
            logs,
            error,
        }
    }

    /// Helper function to create a failed TransactionSignResult
    pub fn failed(logs: Vec<String>, error_msg: String) -> TransactionSignResult {
        TransactionSignResult::new(
            false,
            None, // No transaction hash
            None, // No signed transaction
            logs,
            Some(error_msg),
        )
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyActionResult {
    pub success: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "transactionHash")]
    pub transaction_hash: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl KeyActionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        success: bool,
        transaction_hash: Option<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        logs: Vec<String>,
        error: Option<String>,
    ) -> KeyActionResult {
        KeyActionResult {
            success,
            transaction_hash,
            signed_transaction,
            logs,
            error,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationInfoStruct {
    #[wasm_bindgen(getter_with_clone, js_name = "credentialId")]
    pub credential_id: Vec<u8>,
    #[wasm_bindgen(getter_with_clone, js_name = "credentialPublicKey")]
    pub credential_public_key: Vec<u8>,
    #[wasm_bindgen(getter_with_clone, js_name = "userId")]
    pub user_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "vrfPublicKey")]
    pub vrf_public_key: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl RegistrationInfoStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        user_id: String,
        vrf_public_key: Option<Vec<u8>>,
    ) -> RegistrationInfoStruct {
        RegistrationInfoStruct {
            credential_id,
            credential_public_key,
            user_id,
            vrf_public_key,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCheckResult {
    pub verified: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "registrationInfo")]
    pub registration_info: Option<RegistrationInfoStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl RegistrationCheckResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verified: bool,
        registration_info: Option<RegistrationInfoStruct>,
        logs: Vec<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        error: Option<String>,
    ) -> RegistrationCheckResult {
        RegistrationCheckResult {
            verified,
            registration_info,
            logs,
            signed_transaction,
            error,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResult {
    pub verified: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "registrationInfo")]
    pub registration_info: Option<RegistrationInfoStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub logs: Vec<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "signedTransaction")]
    pub signed_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone, js_name = "preSignedDeleteTransaction")]
    pub pre_signed_delete_transaction: Option<JsonSignedTransactionStruct>,
    #[wasm_bindgen(getter_with_clone)]
    pub error: Option<String>,
}

#[wasm_bindgen]
impl RegistrationResult {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verified: bool,
        registration_info: Option<RegistrationInfoStruct>,
        logs: Vec<String>,
        signed_transaction: Option<JsonSignedTransactionStruct>,
        pre_signed_delete_transaction: Option<JsonSignedTransactionStruct>,
        error: Option<String>,
    ) -> RegistrationResult {
        RegistrationResult {
            verified,
            registration_info,
            logs,
            signed_transaction,
            pre_signed_delete_transaction,
            error,
        }
    }
}

// Key action types with grouped parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct AddKeyRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub verification: Verification,
    #[wasm_bindgen(getter_with_clone)]
    pub decryption: Decryption,
    #[wasm_bindgen(getter_with_clone)]
    pub transaction: AddKeyTxData,
}

#[wasm_bindgen]
impl AddKeyRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verification: Verification,
        decryption: Decryption,
        transaction: AddKeyTxData,
    ) -> AddKeyRequest {
        AddKeyRequest {
            verification,
            decryption,
            transaction,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DeleteKeyRequest {
    #[wasm_bindgen(getter_with_clone)]
    pub verification: Verification,
    #[wasm_bindgen(getter_with_clone)]
    pub decryption: Decryption,
    #[wasm_bindgen(getter_with_clone)]
    pub transaction: DeleteKeyTxData,
}

#[wasm_bindgen]
impl DeleteKeyRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verification: Verification,
        decryption: Decryption,
        transaction: DeleteKeyTxData,
    ) -> DeleteKeyRequest {
        DeleteKeyRequest {
            verification,
            decryption,
            transaction,
        }
    }
}

// Add key transaction-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct AddKeyTxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub new_public_key: String,
    #[wasm_bindgen(getter_with_clone)]
    pub access_key_json: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl AddKeyTxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        new_public_key: String,
        access_key_json: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
    ) -> AddKeyTxData {
        AddKeyTxData {
            signer_account_id,
            new_public_key,
            access_key_json,
            nonce,
            block_hash_bytes,
        }
    }
}

// Delete key transaction-specific parameters
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DeleteKeyTxData {
    #[wasm_bindgen(getter_with_clone)]
    pub signer_account_id: String,
    #[wasm_bindgen(getter_with_clone)]
    pub public_key_to_delete: String,
    pub nonce: u64,
    #[wasm_bindgen(getter_with_clone)]
    pub block_hash_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl DeleteKeyTxData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer_account_id: String,
        public_key_to_delete: String,
        nonce: u64,
        block_hash_bytes: Vec<u8>,
    ) -> DeleteKeyTxData {
        DeleteKeyTxData {
            signer_account_id,
            public_key_to_delete,
            nonce,
            block_hash_bytes,
        }
    }
}

/// Response for COSE extraction with just the result
#[wasm_bindgen]
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoseExtractionResult {
    #[wasm_bindgen(getter_with_clone, js_name = "cosePublicKeyBytes")]
    #[serde(rename = "cosePublicKeyBytes")]
    pub cose_public_key_bytes: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSignedTransactionStruct {
    #[wasm_bindgen(getter_with_clone, js_name = "transactionJson")]
    pub transaction_json: String,
    #[wasm_bindgen(getter_with_clone, js_name = "signatureJson")]
    pub signature_json: String,
    #[wasm_bindgen(getter_with_clone, js_name = "borshBytes")]
    pub borsh_bytes: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl JsonSignedTransactionStruct {
    #[wasm_bindgen(constructor)]
    pub fn new(
        transaction_json: String,
        signature_json: String,
        borsh_bytes: Option<Vec<u8>>,
    ) -> JsonSignedTransactionStruct {
        JsonSignedTransactionStruct {
            transaction_json,
            signature_json,
            borsh_bytes,
        }
    }
}

// === STRUCT CONVERSIONS ===

impl TryFrom<&VrfChallengeStruct> for VrfData {
    type Error = JsValue;

    fn try_from(vrf_challenge: &VrfChallengeStruct) -> Result<Self, Self::Error> {
        Ok(VrfData {
            vrf_input_data: base64url_decode(&vrf_challenge.vrf_input)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF input: {}", e)))?,
            vrf_output: base64url_decode(&vrf_challenge.vrf_output)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF output: {}", e)))?,
            vrf_proof: base64url_decode(&vrf_challenge.vrf_proof)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF proof: {}", e)))?,
            public_key: base64url_decode(&vrf_challenge.vrf_public_key)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode VRF public key: {}", e)))?,
            user_id: vrf_challenge.user_id.clone(),
            rp_id: vrf_challenge.rp_id.clone(),
            block_height: vrf_challenge.block_height,
            block_hash: base64url_decode(&vrf_challenge.block_hash)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode block hash: {}", e)))?,
        })
    }
}

impl From<&WebAuthnAuthenticationCredentialStruct> for WebAuthnAuthenticationCredential {
    fn from(credential: &WebAuthnAuthenticationCredentialStruct) -> Self {
        WebAuthnAuthenticationCredential {
            id: credential.id.clone(),
            raw_id: credential.raw_id.clone(),
            response: WebAuthnAuthenticationResponse {
                client_data_json: credential.client_data_json.clone(),
                authenticator_data: credential.authenticator_data.clone(),
                signature: credential.signature.clone(),
                user_handle: credential.user_handle.clone(),
            },
            authenticator_attachment: credential.authenticator_attachment.clone(),
            auth_type: credential.credential_type.clone(),
        }
    }
}

impl From<&WebAuthnRegistrationCredentialStruct> for WebAuthnRegistrationCredential {
    fn from(credential: &WebAuthnRegistrationCredentialStruct) -> Self {
        WebAuthnRegistrationCredential {
            id: credential.id.clone(),
            raw_id: credential.raw_id.clone(),
            response: WebAuthnRegistrationResponse {
                client_data_json: credential.client_data_json.clone(),
                attestation_object: credential.attestation_object.clone(),
                transports: credential.transports.clone(),
            },
            authenticator_attachment: credential.authenticator_attachment.clone(),
            reg_type: credential.credential_type.clone(),
        }
    }
}

// === CLEAN RUST ENUMS WITH NUMERIC CONVERSION ===
// These export to TypeScript as numeric enums and we convert directly from numbers

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq)]
pub enum WorkerRequestType {
    DeriveNearKeypairAndEncrypt,
    RecoverKeypairFromPasskey,
    CheckCanRegisterUser,
    SignVerifyAndRegisterUser,
    DecryptPrivateKeyWithPrf,
    SignTransactionWithActions,
    SignTransferTransaction,
    AddKeyWithPrf,
    DeleteKeyWithPrf,
    ExtractCosePublicKey,
}

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq)]
pub enum WorkerResponseType {
    EncryptionSuccess,
    DeriveNearKeyFailure,
    RecoverKeypairSuccess,
    RecoverKeypairFailure,
    RegistrationSuccess,
    RegistrationFailure,
    SignatureSuccess,
    SignatureFailure,
    DecryptionSuccess,
    DecryptionFailure,
    CoseExtractionSuccess,
    CoseExtractionFailure,
    VerificationProgress,
    VerificationComplete,
    SigningProgress,
    SigningComplete,
    RegistrationProgress,
    RegistrationComplete,
    Error,
}

// === NUMERIC CONVERSION TRAITS ===
// Clean conversion from TypeScript numeric enum values

impl From<u32> for WorkerRequestType {
    fn from(value: u32) -> Self {
        match value {
            0 => WorkerRequestType::DeriveNearKeypairAndEncrypt,
            1 => WorkerRequestType::RecoverKeypairFromPasskey,
            2 => WorkerRequestType::CheckCanRegisterUser,
            3 => WorkerRequestType::SignVerifyAndRegisterUser,
            4 => WorkerRequestType::DecryptPrivateKeyWithPrf,
            5 => WorkerRequestType::SignTransactionWithActions,
            6 => WorkerRequestType::SignTransferTransaction,
            7 => WorkerRequestType::AddKeyWithPrf,
            8 => WorkerRequestType::DeleteKeyWithPrf,
            9 => WorkerRequestType::ExtractCosePublicKey,
            _ => WorkerRequestType::ExtractCosePublicKey, // Default fallback
        }
    }
}

impl From<WorkerResponseType> for u32 {
    fn from(value: WorkerResponseType) -> Self {
        match value {
            WorkerResponseType::EncryptionSuccess => 0,
            WorkerResponseType::DeriveNearKeyFailure => 1,
            WorkerResponseType::RecoverKeypairSuccess => 2,
            WorkerResponseType::RecoverKeypairFailure => 3,
            WorkerResponseType::RegistrationSuccess => 4,
            WorkerResponseType::RegistrationFailure => 5,
            WorkerResponseType::SignatureSuccess => 6,
            WorkerResponseType::SignatureFailure => 7,
            WorkerResponseType::DecryptionSuccess => 8,
            WorkerResponseType::DecryptionFailure => 9,
            WorkerResponseType::CoseExtractionSuccess => 10,
            WorkerResponseType::CoseExtractionFailure => 11,
            WorkerResponseType::VerificationProgress => 12,
            WorkerResponseType::VerificationComplete => 13,
            WorkerResponseType::SigningProgress => 14,
            WorkerResponseType::SigningComplete => 15,
            WorkerResponseType::RegistrationProgress => 16,
            WorkerResponseType::RegistrationComplete => 17,
            WorkerResponseType::Error => 18,
        }
    }
}

// === MESSAGE HANDLER FUNCTIONS ===

/// Handle derive keypair request
async fn handle_derive_near_keypair_and_encrypt_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let request: DeriveKeypairPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Invalid payload for DERIVE_NEAR_KEYPAIR_AND_ENCRYPT: {:?}", e))?;

    let dual_prf_outputs = DualPrfOutputs::new(
        request.dual_prf_outputs.aes_prf_output,
        request.dual_prf_outputs.ed25519_prf_output,
    );

    let result = derive_and_encrypt_keypair(&dual_prf_outputs, &request.near_account_id)
        .map_err(|e| format!("Failed to derive and encrypt keypair: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle recover keypair request
async fn handle_recover_keypair_from_passkey_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let request: RecoverKeypairPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Invalid payload for RECOVER_KEYPAIR_FROM_PASSKEY: {:?}", e))?;

    // Extract PRF outputs
    let aes_prf_output = request.credential.client_extension_results.prf.results.first
        .ok_or_else(|| "Missing AES PRF output (first) in credential".to_string())?;
    let ed25519_prf_output = request.credential.client_extension_results.prf.results.second
        .ok_or_else(|| "Missing Ed25519 PRF output (second) in credential".to_string())?;

    // Create recovery credential struct
    let recovery_credential = WebAuthnAuthenticationCredentialRecoveryStruct::new(
        request.credential.id,
        request.credential.raw_id,
        request.credential.credential_type,
        request.credential.authenticator_attachment,
        request.credential.response.client_data_json,
        request.credential.response.authenticator_data,
        request.credential.response.signature,
        request.credential.response.user_handle,
        aes_prf_output,
        ed25519_prf_output,
    );

    let result = recover_keypair_from_passkey(&recovery_credential, request.account_id_hint)
        .map_err(|e| format!("Failed to recover keypair: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle check can register user request
async fn handle_check_can_register_user_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let parsed_payload: CheckCanRegisterUserPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Failed to parse CheckCanRegisterUser payload: {}", e))?;

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnRegistrationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.attestation_object,
        Some(parsed_payload.credential.response.transports),
        parsed_payload.credential.client_extension_results.prf.results.second,
    );

    let check_request = RegistrationCheckRequest::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    // Call the async WASM function
    let result = check_can_register_user(&vrf_challenge, &credential, &check_request).await
        .map_err(|e| format!("CheckCanRegisterUser failed: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle sign verify and register user request
async fn handle_sign_verify_and_register_user_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let parsed_payload: SignVerifyAndRegisterUserPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Failed to parse SignVerifyAndRegisterUser payload: {}", e))?;

    // DEBUG: Log received payload details
    console_log!("RUST: DEBUG - Received payload details:");
    console_log!("RUST: DEBUG - PRF output length: {}", parsed_payload.prf_output.len());
    console_log!("RUST: DEBUG - PRF output preview: {}...",
        if parsed_payload.prf_output.len() > 20 {
            &parsed_payload.prf_output[..20]
        } else {
            &parsed_payload.prf_output
        });
    console_log!("RUST: DEBUG - Encrypted data length: {}", parsed_payload.encrypted_private_key_data.len());
    console_log!("RUST: DEBUG - Encrypted data preview: {}...",
        if parsed_payload.encrypted_private_key_data.len() > 20 {
            &parsed_payload.encrypted_private_key_data[..20]
        } else {
            &parsed_payload.encrypted_private_key_data
        });
    console_log!("RUST: DEBUG - IV length: {}", parsed_payload.encrypted_private_key_iv.len());
    console_log!("RUST: DEBUG - IV preview: {}...",
        if parsed_payload.encrypted_private_key_iv.len() > 20 {
            &parsed_payload.encrypted_private_key_iv[..20]
        } else {
            &parsed_payload.encrypted_private_key_iv
        });

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnRegistrationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.attestation_object,
        Some(parsed_payload.credential.response.transports),
        parsed_payload.credential.client_extension_results.prf.results.second,
    );

    let verification = Verification::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    let decryption = Decryption::new(
        parsed_payload.prf_output,
        parsed_payload.encrypted_private_key_data,
        parsed_payload.encrypted_private_key_iv,
    );

    let nonce = parsed_payload.nonce.parse::<u64>()
        .map_err(|e| format!("Invalid nonce format: {}", e))?;

    let transaction = RegistrationTxData::new(
        parsed_payload.near_account_id,
        nonce,
        parsed_payload.block_hash_bytes,
    );

    let registration_request = RegistrationRequest::new(
        verification,
        decryption,
        transaction,
    );

    // Call the async WASM function
    let result = sign_verify_and_register_user(
        &vrf_challenge,
        &credential,
        &registration_request,
        parsed_payload.deterministic_vrf_public_key
    ).await
    .map_err(|e| format!("SignVerifyAndRegisterUser failed: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle decrypt private key request
async fn handle_decrypt_private_key_with_prf_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let request: DecryptKeyPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Invalid payload for DECRYPT_PRIVATE_KEY_WITH_PRF: {:?}", e))?;

    let decrypt_request = DecryptPrivateKeyRequest::new(
        request.near_account_id,
        request.prf_output,
        request.encrypted_private_key_data,
        request.encrypted_private_key_iv,
    );

    let result = decrypt_private_key_with_prf(&decrypt_request)
        .map_err(|e| format!("Failed to decrypt private key: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle sign transaction with actions request
async fn handle_sign_transaction_with_actions_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let parsed_payload: SignTransactionWithActionsPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Failed to parse SignTransactionWithActions payload: {}", e))?;

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnAuthenticationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.authenticator_data,
        parsed_payload.credential.response.signature,
        parsed_payload.credential.response.user_handle,
    );

    let verification = Verification::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    let decryption = Decryption::new(
        parsed_payload.prf_output,
        parsed_payload.encrypted_private_key_data,
        parsed_payload.encrypted_private_key_iv,
    );

    let nonce = parsed_payload.nonce.parse::<u64>()
        .map_err(|e| format!("Invalid nonce format: {}", e))?;

    let transaction = TxData::new(
        parsed_payload.near_account_id,
        parsed_payload.receiver_id,
        nonce,
        parsed_payload.block_hash_bytes,
        parsed_payload.actions,
    );

    let signing_request = TransactionSigningRequest::new(
        verification,
        decryption,
        transaction,
    );

    // Call the async WASM function
    let result = verify_and_sign_near_transaction_with_actions(&vrf_challenge, &credential, &signing_request).await
        .map_err(|e| format!("SignTransactionWithActions failed: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle sign transfer transaction request
async fn handle_sign_transfer_transaction_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let parsed_payload: SignTransferTransactionPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Failed to parse SignTransferTransaction payload: {}", e))?;

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnAuthenticationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.authenticator_data,
        parsed_payload.credential.response.signature,
        parsed_payload.credential.response.user_handle,
    );

    let verification = Verification::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    let decryption = Decryption::new(
        parsed_payload.prf_output,
        parsed_payload.encrypted_private_key_data,
        parsed_payload.encrypted_private_key_iv,
    );

    let nonce = parsed_payload.nonce.parse::<u64>()
        .map_err(|e| format!("Invalid nonce format: {}", e))?;

    let transaction = TransferTxData::new(
        parsed_payload.near_account_id,
        parsed_payload.receiver_id,
        nonce,
        parsed_payload.block_hash_bytes,
        parsed_payload.deposit_amount,
    );

    let transfer_request = TransferTransactionRequest::new(
        verification,
        decryption,
        transaction,
    );

    // Call the async WASM function
    let result = verify_and_sign_near_transfer_transaction(&vrf_challenge, &credential, &transfer_request).await
        .map_err(|e| format!("SignTransferTransaction failed: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle add key with PRF request
async fn handle_add_key_with_prf_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let parsed_payload: AddKeyWithPrfPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Failed to parse AddKeyWithPrf payload: {}", e))?;

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnAuthenticationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.authenticator_data,
        parsed_payload.credential.response.signature,
        parsed_payload.credential.response.user_handle,
    );

    let verification = Verification::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    let decryption = Decryption::new(
        parsed_payload.prf_output,
        parsed_payload.encrypted_private_key_data,
        parsed_payload.encrypted_private_key_iv,
    );

    let nonce = parsed_payload.nonce.parse::<u64>()
        .map_err(|e| format!("Invalid nonce format: {}", e))?;

    let transaction = AddKeyTxData::new(
        parsed_payload.near_account_id,
        parsed_payload.new_public_key,
        parsed_payload.access_key_json,
        nonce,
        parsed_payload.block_hash_bytes,
    );

    let add_key_request = AddKeyRequest::new(
        verification,
        decryption,
        transaction,
    );

    // Call the async WASM function
    let result = add_key_with_prf(&vrf_challenge, &credential, &add_key_request).await
        .map_err(|e| format!("AddKeyWithPrf failed: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle delete key with PRF request
async fn handle_delete_key_with_prf_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let parsed_payload: DeleteKeyWithPrfPayload = serde_json::from_value(payload)
        .map_err(|e| format!("Failed to parse DeleteKeyWithPrf payload: {}", e))?;

    // Convert payload to WASM structs
    let vrf_challenge = VrfChallengeStruct::new(
        parsed_payload.vrf_challenge.vrf_input,
        parsed_payload.vrf_challenge.vrf_output,
        parsed_payload.vrf_challenge.vrf_proof,
        parsed_payload.vrf_challenge.vrf_public_key,
        parsed_payload.vrf_challenge.user_id,
        parsed_payload.vrf_challenge.rp_id,
        parsed_payload.vrf_challenge.block_height,
        parsed_payload.vrf_challenge.block_hash,
    );

    let credential = WebAuthnAuthenticationCredentialStruct::new(
        parsed_payload.credential.id,
        parsed_payload.credential.raw_id,
        parsed_payload.credential.credential_type,
        parsed_payload.credential.authenticator_attachment,
        parsed_payload.credential.response.client_data_json,
        parsed_payload.credential.response.authenticator_data,
        parsed_payload.credential.response.signature,
        parsed_payload.credential.response.user_handle,
    );

    let verification = Verification::new(
        parsed_payload.contract_id,
        parsed_payload.near_rpc_url,
    );

    let decryption = Decryption::new(
        parsed_payload.prf_output,
        parsed_payload.encrypted_private_key_data,
        parsed_payload.encrypted_private_key_iv,
    );

    let nonce = parsed_payload.nonce.parse::<u64>()
        .map_err(|e| format!("Invalid nonce format: {}", e))?;

    let transaction = DeleteKeyTxData::new(
        parsed_payload.near_account_id,
        parsed_payload.public_key_to_delete,
        nonce,
        parsed_payload.block_hash_bytes,
    );

    let delete_key_request = DeleteKeyRequest::new(
        verification,
        decryption,
        transaction,
    );

    // Call the async WASM function
    let result = delete_key_with_prf(&vrf_challenge, &credential, &delete_key_request).await
        .map_err(|e| format!("DeleteKeyWithPrf failed: {:?}", e))?;

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Handle extract COSE public key request
async fn handle_extract_cose_public_key_msg(payload: serde_json::Value) -> Result<serde_json::Value, String> {
    let request: ExtractCosePayload = serde_json::from_value(payload)
        .map_err(|e| format!("Invalid payload for EXTRACT_COSE_PUBLIC_KEY: {:?}", e))?;

    let cose_key_bytes = extract_cose_public_key_from_attestation(&request.attestation_object_base64url)
        .map_err(|e| format!("Failed to extract COSE public key: {:?}", e))?;

    let result = CoseExtractionResult {
        cose_public_key_bytes: cose_key_bytes,
    };

    serde_json::to_value(&result)
        .map_err(|e| format!("Failed to serialize result: {:?}", e))
}

/// Unified message handler for all signer worker operations
/// This replaces the TypeScript-based message dispatching with a Rust-based approach
/// for better type safety and performance
#[wasm_bindgen]
pub async fn handle_signer_message(message_json: &str) -> Result<String, JsValue> {
    console_error_panic_hook::set_once();

    // Parse the JSON message
    let msg: SignerWorkerMessage = serde_json::from_str(message_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse message: {:?}", e)))?;

    // Convert numeric enum to WorkerRequestType using From trait
    let request_type = WorkerRequestType::from(msg.msg_type);

    // Route message to appropriate handler
    let response_payload = match request_type {
        WorkerRequestType::DeriveNearKeypairAndEncrypt => {
            handle_derive_near_keypair_and_encrypt_msg(msg.payload).await
        },
        WorkerRequestType::RecoverKeypairFromPasskey => {
            handle_recover_keypair_from_passkey_msg(msg.payload).await
        },
        WorkerRequestType::CheckCanRegisterUser => {
            handle_check_can_register_user_msg(msg.payload).await
        },
        WorkerRequestType::SignVerifyAndRegisterUser => {
            handle_sign_verify_and_register_user_msg(msg.payload).await
        },
        WorkerRequestType::DecryptPrivateKeyWithPrf => {
            handle_decrypt_private_key_with_prf_msg(msg.payload).await
        },
        WorkerRequestType::SignTransactionWithActions => {
            handle_sign_transaction_with_actions_msg(msg.payload).await
        },
        WorkerRequestType::SignTransferTransaction => {
            handle_sign_transfer_transaction_msg(msg.payload).await
        },
        WorkerRequestType::AddKeyWithPrf => {
            handle_add_key_with_prf_msg(msg.payload).await
        },
        WorkerRequestType::DeleteKeyWithPrf => {
            handle_delete_key_with_prf_msg(msg.payload).await
        },
        WorkerRequestType::ExtractCosePublicKey => {
            handle_extract_cose_public_key_msg(msg.payload).await
        },
    };

    // Handle the result
    let payload = match response_payload {
        Ok(payload) => payload,
        Err(error_msg) => {
            let error_response = SignerWorkerResponse {
                response_type: u32::from(WorkerResponseType::Error),
                payload: serde_json::json!({
                    "error": error_msg,
                    "context": { "type": msg.msg_type }
                }),
            };
            return Ok(serde_json::to_string(&error_response)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize error response: {:?}", e)))?);
        }
    };

    // Determine response type based on request type
    let response_type = match request_type {
        WorkerRequestType::DeriveNearKeypairAndEncrypt => WorkerResponseType::EncryptionSuccess,
        WorkerRequestType::RecoverKeypairFromPasskey => WorkerResponseType::RecoverKeypairSuccess,
        WorkerRequestType::CheckCanRegisterUser => WorkerResponseType::RegistrationSuccess,
        WorkerRequestType::SignVerifyAndRegisterUser => WorkerResponseType::RegistrationSuccess,
        WorkerRequestType::DecryptPrivateKeyWithPrf => WorkerResponseType::DecryptionSuccess,
        WorkerRequestType::SignTransactionWithActions => WorkerResponseType::SignatureSuccess,
        WorkerRequestType::SignTransferTransaction => WorkerResponseType::SignatureSuccess,
        WorkerRequestType::AddKeyWithPrf => WorkerResponseType::SignatureSuccess,
        WorkerRequestType::DeleteKeyWithPrf => WorkerResponseType::SignatureSuccess,
        WorkerRequestType::ExtractCosePublicKey => WorkerResponseType::CoseExtractionSuccess,
    };

    // Create the final response
    let response = SignerWorkerResponse {
        response_type: u32::from(response_type),
        payload,
    };

    // Return JSON string
    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {:?}", e)))
}
