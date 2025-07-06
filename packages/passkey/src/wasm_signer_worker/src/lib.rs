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
use crate::crypto::{
    decrypt_private_key_with_prf,
    derive_ed25519_key_from_prf_output,
};
use bs58;

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

#[wasm_bindgen]
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

    let cose_public_key_bytes = crate::cose::extract_cose_public_key_from_attestation_core(attestation_object_b64u)
        .map_err(|e| JsValue::from_str(&format!("Failed to extract COSE public key: {}", e)))?;

    console_log!("RUST: WASM binding - COSE public key extraction successful ({} bytes)", cose_public_key_bytes.len());
    Ok(cose_public_key_bytes)
}

/// Dual PRF key derivation for WASM
#[wasm_bindgen]
pub fn derive_and_encrypt_keypair_from_dual_prf_wasm(request_json: &str) -> Result<String, JsValue> {
    console_log!("RUST: WASM binding - starting dual PRF keypair derivation");

    // Parse the request
    let request: DualPrfDeriveKeypairRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    // Call the dual PRF derivation function
    let (public_key, encrypted_result) = crate::crypto::derive_and_encrypt_keypair_from_dual_prf(
        &request.dual_prf_outputs,
        &request.account_id
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Create structured response
    let response = crate::types::KeyGenerationResponse {
        public_key,
        encrypted_private_key: encrypted_result,
    };

    Ok(response.to_json())
}

#[wasm_bindgen]
pub fn recover_keypair_from_passkey(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: WASM binding - deriving deterministic keypair from passkey using PRF");

    let request: RecoverKeypairRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    console_log!("RUST: Parsed registration credential with ID: {}", request.credential.id);

    // Extract Ed25519 PRF output from credential extension results
    let ed25519_prf_output = request.credential.client_extension_results
        .as_ref()
        .and_then(|ext| ext["prf"].as_object())
        .and_then(|prf| prf["results"].as_object())
        .and_then(|results| results["second"].as_str())
        .ok_or_else(|| JsValue::from_str("Ed25519 PRF output (second) missing from credential extension results"))?;

    console_log!("RUST: Extracted Ed25519 PRF output for key derivation");

    // Use account hint if provided, otherwise generate placeholder
    let account_id = request.account_id_hint
        .as_deref()
        .unwrap_or("recovery-account.testnet");

    // Derive Ed25519 keypair from PRF output using account-specific HKDF
    let (_private_key, public_key) = derive_ed25519_key_from_prf_output(ed25519_prf_output, account_id)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Ed25519 key from PRF: {}", e)))?;

    // Format as NEAR public key (public_key is already in the correct format)
    let near_public_key = format!("ed25519:{}", public_key);

    console_log!("RUST: Successfully derived NEAR keypair from Ed25519 PRF output");

    let response = RecoverKeypairResponse {
        public_key: near_public_key,
        account_id_hint: request.account_id_hint.clone(),
    };

    console_log!("RUST: PRF-based keypair derivation from passkey successful");
    Ok(response.to_json())
}


#[wasm_bindgen]
pub fn decrypt_private_key_with_prf_as_string(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Decrypting private key with PRF and returning as string");

    let request: DecryptPrivateKeyRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    // Support both legacy single PRF and new dual PRF workflows
    let prf_output = if let Some(aes_prf_output) = &request.aes_prf_output_base64 {
        console_log!("RUST: Using AES PRF output for decryption (dual PRF workflow)");
        aes_prf_output
    } else {
        return Err(JsValue::from_str("aes_prf_output_base64 must be provided"));
    };

    // Use the core function to decrypt and get SigningKey
    let signing_key = decrypt_private_key_with_prf(
        prf_output,
        &request.near_account_id,
        &request.encrypted_private_key_data,
        &request.encrypted_private_key_iv,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

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

    let response = PrivateKeyDecryptionResponse {
        private_key: private_key_near_format,
    };

    console_log!("RUST: Successfully decrypted private key and formatted as string");
    Ok(response.to_json())
}

// === WASM BINDINGS FOR TRANSACTION SIGNING ===
// COMBINED VERIFICATION + SIGNING WITH PROGRESS

#[wasm_bindgen]
pub async fn verify_and_sign_near_transaction_with_actions(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Starting combined verification + signing with progress");

    let request: VerifyAndSignTransactionRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    // Step 1: Send verification progress with enhanced logging
    let verification_logs = vec![
        format!("Starting contract verification for {}", request.contract_id),
        "Parsing VRF challenge data...".to_string(),
        "Preparing WebAuthn credential for verification...".to_string()
    ];

    send_progress_with_logs(
        "VERIFICATION_PROGRESS",
        "contract_verification",
        "Verifying authentication with contract...",
        &format!(r#"{{"contractId": "{}"}}"#, request.contract_id),
        Some(&verification_logs)
    );

    // Step 2: Perform contract verification via WASM HTTP
    let verification_result = {

        // Parse VRF challenge data
        let vrf_data = parse_vrf_challenge(&request.vrf_challenge_data_json)?;

        // Parse WebAuthn credential
        let webauthn_credential: serde_json::Value = serde_json::from_str(&request.webauthn_credential_json)
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
        perform_contract_verification_wasm(&request.contract_id, vrf_data, webauthn_auth, &request.near_rpc_url)
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
        &format!(r#"{{"signerAccountId": "{}", "receiverId": "{}"}}"#, request.signer_account_id, request.receiver_account_id)
    );

    // Step 5: Perform transaction signing (existing logic)
    let private_key = match decrypt_private_key_with_prf(
        &request.prf_output_base64,
        &request.signer_account_id,
        &request.encrypted_private_key_data,
        &request.encrypted_private_key_iv,
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
    let action_params: Vec<ActionParams> = serde_json::from_str(&request.actions_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse actions: {}", e)))?;

    let actions = build_actions_from_params(action_params)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Build and sign transaction
    let transaction = build_transaction_with_actions(
        &request.signer_account_id,
        &request.receiver_account_id,
        request.nonce,
        &request.block_hash_bytes,
        &private_key,
        actions,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let signed_tx_bytes = sign_transaction(transaction, &private_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Step 6: Send signing complete with structured response
    let json_signed_tx = match JsonSignedTransaction::from_borsh_bytes(&signed_tx_bytes) {
        Ok(tx) => Some(tx),
        Err(e) => {
            console_log!("RUST: Warning - Failed to decode signed transaction for structured response: {}", e);
            None
        }
    };

    let response = TransactionSigningResponse {
        success: true,
        signed_transaction: json_signed_tx,
        signed_transaction_borsh: signed_tx_bytes.clone(),
        near_account_id: request.signer_account_id.clone(),
        verification_logs: verification_result.logs,
        error: None,
    };

    send_progress_message(
        "SIGNING_COMPLETE",
        "signing_complete",
        "Transaction signed successfully",
        &response.to_json()
    );

    console_log!("RUST: Combined verification + signing completed successfully");
    Ok(response.to_json())
}

#[wasm_bindgen]
pub async fn verify_and_sign_near_transfer_transaction(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Starting transfer transaction verification + signing with progress");

    let request: VerifyAndSignTransferRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    // Convert transfer parameters to action-based format
    let transfer_actions = vec![ActionParams::Transfer {
        deposit: request.deposit_amount.clone(),
    }];

    let actions_json = serde_json::to_string(&transfer_actions)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize transfer action: {}", e)))?;

    // Create request for the main verification + signing function
    let main_request = VerifyAndSignTransactionRequest {
        prf_output_base64: request.prf_output_base64,
        encrypted_private_key_data: request.encrypted_private_key_data,
        encrypted_private_key_iv: request.encrypted_private_key_iv,
        signer_account_id: request.signer_account_id,
        receiver_account_id: request.receiver_account_id,
        nonce: request.nonce,
        block_hash_bytes: request.block_hash_bytes,
        actions_json,
        contract_id: request.contract_id,
        vrf_challenge_data_json: request.vrf_challenge_data_json,
        webauthn_credential_json: request.webauthn_credential_json,
        near_rpc_url: request.near_rpc_url,
    };

    let main_request_json = serde_json::to_string(&main_request)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize main request: {}", e)))?;

    // Delegate to the main verification + signing function
    verify_and_sign_near_transaction_with_actions(&main_request_json).await
}


/// Check if user can register (view function)
#[wasm_bindgen]
pub async fn check_can_register_user(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Checking if user can register (view function)");

    let request: CheckCanRegisterUserRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    // Parse VRF challenge data
    let vrf_data = parse_vrf_challenge(&request.vrf_challenge_data_json)?;

    // Parse WebAuthn registration credential
    let webauthn_registration_data: serde_json::Value = serde_json::from_str(&request.webauthn_registration_json)
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
    let registration_result = crate::http::check_can_register_user_wasm(&request.contract_id, vrf_data, webauthn_registration, &request.near_rpc_url)
            .await
    .map_err(|e| JsValue::from_str(&format!("Registration check failed: {}", e)))?;

    // Create structured response
    let signed_transaction = if let Some(ref signed_tx_bytes) = registration_result.signed_transaction_borsh {
        JsonSignedTransaction::from_borsh_bytes(signed_tx_bytes).ok()
    } else {
        None
    };

    let registration_info = registration_result.registration_info.map(|info| RegistrationInfo {
        credential_id: info.credential_id,
        credential_public_key: info.credential_public_key,
        user_id: "".to_string(), // Not available from contract response
        vrf_public_key: None, // Not available from contract response
    });

    let response = RegistrationCheckResponse {
        verified: registration_result.verified,
        registration_info,
        logs: registration_result.logs,
        signed_transaction,
        error: registration_result.error,
    };

    Ok(response.to_json())
}

/// Actually register user (STATE-CHANGING FUNCTION - uses send_tx RPC)
#[wasm_bindgen]
pub async fn sign_verify_and_register_user(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Performing actual user registration (state-changing function)");

    let request: SignVerifyAndRegisterUserRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    // Parse VRF challenge data
    let vrf_data = parse_vrf_challenge(&request.vrf_challenge_data_json)?;

    // Parse WebAuthn registration credential
    let webauthn_registration_data: serde_json::Value = serde_json::from_str(&request.webauthn_registration_json)
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
        &request.contract_id,
        vrf_data,
        webauthn_registration,
        &request.signer_account_id,
        &request.encrypted_private_key_data,
        &request.encrypted_private_key_iv,
        &request.prf_output_base64,
        request.nonce,
        &request.block_hash_bytes,
    )
    .await
    .map_err(|e| JsValue::from_str(&format!("Actual registration failed: {}", e)))?;

    // Create structured response with embedded borsh bytes
    let signed_transaction = if let Some(ref signed_tx_bytes) = registration_result.signed_transaction_borsh {
        JsonSignedTransaction::from_borsh_bytes(signed_tx_bytes).ok()
    } else {
        None
    };

    let pre_signed_delete_transaction = if let Some(ref delete_tx_bytes) = registration_result.pre_signed_delete_transaction {
        JsonSignedTransaction::from_borsh_bytes(delete_tx_bytes).ok()
    } else {
        None
    };

    let registration_info = registration_result.registration_info.map(|info| RegistrationInfo {
        credential_id: info.credential_id,
        credential_public_key: info.credential_public_key,
        user_id: "".to_string(), // Not available from contract response
        vrf_public_key: None, // Not available from contract response
    });

    let response = RegistrationResponse {
        verified: registration_result.verified,
        registration_info,
        logs: registration_result.logs,
        signed_transaction,
        pre_signed_delete_transaction,
        error: registration_result.error,
    };

    Ok(response.to_json())
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

/// Convenience function for adding keys with PRF authentication
#[wasm_bindgen]
pub async fn add_key_with_prf(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Starting AddKey transaction with PRF authentication");

    let request: AddKeyWithPrfRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    let add_key_action = ActionParams::AddKey {
        public_key: request.new_public_key.clone(),
        access_key: request.access_key_json.clone(),
    };

    let actions_json = serde_json::to_string(&vec![add_key_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize add key action: {}", e)))?;

    let main_request = VerifyAndSignTransactionRequest {
        prf_output_base64: request.prf_output_base64,
        encrypted_private_key_data: request.encrypted_private_key_data,
        encrypted_private_key_iv: request.encrypted_private_key_iv,
        signer_account_id: request.signer_account_id.clone(),
        receiver_account_id: request.signer_account_id.clone(), // receiver_id is same as signer for add key
        nonce: request.nonce,
        block_hash_bytes: request.block_hash_bytes,
        actions_json,
        contract_id: request.contract_id,
        vrf_challenge_data_json: request.vrf_challenge_data_json,
        webauthn_credential_json: request.webauthn_credential_json,
        near_rpc_url: request.near_rpc_url,
    };

    let main_request_json = serde_json::to_string(&main_request)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize main request: {}", e)))?;

    verify_and_sign_near_transaction_with_actions(&main_request_json).await
}

/// Convenience function for deleting keys with PRF authentication
#[wasm_bindgen]
pub async fn delete_key_with_prf(
    request_json: &str,
) -> Result<String, JsValue> {
    console_log!("RUST: Starting DeleteKey transaction with PRF authentication");

    let request: DeleteKeyWithPrfRequest = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse request: {}", e)))?;

    let delete_key_action = ActionParams::DeleteKey {
        public_key: request.public_key_to_delete.clone(),
    };

    let actions_json = serde_json::to_string(&vec![delete_key_action])
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize delete key action: {}", e)))?;

    let main_request = VerifyAndSignTransactionRequest {
        prf_output_base64: request.prf_output_base64,
        encrypted_private_key_data: request.encrypted_private_key_data,
        encrypted_private_key_iv: request.encrypted_private_key_iv,
        signer_account_id: request.signer_account_id.clone(),
        receiver_account_id: request.signer_account_id.clone(), // receiver_id is same as signer for delete key
        nonce: request.nonce,
        block_hash_bytes: request.block_hash_bytes,
        actions_json,
        contract_id: request.contract_id,
        vrf_challenge_data_json: request.vrf_challenge_data_json,
        webauthn_credential_json: request.webauthn_credential_json,
        near_rpc_url: request.near_rpc_url,
    };

    let main_request_json = serde_json::to_string(&main_request)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize main request: {}", e)))?;

    verify_and_sign_near_transaction_with_actions(&main_request_json).await
}