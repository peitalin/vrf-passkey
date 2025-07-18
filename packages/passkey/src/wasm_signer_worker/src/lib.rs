mod actions;
mod config;
mod crypto;
mod cose;
mod error;
mod handlers;
mod http;
#[cfg(test)]
mod tests;
mod transaction;
mod types;

use wasm_bindgen::prelude::*;
use serde_json;

// Import from modules
use crate::types::*;
use crate::error::*;
use crate::types::worker_messages::{
    WorkerRequestType,
    WorkerResponseType,
    SignerWorkerMessage,
    SignerWorkerResponse
};

// === CONSOLE LOGGING ===

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    pub fn warn(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn error(s: &str);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn log(s: &str) {
    println!("{}", s);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn warn(s: &str) {
    println!("Warning: {}", s);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn error(s: &str) {
    println!("Error: {}", s);
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// === PROGRESS MESSAGING ===

/// Progress messaging function that sends messages back to main thread
/// Used by handlers to provide real-time updates during long operations
pub fn send_progress_message(message_type: &str, step: &str, message: &str, data: &str) {
    // Convert message type to WorkerResponseType
    let response_type = match message_type {
        "VERIFICATION_PROGRESS" => WorkerResponseType::VerificationProgress,
        "VERIFICATION_COMPLETE" => WorkerResponseType::VerificationComplete,
        "SIGNING_PROGRESS" => WorkerResponseType::SigningProgress,
        "SIGNING_COMPLETE" => WorkerResponseType::SigningComplete,
        "REGISTRATION_PROGRESS" => WorkerResponseType::RegistrationProgress,
        "REGISTRATION_COMPLETE" => WorkerResponseType::RegistrationComplete,
        _ => WorkerResponseType::VerificationProgress, // Default fallback
    };

    // Create progress payload
    let payload = serde_json::json!({
        "step": step,
        "message": message,
        "data": serde_json::from_str::<serde_json::Value>(data).unwrap_or_else(|_| serde_json::json!({}))
    });

    // Create response structure
    let response = SignerWorkerResponse {
        response_type: u32::from(response_type),
        payload,
    };

    // Post message to main thread (only works in WASM context)
    if let Ok(response_json) = serde_json::to_string(&response) {
#[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(js_namespace = ["self"], js_name = postMessage)]
            fn post_message_to_main_thread(data: &str);
        }

        // Only try to post message in WASM context
        #[cfg(target_arch = "wasm32")]
        {
            post_message_to_main_thread(&response_json);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // In non-WASM context (like tests), just log the progress
            let _ = response_json; // Suppress unused warning
            println!("Progress: {} - {} - {}", message_type, step, message);
        }
    }
}

// Re-export public structs from handlers
pub use handlers::{
    Decryption,
    TxData,
    Verification,
    BatchSigningPayload,
    VerificationPayload,
    DecryptionPayload,
    TransactionPayload,
    DualPrfOutputs,
    EncryptionResult,
    WebAuthnRegistrationCredentialStruct,
    WebAuthnAuthenticationCredentialStruct,
    WebAuthnAuthenticationCredentialRecoveryStruct,
    VrfChallengeStruct,
    RecoverKeypairResult,
    DecryptPrivateKeyRequest,
    DecryptPrivateKeyResult,
    RegistrationCheckRequest,
    RegistrationTxData,
    RegistrationRequest,
    TransactionSignResult,
    KeyActionResult,
    RegistrationInfoStruct,
    RegistrationCheckResult,
    RegistrationResult,
    CoseExtractionResult,
    JsonSignedTransactionStruct,
};

// === MESSAGE HANDLER FUNCTIONS ===

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
            let request = msg.parse_payload::<DeriveKeypairPayload>(request_type)?;
            let result = handlers::handle_derive_near_keypair_and_encrypt_msg(request).await?;
            result.to_json()
        },
        WorkerRequestType::RecoverKeypairFromPasskey => {
            let request = msg.parse_payload::<RecoverKeypairPayload>(request_type)?;
            let result = handlers::handle_recover_keypair_from_passkey_msg(request).await?;
            result.to_json()
        },
        WorkerRequestType::CheckCanRegisterUser => {
            let request = msg.parse_payload::<CheckCanRegisterUserPayload>(request_type)?;
            let result = handlers::handle_check_can_register_user_msg(request).await?;
            result.to_json()
        },
        WorkerRequestType::SignVerifyAndRegisterUser => {
            let request = msg.parse_payload::<SignVerifyAndRegisterUserPayload>(request_type)?;
            let result = handlers::handle_sign_verify_and_register_user_msg(request).await?;
            result.to_json()
        },
        WorkerRequestType::DecryptPrivateKeyWithPrf => {
            let request = msg.parse_payload::<DecryptKeyPayload>(request_type)?;
            let result = handlers::handle_decrypt_private_key_with_prf_msg(request).await?;
            result.to_json()
        },
        WorkerRequestType::SignTransactionsWithActions => {
            let request = msg.parse_payload::<BatchSigningPayload>(request_type)?;
            let result = handlers::handle_sign_transactions_with_actions_msg(request).await?;
            result.to_json()
        },
        WorkerRequestType::ExtractCosePublicKey => {
            let request = msg.parse_payload::<ExtractCosePayload>(request_type)?;
            let result = handlers::handle_extract_cose_public_key_msg(request).await?;
            result.to_json()
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
        WorkerRequestType::SignTransactionsWithActions => WorkerResponseType::SignatureSuccess,
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
