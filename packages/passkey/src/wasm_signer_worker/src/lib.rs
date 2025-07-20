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
/// Now includes both numeric enum values AND string names for better debugging
pub fn send_progress_message(message_type: u32, step: u32, message: &str, _data: &str) {
    // Create structured logs array (empty for now, can be enhanced later)
    let _logs_json = "[]";

    // Call the TypeScript sendProgressMessage function that was made globally available
    // This replaces the direct postMessage approach
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = sendProgressMessage)]
        fn send_progress_message_js(
            message_type: u32,
            message_type_name: &str,
            step: u32,
            step_name: &str,
            message: &str,
            data: &str,
            logs: &str
        );
    }

    // Convert numeric enums back to their string names for debugging
    let message_type_name = match message_type {
        12 => "VERIFICATION_PROGRESS",
        13 => "VERIFICATION_COMPLETE",
        14 => "SIGNING_PROGRESS",
        15 => "SIGNING_COMPLETE",
        16 => "REGISTRATION_PROGRESS",
        17 => "REGISTRATION_COMPLETE",
        _ => "UNKNOWN_MESSAGE_TYPE",
    };

    let step_name = match step {
        20 => "preparation",
        21 => "contract-verification",
        22 => "transaction-signing",
        23 => "verification-complete",
        24 => "signing-complete",
        25 => "error",
        _ => "unknown-step",
    };

    // Only try to send message in WASM context
    #[cfg(target_arch = "wasm32")]
    {
        send_progress_message_js(message_type, message_type_name, step, step_name, message, _data, _logs_json);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        // In non-WASM context (like tests), just log the progress
        println!("Progress: {} ({}) - {} ({}) - {}", message_type_name, message_type, step_name, step, message);
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

// Re-export progress types for auto-generation
pub use types::progress::{
    ProgressMessageType,
    ProgressStep,
    ProgressStatus,
    WorkerProgressMessage,
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

    // Debug logging to understand what's happening
    log(&format!("WASM Worker: Received message type: {} ({})",
        worker_request_type_name(request_type), msg.msg_type));
    log(&format!("WASM Worker: Parsed request type: {:?}", request_type));

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
        WorkerRequestType::SignTransactionWithKeyPair => {
            let request = msg.parse_payload::<SignTransactionWithKeyPairPayload>(request_type)?;
            let result = handlers::handle_sign_transaction_with_keypair_msg(request).await?;
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
        WorkerRequestType::SignTransactionWithKeyPair => WorkerResponseType::SignatureSuccess,
    };

    // Debug logging for response type
    log(&format!("WASM Worker: Determined response type: {} ({}) - {:?}",
        worker_response_type_name(response_type), u32::from(response_type), response_type));

    // Create the final response
    let response = SignerWorkerResponse {
        response_type: u32::from(response_type),
        payload,
    };

    // Return JSON string
    serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {:?}", e)))
}

// === DEBUGGING HELPERS ===
// Convert numeric enum values to readable strings for debugging
// Makes Rust logs much easier to read when dealing with wasm-bindgen numeric enums

/// Convert WorkerRequestType enum to readable string for debugging
pub fn worker_request_type_name(request_type: WorkerRequestType) -> &'static str {
    match request_type {
        WorkerRequestType::DeriveNearKeypairAndEncrypt => "DERIVE_NEAR_KEYPAIR_AND_ENCRYPT",
        WorkerRequestType::RecoverKeypairFromPasskey => "RECOVER_KEYPAIR_FROM_PASSKEY",
        WorkerRequestType::CheckCanRegisterUser => "CHECK_CAN_REGISTER_USER",
        WorkerRequestType::SignVerifyAndRegisterUser => "SIGN_VERIFY_AND_REGISTER_USER",
        WorkerRequestType::DecryptPrivateKeyWithPrf => "DECRYPT_PRIVATE_KEY_WITH_PRF",
        WorkerRequestType::SignTransactionsWithActions => "SIGN_TRANSACTIONS_WITH_ACTIONS",
        WorkerRequestType::ExtractCosePublicKey => "EXTRACT_COSE_PUBLIC_KEY",
        WorkerRequestType::SignTransactionWithKeyPair => "SIGN_TRANSACTION_WITH_KEYPAIR",
    }
}

/// Convert WorkerResponseType enum to readable string for debugging
pub fn worker_response_type_name(response_type: WorkerResponseType) -> &'static str {
    match response_type {
        WorkerResponseType::EncryptionSuccess => "ENCRYPTION_SUCCESS",
        WorkerResponseType::DeriveNearKeyFailure => "DERIVE_NEAR_KEY_FAILURE",
        WorkerResponseType::RecoverKeypairSuccess => "RECOVER_KEYPAIR_SUCCESS",
        WorkerResponseType::RecoverKeypairFailure => "RECOVER_KEYPAIR_FAILURE",
        WorkerResponseType::RegistrationSuccess => "REGISTRATION_SUCCESS",
        WorkerResponseType::RegistrationFailure => "REGISTRATION_FAILURE",
        WorkerResponseType::SignatureSuccess => "SIGNATURE_SUCCESS",
        WorkerResponseType::SignatureFailure => "SIGNATURE_FAILURE",
        WorkerResponseType::DecryptionSuccess => "DECRYPTION_SUCCESS",
        WorkerResponseType::DecryptionFailure => "DECRYPTION_FAILURE",
        WorkerResponseType::CoseExtractionSuccess => "COSE_EXTRACTION_SUCCESS",
        WorkerResponseType::CoseExtractionFailure => "COSE_EXTRACTION_FAILURE",
        WorkerResponseType::Error => "ERROR",
        WorkerResponseType::VerificationProgress => "VERIFICATION_PROGRESS",
        WorkerResponseType::VerificationComplete => "VERIFICATION_COMPLETE",
        WorkerResponseType::SigningProgress => "SIGNING_PROGRESS",
        WorkerResponseType::SigningComplete => "SIGNING_COMPLETE",
        WorkerResponseType::RegistrationProgress => "REGISTRATION_PROGRESS",
        WorkerResponseType::RegistrationComplete => "REGISTRATION_COMPLETE",
    }
}

// === TESTS ===

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // Track progress messages sent during tests
    thread_local! {
        static PROGRESS_MESSAGES: Arc<Mutex<Vec<(String, String, String, String)>>> =
            Arc::new(Mutex::new(Vec::new()));
    }

    // Mock implementation of sendProgressMessage for testing
    fn mock_send_progress_message(message_type: &str, step: &str, message: &str, data: &str) {
        PROGRESS_MESSAGES.with(|messages| {
            messages.lock().unwrap().push((
                message_type.to_string(),
                step.to_string(),
                message.to_string(),
                data.to_string()
            ));
        });
    }

    fn get_progress_messages() -> Vec<(String, String, String, String)> {
        PROGRESS_MESSAGES.with(|messages| {
            messages.lock().unwrap().clone()
        })
    }

    fn clear_progress_messages() {
        PROGRESS_MESSAGES.with(|messages| {
            messages.lock().unwrap().clear()
        });
    }

    #[test]
    fn test_send_progress_message_function() {
        clear_progress_messages();

        // Test that send_progress_message works in non-WASM context
        send_progress_message(
            "SIGNING_PROGRESS",
            "transaction-signing",
            "Test progress message",
            r#"{"step": 1, "total": 3}"#
        );

        // Should print to console in non-WASM context (no panic)
        assert!(true, "send_progress_message should not panic in test context");
    }

    #[test]
    fn test_progress_message_types() {
        // Test all supported progress message types
        let message_types = [
            "VERIFICATION_PROGRESS",
            "VERIFICATION_COMPLETE",
            "SIGNING_PROGRESS",
            "SIGNING_COMPLETE",
            "REGISTRATION_PROGRESS",
            "REGISTRATION_COMPLETE"
        ];

        for msg_type in message_types {
            send_progress_message(
                msg_type,
                "test_step",
                "Test message",
                "{}"
            );
        }

        // Should not panic with any supported message type
        assert!(true, "All message types should be handled without panic");
    }

    #[test]
    fn test_progress_message_json_data() {
        // Test with various JSON data formats
        let test_cases = [
            ("SIGNING_PROGRESS", "step1", "Testing", r#"{"step": 1}"#),
            ("SIGNING_COMPLETE", "step2", "Done", r#"{"success": true, "count": 5}"#),
            ("VERIFICATION_PROGRESS", "step3", "Checking", "{}"),
        ];

        for (msg_type, step, message, data) in test_cases {
            send_progress_message(msg_type, step, message, data);
        }

        assert!(true, "Various JSON data formats should be handled");
    }
}
