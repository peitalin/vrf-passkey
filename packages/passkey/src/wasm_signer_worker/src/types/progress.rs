//! Progress Message Types - Auto-Generated TypeScript Interface
//!
//! These Rust types use wasm-bindgen to automatically generate corresponding
//! TypeScript types, ensuring type safety between Rust and TypeScript.
//!
//! MESSAGING FLOW DOCUMENTATION:
//! =============================
//!
//! 1. PROGRESS MESSAGES (During Operation):
//!    Rust WASM → send_progress_message() → TypeScript sendProgressMessage() → postMessage() → Main Thread
//!    - Used for real-time updates during long operations
//!    - Multiple progress messages can be sent per operation
//!    - Does not affect the final result
//!
//! 2. FINAL RESULTS (Operation Complete):
//!    Rust WASM → return value from handle_signer_message() → TypeScript worker → postMessage() → Main Thread
//!    - Contains the actual operation result (success/error)
//!    - Only one result message per operation
//!    - This is what the main thread awaits for completion

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

/// Progress message types that can be sent during WASM operations
/// Values align with TypeScript WorkerResponseType enum for proper mapping
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgressMessageType {
    VerificationProgress = 12,
    VerificationComplete = 13,
    SigningProgress = 14,
    SigningComplete = 15,
    RegistrationProgress = 16,
    RegistrationComplete = 17,
}

/// Progress step identifiers for different phases of operations
/// Values start at 20 to avoid conflicts with WorkerResponseType enum
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgressStep {
    Preparation = 20,
    ContractVerification = 21,
    TransactionSigning = 22,
    VerificationComplete = 23,
    SigningComplete = 24,
    Error = 25,
}

/// Status of a progress message
/// Auto-generates TypeScript enum: ProgressStatus
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgressStatus {
    Progress = "progress",
    Success = "success",
    Error = "error",
}

/// Base progress message structure sent from WASM to TypeScript
/// Auto-generates TypeScript interface: WorkerProgressMessage
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerProgressMessage {
    #[wasm_bindgen(getter_with_clone)]
    pub message_type: String, // Will contain ProgressMessageType value

    #[wasm_bindgen(getter_with_clone)]
    pub step: String, // Will contain ProgressStep value

    #[wasm_bindgen(getter_with_clone)]
    pub message: String,

    #[wasm_bindgen(getter_with_clone)]
    pub status: String, // Will contain ProgressStatus value

    pub timestamp: f64,

    #[wasm_bindgen(getter_with_clone)]
    pub data: Option<String>, // JSON stringified data
}

#[wasm_bindgen]
impl WorkerProgressMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        message_type: &str,
        step: &str,
        message: &str,
        status: &str,
        timestamp: f64,
        data: Option<String>,
    ) -> WorkerProgressMessage {
        WorkerProgressMessage {
            message_type: message_type.to_string(),
            step: step.to_string(),
            message: message.to_string(),
            status: status.to_string(),
            timestamp,
            data,
        }
    }
}

/// Type-safe helper for sending progress messages from WASM
/// This ensures all progress messages use the correct types
/// Now uses numeric enum values directly for better type safety
pub fn send_progress_message(
    message_type: ProgressMessageType,
    step: ProgressStep,
    message: &str,
    data: Option<&str>,
) {
    crate::send_progress_message(
        message_type as u32,
        step as u32,
        message,
        data.unwrap_or("{}"),
    );
}

/// Type-safe helper for sending completion messages from WASM
pub fn send_completion_message(
    message_type: ProgressMessageType,
    step: ProgressStep,
    message: &str,
    data: Option<&str>,
) {
    // Completion messages have the same structure as progress, just different status
    crate::send_progress_message(
        message_type as u32,
        step as u32,
        message,
        data.unwrap_or("{}"),
    );
}

/// Type-safe helper for sending error messages from WASM
pub fn send_error_message(
    message_type: ProgressMessageType,
    step: ProgressStep,
    message: &str,
    error: &str,
) {
    let error_data = serde_json::json!({ "error": error }).to_string();
    crate::send_progress_message(
        message_type as u32,
        step as u32,
        message,
        &error_data,
    );
}

// === DEBUGGING HELPERS ===
// Convert numeric enum values to readable strings for debugging
// This makes Rust logs easier to read when dealing with numeric enum values

/// Convert ProgressMessageType enum to readable string for debugging
pub fn progress_message_type_name(message_type: ProgressMessageType) -> &'static str {
    match message_type {
        ProgressMessageType::VerificationProgress => "VERIFICATION_PROGRESS",     // 12
        ProgressMessageType::VerificationComplete => "VERIFICATION_COMPLETE",     // 13
        ProgressMessageType::SigningProgress => "SIGNING_PROGRESS",               // 14
        ProgressMessageType::SigningComplete => "SIGNING_COMPLETE",               // 15
        ProgressMessageType::RegistrationProgress => "REGISTRATION_PROGRESS",     // 16
        ProgressMessageType::RegistrationComplete => "REGISTRATION_COMPLETE",     // 17
    }
}

/// Convert ProgressStep enum to readable string for debugging
pub fn progress_step_name(step: ProgressStep) -> &'static str {
    match step {
        ProgressStep::Preparation => "preparation",                               // 20
        ProgressStep::ContractVerification => "contract-verification",            // 21
        ProgressStep::TransactionSigning => "transaction-signing",                // 22
        ProgressStep::VerificationComplete => "verification-complete",            // 23
        ProgressStep::SigningComplete => "signing-complete",                      // 24
        ProgressStep::Error => "error",                                           // 25
    }
}

/// Convert ProgressStatus enum to readable string for debugging
pub fn progress_status_name(status: ProgressStatus) -> &'static str {
    match status {
        ProgressStatus::Progress => "progress",
        ProgressStatus::Success => "success",
        ProgressStatus::Error => "error",
        ProgressStatus::__Invalid => "invalid",
    }
}

/// Enhanced logging helper that includes enum names for better debugging
pub fn log_progress_message(
    message_type: ProgressMessageType,
    step: ProgressStep,
    message: &str,
) {
    crate::log(&format!(
        "Progress: {} ({}) - {} ({}) - {}",
        progress_message_type_name(message_type),
        message_type as u32,
        progress_step_name(step),
        step as u32,
        message
    ));
}