use crate::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE};

/// Base64 URL encode bytes
pub fn base64_url_encode(bytes: &[u8]) -> String {
    BASE64_URL_ENGINE.encode(bytes)
}

/// Base64 URL decode string
pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_ENGINE.decode(s)
}

/// Process PRF input - handles both Vec<u8> (from ArrayBuffer) and String (base64url)
/// This centralizes PRF processing logic and makes the TypeScript interface cleaner
pub fn process_prf_input(prf_input: &serde_json::Value) -> Result<Vec<u8>, String> {
    match prf_input {
        // Case 1: Array of numbers (from ArrayBuffer via toWasmByteArray)
        serde_json::Value::Array(arr) => {
            let bytes: Result<Vec<u8>, _> = arr.iter()
                .map(|v| v.as_u64().map(|n| n as u8).ok_or("Invalid byte value"))
                .collect();
            bytes.map_err(|e| format!("Failed to convert array to bytes: {}", e))
        },

        // Case 2: Base64url string (direct from credential)
        serde_json::Value::String(s) => {
            base64_url_decode(s).map_err(|e| format!("Failed to decode base64url string: {}", e))
        },

        _ => Err("PRF input must be either an array of numbers or a base64url string".to_string())
    }
}

/// Create VRF worker response with error
pub fn create_error_response(message_id: Option<String>, error: String) -> VRFWorkerResponse {
    VRFWorkerResponse {
        id: message_id,
        success: false,
        data: None,
        error: Some(error),
    }
}

/// Create VRF worker response with success data
pub fn create_success_response(message_id: Option<String>, data: Option<serde_json::Value>) -> VRFWorkerResponse {
    VRFWorkerResponse {
        id: message_id,
        success: true,
        data,
        error: None,
    }
}