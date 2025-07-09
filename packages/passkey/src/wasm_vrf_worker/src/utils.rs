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