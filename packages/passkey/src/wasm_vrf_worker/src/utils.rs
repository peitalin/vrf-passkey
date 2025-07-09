/// Utility functions and helpers for the VRF worker
///
/// This module provides common functionality used throughout the VRF worker,
/// including validation, encoding/decoding, and other helper functions.

use crate::types::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE};

// === BASE64 UTILITIES ===

/// Base64 URL encode bytes
pub fn base64_url_encode(bytes: &[u8]) -> String {
    BASE64_URL_ENGINE.encode(bytes)
}

/// Base64 URL decode string
pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_ENGINE.decode(s)
}

// === RESPONSE HELPERS ===

/// Create a standardized error response
pub fn create_error_response(message_id: Option<String>, error: String) -> VRFWorkerResponse {
    VRFWorkerResponse {
        id: message_id,
        success: false,
        data: None,
        error: Some(error),
    }
}

/// Create a standardized success response
pub fn create_success_response(message_id: Option<String>, data: Option<serde_json::Value>) -> VRFWorkerResponse {
    VRFWorkerResponse {
        id: message_id,
        success: true,
        data,
        error: None,
    }
}