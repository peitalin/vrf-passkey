/// Utility functions and helpers for the VRF worker
///
/// This module provides common functionality used throughout the VRF worker,
/// including validation, encoding/decoding, and other helper functions.

use crate::types::*;
use base64ct::{Base64UrlUnpadded, Encoding};

// === BASE64 UTILITIES ===

/// Base64 URL encode bytes
pub fn base64_url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Base64 URL decode string
pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(s)
        .map_err(|e| format!("Base64 decode error: {}", e))
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