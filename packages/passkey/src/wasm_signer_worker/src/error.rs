use wasm_bindgen::JsValue;
use std::fmt;

// Custom error type for KDF operations
#[derive(Debug)]
pub enum KdfError {
    JsonParseError(String),
    Base64DecodeError(String),
    InvalidClientData,
    MissingField(&'static str),
    HkdfError,
    InvalidOperationContext,
    InvalidInput(String),
    EncryptionError(String),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KdfError::JsonParseError(e) => write!(f, "JSON parse error: {}", e),
            KdfError::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            KdfError::InvalidClientData => write!(f, "Invalid client data"),
            KdfError::MissingField(field) => write!(f, "Missing field: {}", field),
            KdfError::HkdfError => write!(f, "HKDF operation failed"),
            KdfError::InvalidOperationContext => write!(f, "Invalid operation context"),
            KdfError::InvalidInput(e) => write!(f, "Invalid input: {}", e),
            KdfError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
        }
    }
}

impl From<KdfError> for JsValue {
    fn from(err: KdfError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}