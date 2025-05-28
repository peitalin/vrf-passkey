mod error;
use error::KdfError;

use wasm_bindgen::prelude::*;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    fn warn(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn error(s: &str);
}

#[cfg(target_arch = "wasm32")]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! console_log {
    ($($t:tt)*) => (eprintln!("[LOG] {}", format_args!($($t)*)))
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// Struct for parsing client data JSON
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ClientDataForKdf {
    challenge: String,
    #[allow(dead_code)]
    origin: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    ceremony_type: String,
}

// Struct for WebAuthn response (registration)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct WebAuthnRegistrationResponse {
    client_data_json: String,
    attestation_object: String,
}

// Struct for WebAuthn response (authentication)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct WebAuthnAuthenticationResponse {
    client_data_json: String,
    signature: String,
    #[allow(dead_code)]
    authenticator_data: String,
    #[allow(dead_code)]
    user_handle: Option<String>,
}


// Helper function for base64url decoding
fn base64_url_decode(input: &str) -> Result<Vec<u8>, KdfError> {
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|e| KdfError::Base64DecodeError(format!("{:?}", e)))
}

// Operation context for determining salt
enum OperationContext {
    Registration,
    Authentication,
}

impl OperationContext {
    fn from_str(s: &str) -> Result<Self, KdfError> {
        match s {
            "registration" => Ok(OperationContext::Registration),
            "authentication" => Ok(OperationContext::Authentication),
            _ => Err(KdfError::InvalidOperationContext),
        }
    }

    fn get_salt(&self) -> &'static [u8] {
        match self {
            OperationContext::Registration => b"webauthn.kdf.registration.v1",
            OperationContext::Authentication => b"webauthn.kdf.authentication.v1",
        }
    }
}


// Extract and decode challenge from client data
fn extract_challenge(client_data_json: &str) -> Result<Vec<u8>, KdfError> {
    // Base64url decode clientDataJSON
    let client_data_bytes = base64_url_decode(client_data_json)?;

    // Parse the inner JSON
    let client_data_str = std::str::from_utf8(&client_data_bytes)
        .map_err(|_| KdfError::InvalidClientData)?;

    let client_data: ClientDataForKdf = serde_json::from_str(client_data_str)
        .map_err(|e| KdfError::JsonParseError(e.to_string()))?;

    // Base64url decode the challenge
    base64_url_decode(&client_data.challenge)
}

// Select Input Key Material (IKM) based on operation type
fn select_ikm(context: &OperationContext, response_json: &str) -> Result<Vec<u8>, KdfError> {
    match context {
        OperationContext::Registration => {
            let response: WebAuthnRegistrationResponse = serde_json::from_str(response_json)
                .map_err(|e| KdfError::JsonParseError(e.to_string()))?;

            // For registration: base64url decode attestationObject, then SHA256 hash it
            let attestation_bytes = base64_url_decode(&response.attestation_object)?;

            let mut hasher = Sha256::new();
            hasher.update(&attestation_bytes);
            Ok(hasher.finalize().to_vec())
        }
        OperationContext::Authentication => {
            let response: WebAuthnAuthenticationResponse = serde_json::from_str(response_json)
                .map_err(|e| KdfError::JsonParseError(e.to_string()))?;

            // For authentication: base64url decode signature
            base64_url_decode(&response.signature)
        }
    }
}

// Perform HKDF-SHA256 operation
fn perform_hkdf(context: &OperationContext, ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, KdfError> {
    let salt = context.get_salt();

    // Create HKDF instance
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    // Expand to desired length
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| KdfError::HkdfError)?;

    Ok(okm)
}

// Core KDF function without wasm_bindgen attribute for testing
pub fn derive_encryption_key_core(
    js_webauthn_inner_response_json_str: &str,
    operation_context_str: &str,
) -> Result<Vec<u8>, KdfError> {
    console_log!("RUST: Deriving encryption key for {}", operation_context_str);

    // Parse operation context
    let context = OperationContext::from_str(operation_context_str)?;

    // Extract client_data_json field to get challenge
    let client_data_json = match &context {
        OperationContext::Registration => {
            let response: WebAuthnRegistrationResponse = serde_json::from_str(js_webauthn_inner_response_json_str)
                .map_err(|e| KdfError::JsonParseError(e.to_string()))?;
            response.client_data_json
        }
        OperationContext::Authentication => {
            let response: WebAuthnAuthenticationResponse = serde_json::from_str(js_webauthn_inner_response_json_str)
                .map_err(|e| KdfError::JsonParseError(e.to_string()))?;
            response.client_data_json
        }
    };

    // Extract challenge bytes
    let challenge_bytes = extract_challenge(&client_data_json)?;

    // Select IKM based on operation type
    let ikm = select_ikm(&context, js_webauthn_inner_response_json_str)?;

    // Perform HKDF with challenge as info
    let key = perform_hkdf(&context, &ikm, &challenge_bytes, 32)?;

    console_log!("RUST: Successfully derived 32-byte encryption key");
    Ok(key)
}

#[wasm_bindgen]
pub fn derive_encryption_key_from_webauthn_js(
    js_webauthn_inner_response_json_str: &str,
    operation_context_str: &str,
) -> Result<Vec<u8>, JsValue> {
    derive_encryption_key_core(js_webauthn_inner_response_json_str, operation_context_str)
        .map_err(|e| JsValue::from(e))
}

#[wasm_bindgen]
pub fn encrypt_data_aes_gcm(plain_text_data_str: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Encryption key must be 32 bytes for AES-256-GCM."));
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let mut iv_bytes = [0u8; 12];
    getrandom::getrandom(&mut iv_bytes).map_err(|e| JsValue::from_str(&format!("Failed to generate IV: {}", e)))?;
    let nonce = GenericArray::from_slice(&iv_bytes);

    let ciphertext = cipher.encrypt(nonce, plain_text_data_str.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

    let result = format!(
        r#"{{"encrypted_data_b64u": "{}", "iv_b64u": "{}"}}"#,
        Base64UrlUnpadded::encode_string(&ciphertext),
        Base64UrlUnpadded::encode_string(&iv_bytes)
    );
    Ok(result)
}

#[wasm_bindgen]
pub fn decrypt_data_aes_gcm(encrypted_data_b64u: &str, iv_b64u: &str, key_bytes: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Decryption key must be 32 bytes for AES-256-GCM."));
    }
    let key_ga = GenericArray::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key_ga);

    let iv_bytes = Base64UrlUnpadded::decode_vec(iv_b64u)
        .map_err(|e| JsValue::from_str(&format!("Base64UrlUnpadded decode error for IV: {}", e)))?;
    if iv_bytes.len() != 12 {
        return Err(JsValue::from_str("Decryption IV must be 12 bytes."));
    }
    let nonce = GenericArray::from_slice(&iv_bytes);

    let encrypted_data = Base64UrlUnpadded::decode_vec(encrypted_data_b64u)
        .map_err(|e| JsValue::from_str(&format!("Base64UrlUnpadded decode error for encrypted data: {}", e)))?;

    let decrypted_bytes = cipher.decrypt(nonce, encrypted_data.as_slice())
        .map_err(|e| JsValue::from_str(&format!("Decryption error: {}", e)))?;

    String::from_utf8(decrypted_bytes).map_err(|e| JsValue::from_str(&format!("UTF-8 decoding error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_kdf() {
        // Test data with properly encoded clientDataJSON
        // The challenge "dGVzdC1jaGFsbGVuZ2U" decodes to "test-challenge"
        // The full clientDataJSON decodes to: {"type":"webauthn.create","challenge":"dGVzdC1jaGFsbGVuZ2U","origin":"https://example.com"}
        let registration_json = r#"{
            "clientDataJson": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ",
            "attestationObject": "VGVzdCBhdHRlc3RhdGlvbiBvYmplY3Q"
        }"#;

        let result = derive_encryption_key_core(registration_json, "registration");
        match &result {
            Err(e) => eprintln!("Error: {:?}", e),
            Ok(_) => {}
        }
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);

        // Key should be deterministic for same input
        let key2 = derive_encryption_key_core(registration_json, "registration").unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_authentication_kdf() {
        // The challenge "dGVzdC1jaGFsbGVuZ2U" decodes to "test-challenge"
        // The full clientDataJSON decodes to: {"type":"webauthn.get","challenge":"dGVzdC1jaGFsbGVuZ2U","origin":"https://example.com"}
        let auth_json = r#"{
            "clientDataJson": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ",
            "signature": "VGVzdCBzaWduYXR1cmU",
            "authenticatorData": "VGVzdCBhdXRoZW50aWNhdG9yIGRhdGE"
        }"#;

        let result = derive_encryption_key_core(auth_json, "authentication");
        match &result {
            Err(e) => eprintln!("Error: {:?}", e),
            Ok(_) => {}
        }
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_different_contexts_produce_different_keys() {
        // Same base data but will be processed differently based on context
        let reg_json = r#"{
            "clientDataJson": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ",
            "attestationObject": "VGVzdCBhdHRlc3RhdGlvbiBvYmplY3Q"
        }"#;

        let auth_json = r#"{
            "clientDataJson": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ",
            "signature": "VGVzdCBzaWduYXR1cmU",
            "authenticatorData": "VGVzdCBhdXRoZW50aWNhdG9yIGRhdGE"
        }"#;

        let reg_key = derive_encryption_key_core(reg_json, "registration").unwrap();
        let auth_key = derive_encryption_key_core(auth_json, "authentication").unwrap();

        // Keys should be different due to different salts and IKM
        assert_ne!(reg_key, auth_key);
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let key = vec![0u8; 32]; // Test key
        let plaintext = "Hello, WebAuthn KDF!";

        let encrypted = encrypt_data_aes_gcm(plaintext, &key).unwrap();

        // Parse the JSON result
        let encrypted_obj: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
        let encrypted_data = encrypted_obj["encrypted_data_b64u"].as_str().unwrap();
        let iv = encrypted_obj["iv_b64u"].as_str().unwrap();

        let decrypted = decrypt_data_aes_gcm(encrypted_data, iv, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_operation_context() {
        let json = r#"{
            "clientDataJson": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ",
            "attestationObject": "VGVzdCBhdHRlc3RhdGlvbiBvYmplY3Q"
        }"#;

        let result = derive_encryption_key_core(json, "invalid_context");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_encoding() {
        // Test that our test data is properly encoded
        let client_data_json = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ";
        let decoded = base64_url_decode(client_data_json).unwrap();
        let decoded_str = std::str::from_utf8(&decoded).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(decoded_str).unwrap();

        assert_eq!(parsed["type"], "webauthn.create");
        assert_eq!(parsed["challenge"], "dGVzdC1jaGFsbGVuZ2U");
        assert_eq!(parsed["origin"], "https://example.com");

        // Verify the challenge itself is valid base64url
        let challenge_decoded = base64_url_decode(parsed["challenge"].as_str().unwrap()).unwrap();
        let challenge_str = std::str::from_utf8(&challenge_decoded).unwrap();
        assert_eq!(challenge_str, "test-challenge");
    }
}
