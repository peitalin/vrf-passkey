use wasm_bindgen::prelude::*;
use web_sys::console;
use js_sys::{JSON, Date};
use std::cell::RefCell;
use std::rc::Rc;

// VRF and crypto imports following the contract test pattern
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
use vrf_wasm::traits::WasmRngFromSeed;
use rand_core::SeedableRng;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use hkdf::Hkdf;
use getrandom::getrandom;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE};
use zeroize::ZeroizeOnDrop;

// Import modules
mod config;
mod errors;
mod types;
mod utils;
mod manager;
mod handlers;

#[cfg(test)]
mod tests;

// Re-export types and utilities
pub use types::*;
pub use utils::*;
pub use manager::*;
use handlers::*;
use config::*;
use errors::{VrfWorkerError, VrfResult, HkdfError, AesError, SerializationError};

// Set up panic hook for better error messages
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

// === GLOBAL STATE ===

thread_local! {
    static VRF_MANAGER: Rc<RefCell<VRFKeyManager>> = Rc::new(RefCell::new(VRFKeyManager::new()));
}

// === WASM EXPORTS ===

#[wasm_bindgen]
pub fn handle_message(message: JsValue) -> Result<JsValue, JsValue> {
    // Convert JsValue to JSON string first, then parse
    let message_str = JSON::stringify(&message)
        .map_err(|_e| JsValue::from_str("Failed to stringify message"))?;
    let message_str = message_str.as_string()
        .ok_or_else(|| JsValue::from_str("Message is not a string"))?;

    let message: VRFWorkerMessage = serde_json::from_str(&message_str)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse message: {}", e)))?;

    web_sys::console::log_1(&format!("VRF WASM Web Worker: Received message - {}", message.msg_type).into());

    let response = VRF_MANAGER.with(|manager| {
        match message.msg_type.as_str() {
            "PING" => handle_ping(message.id),
            "UNLOCK_VRF_KEYPAIR" => handle_unlock_vrf_keypair(manager, message.id, message.data),
            "GENERATE_VRF_CHALLENGE" => handle_generate_vrf_challenge(manager, message.id, message.data),
            "GENERATE_VRF_KEYPAIR_BOOTSTRAP" => handle_generate_vrf_keypair_bootstrap(manager, message.id, message.data),
            "ENCRYPT_VRF_KEYPAIR_WITH_PRF" => handle_encrypt_vrf_keypair_with_prf(manager, message.id, message.data),
            "CHECK_VRF_STATUS" => handle_check_vrf_status(manager, message.id),
            "LOGOUT" => handle_logout(manager, message.id),
            "DERIVE_VRF_KEYPAIR_FROM_PRF" => handle_derive_vrf_keypair_from_prf(manager, message.id, message.data),
            _ => handle_unknown_message(message.msg_type, message.id),
        }
    });

    // Convert response to JsValue
    let response_json = serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {}", e)))?;

    JSON::parse(&response_json)
        .map_err(|_e| JsValue::from_str("Failed to parse response JSON"))
}