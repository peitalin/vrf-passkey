use wasm_bindgen::prelude::*;
use web_sys::console;
use js_sys::{JSON, Date};
use serde::{Deserialize, Serialize};
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

// Set up panic hook for better error messages
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

// === GLOBAL STATE ===

thread_local! {
    static VRF_MANAGER: Rc<RefCell<VRFKeyManager>> = Rc::new(RefCell::new(VRFKeyManager::new()));
}

// === TYPE DEFINITIONS ===

#[derive(Serialize, Deserialize)]
pub struct VRFKeypairData {
    /// Bincode-serialized ECVRFKeyPair (includes both private key and public key)
    pub keypair_bytes: Vec<u8>,
    /// Base64url-encoded public key for convenience
    pub public_key_base64: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVRFData {
    pub encrypted_vrf_data_b64u: String,
    pub aes_gcm_nonce_b64u: String,
}

#[derive(Serialize, Deserialize)]
pub struct VRFInputData {
    pub user_id: String,
    pub rp_id: String,
    pub session_id: String,
    pub block_height: u64,
    pub block_hash: Vec<u8>,
    pub timestamp: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct VRFChallengeData {
    #[serde(rename = "vrfInput")]
    pub vrf_input: String,
    #[serde(rename = "vrfOutput")]
    pub vrf_output: String,
    #[serde(rename = "vrfProof")]
    pub vrf_proof: String,
    #[serde(rename = "vrfPublicKey")]
    pub vrf_public_key: String,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "blockHeight")]
    pub block_height: u64,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct VRFWorkerMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub id: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
pub struct VRFWorkerResponse {
    pub id: Option<String>,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

// === SECURE VRF KEYPAIR WRAPPER ===

/// Secure VRF keypair wrapper with automatic memory zeroization
#[derive(ZeroizeOnDrop)]
pub struct SecureVRFKeyPair {
    keypair: ECVRFKeyPair,
}

impl SecureVRFKeyPair {
    pub fn new(keypair: ECVRFKeyPair) -> Self {
        Self { keypair }
    }

    pub fn inner(&self) -> &ECVRFKeyPair {
        &self.keypair
    }
}

// === VRF KEY MANAGER ===

pub struct VRFKeyManager {
    vrf_keypair: Option<SecureVRFKeyPair>,
    session_active: bool,
    session_start_time: f64,
}

impl VRFKeyManager {
    pub fn new() -> Self {
        console::log_1(&"VRF WASM Web Worker: VRFKeyManager ready (no user session active)".into());
        Self {
            vrf_keypair: None,
            session_active: false,
            session_start_time: 0.0,
        }
    }

    pub fn generate_vrf_keypair_bootstrap(
        &mut self,
        vrf_input_params: Option<VRFInputData>,
    ) -> Result<VrfKeypairBootstrapResponse, String> {
        console::log_1(&"VRF WASM Web Worker: Generating VRF keypair for bootstrapping".into());
        console::log_1(&"📝 VRF keypair will be stored in memory unencrypted until PRF encryption".into());

        // Clear any existing keypair (automatic zeroization via ZeroizeOnDrop)
        self.vrf_keypair.take();

        // Generate VRF keypair with cryptographically secure randomness
        let vrf_keypair = self.generate_vrf_keypair()?;

        // Get public key bytes for response
        let vrf_public_key_bytes = bincode::serialize(&vrf_keypair.pk)
            .map_err(|e| format!("Failed to serialize VRF public key: {:?}", e))?;
        let vrf_public_key_b64 = base64_url_encode(&vrf_public_key_bytes);

        // Store VRF keypair in memory (unencrypted)
        self.vrf_keypair = Some(SecureVRFKeyPair::new(vrf_keypair));
        self.session_active = true;
        self.session_start_time = Date::now();

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair generated and stored in memory".into());
        console::log_1(&format!("📝 VRF Public Key: {}...", &vrf_public_key_b64[..20.min(vrf_public_key_b64.len())]).into());

        let mut result = VrfKeypairBootstrapResponse {
            vrf_public_key: vrf_public_key_b64,
            vrf_challenge_data: None,
        };

        // Generate VRF challenge if input parameters provided
        if let Some(vrf_input) = vrf_input_params {
            console::log_1(&"VRF WASM Web Worker: Generating VRF challenge using bootstrapped keypair".into());

            let vrf_keypair = self.vrf_keypair.as_ref().unwrap().inner();
            let challenge_result = self.generate_vrf_challenge_with_keypair(vrf_keypair, vrf_input)?;
            result.vrf_challenge_data = Some(challenge_result);

            console::log_1(&"✅ VRF WASM Web Worker: VRF challenge generated successfully".into());
        }

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair bootstrap completed".into());
        Ok(result)
    }

    /// Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
    /// This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
    pub fn encrypt_vrf_keypair_with_prf(
        &mut self,
        expected_public_key: String,
        prf_key: Vec<u8>,
    ) -> Result<EncryptedVrfKeypairResponse, String> {
        console::log_1(&"VRF WASM Web Worker: Encrypting VRF keypair with PRF output".into());
        console::log_1(&format!("📝 Expected public key: {}...", &expected_public_key[..20.min(expected_public_key.len())]).into());

        // Verify we have an active VRF keypair in memory
        if !self.session_active || self.vrf_keypair.is_none() {
            return Err("No VRF keypair in memory - please generate keypair first".to_string());
        }

        // Get the VRF keypair from memory and extract its public key
        let vrf_keypair = self.vrf_keypair.as_ref().unwrap().inner();
        let stored_public_key_bytes = bincode::serialize(&vrf_keypair.pk)
            .map_err(|e| format!("Failed to serialize stored VRF public key: {:?}", e))?;
        let stored_public_key = base64_url_encode(&stored_public_key_bytes);

        // Verify the public key matches what's expected
        if stored_public_key != expected_public_key {
            return Err(format!(
                "VRF public key mismatch - expected: {}..., stored: {}...",
                &expected_public_key[..20.min(expected_public_key.len())],
                &stored_public_key[..20.min(stored_public_key.len())]
            ));
        }

        console::log_1(&"✅ VRF WASM Web Worker: Public key verification successful".into());

        // Encrypt the VRF keypair
        let (vrf_public_key, encrypted_vrf_keypair) = self.encrypt_vrf_keypair_data(vrf_keypair, &prf_key)?;

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair encrypted with PRF output".into());
        console::log_1(&"📝 VRF keypair ready for persistent storage".into());

        Ok(EncryptedVrfKeypairResponse {
            vrf_public_key,
            encrypted_vrf_keypair,
        })
    }

    pub fn unlock_vrf_keypair(
        &mut self,
        near_account_id: String,
        encrypted_vrf_data: EncryptedVRFData,
        prf_key: Vec<u8>,
    ) -> Result<(), String> {
        console::log_1(&format!("VRF WASM Web Worker: Unlocking VRF keypair for {}", near_account_id).into());

        // Clear any existing keypair (automatic zeroization via ZeroizeOnDrop)
        self.vrf_keypair.take();

        // Decrypt VRF keypair using PRF-derived AES key
        let decrypted_keypair = self.decrypt_vrf_keypair(encrypted_vrf_data, prf_key)?;

        // Wrap in secure container for automatic zeroization
        self.vrf_keypair = Some(SecureVRFKeyPair::new(decrypted_keypair));
        self.session_active = true;
        self.session_start_time = Date::now();

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair unlocked successfully".into());
        console::log_1(&format!("VRF WASM Web Worker: Session active for {}", near_account_id).into());

        Ok(())
    }

    pub fn generate_vrf_challenge(&self, input_data: VRFInputData) -> Result<VRFChallengeData, String> {
        if !self.session_active || self.vrf_keypair.is_none() {
            return Err("VRF keypair not unlocked - please login first".to_string());
        }

        console::log_1(&"VRF WASM Web Worker: Generating VRF challenge".into());
        console::log_1(&format!("  - User ID: {}", input_data.user_id).into());
        console::log_1(&format!("  - RP ID: {}", input_data.rp_id).into());
        console::log_1(&format!("  - Session ID: {}", input_data.session_id).into());
        console::log_1(&format!("  - Block Height: {}", input_data.block_height).into());

        let vrf_keypair = self.vrf_keypair.as_ref().unwrap().inner();

        // Construct VRF input according to specification from the contract test
        let domain_separator = b"web_authn_challenge_v1";
        let user_id_bytes = input_data.user_id.as_bytes();
        let rp_id_bytes = input_data.rp_id.as_bytes();
        let session_id_bytes = input_data.session_id.as_bytes();
        let block_height_bytes = input_data.block_height.to_le_bytes();
        let timestamp = input_data.timestamp.unwrap_or_else(|| js_sys::Date::now() as u64);
        let timestamp_bytes = timestamp.to_le_bytes();

        // Concatenate all input components following the test pattern
        let mut vrf_input_data = Vec::new();
        vrf_input_data.extend_from_slice(domain_separator);
        vrf_input_data.extend_from_slice(user_id_bytes);
        vrf_input_data.extend_from_slice(rp_id_bytes);
        vrf_input_data.extend_from_slice(session_id_bytes);
        vrf_input_data.extend_from_slice(&block_height_bytes);
        vrf_input_data.extend_from_slice(&input_data.block_hash);
        vrf_input_data.extend_from_slice(&timestamp_bytes);

        // Hash the input data (VRF input should be hashed)
        let vrf_input = Sha256::digest(&vrf_input_data).to_vec();

        // Generate VRF proof and output using the proper vrf-wasm API
        let proof = vrf_keypair.prove(&vrf_input);
        let vrf_output = proof.to_hash().to_vec();

        let result = VRFChallengeData {
            vrf_input: base64_url_encode(&vrf_input),
            vrf_output: base64_url_encode(&vrf_output),
            vrf_proof: base64_url_encode(&bincode::serialize(&proof).unwrap()),
            vrf_public_key: base64_url_encode(&bincode::serialize(&vrf_keypair.pk).unwrap()),
            rp_id: input_data.rp_id,
            block_height: input_data.block_height,
            block_hash: base64_url_encode(&input_data.block_hash),
        };

        console::log_1(&"✅ VRF WASM Web Worker: VRF challenge generated successfully".into());
        console::log_1(&format!("  - VRF Input: {}...", &result.vrf_input[..20.min(result.vrf_input.len())]).into());
        console::log_1(&format!("  - VRF Output: {}...", &result.vrf_output[..20.min(result.vrf_output.len())]).into());

        Ok(result)
    }

    /// Generate VRF challenge using a specific keypair (can be in-memory or provided)
    pub fn generate_vrf_challenge_with_keypair(&self, vrf_keypair: &ECVRFKeyPair, input_data: VRFInputData) -> Result<VRFChallengeData, String> {
        console::log_1(&"VRF WASM Web Worker: Generating VRF challenge using provided keypair".into());
        console::log_1(&format!("  - User ID: {}", input_data.user_id).into());
        console::log_1(&format!("  - RP ID: {}", input_data.rp_id).into());
        console::log_1(&format!("  - Session ID: {}", input_data.session_id).into());
        console::log_1(&format!("  - Block Height: {}", input_data.block_height).into());

        // Construct VRF input according to specification from the contract test
        let domain_separator = b"web_authn_challenge_v1";
        let user_id_bytes = input_data.user_id.as_bytes();
        let rp_id_bytes = input_data.rp_id.as_bytes();
        let session_id_bytes = input_data.session_id.as_bytes();
        let block_height_bytes = input_data.block_height.to_le_bytes();
        let timestamp = input_data.timestamp.unwrap_or_else(|| js_sys::Date::now() as u64);
        let timestamp_bytes = timestamp.to_le_bytes();

        // Concatenate all input components following the test pattern
        let mut vrf_input_data = Vec::new();
        vrf_input_data.extend_from_slice(domain_separator);
        vrf_input_data.extend_from_slice(user_id_bytes);
        vrf_input_data.extend_from_slice(rp_id_bytes);
        vrf_input_data.extend_from_slice(session_id_bytes);
        vrf_input_data.extend_from_slice(&block_height_bytes);
        vrf_input_data.extend_from_slice(&input_data.block_hash);
        vrf_input_data.extend_from_slice(&timestamp_bytes);

        // Hash the input data (VRF input should be hashed)
        let vrf_input = Sha256::digest(&vrf_input_data).to_vec();

        // Generate VRF proof and output using the proper vrf-wasm API
        let proof = vrf_keypair.prove(&vrf_input);
        let vrf_output = proof.to_hash().to_vec();

        let result = VRFChallengeData {
            vrf_input: base64_url_encode(&vrf_input),
            vrf_output: base64_url_encode(&vrf_output),
            vrf_proof: base64_url_encode(&bincode::serialize(&proof).unwrap()),
            vrf_public_key: base64_url_encode(&bincode::serialize(&vrf_keypair.pk).unwrap()),
            rp_id: input_data.rp_id,
            block_height: input_data.block_height,
            block_hash: base64_url_encode(&input_data.block_hash),
        };

        console::log_1(&"✅ VRF WASM Web Worker: VRF challenge generated successfully using provided keypair".into());
        console::log_1(&format!("  - VRF Input: {}...", &result.vrf_input[..20.min(result.vrf_input.len())]).into());
        console::log_1(&format!("  - VRF Output: {}...", &result.vrf_output[..20.min(result.vrf_output.len())]).into());

        Ok(result)
    }

    pub fn get_vrf_status(&self) -> serde_json::Value {
        let session_duration = if self.session_active {
            Date::now() - self.session_start_time
        } else {
            0.0
        };

        serde_json::json!({
            "active": self.session_active,
            "sessionDuration": session_duration
        })
    }

    pub fn logout(&mut self) -> Result<(), String> {
        console::log_1(&"🚪 VRF WASM Web Worker: Logging out and securely clearing VRF keypair".into());

        // Clear VRF keypair (automatic zeroization via ZeroizeOnDrop)
        if self.vrf_keypair.take().is_some() {
            console::log_1(&"🔒 VRF WASM Web Worker: VRF keypair cleared with automatic zeroization".into());
        }

        // Clear session data
        self.session_active = false;
        self.session_start_time = 0.0;

        console::log_1(&"✅ VRF WASM Web Worker: Session cleared securely with automatic zeroization".into());
        Ok(())
    }

    fn decrypt_vrf_keypair(
        &self,
        encrypted_vrf_data: EncryptedVRFData,
        prf_key: Vec<u8>,
    ) -> Result<ECVRFKeyPair, String> {
        // Use HKDF-SHA256 to derive AES key from PRF key for better security
        console::log_1(&"VRF WASM Web Worker: Deriving AES key using HKDF-SHA256".into());

        let hk = Hkdf::<Sha256>::new(None, &prf_key);
        let mut aes_key = [0u8; 32];
        hk.expand(b"vrf-aes-key", &mut aes_key)
            .map_err(|_| "HKDF key derivation failed".to_string())?;

        // Decode encrypted data and IV
        let encrypted_data = base64_url_decode(&encrypted_vrf_data.encrypted_vrf_data_b64u)
            .map_err(|e| format!("Failed to decode encrypted data: {}", e))?;
        let iv_nonce_bytes = base64_url_decode(&encrypted_vrf_data.aes_gcm_nonce_b64u)
            .map_err(|e| format!("Failed to decode IV: {}", e))?;

        if iv_nonce_bytes.len() != 12 {
            return Err("Invalid IV length for AES-GCM".to_string());
        }

        // Decrypt the VRF keypair using derived AES key
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&iv_nonce_bytes);

        let decrypted_data = cipher
            .decrypt(nonce, encrypted_data.as_ref())
            .map_err(|e| format!("Failed to decrypt VRF keypair: {}", e))?;

        // Parse decrypted keypair data using bincode (not JSON)
        let keypair_data: VRFKeypairData = bincode::deserialize(&decrypted_data)
            .map_err(|e| format!("Failed to deserialize keypair data: {}", e))?;

        // Reconstruct ECVRFKeyPair from the stored bincode bytes
        // This preserves the exact original keypair without regeneration
        let keypair: ECVRFKeyPair = bincode::deserialize(&keypair_data.keypair_bytes)
            .map_err(|e| format!("Failed to deserialize VRF keypair: {}", e))?;

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair successfully restored from bincode".into());
        Ok(keypair)
    }

    /// Generate a new VRF keypair with cryptographically secure randomness
    fn generate_vrf_keypair(&self) -> Result<ECVRFKeyPair, String> {
        console::log_1(&"VRF WASM Web Worker: Generating VRF keypair with secure randomness".into());

        // Generate VRF keypair with cryptographically secure randomness
        let mut rng = WasmRngFromSeed::from_entropy();
        let vrf_keypair = ECVRFKeyPair::generate(&mut rng);

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair generated successfully".into());

        Ok(vrf_keypair)
    }

    /// Encrypt VRF keypair data using PRF-derived AES key
    fn encrypt_vrf_keypair_data(&self, vrf_keypair: &ECVRFKeyPair, prf_key: &[u8]) -> Result<(String, serde_json::Value), String> {
        console::log_1(&"VRF WASM Web Worker: Encrypting VRF keypair data".into());

        // Serialize the entire keypair using bincode for efficient, deterministic storage
        let vrf_keypair_bytes = bincode::serialize(vrf_keypair)
            .map_err(|e| format!("Failed to serialize VRF keypair with bincode: {:?}", e))?;

        // Get public key bytes for convenience
        let vrf_public_key_bytes = bincode::serialize(&vrf_keypair.pk)
            .map_err(|e| format!("Failed to serialize VRF public key: {:?}", e))?;

        // Create VRF keypair data structure
        let keypair_data = VRFKeypairData {
            keypair_bytes: vrf_keypair_bytes,
            public_key_base64: base64_url_encode(&vrf_public_key_bytes),
        };

        // Serialize the VRF keypair data using bincode
        let keypair_data_bytes = bincode::serialize(&keypair_data)
            .map_err(|e| format!("Failed to serialize VRF keypair data: {:?}", e))?;

        // Encrypt the VRF keypair data using AES-GCM
        let encrypted_keypair = self.encrypt_vrf_keypair(&keypair_data_bytes, prf_key)?;

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair encrypted successfully".into());

        Ok((base64_url_encode(&vrf_public_key_bytes), encrypted_keypair))
    }

    /// Enhanced VRF keypair generation with explicit control over memory storage and challenge generation
    ///
    /// @param prf_key - PRF output from WebAuthn ceremony for encryption
    /// @param vrf_input_params - Optional parameters to generate VRF challenge/proof
    /// @param save_in_memory - Whether to persist the generated VRF keypair in WASM worker memory
    pub fn generate_and_encrypt_vrf_keypair(
        &mut self,
        prf_key: Vec<u8>,
        vrf_input_params: Option<VRFInputData>,
        save_in_memory: bool
    ) -> Result<VrfKeypairWithChallengeResponse, String> {
        console::log_1(&format!("VRF WASM Web Worker: Generating VRF keypair - saveInMemory: {}, withChallenge: {}",
            save_in_memory, vrf_input_params.is_some()).into());

        // Generate VRF keypair once
        let vrf_keypair = self.generate_vrf_keypair()?;

        // Encrypt the VRF keypair
        let (vrf_public_key, encrypted_vrf_keypair) = self.encrypt_vrf_keypair_data(&vrf_keypair, &prf_key)?;

        console::log_1(&"✅ VRF WASM Web Worker: VRF keypair generation and encryption completed".into());

        let mut result = VrfKeypairWithChallengeResponse {
            vrf_public_key,
            encrypted_vrf_keypair,
            vrf_challenge_data: None,
        };

        // Store VRF keypair in memory if explicitly requested
        if save_in_memory {
            // Serialize keypair for storage and recreation (since ECVRFKeyPair doesn't implement Clone)
            let vrf_keypair_bytes = bincode::serialize(&vrf_keypair)
                .map_err(|e| format!("Failed to serialize VRF keypair for storage: {:?}", e))?;

            // Recreate keypair from serialized data for in-memory storage
            let vrf_keypair_for_storage: ECVRFKeyPair = bincode::deserialize(&vrf_keypair_bytes)
                .map_err(|e| format!("Failed to deserialize VRF keypair for storage: {:?}", e))?;

            // Store the VRF keypair in memory
            self.vrf_keypair = Some(SecureVRFKeyPair::new(vrf_keypair_for_storage));
            self.session_active = true;
            self.session_start_time = Date::now();

            console::log_1(&"✅ VRF WASM Web Worker: VRF keypair stored in memory".into());
        }

        // Generate VRF challenge if input parameters provided (regardless of save_in_memory flag)
        if let Some(vrf_input) = vrf_input_params {
            console::log_1(&"VRF WASM Web Worker: Generating VRF challenge".into());

            // Use the fresh keypair for challenge generation (consistent with the encrypted version)
            let challenge_result = self.generate_vrf_challenge_with_keypair(&vrf_keypair, vrf_input)?;
            result.vrf_challenge_data = Some(challenge_result);

            console::log_1(&"✅ VRF WASM Web Worker: VRF challenge generated successfully".into());
        }

        console::log_1(&"✅ VRF WASM Web Worker: Enhanced VRF keypair generation completed".into());

        Ok(result)
    }

    fn encrypt_vrf_keypair(&self, data: &[u8], key: &[u8]) -> Result<serde_json::Value, String> {
        console::log_1(&"VRF WASM Web Worker: Deriving AES key using HKDF-SHA256 for encryption".into());

        // Use HKDF-SHA256 to derive AES key from PRF key for better security
        let hk = Hkdf::<Sha256>::new(None, key);
        let mut aes_key = [0u8; 32];
        hk.expand(b"vrf-aes-key", &mut aes_key)
            .map_err(|_| "HKDF key derivation failed".to_string())?;

        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;

        // Generate cryptographically secure random IV/nonce
        let mut iv_nonce_bytes = [0u8; 12];
        getrandom(&mut iv_nonce_bytes)
            .map_err(|e| format!("Failed to generate secure IV: {}", e))?;
        let nonce = Nonce::from_slice(&iv_nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(serde_json::json!({
            "encrypted_vrf_data_b64u": base64_url_encode(&ciphertext),
            "aes_gcm_nonce_b64u": base64_url_encode(&iv_nonce_bytes)
        }))
    }
}

#[derive(Serialize, Deserialize)]
pub struct VrfKeypairResponse {
    pub vrf_public_key: String,
    pub encrypted_vrf_keypair: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct VrfKeypairWithChallengeResponse {
    pub vrf_public_key: String,
    pub encrypted_vrf_keypair: serde_json::Value,
    pub vrf_challenge_data: Option<VRFChallengeData>,
}

#[derive(Serialize, Deserialize)]
pub struct VrfKeypairBootstrapResponse {
    pub vrf_public_key: String,
    pub vrf_challenge_data: Option<VRFChallengeData>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVrfKeypairResponse {
    pub vrf_public_key: String,
    pub encrypted_vrf_keypair: serde_json::Value,
}

// === UTILITY FUNCTIONS ===

fn base64_url_encode(bytes: &[u8]) -> String {
    BASE64_URL_ENGINE.encode(bytes)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_ENGINE.decode(s)
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

    let response = match message.msg_type.as_str() {
        "PING" => VRFWorkerResponse {
            id: message.id,
            success: true,
            data: Some(serde_json::json!({
                "status": "alive",
                "timestamp": Date::now()
            })),
            error: None,
        },

        "UNLOCK_VRF_KEYPAIR" => {
            VRF_MANAGER.with(|manager| {
                match message.data {
                    Some(data) => {
                        let near_account_id = data["nearAccountId"].as_str()
                            .unwrap_or("");

                        // Debug: Log the received encrypted VRF data structure
                        console::log_1(&format!("VRF WASM: Received encryptedVrfData: {}",
                            serde_json::to_string_pretty(&data["encryptedVrfData"]).unwrap_or_else(|_| "failed to serialize".to_string())).into());

                        let encrypted_vrf_data_result = serde_json::from_value::<EncryptedVRFData>(data["encryptedVrfData"].clone());

                        // Debug: Log the parsing result
                        match &encrypted_vrf_data_result {
                            Ok(_) => console::log_1(&"VRF WASM: Successfully parsed EncryptedVRFData".into()),
                            Err(e) => console::log_1(&format!("VRF WASM: Failed to parse EncryptedVRFData: {}", e).into()),
                        }

                        let prf_key: Vec<u8> = data["prfKey"].as_array()
                            .unwrap_or(&vec![])
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();

                        if near_account_id.is_empty() {
                            VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some("Missing nearAccountId".to_string()),
                            }
                        } else if let Ok(encrypted_vrf_data) = encrypted_vrf_data_result {
                            let mut manager = manager.borrow_mut();
                            match manager.unlock_vrf_keypair(near_account_id.to_string(), encrypted_vrf_data, prf_key) {
                                Ok(_) => VRFWorkerResponse {
                                    id: message.id,
                                    success: true,
                                    data: None,
                                    error: None,
                                },
                                Err(e) => VRFWorkerResponse {
                                    id: message.id,
                                    success: false,
                                    data: None,
                                    error: Some(e),
                                }
                            }
                        } else {
                            VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some("Failed to parse encrypted VRF data".to_string()),
                            }
                        }
                    }
                    None => VRFWorkerResponse {
                        id: message.id,
                        success: false,
                        data: None,
                        error: Some("Missing unlock data".to_string()),
                    }
                }
            })
        }

        "GENERATE_VRF_CHALLENGE" => {
            VRF_MANAGER.with(|manager| {
                match message.data {
                    Some(data) => {
                        match serde_json::from_value::<VRFInputData>(data) {
                            Ok(input_data) => {
                                let manager = manager.borrow();
                                match manager.generate_vrf_challenge(input_data) {
                                    Ok(challenge_data) => VRFWorkerResponse {
                                        id: message.id,
                                        success: true,
                                        data: Some(serde_json::to_value(&challenge_data).unwrap()),
                                        error: None,
                                    },
                                    Err(e) => VRFWorkerResponse {
                                        id: message.id,
                                        success: false,
                                        data: None,
                                        error: Some(e),
                                    }
                                }
                            }
                            Err(e) => VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some(format!("Failed to parse VRF input data: {}", e)),
                            }
                        }
                    }
                    None => VRFWorkerResponse {
                        id: message.id,
                        success: false,
                        data: None,
                        error: Some("Missing VRF input data".to_string()),
                    }
                }
            })
        }

        "GENERATE_VRF_KEYPAIR" => {
            VRF_MANAGER.with(|manager| {
                match message.data {
                    Some(data) => {
                        let prf_key: Vec<u8> = data["prfKey"].as_array()
                            .unwrap_or(&vec![])
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();

                        if prf_key.is_empty() {
                            VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some("Missing or invalid PRF key".to_string()),
                            }
                        } else {
                            // Get explicit saveInMemory flag
                            let save_in_memory = data.get("saveInMemory")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            // Check if VRF input parameters are provided for challenge generation
                            let vrf_input_params = data.get("vrfInputParams")
                                .and_then(|params| serde_json::from_value::<VRFInputData>(params.clone()).ok());

                            let mut manager = manager.borrow_mut();

                            console::log_1(&format!("VRF WASM Web Worker: Generating VRF keypair - saveInMemory: {}, withChallenge: {}",
                                save_in_memory, vrf_input_params.is_some()).into());

                            match manager.generate_and_encrypt_vrf_keypair(
                                prf_key,
                                vrf_input_params,
                                save_in_memory
                            ) {
                                Ok(keypair_data) => {
                                    // Structure response to match expected format
                                    let response_data = serde_json::json!({
                                        "vrf_public_key": keypair_data.vrf_public_key,
                                        "encrypted_vrf_keypair": keypair_data.encrypted_vrf_keypair,
                                        "vrf_challenge_data": keypair_data.vrf_challenge_data
                                    });

                                    VRFWorkerResponse {
                                        id: message.id,
                                        success: true,
                                        data: Some(response_data),
                                        error: None,
                                    }
                                },
                                Err(e) => VRFWorkerResponse {
                                    id: message.id,
                                    success: false,
                                    data: None,
                                    error: Some(e),
                                }
                            }
                        }
                    }
                    None => VRFWorkerResponse {
                        id: message.id,
                        success: false,
                        data: None,
                        error: Some("Missing VRF keypair generation data".to_string()),
                    }
                }
            })
        }

        "GENERATE_VRF_KEYPAIR_BOOTSTRAP" => {
            VRF_MANAGER.with(|manager| {
                match message.data {
                    Some(data) => {
                        // Check if VRF input parameters are provided for challenge generation
                        let vrf_input_params = data.get("vrfInputParams")
                            .and_then(|params| serde_json::from_value::<VRFInputData>(params.clone()).ok());

                        let mut manager = manager.borrow_mut();

                        console::log_1(&format!("VRF WASM Web Worker: Generating bootstrap VRF keypair - withChallenge: {}",
                            vrf_input_params.is_some()).into());

                        match manager.generate_vrf_keypair_bootstrap(vrf_input_params) {
                            Ok(bootstrap_data) => {
                                // Structure response to match expected format
                                let response_data = serde_json::json!({
                                    "vrf_public_key": bootstrap_data.vrf_public_key,
                                    "vrf_challenge_data": bootstrap_data.vrf_challenge_data
                                });

                                VRFWorkerResponse {
                                    id: message.id,
                                    success: true,
                                    data: Some(response_data),
                                    error: None,
                                }
                            },
                            Err(e) => VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some(e),
                            }
                        }
                    }
                    None => VRFWorkerResponse {
                        id: message.id,
                        success: false,
                        data: None,
                        error: Some("Missing VRF bootstrap generation data".to_string()),
                    }
                }
            })
        }

        "ENCRYPT_VRF_KEYPAIR_WITH_PRF" => {
            VRF_MANAGER.with(|manager| {
                match message.data {
                    Some(data) => {
                        let expected_public_key = data["expectedPublicKey"].as_str()
                            .unwrap_or("")
                            .to_string();

                        let prf_key: Vec<u8> = data["prfKey"].as_array()
                            .unwrap_or(&vec![])
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();

                        if expected_public_key.is_empty() {
                            VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some("Missing expected public key".to_string()),
                            }
                        } else if prf_key.is_empty() {
                            VRFWorkerResponse {
                                id: message.id,
                                success: false,
                                data: None,
                                error: Some("Missing or invalid PRF key".to_string()),
                            }
                        } else {
                            let mut manager = manager.borrow_mut();

                            console::log_1(&"VRF WASM Web Worker: Encrypting VRF keypair with PRF output".into());

                            match manager.encrypt_vrf_keypair_with_prf(expected_public_key, prf_key) {
                                Ok(encrypted_data) => {
                                    // Structure response to match expected format
                                    let response_data = serde_json::json!({
                                        "vrf_public_key": encrypted_data.vrf_public_key,
                                        "encrypted_vrf_keypair": encrypted_data.encrypted_vrf_keypair
                                    });

                                    VRFWorkerResponse {
                                        id: message.id,
                                        success: true,
                                        data: Some(response_data),
                                        error: None,
                                    }
                                },
                                Err(e) => VRFWorkerResponse {
                                    id: message.id,
                                    success: false,
                                    data: None,
                                    error: Some(e),
                                }
                            }
                        }
                    }
                    None => VRFWorkerResponse {
                        id: message.id,
                        success: false,
                        data: None,
                        error: Some("Missing VRF encryption data".to_string()),
                    }
                }
            })
        }

        "CHECK_VRF_STATUS" => {
            VRF_MANAGER.with(|manager| {
                let manager = manager.borrow();
                let status = manager.get_vrf_status();
                VRFWorkerResponse {
                    id: message.id,
                    success: true,
                    data: Some(status),
                    error: None,
                }
            })
        }

        "LOGOUT" => {
            VRF_MANAGER.with(|manager| {
                let mut manager = manager.borrow_mut();
                match manager.logout() {
                    Ok(_) => VRFWorkerResponse {
                        id: message.id,
                        success: true,
                        data: None,
                        error: None,
                    },
                    Err(e) => VRFWorkerResponse {
                        id: message.id,
                        success: false,
                        data: None,
                        error: Some(e),
                    }
                }
            })
        }

        _ => VRFWorkerResponse {
            id: message.id,
            success: false,
            data: None,
            error: Some(format!("Unknown message type: {}", message.msg_type)),
        }
    };

    // Convert response to JsValue
    let response_json = serde_json::to_string(&response)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize response: {}", e)))?;

    JSON::parse(&response_json)
        .map_err(|_e| JsValue::from_str("Failed to parse response JSON"))
}