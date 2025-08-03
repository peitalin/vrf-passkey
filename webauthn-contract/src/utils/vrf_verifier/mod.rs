//!
//! VRF Verification Library for NEAR Contracts
//!
//! This module provides verification functions for VRF outputs and proofs generated
//! by frontend wasm-workers using the `vrf-wasm` crate with browser RNG.
//!
//! We use vrf-wasm for browser-based VRF generation
//! and use vrf-contract-verifier for contract-based VRF verification

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
// mod vrf_wasm_verifier;
// pub use vrf_wasm_verifier::verify_vrf_2;
use vrf_contract_verifier::{verify_vrf, VerificationError};
use crate::contract_state::VRFSettings;

/// VRF input components for NEAR-based challenges
#[derive(Debug, Clone)]
#[near_sdk::near(serializers = [borsh, json])]
pub struct VRFInputComponents {
    pub account_id: String,            // User account for binding
    pub block_height: u64,             // NEAR block height for freshness
    pub challenge_data: Vec<u8>,       // Additional challenge data
    pub expiration_block: Option<u64>, // Optional expiration
}

/// VRF verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VRFVerificationError {
    InvalidProof(String),
    InvalidPublicKey,
    InvalidInput,
    DeserializationFailed,
    VerificationFailed,
    StaleChallenge,
}

impl From<vrf_contract_verifier::VerificationError> for VRFVerificationError {
    fn from(error: vrf_contract_verifier::VerificationError) -> Self {
        match error {
            VerificationError::InvalidProof => VRFVerificationError::InvalidProof("Invalid proof".to_string()),
            VerificationError::InvalidPublicKey => VRFVerificationError::InvalidPublicKey,
            VerificationError::InvalidInput => VRFVerificationError::InvalidInput,
            VerificationError::InvalidProofLength => VRFVerificationError::InvalidProof("Invalid proof length".to_string()),
            VerificationError::DecompressionFailed => VRFVerificationError::InvalidProof("Decompression failed".to_string()),
            VerificationError::InvalidScalar => VRFVerificationError::InvalidProof("Invalid scalar".to_string()),
            VerificationError::InvalidGamma => VRFVerificationError::InvalidProof("Invalid gamma".to_string()),
            VerificationError::ZeroPublicKey => VRFVerificationError::InvalidProof("Zero public key".to_string()),
            VerificationError::ExpandMessageXmdFailed => VRFVerificationError::InvalidProof("Expand message xmd failed".to_string()),
        }
    }
}

/// VRF verification data structure for WebAuthn challenges
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct VRFVerificationData {
    /// SHA256 hash of concatenated VRF input components:
    /// domain_separator + user_id + rp_id + session_id + block_height + block_hash
    /// This hashed data is used for VRF proof verification
    pub vrf_input_data: Vec<u8>,
    /// Used as the WebAuthn challenge (VRF output)
    pub vrf_output: Vec<u8>,
    /// Proves vrf_output was correctly derived from vrf_input_data
    pub vrf_proof: Vec<u8>,
    /// VRF public key used to verify the proof
    pub public_key: Vec<u8>,
    /// User ID (account_id in NEAR protocol) - cryptographically bound in VRF input
    pub user_id: String,
    /// Relying Party ID (domain) used in VRF input construction
    pub rp_id: String,
    /// Block height for freshness validation (must be recent)
    pub block_height: u64,
    /// Block hash included in VRF input (for entropy only, not validated on-chain)
    /// NOTE: NEAR contracts cannot access historical block hashes, so this is used
    /// purely for additional entropy in the VRF input construction
    pub block_hash: Vec<u8>,
}

/// VRF authentication response with output
#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct VerifiedVRFAuthenticationResponse {
    pub verified: bool,
    pub vrf_output: Option<Vec<u8>>, // 64-byte VRF output if verification succeeds
    pub authentication_info: Option<String>,
}

/// Verify VRF proof and extract WebAuthn challenge
/// Returns the challenge and parameters needed for WebAuthn verification
/// This function performs no state modifications and can be called from both
/// registration and view functions
///
/// # Arguments
/// * `vrf_data` - VRF verification data containing proof, input, output and metadata
/// * `vrf_settings` - VRF settings for validation parameters
///
/// # Returns
/// * `Option<String>` - On success returns WebAuthn challenge derived from VRF output (base64url encoded)
///   On failure returns None
pub fn verify_vrf_and_extract_challenge(
    vrf_data: &VRFVerificationData,
    vrf_settings: &VRFSettings,
) -> Option<String> {
    // 1. Validate block height freshness
    let current_height = near_sdk::env::block_height();
    if current_height < vrf_data.block_height ||
       current_height > vrf_data.block_height + vrf_settings.max_block_age {
        near_sdk::log!("VRF challenge is stale or invalid: current_height={}, vrf_height={}",
             current_height, vrf_data.block_height);
        return None;
    } else {
        near_sdk::log!("VRF block height validation passed: current={}, vrf={}, window={} blocks",
            current_height, vrf_data.block_height, vrf_settings.max_block_age);
    }

    // 2. Verify the VRF proof and validate VRF output
    let verified_vrf_output = match verify_vrf(
        &vrf_data.vrf_proof,
        &vrf_data.public_key,
        &vrf_data.vrf_input_data
    ) {
        Ok(vrf_output) => vrf_output.to_vec(),
        Err(_) => {
            near_sdk::log!("VRF proof verification failed");
            return None;
        }
    };

    // 3. Validate that the claimed VRF output matches the verified output
    if verified_vrf_output != vrf_data.vrf_output {
        near_sdk::log!("VRF output mismatch: client claimed output doesn't match verified output");
        return None;
    }

    // 4. Extract WebAuthn challenge from VRF output
    let vrf_webauthn_challenge = &vrf_data.vrf_output[0..32]; // First 32 bytes as challenge
    let vrf_challenge_b64url = BASE64_URL_ENGINE.encode(vrf_webauthn_challenge);
    near_sdk::log!("VRF proof verified, extracted challenge: {} bytes", vrf_webauthn_challenge.len());

    Some(vrf_challenge_b64url)
}
