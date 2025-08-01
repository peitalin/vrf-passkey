//! VRF Verification Library for NEAR Contracts
//!
//! This module provides verification functions for VRF outputs and proofs generated
//! by frontend wasm-workers using the `vrf-wasm` crate with browser RNG.

// Wrappers for the `vrf-wasm` and `vrf-contract-verifier` crates
mod vrf_contract_verifier_wrapper;
// mod vrf_wasm_verifier_wrapper;

pub use vrf_contract_verifier_wrapper::verify_vrf_1;
// pub use vrf_wasm_verifier_wrapper::verify_vrf_2;
use vrf_contract_verifier::VerificationError;

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
