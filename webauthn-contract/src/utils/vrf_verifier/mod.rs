//! VRF Verification Library for NEAR Contracts
//!
//! This module provides verification functions for VRF outputs and proofs generated
//! by frontend wasm-workers using the `vrf-wasm` crate with browser RNG.
//!
//! Frontend responsibilities (using vrf-wasm):
//! - Generate VRF keypairs with WasmRng or WasmRngFromSeed
//! - Create VRF proofs using ECVRFKeyPair::prove()
//! - Serialize proofs and public keys using bincode
//! - Send serialized data to contract
//!
//! Contract responsibilities (this module):
//! - Deserialize VRF proofs and public keys
//! - Verify VRF proofs using ECVRFProof::verify()
//! - Extract VRF outputs using ECVRFProof::to_hash()
//! - Validate freshness and domain separation

// Wrappers for the `vrf-wasm` and `vrf-contract-verifier` crates
mod vrf_contract_verifier_wrapper;
mod vrf_wasm_verifier_wrapper;

pub use vrf_contract_verifier_wrapper::verify_vrf_1;
// pub use vrf_wasm_verifier_wrapper::verify_vrf_2;

use vrf_contract_verifier::VerificationError;
use near_sdk::{env, log};

/// VRF input components for NEAR-based challenges
#[derive(Debug, Clone)]
#[near_sdk::near(serializers = [borsh, json])]
pub struct VRFInputComponents {
    pub account_id: String,           // User account for binding
    pub block_height: u64,           // NEAR block height for freshness
    pub challenge_data: Vec<u8>,     // Additional challenge data
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

/// Validate that the challenge is fresh based on block height
pub fn validate_challenge_freshness(
    components: &VRFInputComponents
) -> Result<(), VRFVerificationError> {
    let current_block = env::block_height();

    // Check expiration if set
    if let Some(expiration_block) = components.expiration_block {
        if current_block > expiration_block {
            log!("Challenge expired: current block {} > expiration {}",
                 current_block, expiration_block);
            return Err(VRFVerificationError::StaleChallenge);
        }
    }
    // For block-based VRF, we validate the block height instead of timestamp
    // Allow a reasonable window of recent blocks (e.g., last 10 blocks)
    // Check that referenced block is not too old (max 100 blocks = ~5 minutes)
    let max_block_age = 100u64;
    if current_block < components.block_height {
        log!("Challenge block is in the future: {} > {}",
             components.block_height, current_block);
        return Err(VRFVerificationError::StaleChallenge);
    }

    let block_age = current_block - components.block_height;
    if block_age > max_block_age {
        log!("Challenge too old: {} blocks ago (max: {})", block_age, max_block_age);
        return Err(VRFVerificationError::StaleChallenge);
    }

    log!("Challenge freshness validated: block {}, age {} blocks",
         components.block_height, block_age);
    Ok(())
}
