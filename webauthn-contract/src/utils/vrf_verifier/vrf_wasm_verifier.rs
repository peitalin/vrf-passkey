//!
//! NOTE: Use lighter weight vrf_contract_verifier instead of vrf_wasm
//!
//! We use vrf-wasm for browser-based VRF generation
//! and use vrf-contract-verifier for contract-based VRF verification
//! This module is just for compatibility testing.
//!

// use vrf_wasm::ecvrf::{ECVRFProof, ECVRFPublicKey};
// use vrf_wasm::vrf::VRFProof; // Trait for verify() and to_hash() methods
// use near_sdk::log;

// use super::VRFVerificationError;

// /// Main VRF verification function for contract use
// /// Verifies a VRF proof against input and public key using vrf-wasm
// pub fn verify_vrf_2(
//     proof_bytes: &[u8],
//     public_key_bytes: &[u8],
//     input: &[u8],
// ) -> Result<[u8; 64], VRFVerificationError> {
//     log!("Verifying VRF proof: {} bytes proof, {} bytes pubkey, {} bytes input",
//          proof_bytes.len(), public_key_bytes.len(), input.len());

//     // Deserialize public key
//     let public_key: ECVRFPublicKey = bincode::deserialize(public_key_bytes)
//         .map_err(|_| VRFVerificationError::DeserializationFailed)?;

//     // Deserialize proof
//     let proof: ECVRFProof = bincode::deserialize(proof_bytes)
//         .map_err(|_| VRFVerificationError::DeserializationFailed)?;

//     // Verify the proof
//     proof.verify(input, &public_key)
//         .map_err(|_| VRFVerificationError::VerificationFailed)?;

//     // Extract VRF output hash
//     let vrf_output = proof.to_hash();

//     log!("VRF verification successful, output: {} bytes", vrf_output.len());
//     Ok(vrf_output)
// }
