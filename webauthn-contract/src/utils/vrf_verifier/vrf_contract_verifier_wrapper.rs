use vrf_contract_verifier::verify_vrf;

use super::VRFVerificationError;

/// Main VRF verification function for contract use
/// Verifies a VRF proof against input and public key using vrf-wasm
pub fn verify_vrf_1(
    proof_bytes: &[u8],
    public_key_bytes: &[u8],
    input: &[u8],
) -> Result<[u8; 64], VRFVerificationError> {
    verify_vrf(&proof_bytes, &public_key_bytes, &input)
        .map_err(|e| VRFVerificationError::from(e))
}
