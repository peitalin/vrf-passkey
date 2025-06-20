use serde_json::json;
use rand_core::SeedableRng;
use vrf_wasm::{
    ecvrf::{ECVRFProof, ECVRFPublicKey, ECVRFKeyPair},
    traits::WasmRngFromSeed,
    VRFKeyPair,
    VRFProof,
};

/// VRF proof data structure for testing
#[derive(Debug)]
pub struct VrfTestData {
    pub proof: ECVRFProof,
    pub public_key: ECVRFPublicKey,
    pub input: Vec<u8>,
    pub expected_output: Vec<u8>,
}

impl VrfTestData {
    pub fn proof_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.proof).unwrap()
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.public_key).unwrap()
    }
}

/// Test VRF data structure for registration
#[derive(Debug)]
pub struct VrfRegistrationData {
    pub input_data: Vec<u8>,    // VRF input (hashed to 32 bytes)
    pub output: Vec<u8>,        // VRF output (64 bytes full hash)
    pub proof: ECVRFProof,      // VRF proof
    pub public_key: ECVRFPublicKey, // VRF public key
    pub rp_id: String,          // Relying Party ID used in construction
    pub block_height: u64,
    pub block_hash: Vec<u8>,
}

// Test VRF data structure for authentication (subsequent logins)
#[derive(Debug)]
pub struct VrfAuthenticationData {
    pub input_data: Vec<u8>,    // VRF input (hashed to 32 bytes)
    pub output: Vec<u8>,        // VRF output (64 bytes full hash)
    pub proof: ECVRFProof,      // VRF proof
    pub public_key: ECVRFPublicKey, // VRF public key (same as registration)
    pub rp_id: String,          // Relying Party ID used in construction
    pub block_height: u64,
    pub block_hash: Vec<u8>,
}

impl VrfRegistrationData {
    pub fn proof_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.proof).unwrap()
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.public_key).unwrap()
    }

    pub fn to_vrf_verification_data(&self) -> serde_json::Value {
        json!({
            "vrf_input_data": self.input_data,
            "vrf_output": self.output,
            "vrf_proof": self.proof_bytes(),
            "public_key": self.pubkey_bytes(),
            "rp_id": self.rp_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash
        })
    }
}

impl VrfAuthenticationData {
    pub fn proof_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.proof).unwrap()
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.public_key).unwrap()
    }

    pub fn to_vrf_authentication_data(&self) -> serde_json::Value {
        json!({
            "vrf_input_data": self.input_data,
            "vrf_output": self.output,
            "vrf_proof": self.proof_bytes(),
            "public_key": self.pubkey_bytes(),
            "rp_id": self.rp_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash
        })
    }
}

pub async fn generate_test_vrf_wasm_data() -> Result<VrfTestData, Box<dyn std::error::Error>> {
    // Create deterministic keypair using WasmRngFromSeed
    let seed = [42u8; 32];
    let mut rng = WasmRngFromSeed::from_seed(seed);
    let keypair = ECVRFKeyPair::generate(&mut rng);

    // Test input
    let input = b"test_vrf_wasm_input_v1.0".to_vec();

    // Generate VRF proof using vrf-wasm
    let proof = keypair.prove(&input);
    let vrf_output = proof.to_hash();

    // Verify the proof works locally
    assert!(proof.verify(&input, &keypair.pk).is_ok(), "Generated proof should be valid");

    Ok(VrfTestData {
        proof,
        public_key: keypair.pk,
        input: input.clone(),
        expected_output: vrf_output.to_vec(),
    })
}
