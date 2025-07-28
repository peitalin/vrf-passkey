//! Lib `vrf-wasm` Integration Test
//!
//! Comprehensive test suite for VRF verification using native vrf-wasm library
//! with browser feature flag. Tests against wasm_worker_vrf_utils module.

// use near_workspaces::types::Gas;
// use serde_json::json;
// use tokio::sync::OnceCell;
// use rand_core::SeedableRng;

// use vrf_wasm::ecvrf::{ECVRFKeyPair, ECVRFProof};
// use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
// use vrf_wasm::traits::WasmRngFromSeed;

// mod utils_mocks;
// mod utils_contracts;

// use utils_mocks::generate_test_vrf_wasm_data;
// use utils_contracts::deploy_test_contract;

// // name of the `vrf-wasm` based verify function in the contract
// const VERIFY_FUNCTION_NAME: &str = "verify_vrf_2";

// // Shared contract instance for all tests (expensive to deploy)
// static CONTRACT: OnceCell<near_workspaces::Contract> = OnceCell::const_new();

// async fn get_contract() -> &'static near_workspaces::Contract {
//     CONTRACT.get_or_init(|| async {
//         println!("Deploying shared test contract for VRF WASM tests...");
//         deploy_test_contract().await.expect("Failed to deploy test contract")
//     }).await
// }

// ////////////////////////////////////////////////////////////
// /// BEGIN TESTS
// ////////////////////////////////////////////////////////////

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_vrf_wasm_valid_proof_passes() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Valid vrf-wasm proof should pass");

//         let contract = get_contract().await;
//         let test_data = generate_test_vrf_wasm_data().await?;

//         let result = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": test_data.proof_bytes(),
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?;

//         let verification_result: serde_json::Value = result.json()?;
//         let verified = verification_result["verified"].as_bool().unwrap_or(false);

//         assert!(verified, "Valid vrf-wasm proof should pass verification");

//         // Check that VRF output was returned
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_some(), "Valid proof should return VRF output");

//         println!("PASSED: Valid vrf-wasm proof verified successfully");
//         println!("  - VRF output returned: {} bytes", vrf_output.unwrap().len());
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_wasm_wrong_s_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Proof with wrong s (scalar) should fail");

//         let contract = get_contract().await;
//         let test_data = generate_test_vrf_wasm_data().await?;

//         // Extract components and corrupt the scalar
//         let (gamma, challenge, scalar) = test_data.proof.to_components();
//         let mut corrupted_scalar = scalar;
//         corrupted_scalar[0] = corrupted_scalar[0].wrapping_add(1);

//         // Try to reconstruct proof with corrupted scalar
//         let corrupted_proof_bytes = match ECVRFProof::from_components(&gamma, &challenge, &corrupted_scalar) {
//             Ok(proof) => {
//                 println!("Successfully created corrupted proof from components");
//                 bincode::serialize(&proof).unwrap()
//             }
//             Err(e) => {
//                 println!("Component reconstruction failed ({}), using serialization corruption", e);
//                 // Fallback: corrupt serialized proof directly
//                 let mut bytes = test_data.proof_bytes();
//                 let len = bytes.len();
//                 if len > 50 {
//                     // Corrupt what should be the scalar part (typically near the end)
//                     bytes[len - 10] = bytes[len - 10].wrapping_add(1);
//                 }
//                 bytes
//             }
//         };

//         let result = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": corrupted_proof_bytes,
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?;

//         let verification_result: serde_json::Value = result.json()?;
//         let verified = verification_result["verified"].as_bool().unwrap_or(true);

//         assert!(!verified, "Proof with wrong s should fail verification");

//         // Check that no VRF output was returned
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_none() || vrf_output.unwrap().is_empty(), "Invalid proof should not return VRF output");

//         println!("PASSED: Wrong s correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_wasm_wrong_c_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Proof with wrong c (challenge) should fail");

//         let contract = get_contract().await;
//         let test_data = generate_test_vrf_wasm_data().await?;

//         // Extract components and corrupt the challenge
//         let (gamma, challenge, scalar) = test_data.proof.to_components();
//         let mut corrupted_challenge = challenge;
//         corrupted_challenge[0] = corrupted_challenge[0].wrapping_add(1);

//         // Try to reconstruct proof with corrupted challenge
//         let corrupted_proof_bytes = match ECVRFProof::from_components(&gamma, &corrupted_challenge, &scalar) {
//             Ok(proof) => {
//                 println!("Successfully created corrupted proof from components");
//                 bincode::serialize(&proof).unwrap()
//             }
//             Err(e) => {
//                 println!("Component reconstruction failed ({}), using serialization corruption", e);
//                 // Fallback: corrupt serialized proof directly
//                 let mut bytes = test_data.proof_bytes();
//                 let len = bytes.len();
//                 if len > 40 {
//                     // Corrupt what should be the challenge part (typically in the middle)
//                     bytes[len / 2] = bytes[len / 2].wrapping_add(1);
//                 }
//                 bytes
//             }
//         };

//         let result = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": corrupted_proof_bytes,
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?;

//         let verification_result: serde_json::Value = result.json()?;
//         let verified = verification_result["verified"].as_bool().unwrap_or(true);

//         assert!(!verified, "Proof with wrong c should fail verification");

//         // Check that no VRF output was returned
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_none() || vrf_output.unwrap().is_empty(), "Invalid proof should not return VRF output");

//         println!("PASSED: Wrong c correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_wasm_wrong_gamma_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Proof with wrong gamma should fail");

//         let contract = get_contract().await;
//         let test_data = generate_test_vrf_wasm_data().await?;

//         // Approach: Corrupt the serialized proof directly instead of components
//         // This avoids curve validation issues when creating invalid gamma points
//         let mut corrupted_proof_bytes = test_data.proof_bytes();

//         // Corrupt some bytes in the serialized proof (gamma is typically at the beginning)
//         let len = corrupted_proof_bytes.len();
//         if len > 10 {
//             println!("Corrupting serialized proof directly to create invalid gamma");
//             corrupted_proof_bytes[8] = corrupted_proof_bytes[8].wrapping_add(1);
//             corrupted_proof_bytes[9] = corrupted_proof_bytes[9].wrapping_add(1);
//         }

//         let result = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": corrupted_proof_bytes,
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?;

//         let verification_result: serde_json::Value = result.json()?;
//         let verified = verification_result["verified"].as_bool().unwrap_or(true);

//         assert!(!verified, "Proof with wrong gamma should fail verification");

//         // Check that no VRF output was returned
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_none() || vrf_output.unwrap().is_empty(), "Invalid proof should not return VRF output");

//         println!("PASSED: Wrong gamma correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_wasm_malformed_public_key_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Malformed public key should fail");

//         let contract = get_contract().await;
//         let test_data = generate_test_vrf_wasm_data().await?;

//         // Create invalid public key bytes (corrupted serialization)
//         let mut invalid_pubkey_bytes = test_data.pubkey_bytes();
//         // Corrupt the serialized data
//         invalid_pubkey_bytes[0] = invalid_pubkey_bytes[0].wrapping_add(1);

//         let result = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": test_data.proof_bytes(),
//                 "public_key_bytes": invalid_pubkey_bytes,
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?;

//         let verification_result: serde_json::Value = result.json()?;
//         let verified = verification_result["verified"].as_bool().unwrap_or(true);

//         assert!(!verified, "Malformed public key should fail verification");

//         // Check that no VRF output was returned
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_none() || vrf_output.unwrap().is_empty(), "Invalid proof should not return VRF output");

//         println!("PASSED: Malformed public key correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_wasm_roundtrip_verification() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Roundtrip: output == contract.verify(input, pk, proof)");

//         let contract = get_contract().await;
//         let test_data = generate_test_vrf_wasm_data().await?;

//         // First verify the proof and get the output
//         let result = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": test_data.proof_bytes(),
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?;

//         let verification_result: serde_json::Value = result.json()?;
//         let verified = verification_result["verified"].as_bool().unwrap_or(false);

//         assert!(verified, "Roundtrip test requires valid proof");

//         // Compute expected output locally using vrf-wasm
//         let expected_output = test_data.proof.to_hash();

//         // Extract VRF output from contract response
//         let contract_output_opt = verification_result["vrf_output"].as_array();

//         if let Some(contract_output_array) = contract_output_opt {
//             // Convert JSON array to Vec<u8>
//             let contract_output: Vec<u8> = contract_output_array
//                 .iter()
//                 .map(|v| v.as_u64().unwrap() as u8)
//                 .collect();

//             // Full roundtrip comparison
//             assert_eq!(contract_output, expected_output.to_vec(), "VRF outputs must match exactly");

//             println!("PASSED: Full roundtrip verification successful");
//             println!("  - Expected output: {} bytes", expected_output.len());
//             println!("  - Contract output: {} bytes", contract_output.len());
//             println!("  - Expected hash: {:02x}{:02x}...{:02x}{:02x}",
//                      expected_output[0], expected_output[1],
//                      expected_output[30], expected_output[31]);
//             println!("  - Contract hash: {:02x}{:02x}...{:02x}{:02x}",
//                      contract_output[0], contract_output[1],
//                      contract_output[30], contract_output[31]);
//             println!("VRF outputs match exactly");
//         } else {
//             return Err("Contract didn't return VRF output".into());
//         }

//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_deterministic_vrf_wasm_generation() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Testing deterministic VRF generation with vrf-wasm...");

//         let seed = [123u8; 32];
//         let input = b"deterministic_test";

//         // Generate twice with same seed
//         let mut rng1 = WasmRngFromSeed::from_seed(seed);
//         let keypair1 = ECVRFKeyPair::generate(&mut rng1);
//         let proof1 = keypair1.prove(input);
//         let output1 = proof1.to_hash();

//         let mut rng2 = WasmRngFromSeed::from_seed(seed);
//         let keypair2 = ECVRFKeyPair::generate(&mut rng2);
//         let proof2 = keypair2.prove(input);
//         let output2 = proof2.to_hash();

//         assert_eq!(output1, output2, "VRF outputs should be deterministic");
//         println!("VRF-WASM generation is deterministic: {} bytes", output1.len());

//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_wasm_component_extraction() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Testing VRF-WASM component extraction...");

//         let seed = [99u8; 32];
//         let mut rng = WasmRngFromSeed::from_seed(seed);
//         let keypair = ECVRFKeyPair::generate(&mut rng);
//         let input = b"component_test";
//         let proof = keypair.prove(input);

//         // Extract individual components
//         let gamma_bytes = proof.gamma_bytes();
//         let challenge_bytes = proof.challenge_bytes();
//         let scalar_bytes = proof.scalar_bytes();

//         println!("- Gamma: {} bytes", gamma_bytes.len());
//         println!("- Challenge: {} bytes", challenge_bytes.len());
//         println!("- Scalar: {} bytes", scalar_bytes.len());

//         // Verify component sizes
//         assert_eq!(gamma_bytes.len(), 32, "Gamma should be 32 bytes");
//         assert_eq!(challenge_bytes.len(), 16, "Challenge should be 16 bytes");
//         assert_eq!(scalar_bytes.len(), 32, "Scalar should be 32 bytes");

//         // Test reconstruction
//         let (gamma, challenge, scalar) = proof.to_components();
//         let reconstructed = ECVRFProof::from_components(&gamma, &challenge, &scalar)?;

//         // Verify reconstructed proof works
//         assert!(reconstructed.verify(input, &keypair.pk).is_ok());
//         assert_eq!(reconstructed.to_hash(), proof.to_hash());

//         println!("Component extraction and reconstruction successful");
//         Ok(())
//     }
// }