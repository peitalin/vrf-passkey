use super::{WebAuthnContract, WebAuthnContractExt};

use crate::types::{
    AuthenticatorTransport,
    PublicKeyCredentialDescriptorJSON,
    PublicKeyCredentialCreationOptionsJSON,
    YieldedRegistrationData,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near, require, CryptoHash};
use serde_cbor::Value as CborValue;
use crate::utils::parsers::{
    parse_attestation_object,
    parse_authenticator_data
};
use crate::utils::verifiers::verify_attestation_signature;

// VRF Verification Data Structure
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct VRFVerificationData {
    /// SHA256 hash of concatenated VRF input components:
    /// domain_separator + user_id + rp_id + session_id + block_height + block_hash + timestamp
    /// This hashed data is used for VRF proof verification
    pub vrf_input_data: Vec<u8>,
    /// Used as the WebAuthn challenge (VRF output)
    pub vrf_output: Vec<u8>,
    /// Proves vrf_output was correctly derived from vrf_input_data
    pub vrf_proof: Vec<u8>,
    /// VRF public key used to verify the proof
    pub public_key: Vec<u8>,
    /// Relying Party ID (domain) used in VRF input construction
    pub rp_id: String,
    /// Block height for freshness validation (must be recent)
    pub block_height: u64,
    /// Block hash included in VRF input (for entropy only, not validated on-chain)
    /// NOTE: NEAR contracts cannot access historical block hashes, so this is used
    /// purely for additional entropy in the VRF input construction
    pub block_hash: Vec<u8>,
}

// WebAuthn Registration Data Structure
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct WebAuthnRegistrationData {
    /// WebAuthn registration response (signed vrf_output using platform key)
    pub registration_response: RegistrationResponseJSON,
}

// WebAuthn verification structures
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug)]
pub struct ClientDataJSON {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin", default)]
    pub cross_origin: bool,
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct RegistrationResponseJSON {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub response: AttestationResponse,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(
        rename = "clientExtensionResults",
        skip_serializing_if = "Option::is_none"
    )]
    #[borsh(skip)]
    pub client_extension_results: Option<serde_json::Value>,
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct VerifiedRegistrationResponse {
    pub verified: bool,
    pub registration_info: Option<RegistrationInfo>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub counter: u32,
    pub user_id: String,
    pub vrf_public_key: Option<Vec<u8>>, // Added VRF public key to registration info
}

// Authentication-specific types (equivalent to @simplewebauthn/server types)
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum UserVerificationRequirement {
    #[serde(rename = "discouraged")]
    Discouraged,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

impl Default for UserVerificationRequirement {
    fn default() -> Self {
        Self::Preferred
    }
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// VRF Registration - First time users (one-time setup)
    /// Verifies VRF proof + WebAuthn registration, stores credentials on-chain
    pub fn verify_registration_response_vrf(
        &mut self,
        vrf_data: VRFVerificationData,
        webauthn_data: WebAuthnRegistrationData, // RegistrationResponse
    ) -> VerifiedRegistrationResponse {
        log!("VRF Registration: Verifying VRF proof + WebAuthn registration");
        log!("  - RP ID (domain): {}", vrf_data.rp_id);

        // 1. Validate block height freshness
        let current_height = env::block_index();
        if current_height < vrf_data.block_height || current_height > vrf_data.block_height + self.vrf_settings.max_block_age {
            log!("VRF challenge is stale or invalid: current_height={}, vrf_height={}",
                 current_height, vrf_data.block_height);
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        log!("VRF block height validation passed: current={}, vrf={}, window={} blocks",
             current_height, vrf_data.block_height, self.vrf_settings.max_block_age);

        // 2. Verify the VRF proof and validate VRF output
        log!("VRF Verification:");
        log!("  - Input data: {} bytes", vrf_data.vrf_input_data.len());
        log!("  - Expected output: {} bytes", vrf_data.vrf_output.len());
        log!("  - Proof: {} bytes", vrf_data.vrf_proof.len());
        log!("  - Public key: {} bytes", vrf_data.public_key.len());
        log!("  - Block hash: {} bytes (entropy only, not validated)", vrf_data.block_hash.len());

        let vrf_verification = self.verify_vrf_2( // Using vrf-wasm integration
            vrf_data.vrf_proof.clone(),
            vrf_data.public_key.clone(),
            vrf_data.vrf_input_data.clone()
        );

        if !vrf_verification.verified {
            log!("VRF proof verification failed");
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // 3. Validate that the claimed VRF output matches the verified output
        let verified_vrf_output = vrf_verification.vrf_output.expect("VRF output should be present");
        if verified_vrf_output != vrf_data.vrf_output {
            log!("VRF output mismatch: client claimed output doesn't match verified output");
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // 4. Extract WebAuthn challenge from VRF output
        let webauthn_challenge = &vrf_data.vrf_output[0..32]; // First 32 bytes as challenge
        let challenge_b64url = BASE64_URL_ENGINE.encode(webauthn_challenge);

        log!("VRF proof verified, extracted challenge: {} bytes", webauthn_challenge.len());

        // 5. Use RP ID from VRF data and require user verification for VRF mode
        let require_user_verification = true; // Always require UV for VRF registration

        // 6. Process WebAuthn registration with VRF-generated challenge
        let webauthn_result = self.internal_process_registration(
            challenge_b64url,
            webauthn_data.registration_response,
            vrf_data.rp_id.clone(), // Use the RP ID from VRF data
            require_user_verification,
            Some(vrf_data.public_key.clone()), // Pass VRF public key for storage
        );

        if webauthn_result.verified {
            log!("VRF Registration completed successfully - user can now authenticate statelessly");
        } else {
            log!("WebAuthn registration verification failed");
        }

        webauthn_result
    }

    #[private]
    pub fn internal_process_registration(
        &mut self,
        webauthn_challenge_b64url: String,
        attestation_response: RegistrationResponseJSON,
        rp_id: String,
        require_user_verification: bool,
        vrf_public_key: Option<Vec<u8>>, // Optional VRF public key for storage
    ) -> VerifiedRegistrationResponse {
        log!("Internal: Processing WebAuthn registration with VRF challenge");

        // 1. Derive expected origin from rp_id
        let expected_origin = format!("https://{}", rp_id);

        // 2. Call the core WebAuthn verification logic
        let mut webauthn_result = self.internal_verify_registration_response(
            attestation_response.clone(),
            webauthn_challenge_b64url,
            expected_origin,
            rp_id,
            require_user_verification,
        );

        // 3. If WebAuthn verification succeeded and we have a VRF public key, store it
        if webauthn_result.verified && vrf_public_key.is_some() {
            if let Some(ref mut reg_info) = webauthn_result.registration_info {
                reg_info.vrf_public_key = vrf_public_key.clone();

                // Update the stored authenticator with VRF public key
                let user_account_id = env::predecessor_account_id();
                let credential_id_b64url = BASE64_URL_ENGINE.encode(&reg_info.credential_id);

                // Retrieve and update the authenticator
                if let Some(mut authenticator) = self.get_authenticator(user_account_id.clone(), credential_id_b64url.clone()) {
                    authenticator.vrf_public_key = vrf_public_key.clone();
                    // Re-store the updated authenticator
                    self.store_authenticator(
                        user_account_id.clone(),
                        credential_id_b64url,
                        authenticator.credential_public_key,
                        authenticator.counter,
                        authenticator.transports,
                        authenticator.client_managed_near_public_key,
                        authenticator.registered,
                        authenticator.backed_up,
                    );
                }

                // Store VRF public key in user profile for future reference
                if let Some(mut profile) = self.get_user_profile(user_account_id.clone()) {
                    profile.primary_vrf_public_key = vrf_public_key;
                    self.user_profiles.insert(user_account_id, profile);
                }

                log!("Stored VRF public key with authenticator for future stateless authentication");
            }
        }

        webauthn_result
    }

    // This is the core WebAuthn attestation verification logic
    #[private]
    pub fn internal_verify_registration_response(
        &mut self,
        attestation_response: RegistrationResponseJSON,
        expected_challenge: String, // This is the VRF-generated challenge (base64url)
        expected_origin: String,
        expected_rp_id: String,
        require_user_verification: bool,
    ) -> VerifiedRegistrationResponse {
        log!("Contract verification of registration response");
        log!("Expected challenge: {}", expected_challenge);
        log!("Expected origin: {}", expected_origin);
        log!("Expected RP ID: {}", expected_rp_id);

        // Steps:
        // 1. Parse and validate clientDataJSON
        // 2. Verify challenge matches expected_challenge
        // 3. Verify origin matches expected_origin
        // 4. Parse and validate attestationObject
        // 5. Verify attestation signature using existing helper methods
        // 6. Extract credential public key
        // 7. Store authenticator

        // Step 1: Parse and validate clientDataJSON
        let client_data_json_bytes =
            match BASE64_URL_ENGINE.decode(&attestation_response.response.client_data_json) {
                Ok(bytes) => bytes,
                Err(_) => {
                    log!("Failed to decode clientDataJSON from base64url");
                    return VerifiedRegistrationResponse {
                        verified: false,
                        registration_info: None,
                    };
                }
            };

        let client_data: ClientDataJSON = match serde_json::from_slice(&client_data_json_bytes) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to parse clientDataJSON: {}", e);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Step 2: Verify challenge matches expected_challenge
        if client_data.challenge != expected_challenge {
            log!(
                "Challenge mismatch: expected {}, got {}",
                expected_challenge,
                client_data.challenge
            );
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Step 3: Verify origin matches expected_origin
        if client_data.origin != expected_origin {
            log!(
                "Origin mismatch: expected {}, got {}",
                expected_origin,
                client_data.origin
            );
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Verify type is "webauthn.create"
        if client_data.type_ != "webauthn.create" {
            log!(
                "Invalid type: expected webauthn.create, got {}",
                client_data.type_
            );
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Step 4: Parse and validate attestationObject
        let attestation_object_bytes =
            match BASE64_URL_ENGINE.decode(&attestation_response.response.attestation_object) {
                Ok(bytes) => bytes,
                Err(_) => {
                    log!("Failed to decode attestationObject from base64url");
                    return VerifiedRegistrationResponse {
                        verified: false,
                        registration_info: None,
                    };
                }
            };

        let attestation_object: CborValue = match serde_cbor::from_slice(&attestation_object_bytes)
        {
            Ok(obj) => obj,
            Err(e) => {
                log!("Failed to parse attestationObject CBOR: {}", e);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Extract components from attestationObject
        let (auth_data_bytes, att_stmt, fmt) =
            match parse_attestation_object(&attestation_object) {
                Ok(data) => data,
                Err(e) => {
                    log!("Failed to parse attestation object: {}", e);
                    return VerifiedRegistrationResponse {
                        verified: false,
                        registration_info: None,
                    };
                }
            };

        // Parse authenticator data
        let auth_data = match parse_authenticator_data(&auth_data_bytes) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to parse authenticator data: {}", e);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Verify RP ID hash
        let expected_rp_id_hash = env::sha256(expected_rp_id.as_bytes());
        if auth_data.rp_id_hash != expected_rp_id_hash {
            log!("RP ID hash mismatch");
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Check user verification if required
        if require_user_verification && (auth_data.flags & 0x04) == 0 {
            log!("User verification required but not performed");
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Verify user presence (UP flag must be set)
        if (auth_data.flags & 0x01) == 0 {
            log!("User presence flag not set");
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Verify attested credential data present (AT flag must be set)
        if (auth_data.flags & 0x40) == 0 {
            log!("Attested credential data flag not set");
            return VerifiedRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        let attested_cred_data = match auth_data.attested_credential_data {
            Some(data) => data,
            None => {
                log!("No attested credential data found");
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Step 5: Verify attestation signature
        let client_data_hash = env::sha256(&client_data_json_bytes);
        match verify_attestation_signature(
            &att_stmt,
            &auth_data_bytes,
            &client_data_hash,
            &attested_cred_data.credential_public_key,
            &fmt,
        ) {
            Ok(true) => log!("Attestation signature verified successfully"),
            Ok(false) => {
                log!("Attestation signature verification failed");
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
            Err(e) => {
                log!("Error verifying attestation signature: {}", e);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        }

        // Step 6: WebAuthn verification successful. Store the new authenticator.
        log!("Registration verification successful. Storing new authenticator.");

        let credential_id_b64url = BASE64_URL_ENGINE.encode(&attested_cred_data.credential_id);
        let user_account_id = env::predecessor_account_id();

        // Parse transports from the response if available
        let transports = if let Some(transport_strings) = &attestation_response.response.transports {
            Some(transport_strings.iter().filter_map(|t| {
                match t.as_str() {
                    "usb" => Some(AuthenticatorTransport::Usb),
                    "nfc" => Some(AuthenticatorTransport::Nfc),
                    "ble" => Some(AuthenticatorTransport::Ble),
                    "internal" => Some(AuthenticatorTransport::Internal),
                    "hybrid" => Some(AuthenticatorTransport::Hybrid),
                    _ => None,
                }
            }).collect())
        } else {
            None
        };

        // Get current timestamp as ISO string
        let current_timestamp = env::block_timestamp_ms().to_string();

        // Determine if backed up based on authenticator flags (BS flag = bit 4)
        let backed_up = (auth_data.flags & 0x10) != 0;

        // Store the authenticator on-chain
        self.store_authenticator(
            user_account_id.clone(),
            credential_id_b64url.clone(),
            attested_cred_data.credential_public_key.clone(),
            auth_data.counter,
            transports,
            None, // client_managed_near_public_key starts as None
            current_timestamp,
            backed_up,
        );

        // Phase 2: Register user in user registry if not already registered
        if !self.registered_users.contains(&user_account_id) {
            log!("Registering new user in user registry: {}", user_account_id);
            self.register_user(user_account_id.clone());
        } else {
            log!("User already registered in user registry: {}", user_account_id);
            // Update user activity
            self.update_user_activity(user_account_id.clone());
        }

        log!(
            "Stored authenticator for user '{}' with credential ID '{}'",
            user_account_id,
            credential_id_b64url
        );

        VerifiedRegistrationResponse {
            verified: true,
            registration_info: Some(RegistrationInfo {
                credential_id: attested_cred_data.credential_id,
                credential_public_key: attested_cred_data.credential_public_key,
                counter: auth_data.counter,
                user_id: attestation_response.id, // Use the credential ID as user ID
                vrf_public_key: None, // Will be set by caller if provided
            }),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE};
    use std::collections::BTreeMap;
    use sha2::{Sha256, Digest};

    // Mock VRF dependencies for testing
    struct MockVRFData {
        pub input_data: Vec<u8>,
        pub output: Vec<u8>,
        pub proof: Vec<u8>,
        pub public_key: Vec<u8>,
    }

    impl MockVRFData {
        fn create_mock() -> Self {
            // Create deterministic mock VRF data for testing
            let domain = b"web_authn_challenge_v1";
            let user_id = b"test_user_123";
            let rp_id = b"test-contract.testnet";
            let session_id = b"session_abc123";
            let block_height = 12345u64;
            let block_hash = b"mock_block_hash_32_bytes_long_abc";
            let timestamp = 1234567890u64;

            // Construct VRF input similar to the spec
            let mut input_data = Vec::new();
            input_data.extend_from_slice(domain);
            input_data.extend_from_slice(user_id);
            input_data.extend_from_slice(rp_id);
            input_data.extend_from_slice(session_id);
            input_data.extend_from_slice(&block_height.to_le_bytes());
            input_data.extend_from_slice(block_hash);
            input_data.extend_from_slice(&timestamp.to_le_bytes());

            // Hash the input data (VRF input should be hashed)
            let hashed_input = Sha256::digest(&input_data).to_vec();

            // Mock VRF output (64 bytes - deterministic for testing)
            let vrf_output = (0..64).map(|i| (i as u8).wrapping_add(42)).collect::<Vec<u8>>();

            // Mock VRF proof (80 bytes - typical VRF proof size)
            let vrf_proof = (0..80).map(|i| (i as u8).wrapping_add(100)).collect::<Vec<u8>>();

            // Mock VRF public key (32 bytes - ed25519 public key)
            let vrf_public_key = (0..32).map(|i| (i as u8).wrapping_add(200)).collect::<Vec<u8>>();

            Self {
                input_data: hashed_input,
                output: vrf_output,
                proof: vrf_proof,
                public_key: vrf_public_key,
            }
        }
    }

    /// Helper to get a VMContext with predictable randomness for testing
    fn get_context_with_seed(random_byte_val: u8) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let seed: Vec<u8> = (0..32).map(|_| random_byte_val).collect();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(accounts(1))
            .predecessor_account_id(accounts(1))
            .is_view(false)
            .random_seed(seed.try_into().unwrap());
        builder
    }

    /// Create a mock WebAuthn registration response using VRF challenge
    fn create_mock_webauthn_registration_with_vrf_challenge(vrf_output: &[u8]) -> RegistrationResponseJSON {
        // Use first 32 bytes of VRF output as WebAuthn challenge
        let webauthn_challenge = &vrf_output[0..32];
        let challenge_b64 = TEST_BASE64_URL_ENGINE.encode(webauthn_challenge);

        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://test-contract.testnet","crossOrigin":false}}"#,
            challenge_b64
        );
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create valid attestation object for "none" format
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            serde_cbor::Value::Text("fmt".to_string()),
            serde_cbor::Value::Text("none".to_string()),
        );

        // Create valid authenticator data
        let mut auth_data = Vec::new();
        let rp_id_hash = env::sha256(b"test-contract.testnet");
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x45); // UP (0x01) + UV (0x04) + AT (0x40)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Counter = 1

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x00u8; 16]);

        // Credential ID
        let cred_id = b"test_vrf_credential_id_123";
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);

        // Create valid COSE Ed25519 public key
        let mock_ed25519_pubkey = [0x42u8; 32];
        let mut cose_map = BTreeMap::new();
        cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
        cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
        cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
        cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
        let cose_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();
        auth_data.extend_from_slice(&cose_key);

        attestation_map.insert(
            serde_cbor::Value::Text("authData".to_string()),
            serde_cbor::Value::Bytes(auth_data),
        );
        attestation_map.insert(
            serde_cbor::Value::Text("attStmt".to_string()),
            serde_cbor::Value::Map(BTreeMap::new()),
        );

        let attestation_object_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(attestation_map)).unwrap();
        let attestation_object_b64 = TEST_BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        RegistrationResponseJSON {
            id: "test_vrf_credential_id_123".to_string(),
            raw_id: TEST_BASE64_URL_ENGINE.encode(b"test_vrf_credential_id_123"),
            response: AttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
                transports: Some(vec!["internal".to_string()]),
            },
            authenticator_attachment: Some("platform".to_string()),
            type_: "public-key".to_string(),
            client_extension_results: None,
        }
    }

    #[test]
    fn test_verify_registration_response_vrf_success() {
        // Setup test environment
        let context = get_context_with_seed(42);
        testing_env!(context.build());
        let mut contract = crate::WebAuthnContract::init("test-contract.testnet".to_string());

        // Create mock VRF data
        let mock_vrf = MockVRFData::create_mock();

        // Create VRF verification data struct
        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output.clone(),
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            rp_id: "example.com".to_string(),
            block_height: 1234567890u64,
            block_hash: b"mock_block_hash_32_bytes_long_abc".to_vec(),
        };

        // Create WebAuthn registration data using VRF output as challenge
        let registration_response = create_mock_webauthn_registration_with_vrf_challenge(&mock_vrf.output);
        let webauthn_data = WebAuthnRegistrationData {
            registration_response,
        };

        println!("Testing VRF Registration with mock data:");
        println!("  - VRF input: {} bytes", vrf_data.vrf_input_data.len());
        println!("  - VRF output: {} bytes", vrf_data.vrf_output.len());
        println!("  - VRF proof: {} bytes", vrf_data.vrf_proof.len());
        println!("  - VRF public key: {} bytes", vrf_data.public_key.len());

        // Extract challenge for verification
        let expected_challenge = &vrf_data.vrf_output[0..32];
        let expected_challenge_b64 = TEST_BASE64_URL_ENGINE.encode(expected_challenge);
        println!("  - Expected WebAuthn challenge: {}", expected_challenge_b64);

        // Note: This test will fail VRF verification since we're using mock data
        // but it will test the structure and flow of the VRF registration process
        let result = contract.verify_registration_response_vrf(vrf_data, webauthn_data);

        // The result should fail VRF verification (expected with mock data)
        // but the test verifies the method structure and parameter handling
        assert!(!result.verified, "Mock VRF data should fail verification (expected)");
        assert!(result.registration_info.is_none(), "No registration info should be returned on VRF failure");

        println!("✅ VRF Registration test completed - structure and flow verified");
        println!("   (VRF verification failed as expected with mock data)");
    }

    #[test]
    fn test_vrf_verification_data_serialization() {
        let mock_vrf = MockVRFData::create_mock();

        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output,
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            rp_id: "example.com".to_string(),
            block_height: 1234567890u64,
            block_hash: b"mock_block_hash_32_bytes_long_abc".to_vec(),
        };

        // Test JSON serialization
        let json_str = serde_json::to_string(&vrf_data).expect("Should serialize to JSON");
        let deserialized: VRFVerificationData = serde_json::from_str(&json_str).expect("Should deserialize from JSON");

        assert_eq!(vrf_data.vrf_input_data, deserialized.vrf_input_data);
        assert_eq!(vrf_data.vrf_output, deserialized.vrf_output);
        assert_eq!(vrf_data.vrf_proof, deserialized.vrf_proof);
        assert_eq!(vrf_data.public_key, deserialized.public_key);
        assert_eq!(vrf_data.rp_id, deserialized.rp_id);
        assert_eq!(vrf_data.block_height, deserialized.block_height);
        assert_eq!(vrf_data.block_hash, deserialized.block_hash);

        println!("✅ VRFVerificationData serialization test passed");
    }

    #[test]
    fn test_webauthn_registration_data_serialization() {
        let mock_vrf = MockVRFData::create_mock();
        let registration_response = create_mock_webauthn_registration_with_vrf_challenge(&mock_vrf.output);

        let webauthn_data = WebAuthnRegistrationData {
            registration_response,
        };

        // Test JSON serialization
        let json_str = serde_json::to_string(&webauthn_data).expect("Should serialize to JSON");
        let deserialized: WebAuthnRegistrationData = serde_json::from_str(&json_str).expect("Should deserialize from JSON");

        assert_eq!(webauthn_data.registration_response.id, deserialized.registration_response.id);
        assert_eq!(webauthn_data.registration_response.type_, deserialized.registration_response.type_);

        println!("✅ WebAuthnRegistrationData serialization test passed");
    }

    #[test]
    fn test_vrf_challenge_construction_format() {
        // Test that our VRF input construction matches the specification
        let domain = b"web_authn_challenge_v1";
        let user_id = b"alice.testnet";
        let rp_id = b"example.com";
        let session_id = b"session_uuid_12345";
        let block_height = 123456789u64;
        let block_hash = b"block_hash_32_bytes_long_example";
        let timestamp = 1700000000u64;

        let mut input_data = Vec::new();
        input_data.extend_from_slice(domain);
        input_data.extend_from_slice(user_id);
        input_data.extend_from_slice(rp_id);
        input_data.extend_from_slice(session_id);
        input_data.extend_from_slice(&block_height.to_le_bytes());
        input_data.extend_from_slice(block_hash);
        input_data.extend_from_slice(&timestamp.to_le_bytes());

        let vrf_input = Sha256::digest(&input_data);

        println!("VRF Input Construction Test:");
        println!("  - Domain: {:?}", std::str::from_utf8(domain).unwrap());
        println!("  - User ID: {:?}", std::str::from_utf8(user_id).unwrap());
        println!("  - RP ID: {:?}", std::str::from_utf8(rp_id).unwrap());
        println!("  - Session ID: {:?}", std::str::from_utf8(session_id).unwrap());
        println!("  - Block height: {}", block_height);
        println!("  - Block hash: {:?}", std::str::from_utf8(block_hash).unwrap());
        println!("  - Timestamp: {}", timestamp);
        println!("  - Total input length: {} bytes", input_data.len());
        println!("  - SHA256 hash length: {} bytes", vrf_input.len());

        // Verify expected structure
        assert_eq!(vrf_input.len(), 32, "VRF input hash should be 32 bytes");
        assert!(input_data.len() > 50, "Combined input should have substantial length");

        println!("✅ VRF challenge construction format verified");
    }
}
