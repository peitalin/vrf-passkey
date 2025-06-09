use super::{WebAuthnContract, WebAuthnContractExt};

use crate::generate_registration_options::{
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

// Structure to hold registration completion data
#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RegistrationCompletionData {
    pub registration_response: RegistrationResponseJSON,
}

#[near_sdk::near(serializers = [json])]
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
    pub client_extension_results: Option<serde_json::Value>,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)] // Added PartialEq
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "residentKey")]
    pub resident_key: Option<String>,
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

// Default matches JS `defaultAuthenticatorSelection` + `requireResidentKey` logic
impl Default for AuthenticatorSelectionCriteria {
    fn default() -> Self {
        Self {
            // JS doesn't set this by default unless preferredAuthenticatorType is used
            authenticator_attachment: None,
            resident_key: Some("preferred".to_string()),
            require_resident_key: Some(false),
            // JS default for requireResidentKey is false if residentKey is 'preferred'
            user_verification: Some("preferred".to_string()),
        }
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)] // Added PartialEq
pub struct AuthenticationExtensionsClientInputsJSON {
    #[serde(rename = "credProps")]
    pub cred_props: Option<bool>,
}

impl Default for AuthenticationExtensionsClientInputsJSON {
    fn default() -> Self {
        Self {
            cred_props: Some(true), // JS sets this to true
        }
    }
}

#[near_sdk::near(serializers = [json])]
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

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    #[serde(rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "hmacCreateSecret", skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,
    #[serde(rename = "minPinLength", skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
}

impl Default for AuthenticationExtensionsClientInputs {
    fn default() -> Self {
        Self {
            appid: None,
            cred_props: None,
            hmac_create_secret: None,
            min_pin_length: None,
        }
    }
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyCredentialRequestOptionsJSON {
    pub challenge: String, // Base64URL encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

// Authentication verification types (equivalent to @simplewebauthn/server types)
#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct AuthenticationResponseJSON {
    pub id: String, // Base64URL credential ID
    #[serde(rename = "rawId")]
    pub raw_id: String, // Base64URL credential ID
    pub response: AuthenticatorAssertionResponseJSON,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    pub type_: String, // Should be "public-key"
    #[serde(rename = "clientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub client_extension_results: Option<serde_json::Value>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionResponseJSON {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // Base64URL encoded
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String, // Base64URL encoded
    pub signature: String, // Base64URL encoded
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>, // Base64URL encoded
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct AuthenticatorDevice {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub counter: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct VerifiedAuthenticationResponse {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_info: Option<AuthenticationInfo>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct AuthenticationInfo {
    pub credential_id: Vec<u8>,
    pub new_counter: u32,
    pub user_verified: bool,
    pub credential_device_type: String, // "singleDevice" or "multiDevice"
    pub credential_backed_up: bool,
    pub origin: String,
    pub rp_id: String,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// Complete registration using an on-chain commitment
    /// This method is called by the client with the WebAuthn response to complete the registration
    pub fn verify_registration_response(
        &mut self,
        registration_response: RegistrationResponseJSON,
        commitment_id: String,
    ) -> VerifiedRegistrationResponse {
        log!("Verifying registration with on-chain commitment id: {}", commitment_id);

        let (user_id, yield_resume_id) = match self.pending_prunes.get(&commitment_id) {
            None => {
                log!("No pending authentication found for commitment_id: {}", commitment_id);
                panic!("No pending authentication found for commitment_id: {}", commitment_id);
            }
            Some(user_id_yield_id) => {
                let user_id = user_id_yield_id.user_id.clone();
                let yield_resume_id: CryptoHash = user_id_yield_id.yield_resume_id.clone().try_into()
                    .expect("Invalid yield_resume_id format in pending_prunes");
                (user_id, yield_resume_id)
            }
        };

        require!(
            env::predecessor_account_id() == user_id,
            "user must be the one who created the commitment_id"
        );

        // 1. Fetch and remove the pending registration data
        let yield_data = match self.pending_registrations.remove(&commitment_id) {
            Some(data) => data,
            None => {
                log!("No pending registration found for commitment_id: {}", commitment_id);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        log!("Pruning auth commitment by resuming yield with id: {:?}", yield_resume_id);
        env::promise_yield_resume(&yield_resume_id, &[]);

        log!("Found and removed pending registration data. Proceeding with verification.");
        // 2. Use internal_process_registration with the stored data
        self.internal_process_registration(
            yield_data.commitment_b64url,
            yield_data.original_challenge_b64url,
            yield_data.salt_b64url,
            registration_response,
            yield_data.rp_id.clone(),
            yield_data.require_user_verification,
        )
    }

    /// This callback is triggered automatically by the runtime if the corresponding
    /// promise from `generate_registration_options` is not resumed within the timeout period.
    #[private]
    pub fn prune_commitment_callback(
        &mut self,
        commitment_id: String // "commitment_id" field from json! args in promise_yield_create()
    ) {
        log!("Pruning commitment via automatic callback: {}", commitment_id);
        require!(
            env::current_account_id() == env::predecessor_account_id(),
            "prune_commitment_callback can only be called by the contract itself"
        );

        // This callback is now responsible for cleaning up both maps.
        // It's idempotent - if the entry is already gone, it does nothing.
        self.pending_registrations.remove(&commitment_id);
        self.pending_prunes.remove(&commitment_id);
    }

    #[private]
    pub fn internal_process_registration(
        &mut self,
        commitment_b64url: String,
        original_challenge_b64url: String,
        salt_b64url: String,
        attestation_response: RegistrationResponseJSON,
        rp_id: String,
        require_user_verification: bool,
    ) -> VerifiedRegistrationResponse {
        log!("Internal: Processing registration with commitment verification");

        // 1. Decode salt and original_challenge
        let original_challenge_bytes = match BASE64_URL_ENGINE.decode(&original_challenge_b64url) {
            Ok(b) => b, Err(_) => { log!("Failed to decode original_challenge_b64url"); return VerifiedRegistrationResponse{verified:false, registration_info:None}; }
        };
        let salt_bytes = match BASE64_URL_ENGINE.decode(&salt_b64url) {
            Ok(b) => b, Err(_) => { log!("Failed to decode salt_b64url"); return VerifiedRegistrationResponse{verified:false, registration_info:None}; }
        };
        let commitment_hash_bytes_from_client = match BASE64_URL_ENGINE.decode(&commitment_b64url) {
            Ok(b) => b, Err(_) => { log!("Failed to decode commitment_b64url from client/args"); return VerifiedRegistrationResponse{verified:false, registration_info:None}; }
        };

        // 2. Recompute commitment
        let mut recomputed_commitment_input = Vec::new();
        recomputed_commitment_input.extend_from_slice(&original_challenge_bytes);
        recomputed_commitment_input.extend_from_slice(&salt_bytes);
        let recomputed_commitment_hash_bytes = env::sha256(&recomputed_commitment_input);

        // 3. Verify commitment
        if recomputed_commitment_hash_bytes != commitment_hash_bytes_from_client {
            log!("Commitment mismatch!");
            log!("Recomputed: {:?}", BASE64_URL_ENGINE.encode(&recomputed_commitment_hash_bytes));
            log!("From Client/Yield: {:?}", commitment_b64url);
            return VerifiedRegistrationResponse { verified: false, registration_info: None };
        }
        log!("Commitment verified successfully!");

        // 4. Derive expected origin from rp_id
        let expected_origin = format!("https://{}", rp_id);
        let expected_rp_id = rp_id;

        // 5. Call the WebAuthn verification logic
        self.internal_verify_registration_response(
            attestation_response,
            original_challenge_b64url,
            expected_origin,
            expected_rp_id,
            require_user_verification,
        )
    }

    // This is the core WebAuthn attestation verification logic
    #[private]
    pub fn internal_verify_registration_response(
        &mut self,
        attestation_response: RegistrationResponseJSON,
        expected_challenge: String, // This is the original_challenge_b64url after commitment check
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
        // 7. Derive NEAR public key from COSE format

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
            None, // name starts as None
            current_timestamp,
            backed_up,
        );

        // Phase 2: Register user in user registry if not already registered
        if !self.registered_users.contains(&user_account_id) {
            log!("Registering new user in user registry: {}", user_account_id);
            // Use account ID as username for contract-based registrations
            let username = user_account_id.to_string();
            self.register_user(user_account_id.clone(), Some(username));
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
            }),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
    use base64::Engine as TestEngine;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use std::collections::BTreeMap;

    // Helper to get a VMContext, random_seed is still useful for internal challenge/userID generation
    fn get_context_with_seed(random_byte_val: u8) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let seed: Vec<u8> = (0..32).map(|_| random_byte_val).collect(); // Create a seed with all same byte for predictability
        builder
            .current_account_id(accounts(0))
            .signer_account_id(accounts(1))
            .predecessor_account_id(accounts(1))
            .is_view(false) // Important: derive_near_pk_from_cose uses env::sha256 which is not view-only
            .random_seed(seed.try_into().unwrap()); // try_into converts Vec<u8> to [u8; 32]
        builder
    }

    fn build_ed25519_cose_key(x_coord: &[u8; 32]) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(CborValue::Integer(1), CborValue::Integer(1)); // kty: OKP
        map.insert(CborValue::Integer(3), CborValue::Integer(-8)); // alg: EdDSA
        map.insert(CborValue::Integer(-2), CborValue::Bytes(x_coord.to_vec())); // x
        serde_cbor::to_vec(&CborValue::Map(map)).unwrap()
    }


    #[test]
    fn test_verify_registration_response_invalid_challenge() {
        let context = get_context_with_seed(14);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::init("test-contract".to_string());

        // Create mock client data with wrong challenge
        let client_data = r#"{"type":"webauthn.create","challenge":"wrong_challenge","origin":"https://example.com","crossOrigin":false}"#;
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create minimal mock attestation object
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        );
        // Mock authData that would be part of attestation_object
        let mock_auth_data_bytes = vec![0u8; 37]; // Minimal valid length for authData
        attestation_map.insert(
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(mock_auth_data_bytes),
        );
        attestation_map.insert(
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(BTreeMap::new()),
        );
        let attestation_object_bytes =
            serde_cbor::to_vec(&CborValue::Map(attestation_map)).unwrap();
        let attestation_object_b64 = TEST_BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        let mock_response = RegistrationResponseJSON {
            id: "test_credential".to_string(),
            raw_id: TEST_BASE64_URL_ENGINE.encode(b"test_credential"),
            response: AttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
                transports: None,
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: None,
        };

        // For testing internal_process_registration directly:
        let original_challenge_bytes = b"expected_challenge";
        let salt_bytes = b"test_salt_123456";
        let mut commitment_input = Vec::new();
        commitment_input.extend_from_slice(original_challenge_bytes);
        commitment_input.extend_from_slice(salt_bytes);
        let commitment_hash_bytes = env::sha256(&commitment_input);
        let commitment_b64url = BASE64_URL_ENGINE.encode(&commitment_hash_bytes);

        // This is the challenge the client *actually* signed (the wrong one)
        let signed_challenge_b64url = "wrong_challenge".to_string();
        let salt_b64url_for_call = BASE64_URL_ENGINE.encode(salt_bytes);

        let result = contract.internal_process_registration(
            commitment_b64url, // Commitment made with "expected_challenge"
            signed_challenge_b64url, // Client returns the challenge it signed, "wrong_challenge"
            salt_b64url_for_call,    // Salt used for the commitment
            mock_response,           // The attestation_response
            "https://example.com".to_string(), // expected_origin
            false, // require_user_verification for this test case
        );

        // The commitment check should fail first if original_challenge_b64url != signed_challenge_b64url_from_client_data
        // OR the clientDataJSON challenge check should fail.
        assert!(!result.verified, "Should fail verification due to challenge mismatch or commitment mismatch");
        assert!(result.registration_info.is_none());
    }

    #[test]
    fn test_verify_registration_response_invalid_origin() {
        let context = get_context_with_seed(15);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::init("test-contract".to_string());

        // Create mock client data with wrong origin
        let client_data = r#"{"type":"webauthn.create","challenge":"test_challenge","origin":"https://evil.com","crossOrigin":false}"#;
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create minimal mock attestation object
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        );
        let mock_auth_data_bytes = vec![0u8; 37];
        attestation_map.insert(
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(mock_auth_data_bytes),
        );
        attestation_map.insert(
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(BTreeMap::new()),
        );
        let attestation_object_bytes =
            serde_cbor::to_vec(&CborValue::Map(attestation_map)).unwrap();
        let attestation_object_b64 = TEST_BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        let mock_response = RegistrationResponseJSON {
            id: "test_credential".to_string(),
            raw_id: TEST_BASE64_URL_ENGINE.encode(b"test_credential"),
            response: AttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
                transports: None,
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: None,
        };

        // For testing internal_process_registration directly:
        let original_challenge_bytes = b"test_challenge";
        let salt_bytes = b"test_salt_origin";
        let mut commitment_input = Vec::new();
        commitment_input.extend_from_slice(original_challenge_bytes);
        commitment_input.extend_from_slice(salt_bytes);
        let commitment_hash_bytes = env::sha256(&commitment_input);
        let commitment_b64url = BASE64_URL_ENGINE.encode(&commitment_hash_bytes);
        let original_challenge_b64url = BASE64_URL_ENGINE.encode(original_challenge_bytes);
        let salt_b64url_for_call = BASE64_URL_ENGINE.encode(salt_bytes);

        let result = contract.internal_process_registration(
            commitment_b64url,
            original_challenge_b64url,
            salt_b64url_for_call,
            mock_response,
            "https://example.com".to_string(), // Correct expected_origin
            false, // require_user_verification for this test case
        );

        assert!(!result.verified, "Should fail verification due to origin mismatch");
        assert!(result.registration_info.is_none());
    }

    #[test]
    fn test_verify_registration_response_real_webauthn_data() {
        let context = get_context_with_seed(16);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::init("test-contract".to_string());

        let client_extension_results = serde_json::json!({
            "credProps": {"rk": true},
            "prf": {"enabled": true, "results": {"first": {}}}
        });

        let challenge_b64url_signed_by_client = "rgLuoFhK5d3by9oCS1f4tA".to_string();

        let client_data_json_str = format!(r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://example.localhost","crossOrigin":false}}"#, challenge_b64url_signed_by_client);
        let client_data_b64_for_attestation = TEST_BASE64_URL_ENGINE.encode(client_data_json_str.as_bytes());

        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        );
        attestation_map.insert(
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(BTreeMap::new()),
        );

        // Create minimal valid authenticator data
        let mut auth_data = Vec::new();
        // RP ID hash (32 bytes) - SHA256 of "example.localhost"
        let rp_id_hash = env::sha256(b"example.localhost");
        auth_data.extend_from_slice(&rp_id_hash);
        // add the UV (User Verification) flag to the authenticator data. The flags are now:
        // Flags (1 byte) - UP (0x01) + UV (0x04) + AT (0x40) = 0x45
        // 0x01 = UP (User Present)
        // 0x04 = UV (User Verified)
        // 0x40 = AT (Attested credential data present)
        auth_data.push(0x45);
        // Counter (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x00u8; 16]);
        // Credential ID length (2 bytes)
        let cred_id = b"FambqICu3jJ2QcaJF038gw";
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        // Credential ID
        auth_data.extend_from_slice(cred_id);

        // Add a minimal COSE Ed25519 public key
        let x_coord = [0x01u8; 32]; // Mock Ed25519 public key
        let cose_key = build_ed25519_cose_key(&x_coord);
        auth_data.extend_from_slice(&cose_key);

        attestation_map.insert(
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(auth_data),
        );
        let attestation_object_bytes =
            serde_cbor::to_vec(&CborValue::Map(attestation_map)).unwrap();
        let attestation_object_b64_for_attestation = TEST_BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        let realistic_response = RegistrationResponseJSON {
            id: "FambqICu3jJ2QcaJF038gw".to_string(),
            raw_id: "FambqICu3jJ2QcaJF038gw".to_string(),
            response: AttestationResponse {
                client_data_json: client_data_b64_for_attestation,
                attestation_object: attestation_object_b64_for_attestation,
                transports: Some(vec!["hybrid".to_string(), "internal".to_string()]),
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: Some(client_extension_results),
        };

        // For commitment, use the *decoded* challenge bytes
        let challenge_bytes_for_commitment = BASE64_URL_ENGINE.decode(&challenge_b64url_signed_by_client).unwrap();
        let salt_bytes = b"test_salt_real_data";
        let mut commitment_input = Vec::new();
        commitment_input.extend_from_slice(&challenge_bytes_for_commitment);
        commitment_input.extend_from_slice(salt_bytes);
        let commitment_hash_bytes = env::sha256(&commitment_input);
        let commitment_b64url_to_yield_or_pass = BASE64_URL_ENGINE.encode(&commitment_hash_bytes);
        let salt_b64url_for_call = BASE64_URL_ENGINE.encode(salt_bytes);

        let result = contract.internal_process_registration(
            commitment_b64url_to_yield_or_pass, // This is what the contract would have yielded/stored
            challenge_b64url_signed_by_client.clone(), // This is what the client sends back, and what clientDataJSON contains
            salt_b64url_for_call,
            realistic_response,
            "example.localhost".to_string(), // rp_id
            true, // require_user_verification for this test case
        );

        assert!(result.verified, "Should verify successfully with realistic data");
        assert!(result.registration_info.is_some(), "Should return registration info");
        if let Some(reg_info) = result.registration_info {
            assert_eq!(reg_info.credential_id, b"FambqICu3jJ2QcaJF038gw");
            assert_eq!(reg_info.user_id, "FambqICu3jJ2QcaJF038gw");
            assert!(reg_info.credential_public_key.len() > 0, "Should have credential public key");
            assert_eq!(reg_info.counter, 1);
        }
    }

    #[test]
    fn test_verify_registration_response_json_deserialization() {
        let context = get_context_with_seed(17);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::init("test-contract".to_string());

        // Test that we can properly deserialize the exact JSON structure from the browser
        let json_input = r#"{
            "attestation_response": {
                "id": "FambqICu3jJ2QcaJF038gw",
                "rawId": "FambqICu3jJ2QcaJF038gw",
                "type": "public-key",
                "clientExtensionResults": {
                    "credProps": {"rk": true},
                    "prf": {"enabled": true, "results": {"first": {}}}
                },
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicmdMdW9GaEs1ZDNieTlvQ1MxZjR0QSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEBWpm6iArt4ydkHGiRdN_IOlAQIDJiABIVggtuG49LMrMgD59dVNmZhO6Z96-yfTjGvTKDjXkXONNk0iWCD5TXGcAAOfarCRsoJwNMAKo4PBb4rpXF5XgYdyJ4-0DQ",
                    "transports": ["hybrid", "internal"]
                }
            },
            "expected_challenge": "rgLuoFhK5d3by9oCS1f4tA",
            "expected_origin": "https://example.localhost",
            "expected_rp_id": "example.localhost",
            "require_user_verification": true
        }"#;

        // Parse the JSON to test deserialization
        let parsed: serde_json::Value =
            serde_json::from_str(json_input).expect("Should parse JSON");
        let attestation_response_json = &parsed["attestation_response"];

        // Try to deserialize the attestation_response part
        let attestation_response: Result<RegistrationResponseJSON, _> =
            serde_json::from_value(attestation_response_json.clone());

        match attestation_response {
            Ok(response) => {
                println!("Successfully deserialized RegistrationResponseJSON");
                assert_eq!(response.id, "FambqICu3jJ2QcaJF038gw");
                assert_eq!(response.raw_id, "FambqICu3jJ2QcaJF038gw");
                assert_eq!(response.type_, "public-key");
                assert!(response.client_extension_results.is_some());

                // For testing internal_process_registration directly:
                let original_challenge_bytes = b"rgLuoFhK5d3by9oCS1f4tA";
                let salt_bytes = b"test_salt_json_deser";
                let mut commitment_input = Vec::new();
                commitment_input.extend_from_slice(original_challenge_bytes);
                commitment_input.extend_from_slice(salt_bytes);
                let commitment_hash_bytes = env::sha256(&commitment_input);
                let commitment_b64url = BASE64_URL_ENGINE.encode(&commitment_hash_bytes);
                let original_challenge_b64url = BASE64_URL_ENGINE.encode(original_challenge_bytes);
                let salt_b64url_for_call = BASE64_URL_ENGINE.encode(salt_bytes);

                // Test the contract call with this data
                let result = contract.internal_process_registration(
                    commitment_b64url,
                    original_challenge_b64url,
                    salt_b64url_for_call,
                    response, // The deserialized attestation_response
                    "example.localhost".to_string(), // rp_id
                    true, // require_user_verification for this test case
                );

                // This test primarily checks deserialization.
                // The actual verification might fail if the mock attestationObject isn't perfectly valid for "none" fmt.
                // We care that it doesn't panic on deserialization of the input struct.
                println!("Contract verification call completed. Verified: {}", result.verified);
            }
            Err(e) => {
                panic!("Failed to deserialize RegistrationResponseJSON: {}", e);
            }
        }
    }

}
