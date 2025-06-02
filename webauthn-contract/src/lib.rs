mod verifiers;
mod parsers;
mod p256_utils;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near, CryptoHash, Gas, GasWeight};
use serde_cbor::Value as CborValue;
use crate::parsers::{
    parse_attestation_object,
    parse_authenticator_data
};
use crate::verifiers::verify_attestation_signature;

const DEFAULT_CHALLENGE_SIZE: usize = 16;
const DATA_ID_REGISTER: u64 = 0;

// Structure to hold yielded registration data
#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
struct YieldedRegistrationData {
    commitment_b64url: String,
    original_challenge_b64url: String,
    salt_b64url: String,
    rp_id: String, // Store rp_id to derive origin and for verification
    require_user_verification: bool,
}

// Structure to hold registration completion data
#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
struct RegistrationCompletionData {
    registration_response: RegistrationResponseJSON,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct RpEntity {
    pub name: String,
    pub id: String,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct UserEntity {
    pub id: String, // base64url encoded Vec<u8>
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct PubKeyCredParam {
    pub alg: i32,
    #[serde(rename = "type")]
    pub type_: String,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticatorTransport {
    #[serde(rename = "usb")]
    Usb,
    #[serde(rename = "nfc")]
    Nfc,
    #[serde(rename = "ble")]
    Ble,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "hybrid")]
    Hybrid,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, Default, PartialEq)] // Added PartialEq
pub struct PublicKeyCredentialDescriptorJSON {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String, // base64url encoded
    pub transports: Option<Vec<AuthenticatorTransport>>,
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

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyCredentialCreationOptionsJSON {
    pub challenge: String,
    pub rp: RpEntity,
    pub user: UserEntity,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u64,
    pub attestation: String,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptorJSON>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    pub extensions: AuthenticationExtensionsClientInputsJSON,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<String>>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RegistrationOptionsWithYieldInfo {
    #[serde(flatten)]
    pub options: PublicKeyCredentialCreationOptionsJSON,
    pub salt_b64url: String,
    pub data_id_b64url: String,
    #[serde(rename = "derpAccountId")]
    pub derp_account_id: Option<String>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RegistrationOptionsJSON {
    #[serde(flatten)]
    pub options: PublicKeyCredentialCreationOptionsJSON,
    #[serde(rename = "derpAccountId")]
    pub derp_account_id: Option<String>,
    #[serde(rename = "dataId")]
    pub data_id: Option<String>, // Base64url encoded data_id for yield-resume
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

// WebAuthn verification structures
#[derive(serde::Deserialize, Debug)]
struct ClientDataJSON {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near(contract_state)]
pub struct WebAuthnContract {
    greeting: String,
    contract_name: String,
}

impl Default for WebAuthnContract {
    fn default() -> Self {
        Self {
            greeting: "Hello".to_string(),
            contract_name: "webauthn-contract.testnet".to_string(),
        }
    }
}

#[near]
impl WebAuthnContract {

    #[init]
    pub fn init(contract_name: String) -> Self {
        Self {
            contract_name,
            greeting: "Hello".to_string(),
        }
    }

    pub fn get_greeting(&self) -> String {
        self.greeting.clone()
    }

    pub fn set_greeting(&mut self, greeting: String) {
        log!("Saving greeting: {}", greeting);
        self.greeting = greeting;
    }

    pub fn get_contract_name(&self) -> String {
        self.contract_name.clone()
    }

    pub fn set_contract_name(&mut self, contract_name: String) {
        log!("Saving contract name: {}", contract_name);
        self.contract_name = contract_name;
    }

    fn generate_challenge_bytes(&self) -> Vec<u8> {
        let seed = env::random_seed();
        seed.into_iter().take(DEFAULT_CHALLENGE_SIZE).collect() // Or full seed if preferred
    }

    /// YIELD-RESUME REGISTRATION FLOW
    /// This yield-resume implementation eliminates server-side challenge storage
    pub fn generate_registration_options(
        &mut self,
        rp_name: String,
        rp_id: String,
        user_name: String,
        user_id: String,
        challenge: Option<String>,
        user_display_name: Option<String>,
        timeout: Option<u64>,
        attestation_type: Option<String>,
        exclude_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        extensions: Option<AuthenticationExtensionsClientInputsJSON>,
        supported_algorithm_ids: Option<Vec<i32>>,
        preferred_authenticator_type: Option<String>,
    ) -> String {
        // 1. Generate challenge and salt
        let (challenge_bytes, challenge_b64url) = match challenge {
            Some(c) => {
                let bytes = BASE64_URL_ENGINE.decode(&c).expect("Failed to decode provided challenge");
                (bytes, c)
            }
            None => {
            let bytes = self.generate_challenge_bytes();
                let b64url = BASE64_URL_ENGINE.encode(&bytes);
                (bytes, b64url)
            }
        };

        let salt_bytes = env::random_seed().iter().copied().take(16).collect::<Vec<u8>>();
        let salt_b64url = BASE64_URL_ENGINE.encode(&salt_bytes);

        // 2. Compute commitment
        let mut commitment_input = Vec::new();
        commitment_input.extend_from_slice(&challenge_bytes);
        commitment_input.extend_from_slice(&salt_bytes);
        let commitment_hash_bytes = env::sha256(&commitment_input);
        let commitment_b64url = BASE64_URL_ENGINE.encode(&commitment_hash_bytes);

        // 3. Generate options (same logic as before)
        let final_user_id_b64url = user_id;
        let final_user_display_name = user_display_name.unwrap_or_else(|| "".to_string());
        let final_timeout = timeout.unwrap_or(60000);
        let final_attestation_type = attestation_type.unwrap_or_else(|| "none".to_string());
        let final_exclude_credentials = exclude_credentials.unwrap_or_else(Vec::new);
        let mut final_authenticator_selection = authenticator_selection.unwrap_or_default();
        if final_authenticator_selection.resident_key.is_none() {
            if final_authenticator_selection.require_resident_key == Some(true) {
                final_authenticator_selection.resident_key = Some("required".to_string());
            }
        } else {
            final_authenticator_selection.require_resident_key =
                Some(final_authenticator_selection.resident_key == Some("required".to_string()));
        }
        let require_user_verification_for_yield = final_authenticator_selection.user_verification == Some("required".to_string());

        let mut final_extensions = extensions.unwrap_or_default();
        final_extensions.cred_props = Some(true);
        let final_supported_algorithm_ids =
            supported_algorithm_ids.unwrap_or_else(|| vec![-8, -7, -257]);
        let pub_key_cred_params: Vec<PubKeyCredParam> = final_supported_algorithm_ids
            .into_iter()
            .map(|alg| PubKeyCredParam {
                alg,
                type_: "public-key".to_string(),
            })
            .collect();
        let mut hints: Option<Vec<String>> = None;
        if let Some(pref_auth_type) = preferred_authenticator_type {
            let mut current_hints = Vec::new();
            match pref_auth_type.as_str() {
                "securityKey" => {
                    current_hints.push("security-key".to_string());
                    final_authenticator_selection.authenticator_attachment =
                        Some("cross-platform".to_string());
                }
                "localDevice" => {
                    current_hints.push("client-device".to_string());
                    final_authenticator_selection.authenticator_attachment =
                        Some("platform".to_string());
                }
                "remoteDevice" => {
                    current_hints.push("hybrid".to_string());
                    final_authenticator_selection.authenticator_attachment =
                        Some("cross-platform".to_string());
                }
                _ => {}
            }
            if !current_hints.is_empty() {
                hints = Some(current_hints);
            }
        }

        let options = PublicKeyCredentialCreationOptionsJSON {
            challenge: challenge_b64url.clone(),
            rp: RpEntity {
                name: rp_name.clone(),
                id: rp_id.clone(),
            },
            user: UserEntity {
                id: final_user_id_b64url,
                name: user_name.clone(),
                display_name: final_user_display_name,
            },
            pub_key_cred_params,
            timeout: final_timeout,
            attestation: final_attestation_type,
            exclude_credentials: final_exclude_credentials,
            authenticator_selection: final_authenticator_selection,
            extensions: final_extensions,
            hints,
        };
        let suggested_derp_account_id = format!("{}.{}", options.user.name, self.contract_name);

        // 4. Create yield data
        let yield_data = YieldedRegistrationData {
            commitment_b64url,
            original_challenge_b64url: challenge_b64url,
            salt_b64url,
            rp_id: rp_id.clone(),
            require_user_verification: require_user_verification_for_yield,
        };

        // 5. Yield with the data
        let yield_args_bytes = serde_json::to_vec(&yield_data).expect("Failed to serialize yield data");

        env::promise_yield_create(
            "resume_registration_callback",
            &yield_args_bytes,
            Gas::from_tgas(10), // Reduced from 50 to 10 TGas
            GasWeight(1),
            DATA_ID_REGISTER,
        );

        // Read the data_id from the register
        let data_id_bytes = env::read_register(DATA_ID_REGISTER)
            .expect("Failed to read data_id from register after yield creation");
        let data_id_b64url = BASE64_URL_ENGINE.encode(&data_id_bytes);

        log!("Yielding registration with commitment stored securely, data_id: {}", data_id_b64url);

        // 6. Return only the options (without commitment info)
        let response = RegistrationOptionsJSON {
            options,
            derp_account_id: Some(suggested_derp_account_id),
            // data_id: Some(data_id_b64url),
            data_id: None,
        };

        serde_json::to_string(&response).expect("Failed to serialize registration options")
    }

    /// Complete registration using yield-resume pattern
    /// This method is called by the client with the WebAuthn response to resume the yielded execution
    pub fn complete_registration(
        &self,
        registration_response: RegistrationResponseJSON,
        data_id: Option<String>, // Optional data_id for testing
    ) -> bool {
        // Get the data_id from parameter (for testing) or from the register (normal flow)
        let data_id_bytes = if let Some(data_id_str) = data_id {
            BASE64_URL_ENGINE.decode(&data_id_str)
                .expect("Failed to decode provided data_id")
        } else {
            env::read_register(DATA_ID_REGISTER)
                .expect("Failed to read data_id from register")
        };

        // The data_id should be a CryptoHash (32 bytes)
        let data_id: CryptoHash = data_id_bytes
            .try_into()
            .expect("Invalid data_id format - expected 32 bytes");

        // Create completion data structure
        let completion_data = RegistrationCompletionData {
            registration_response,
        };

        // Serialize the completion data
        let response_bytes = serde_json::to_vec(&completion_data)
            .expect("Failed to serialize registration completion data");

        // Resume execution with the registration response
        env::promise_yield_resume(&data_id, &response_bytes);

        log!("Resuming registration with user's WebAuthn response");
        true
    }

    /// Callback method for yield-resume registration flow
    /// This method is called when the yield is resumed with the registration response
    #[private]
    pub fn resume_registration_callback(&mut self) -> VerifiedRegistrationResponse {
        // Get the yielded data from promise result 0
        let yield_data_bytes = match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(data) => data,
            _ => {
                log!("Failed to retrieve yielded data");
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        let yield_data: YieldedRegistrationData = match serde_json::from_slice(&yield_data_bytes) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to parse yielded registration data: {}", e);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Get the registration completion data from promise result 1
        let response_bytes = match env::promise_result(1) {
            near_sdk::PromiseResult::Successful(data) => data,
            _ => {
                log!("Failed to retrieve registration completion data");
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        let completion_data: RegistrationCompletionData = match serde_json::from_slice(&response_bytes) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to parse registration completion data: {}", e);
                return VerifiedRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        log!("Processing registration callback with yielded commitment");

        // Use internal_process_registration with the yielded data and verification parameters
        self.internal_process_registration(
            yield_data.commitment_b64url,
            yield_data.original_challenge_b64url,
            yield_data.salt_b64url,
            completion_data.registration_response,
            yield_data.rp_id.clone(),
            yield_data.require_user_verification,
        )
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
        self.verify_registration_response(
            attestation_response,
            original_challenge_b64url,
            expected_origin,
            expected_rp_id,
            require_user_verification,
        )
    }

    // This is the core WebAuthn attestation verification logic
    fn verify_registration_response(
        &self,
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

        // Step 6: WebAuthn verification successful
        log!("Registration verification successful");
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

    const DEFAULT_USER_ID_SIZE: usize = 16;

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

    #[test]
    fn test_generate_registration_options_defaults() {
        let context = get_context_with_seed(1); // Use a predictable seed
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        let rp_name = "My Passkey App".to_string();
        let rp_id = "example.localhost".to_string();
        let user_name = "testuser".to_string();

        // user_id is now a mandatory String (base64url encoded)
        let default_user_id_bytes: Vec<u8> = (0..DEFAULT_USER_ID_SIZE).map(|_| 1).collect();
        let default_user_id_b64url = TEST_BASE64_URL_ENGINE.encode(&default_user_id_bytes);

        let result_json = contract.generate_registration_options(
            rp_name.clone(),
            rp_id.clone(),
            user_name.clone(),
            default_user_id_b64url.clone(), // Provide String for user_id
            None,                           // challenge: Option<String> -> contract generates
            None,                           // userDisplayName
            None,                           // timeout
            None,                           // attestationType
            None,                           // excludeCredentials
            None,                           // authenticatorSelection
            None,                           // extensions
            None,                           // supportedAlgorithmIDs
            None,                           // preferredAuthenticatorType
        );

        // Parse the JSON response
        let result: RegistrationOptionsJSON = serde_json::from_str(&result_json)
            .expect("Failed to parse registration options JSON");
        let options = result.options;

        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 1).collect();
        let expected_challenge_b64url = TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes);
        assert_eq!(options.challenge, expected_challenge_b64url);

        assert_eq!(options.user.id, default_user_id_b64url);
        assert_eq!(options.user.name, user_name);
        assert_eq!(options.user.display_name, "");
        assert_eq!(options.rp.name, rp_name);
        assert_eq!(options.rp.id, rp_id.clone());
        assert_eq!(options.pub_key_cred_params.len(), 3);
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -8));
        assert_eq!(options.timeout, 60000);
        assert_eq!(options.attestation, "none");
        assert_eq!(options.exclude_credentials, Vec::new());
        let expected_auth_selection = AuthenticatorSelectionCriteria::default();
        assert_eq!(options.authenticator_selection, expected_auth_selection);
        assert_eq!(options.extensions.cred_props, Some(true));
        assert!(options.hints.is_none());
        let expected_derp_id = format!("{}.{}", user_name, contract.contract_name); // Use contract_name from state
        assert_eq!(result.derp_account_id, Some(expected_derp_id));
    }

    #[test]
    fn test_generate_registration_options_with_overrides() {
        let context = get_context_with_seed(2);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        let user_id_bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let challenge_bytes = vec![
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
        ];

        let user_id_b64url_input = TEST_BASE64_URL_ENGINE.encode(&user_id_bytes);
        let challenge_b64url_input = TEST_BASE64_URL_ENGINE.encode(&challenge_bytes);

        let custom_display_name = "Custom Name".to_string();
        let custom_timeout = 120000u64;
        let custom_attestation = "direct".to_string();
        let custom_exclude = vec![PublicKeyCredentialDescriptorJSON {
            id: TEST_BASE64_URL_ENGINE.encode(b"cred-id-123"),
            type_: "public-key".to_string(),
            transports: Some(vec![AuthenticatorTransport::Usb]),
        }];
        let custom_auth_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: Some("platform".to_string()),
            resident_key: Some("required".to_string()),
            require_resident_key: None,
            user_verification: Some("required".to_string()),
        };
        let custom_extensions = AuthenticationExtensionsClientInputsJSON {
            cred_props: Some(false),
        };
        let custom_alg_ids = vec![-7, -36];
        let custom_pref_auth_type = "securityKey".to_string();

        let result_json = contract.generate_registration_options(
            "RP".to_string(),
            "rp.example".to_string(),
            "user".to_string(),
            user_id_b64url_input.clone(), // Pass String for user_id
            Some(challenge_b64url_input.clone()), // Pass Option<String> for challenge
            Some(custom_display_name.clone()),
            Some(custom_timeout),
            Some(custom_attestation.clone()),
            Some(custom_exclude.clone()),
            Some(custom_auth_selection.clone()),
            Some(custom_extensions.clone()),
            Some(custom_alg_ids.clone()),
            Some(custom_pref_auth_type.clone()),
        );

        // Parse the JSON response
        let result: RegistrationOptionsJSON = serde_json::from_str(&result_json)
            .expect("Failed to parse registration options JSON");
        let options = result.options;

        assert_eq!(options.challenge, challenge_b64url_input);
        assert_eq!(options.user.id, user_id_b64url_input);
        assert_eq!(options.user.display_name, custom_display_name);
        assert_eq!(options.timeout, custom_timeout);
        assert_eq!(options.attestation, custom_attestation);
        assert_eq!(options.exclude_credentials, custom_exclude);
        let mut expected_auth_sel = custom_auth_selection.clone();
        expected_auth_sel.require_resident_key = Some(true);
        expected_auth_sel.authenticator_attachment = Some("cross-platform".to_string());
        assert_eq!(options.authenticator_selection, expected_auth_sel);
        assert_eq!(options.extensions.cred_props, Some(true));
        assert_eq!(options.pub_key_cred_params.len(), 2);
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -7));
        assert_eq!(options.hints, Some(vec!["security-key".to_string()]));
        let expected_derp_id = format!("{}.{}", "user", contract.contract_name); // Updated user_name for derpId
        assert_eq!(result.derp_account_id, Some(expected_derp_id));
    }

    // Tests for derive_near_pk_from_cose
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
        let mut contract = WebAuthnContract::default();

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
        let mut contract = WebAuthnContract::default();

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
        let mut contract = WebAuthnContract::default();

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
        let mut contract = WebAuthnContract::default(); // Ensure mutable

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
