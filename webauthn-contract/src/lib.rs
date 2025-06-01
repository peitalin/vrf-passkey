use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey as P256PublicKey;
use serde_cbor::Value as CborValue;

const DEFAULT_CHALLENGE_SIZE: usize = 16;
const DEFAULT_USER_ID_SIZE: usize = 16;

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
            authenticator_attachment: None, // JS doesn't set this by default unless preferredAuthenticatorType is used
            resident_key: Some("preferred".to_string()),
            require_resident_key: Some(false), // JS default for requireResidentKey is false if residentKey is 'preferred'
            user_verification: Some("preferred".to_string()),
        }
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)] // Added PartialEq
pub struct AuthenticationExtensionsClientInputsJSON {
    #[serde(rename = "credProps")]
    pub cred_props: Option<bool>,
    // Other potential extensions can be added here if needed by the contract
}

impl Default for AuthenticationExtensionsClientInputsJSON {
    fn default() -> Self {
        Self {
            cred_props: Some(true), // JS sets this to true
        }
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)] // Added PartialEq
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
    pub hints: Option<Vec<String>>, // Added hints field
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct RegistrationOptionsWithDerpIdJSON {
    #[serde(flatten)]
    pub options: PublicKeyCredentialCreationOptionsJSON,
    #[serde(rename = "derpAccountId")]
    pub derp_account_id: Option<String>,
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

#[derive(Debug)]
struct AuthenticatorData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    counter: u32,
    attested_credential_data: Option<AttestedCredentialData>,
}

#[derive(Debug)]
struct AttestedCredentialData {
    aaguid: Vec<u8>,
    credential_id: Vec<u8>,
    credential_public_key: Vec<u8>,
}

#[near(contract_state)]
pub struct WebAuthnContract {
    greeting: String,
    contract_name: String,
    // current_challenge: Option<String>,
}

impl Default for WebAuthnContract {
    fn default() -> Self {
        Self {
            greeting: "Hello".to_string(),
            contract_name: "webauthn-contract.testnet".to_string(),
            // current_challenge: None,
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
            // current_challenge: None,
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

    /// YIELD-RESUME REGISTRATION FLOW (CONCEPTUAL FUTURE IMPLEMENTATION)
    /// This demonstrates how yield-resume could eliminate server-side challenge storage:
    ///
    /// Benefits of this approach:
    /// - Serverless Webauthn: No server-side challenge storage needed
    /// - Challenge is private in the contract state during yield
    /// - More decentralized architecture
    /// - Automatic timeout handling (200 blocks ≈ 20 minutes)

    /*
    // Future yield-resume methods to implement:
    pub fn start_registration(&mut self, username: String) -> Promise { ... }
    pub fn resume_registration(&mut self, data_id: CryptoHash, ...) -> Promise { ... }
    #[private] pub fn finish_registration(&mut self) -> VerifiedRegistrationResponse { ... }
    */

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
    ) -> RegistrationOptionsWithDerpIdJSON {
        let final_challenge_b64url = challenge.unwrap_or_else(|| {
            let bytes = self.generate_challenge_bytes();
            BASE64_URL_ENGINE.encode(&bytes)
        });
        // self.current_challenge = Some(final_challenge_b64url.clone());

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
            challenge: final_challenge_b64url,
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

        RegistrationOptionsWithDerpIdJSON {
            options,
            derp_account_id: Some(suggested_derp_account_id),
        }
    }

    /// Public method to verify registration response
    pub fn verify_registration_response_internal(
        &self,
        attestation_response: RegistrationResponseJSON,
        expected_challenge: String,
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
            match self.parse_attestation_object(&attestation_object) {
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
        let auth_data = match self.parse_authenticator_data(&auth_data_bytes) {
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
        match self.verify_attestation_signature(
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

        // Step 6: WebAuthn verification successful - store credential info only
        // SECURITY: Contract does NOT derive NEAR keys - frontend handles key generation
        // Frontend generates random NEAR keys and provides public key separately if needed
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

    fn parse_attestation_object(
        &self,
        attestation_object: &CborValue,
    ) -> Result<(Vec<u8>, CborValue, String), String> {
        if let CborValue::Map(map) = attestation_object {
            // Extract authData (required)
            let auth_data = map
                .get(&CborValue::Text("authData".to_string()))
                .ok_or("Missing authData in attestation object")?;

            let auth_data_bytes = if let CborValue::Bytes(bytes) = auth_data {
                bytes.clone()
            } else {
                return Err("authData must be bytes".to_string());
            };

            // Extract fmt (required)
            let fmt = map
                .get(&CborValue::Text("fmt".to_string()))
                .ok_or("Missing fmt in attestation object")?;

            let fmt_string = if let CborValue::Text(s) = fmt {
                s.clone()
            } else {
                return Err("fmt must be text".to_string());
            };

            // Extract attStmt (required)
            let att_stmt = map
                .get(&CborValue::Text("attStmt".to_string()))
                .ok_or("Missing attStmt in attestation object")?
                .clone();

            Ok((auth_data_bytes, att_stmt, fmt_string))
        } else {
            Err("Attestation object must be a CBOR map".to_string())
        }
    }

    fn parse_authenticator_data(
        &self,
        auth_data_bytes: &[u8],
    ) -> Result<AuthenticatorData, String> {
        if auth_data_bytes.len() < 37 {
            return Err("Authenticator data too short".to_string());
        }

        // Parse fixed-length portion
        let rp_id_hash = auth_data_bytes[0..32].to_vec();
        let flags = auth_data_bytes[32];
        let counter = u32::from_be_bytes([
            auth_data_bytes[33],
            auth_data_bytes[34],
            auth_data_bytes[35],
            auth_data_bytes[36],
        ]);

        let mut offset = 37;
        let mut attested_credential_data = None;

        // Check if attested credential data is present (AT flag = bit 6)
        if (flags & 0x40) != 0 {
            if auth_data_bytes.len() < offset + 18 {
                return Err("Authenticator data too short for attested credential data".to_string());
            }

            // Parse attested credential data
            let aaguid = auth_data_bytes[offset..offset + 16].to_vec();
            offset += 16;

            let credential_id_length =
                u16::from_be_bytes([auth_data_bytes[offset], auth_data_bytes[offset + 1]]) as usize;
            offset += 2;

            if auth_data_bytes.len() < offset + credential_id_length {
                return Err("Authenticator data too short for credential ID".to_string());
            }

            let credential_id = auth_data_bytes[offset..offset + credential_id_length].to_vec();
            offset += credential_id_length;

            // The rest is the credential public key (COSE format)
            let credential_public_key = auth_data_bytes[offset..].to_vec();

            attested_credential_data = Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key,
            });
        }

        Ok(AuthenticatorData {
            rp_id_hash,
            flags,
            counter,
            attested_credential_data,
        })
    }

    fn verify_attestation_signature(
        &self,
        att_stmt: &CborValue,
        auth_data: &[u8],
        client_data_hash: &[u8],
        credential_public_key: &[u8],
        fmt: &str,
    ) -> Result<bool, String> {
        match fmt {
            "none" => {
                // No signature to verify for "none" attestation
                Ok(true)
            }
            "packed" => self.verify_packed_signature(
                att_stmt,
                auth_data,
                client_data_hash,
                credential_public_key,
            ),
            "fido-u2f" => self.verify_u2f_signature(
                att_stmt,
                auth_data,
                client_data_hash,
                credential_public_key,
            ),
            _ => Err(format!("Unsupported attestation format: {}", fmt)),
        }
    }

    fn verify_packed_signature(
        &self,
        att_stmt: &CborValue,
        auth_data: &[u8],
        client_data_hash: &[u8],
        credential_public_key: &[u8],
    ) -> Result<bool, String> {
        if let CborValue::Map(stmt_map) = att_stmt {
            // Extract signature
            let signature_bytes = stmt_map
                .get(&CborValue::Text("sig".to_string()))
                .and_then(|v| {
                    if let CborValue::Bytes(b) = v {
                        Some(b)
                    } else {
                        None
                    }
                })
                .ok_or("Missing signature in packed attestation")?;

            // Extract algorithm (should be -7 for ES256)
            let alg = stmt_map
                .get(&CborValue::Text("alg".to_string()))
                .and_then(|v| {
                    if let CborValue::Integer(i) = v {
                        Some(*i)
                    } else {
                        None
                    }
                })
                .ok_or("Missing algorithm in packed attestation")?;

            if alg != -7 {
                return Err(format!(
                    "Unsupported algorithm: {} (expected -7 for ES256)",
                    alg
                ));
            }

            // For self-attestation (no x5c), verify against credential key
            if !stmt_map.contains_key(&CborValue::Text("x5c".to_string())) {
                return self.verify_p256_signature(
                    signature_bytes,
                    auth_data,
                    client_data_hash,
                    credential_public_key,
                );
            } else {
                // TODO: Handle full attestation with certificate chain
                return Err("Certificate chain attestation not yet supported".to_string());
            }
        }

        Err("Invalid attestation statement format".to_string())
    }

    fn verify_p256_signature(
        &self,
        signature_bytes: &[u8],
        auth_data: &[u8],
        client_data_hash: &[u8],
        cose_public_key: &[u8],
    ) -> Result<bool, String> {
        // Parse COSE public key to get P-256 coordinates
        let cose_key: CborValue = serde_cbor::from_slice(cose_public_key)
            .map_err(|_| "Failed to parse COSE public key")?;

        let (x_bytes, y_bytes) = self.extract_p256_coordinates_from_cose(&cose_key)?;

        // Create P-256 public key from coordinates
        let public_key = self.create_p256_public_key(&x_bytes, &y_bytes)?;

        // Create verification data: authData || clientDataHash
        let mut verification_data = auth_data.to_vec();
        verification_data.extend_from_slice(client_data_hash);

        // Parse signature (DER encoded)
        let signature =
            Signature::from_der(signature_bytes).map_err(|_| "Invalid signature format")?;

        // Verify signature
        use p256::ecdsa::signature::Verifier;
        match public_key.verify(&verification_data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn extract_p256_coordinates_from_cose(
        &self,
        cose_key: &CborValue,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if let CborValue::Map(map) = cose_key {
            let x = map
                .get(&CborValue::Integer(-2))
                .and_then(|v| {
                    if let CborValue::Bytes(b) = v {
                        Some(b.clone())
                    } else {
                        None
                    }
                })
                .ok_or("Missing x coordinate")?;

            let y = map
                .get(&CborValue::Integer(-3))
                .and_then(|v| {
                    if let CborValue::Bytes(b) = v {
                        Some(b.clone())
                    } else {
                        None
                    }
                })
                .ok_or("Missing y coordinate")?;

            if x.len() != 32 || y.len() != 32 {
                return Err("Invalid coordinate length (expected 32 bytes each)".to_string());
            }

            Ok((x, y))
        } else {
            Err("COSE key must be a map".to_string())
        }
    }

    fn create_p256_public_key(
        &self,
        x_bytes: &[u8],
        y_bytes: &[u8],
    ) -> Result<VerifyingKey, String> {
        // Create uncompressed point: 0x04 || x || y
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(x_bytes);
        uncompressed.extend_from_slice(y_bytes);

        // Create P-256 public key
        let public_key = P256PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|_| "Invalid P-256 public key")?;

        Ok(VerifyingKey::from(public_key))
    }

    fn verify_u2f_signature(
        &self,
        att_stmt: &CborValue,
        auth_data: &[u8],
        client_data_hash: &[u8],
        credential_public_key: &[u8],
    ) -> Result<bool, String> {
        log!("Starting FIDO U2F signature verification");

        // Extract signature from attestation statement
        let signature_bytes = if let CborValue::Map(stmt_map) = att_stmt {
            stmt_map
                .get(&CborValue::Text("sig".to_string()))
                .and_then(|v| {
                    if let CborValue::Bytes(b) = v {
                        Some(b)
                    } else {
                        None
                    }
                })
                .ok_or("Missing signature in U2F attestation statement")?
        } else {
            return Err("Invalid U2F attestation statement format".to_string());
        };

        log!("Extracted signature ({} bytes)", signature_bytes.len());

        // Parse authenticator data to extract components
        if auth_data.len() < 37 {
            return Err("Authenticator data too short for U2F".to_string());
        }

        // Extract RP ID hash (first 32 bytes of authData)
        let rp_id_hash = &auth_data[0..32];
        log!("RP ID hash: {:?}", rp_id_hash);

        // Extract credential ID from authenticator data
        // AuthData format: rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + credIdLen(2) + credId(variable) + pubKey(variable)
        if auth_data.len() < 55 {
            return Err("Authenticator data too short to contain credential".to_string());
        }

        // Skip to credential ID length (at offset 53)
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        if auth_data.len() < 55 + cred_id_len {
            return Err("Authenticator data too short for credential ID".to_string());
        }

        let credential_id = &auth_data[55..55 + cred_id_len];
        log!(
            "Credential ID ({} bytes): {:?}",
            credential_id.len(),
            credential_id
        );

        // Parse credential public key to get uncompressed P-256 point
        let uncompressed_pubkey = self.get_uncompressed_p256_pubkey(credential_public_key)?;
        log!(
            "Uncompressed public key ({} bytes)",
            uncompressed_pubkey.len()
        );

        // Construct U2F signature data: 0x00 || appParam || chlngParam || keyHandle || pubKey
        let mut u2f_signature_data = Vec::new();
        u2f_signature_data.push(0x00); // Reserved byte
        u2f_signature_data.extend_from_slice(rp_id_hash); // Application parameter (32 bytes)
        u2f_signature_data.extend_from_slice(client_data_hash); // Challenge parameter (32 bytes)
        u2f_signature_data.extend_from_slice(credential_id); // Key handle (variable)
        u2f_signature_data.extend_from_slice(&uncompressed_pubkey); // User public key (65 bytes)

        log!(
            "U2F signature data length: {} bytes",
            u2f_signature_data.len()
        );

        // For U2F attestation, we need the attestation certificate's public key
        // If no certificate is provided, we use self-attestation (credential public key)
        let verifying_key = if let CborValue::Map(stmt_map) = att_stmt {
            if let Some(_x5c) = stmt_map.get(&CborValue::Text("x5c".to_string())) {
                // Certificate chain present - extract public key from attestation certificate
                log!("U2F attestation with certificate chain - not yet implemented");
                return Err("U2F attestation with certificate chain not yet supported".to_string());
            } else {
                // Self-attestation - use credential public key
                log!("U2F self-attestation - using credential public key");
                let (x_bytes, y_bytes) =
                    self.extract_p256_coordinates_from_cose_value(credential_public_key)?;
                self.create_p256_public_key(&x_bytes, &y_bytes)?
            }
        } else {
            return Err("Invalid attestation statement format".to_string());
        };

        // Parse and verify signature
        let signature = p256::ecdsa::Signature::from_der(signature_bytes)
            .map_err(|_| "Invalid DER signature format")?;

        // Verify signature
        use p256::ecdsa::signature::Verifier;
        match verifying_key.verify(&u2f_signature_data, &signature) {
            Ok(()) => {
                log!("U2F signature verification successful");
                Ok(true)
            }
            Err(_) => {
                log!("U2F signature verification failed");
                Ok(false)
            }
        }
    }

    // Helper function to extract uncompressed P-256 public key from COSE format
    fn get_uncompressed_p256_pubkey(&self, cose_public_key: &[u8]) -> Result<Vec<u8>, String> {
        let (x_bytes, y_bytes) = self.extract_p256_coordinates_from_cose_value(cose_public_key)?;

        // Create uncompressed point format: 0x04 || x || y
        let mut uncompressed = Vec::with_capacity(65);
        uncompressed.push(0x04); // Uncompressed point indicator
        uncompressed.extend_from_slice(&x_bytes);
        uncompressed.extend_from_slice(&y_bytes);

        Ok(uncompressed)
    }

    // Helper function to extract P-256 coordinates from COSE format (from raw bytes)
    fn extract_p256_coordinates_from_cose_value(
        &self,
        cose_key_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let cose_key: CborValue = serde_cbor::from_slice(cose_key_bytes)
            .map_err(|_| "Failed to parse COSE public key")?;
        self.extract_p256_coordinates_from_cose(&cose_key)
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

    #[test]
    fn test_generate_registration_options_js_defaults_equivalent() {
        let context = get_context_with_seed(1); // Use a predictable seed
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        let rp_name = "My Passkey App".to_string();
        let rp_id = "example.localhost".to_string();
        let user_name = "testuser".to_string();

        // user_id is now a mandatory String (base64url encoded)
        let default_user_id_bytes: Vec<u8> = (0..DEFAULT_USER_ID_SIZE).map(|_| 1).collect();
        let default_user_id_b64url = TEST_BASE64_URL_ENGINE.encode(&default_user_id_bytes);

        let result = contract.generate_registration_options(
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
        let options = result.options;

        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 1).collect();
        let expected_challenge_b64url = TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes);
        assert_eq!(options.challenge, expected_challenge_b64url);
        // assert_eq!(contract.current_challenge, Some(expected_challenge_b64url)); // Verify stored challenge

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
    fn test_generate_registration_options_with_specific_overrides() {
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

        let result = contract.generate_registration_options(
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
        // Note: credProps is always forced to true by the contract logic
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

    fn build_p256_cose_key(x_coord: &[u8; 32], y_coord: &[u8; 32]) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty: EC2
        map.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg: ES256
        map.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv: P-256
        map.insert(CborValue::Integer(-2), CborValue::Bytes(x_coord.to_vec())); // x
        map.insert(CborValue::Integer(-3), CborValue::Bytes(y_coord.to_vec())); // y
        serde_cbor::to_vec(&CborValue::Map(map)).unwrap()
    }

    // Tests for FIDO U2F signature verification
    #[test]
    fn test_verify_u2f_signature_self_attestation() {
        let context = get_context_with_seed(9);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Use known valid P-256 coordinates (from NIST test vectors)
        // These are valid points on the P-256 curve
        let x_coord = [
            0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35,
            0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e,
            0x60, 0xf2, 0x9f, 0xb6,
        ];
        let y_coord = [
            0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
            0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94,
            0xd4, 0x46, 0x22, 0x99,
        ];

        // Build COSE public key
        let cose_public_key = build_p256_cose_key(&x_coord, &y_coord);

        // Build mock authenticator data
        let rp_id_hash = [0x41u8; 32]; // Mock RP ID hash
        let flags = 0x41u8; // User present + attested credential data
        let counter = [0x00, 0x00, 0x00, 0x01u8]; // Counter = 1
        let aaguid = [0x00u8; 16]; // Mock AAGUID
        let credential_id = b"test_credential_id_12345678"; // 28 bytes
        let cred_id_len = (credential_id.len() as u16).to_be_bytes();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash); // 32 bytes
        auth_data.push(flags); // 1 byte
        auth_data.extend_from_slice(&counter); // 4 bytes
        auth_data.extend_from_slice(&aaguid); // 16 bytes
        auth_data.extend_from_slice(&cred_id_len); // 2 bytes (total: 55 bytes)
        auth_data.extend_from_slice(credential_id); // 28 bytes
        auth_data.extend_from_slice(&cose_public_key); // Variable length

        // Mock client data hash
        let client_data_hash = [0x42u8; 32];

        // Build U2F signature data (what should be signed)
        let mut u2f_signature_data = Vec::new();
        u2f_signature_data.push(0x00); // Reserved byte
        u2f_signature_data.extend_from_slice(&rp_id_hash); // Application parameter
        u2f_signature_data.extend_from_slice(&client_data_hash); // Challenge parameter
        u2f_signature_data.extend_from_slice(credential_id); // Key handle

        // Add uncompressed public key (0x04 || x || y)
        u2f_signature_data.push(0x04);
        u2f_signature_data.extend_from_slice(&x_coord);
        u2f_signature_data.extend_from_slice(&y_coord);

        // For testing, we'll create a mock signature (normally this would be generated by a real key)
        // Since we don't have the private key, we'll create a plausible-looking DER signature
        let mock_signature = create_mock_der_signature();

        // Build attestation statement (self-attestation, no x5c)
        let mut att_stmt_map = BTreeMap::new();
        att_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        let att_stmt = CborValue::Map(att_stmt_map);

        // Test the verification (this will fail because we have a mock signature,
        // but it should get through the parsing logic without errors)
        let result = contract.verify_u2f_signature(
            &att_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        // We expect this to return Ok(false) because the signature is mock/invalid
        // But it should not panic or return an error due to parsing issues
        assert!(result.is_ok(), "Should not error on parsing: {:?}", result);
        assert_eq!(
            result.unwrap(),
            false,
            "Mock signature should fail verification"
        );
    }

    #[test]
    fn test_verify_u2f_signature_invalid_public_key() {
        let context = get_context_with_seed(13);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Use invalid P-256 coordinates (not on the curve)
        let x_coord = [0x01u8; 32]; // Invalid point
        let y_coord = [0x02u8; 32]; // Invalid point
        let cose_public_key = build_p256_cose_key(&x_coord, &y_coord);

        // Build minimal valid authenticator data
        let mut auth_data = vec![0u8; 55]; // Minimum length for credential data
        auth_data.extend_from_slice(b"test_cred_id_123456"); // 20 bytes credential ID
        auth_data.extend_from_slice(&cose_public_key); // COSE public key

        // Set credential ID length at correct offset (bytes 53-54)
        let cred_id_len = 20u16;
        auth_data[53] = (cred_id_len >> 8) as u8;
        auth_data[54] = (cred_id_len & 0xff) as u8;

        let client_data_hash = [0u8; 32];
        let mock_signature = create_mock_der_signature();

        let mut att_stmt_map = BTreeMap::new();
        att_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        let att_stmt = CborValue::Map(att_stmt_map);

        let result = contract.verify_u2f_signature(
            &att_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        // Should fail due to invalid public key
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid P-256 public key"));
    }

    #[test]
    fn test_verify_u2f_signature_missing_signature() {
        let context = get_context_with_seed(10);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Empty attestation statement (missing signature)
        let att_stmt_map = BTreeMap::new();
        let att_stmt = CborValue::Map(att_stmt_map);

        let auth_data = vec![0u8; 100]; // Mock auth data
        let client_data_hash = [0u8; 32];
        let cose_public_key = build_p256_cose_key(&[1u8; 32], &[2u8; 32]);

        let result = contract.verify_u2f_signature(
            &att_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing signature"));
    }

    #[test]
    fn test_verify_u2f_signature_invalid_auth_data() {
        let context = get_context_with_seed(11);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Valid attestation statement
        let mock_signature = create_mock_der_signature();
        let mut att_stmt_map = BTreeMap::new();
        att_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        let att_stmt = CborValue::Map(att_stmt_map);

        // Invalid auth data (too short)
        let auth_data = vec![0u8; 30]; // Too short for U2F
        let client_data_hash = [0u8; 32];
        let cose_public_key = build_p256_cose_key(&[1u8; 32], &[2u8; 32]);

        let result = contract.verify_u2f_signature(
            &att_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Authenticator data too short"));
    }

    #[test]
    fn test_get_uncompressed_p256_pubkey() {
        let context = get_context_with_seed(12);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Use valid P-256 coordinates
        let x_coord = [
            0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35,
            0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e,
            0x60, 0xf2, 0x9f, 0xb6,
        ];
        let y_coord = [
            0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
            0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94,
            0xd4, 0x46, 0x22, 0x99,
        ];
        let cose_public_key = build_p256_cose_key(&x_coord, &y_coord);

        let result = contract.get_uncompressed_p256_pubkey(&cose_public_key);

        assert!(result.is_ok());
        let uncompressed = result.unwrap();

        // Should be 65 bytes: 0x04 || x || y
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed indicator
        assert_eq!(&uncompressed[1..33], &x_coord); // X coordinate
        assert_eq!(&uncompressed[33..65], &y_coord); // Y coordinate
    }

    // Helper function to create a mock DER-encoded signature for testing
    fn create_mock_der_signature() -> Vec<u8> {
        // This creates a valid DER structure but with mock values
        // Real signature would be generated by actual private key
        // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        let r = vec![0x01u8; 32]; // Mock r value (32 bytes)
        let s = vec![0x02u8; 32]; // Mock s value (32 bytes)

        let mut der_sig = Vec::new();
        der_sig.push(0x30); // SEQUENCE tag
        der_sig.push(68); // Total length: 2 + 32 + 2 + 32 = 68
        der_sig.push(0x02); // INTEGER tag for r
        der_sig.push(32); // Length of r
        der_sig.extend_from_slice(&r);
        der_sig.push(0x02); // INTEGER tag for s
        der_sig.push(32); // Length of s
        der_sig.extend_from_slice(&s);

        der_sig
    }

    #[test]
    fn test_verify_registration_response_invalid_challenge() {
        let context = get_context_with_seed(14);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Create mock client data with wrong challenge
        let client_data = r#"{"type":"webauthn.create","challenge":"wrong_challenge","origin":"https://example.com","crossOrigin":false}"#;
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create minimal mock attestation object
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        );
        attestation_map.insert(
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(vec![0u8; 100]),
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

        let result = contract.verify_registration_response_internal(
            mock_response,
            "expected_challenge".to_string(),
            "https://example.com".to_string(),
            "example.com".to_string(),
            false,
        );

        assert!(
            !result.verified,
            "Should fail verification due to challenge mismatch"
        );
        assert!(result.registration_info.is_none());
    }

    #[test]
    fn test_verify_registration_response_invalid_origin() {
        let context = get_context_with_seed(15);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Create mock client data with wrong origin
        let client_data = r#"{"type":"webauthn.create","challenge":"test_challenge","origin":"https://evil.com","crossOrigin":false}"#;
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create minimal mock attestation object
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            CborValue::Text("fmt".to_string()),
            CborValue::Text("none".to_string()),
        );
        attestation_map.insert(
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(vec![0u8; 100]),
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

        let result = contract.verify_registration_response_internal(
            mock_response,
            "test_challenge".to_string(),
            "https://example.com".to_string(),
            "example.com".to_string(),
            false,
        );

        assert!(
            !result.verified,
            "Should fail verification due to origin mismatch"
        );
        assert!(result.registration_info.is_none());
    }

    #[test]
    fn test_verify_registration_response_real_webauthn_data() {
        let context = get_context_with_seed(16);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

        // Create a realistic WebAuthn response similar to browser data
        let client_extension_results = serde_json::json!({
            "credProps": {"rk": true},
            "prf": {"enabled": true, "results": {"first": {}}}
        });

        let client_data = r#"{"type":"webauthn.create","challenge":"rgLuoFhK5d3by9oCS1f4tA","origin":"https://example.localhost","crossOrigin":false}"#;
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create a minimal but valid attestation object for "none" attestation
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
        let attestation_object_b64 = TEST_BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        let realistic_response = RegistrationResponseJSON {
            id: "FambqICu3jJ2QcaJF038gw".to_string(),
            raw_id: "FambqICu3jJ2QcaJF038gw".to_string(),
            response: AttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
                transports: Some(vec!["hybrid".to_string(), "internal".to_string()]),
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: Some(client_extension_results),
        };

        let result = contract.verify_registration_response_internal(
            realistic_response,
            "rgLuoFhK5d3by9oCS1f4tA".to_string(),
            "https://example.localhost".to_string(),
            "example.localhost".to_string(),
            true,
        );

        // This should succeed with our mock data
        assert!(
            result.verified,
            "Should verify successfully with realistic data"
        );
        assert!(
            result.registration_info.is_some(),
            "Should return registration info"
        );

        if let Some(reg_info) = result.registration_info {
            assert_eq!(reg_info.credential_id, b"FambqICu3jJ2QcaJF038gw");
            assert_eq!(reg_info.user_id, "FambqICu3jJ2QcaJF038gw");
            assert!(
                reg_info.credential_public_key.len() > 0,
                "Should have credential public key"
            );
            assert_eq!(reg_info.counter, 1);
        }
    }

    #[test]
    fn test_verify_registration_response_json_deserialization() {
        let context = get_context_with_seed(17);
        testing_env!(context.build());
        let contract = WebAuthnContract::default();

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

                // Test the contract call with this data
                let result = contract.verify_registration_response_internal(
                    response,
                    "rgLuoFhK5d3by9oCS1f4tA".to_string(),
                    "https://example.localhost".to_string(),
                    "example.localhost".to_string(),
                    true,
                );

                // We expect this to fail validation but not deserialization
                println!("Contract verification result: verified={}", result.verified);
            }
            Err(e) => {
                panic!("Failed to deserialize RegistrationResponseJSON: {}", e);
            }
        }
    }
}
