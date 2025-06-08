use crate::generate_authentication_options::DATA_REGISTER_ID;

use super::{WebAuthnContract, WebAuthnContractExt};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near, Gas, GasWeight};
use crate::UserIdYieldId;

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

// Structure to hold yielded registration data
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct YieldedRegistrationData {
    pub(crate) commitment_b64url: String,
    pub(crate) original_challenge_b64url: String,
    pub(crate) salt_b64url: String,
    pub(crate) rp_id: String, // Store rp_id to derive origin and for verification
    pub(crate) require_user_verification: bool,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct RegistrationOptionsJSON {
    pub options: PublicKeyCredentialCreationOptionsJSON,
    #[serde(rename = "derpAccountId")]
    pub derp_account_id: Option<String>,
    #[serde(rename = "commitmentId")]
    pub commitment_id: Option<String>,
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

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

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
        let (
            challenge_bytes,
            challenge_b64url
        ) = self.decode_or_generate_new_challenge(challenge);

        let (
            salt_bytes,
            salt_b64url
        ) = self.generate_yield_resume_salt();

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


        // NEW: Store commitment data in a LookupMap
        let commitment_id = BASE64_URL_ENGINE.encode(&env::random_seed()[..16]);
        self.pending_registrations.insert(commitment_id.clone(), yield_data);
        log!("Stored registration commitment with id: {}", commitment_id);

        env::promise_yield_create(
            "prune_commitment_callback",
            &serde_json::json!({
                "commitment_id": commitment_id
            }).to_string().into_bytes().as_slice(),
            Gas::from_tgas(10),
            GasWeight(1),
            DATA_REGISTER_ID,
        );

        // Read the yield_resume_id from the register and store it for explicit pruning
        let yield_resume_id_bytes = env::read_register(DATA_REGISTER_ID)
            .expect("Failed to read yield_resume_id from register after yield creation");
        self.pending_prunes.insert(
            commitment_id.clone(),
            UserIdYieldId {
                user_id: env::predecessor_account_id(),
                yield_resume_id: yield_resume_id_bytes.clone(),
            }
        );

        let yield_resume_id_b64url = BASE64_URL_ENGINE.encode(&yield_resume_id_bytes);
        log!("Yielding prune callback with yield_resume_id: {}", yield_resume_id_b64url);

        // 6. Return only the options (without commitment info)
        let response = RegistrationOptionsJSON {
            options,
            derp_account_id: Some(suggested_derp_account_id),
            commitment_id: Some(commitment_id),
        };

        serde_json::to_string(&response).expect("Failed to serialize registration options")
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
    use base64::Engine as TestEngine;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    use crate::contract_helpers::{DEFAULT_CHALLENGE_SIZE, DEFAULT_USER_ID_SIZE};

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

}
