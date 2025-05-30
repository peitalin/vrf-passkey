use near_sdk::{env, log, near};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;

// Constants for default challenge and userID sizes ( mimicking JS defaults if different from full random_seed)
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
#[derive(Debug, Clone, PartialEq)] // Added PartialEq for test assertions
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
    pub hints: Option<Vec<String>>, // Added hints field
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct RegistrationOptionsWithDerpIdJSON {
    #[serde(flatten)]
    pub options: PublicKeyCredentialCreationOptionsJSON,
    #[serde(rename = "derpAccountId")]
    pub derp_account_id: Option<String>,
}

#[near(contract_state)]
pub struct WebAuthnContract {
    greeting: String,
    contract_name: String,
    current_challenge: Option<String>,
}

impl Default for WebAuthnContract {
    fn default() -> Self {
        Self {
            greeting: "Hello".to_string(),
            contract_name: "webauthn-contract.testnet".to_string(),
            current_challenge: None,
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
            current_challenge: None,
        }
    }

    pub fn get_greeting(&self) -> String {
        self.greeting.clone()
    }

    pub fn set_greeting(&mut self, greeting: String) {
        log!("Saving greeting: {greeting}");
        self.greeting = greeting;
    }

    pub fn get_contract_name(&self) -> String {
        self.contract_name.clone()
    }

    pub fn set_contract_name(&mut self, contract_name: String) {
        log!("Saving contract name: {contract_name}");
        self.contract_name = contract_name;
    }

    fn internal_generate_challenge_bytes(&self) -> Vec<u8> {
        let seed = env::random_seed();
        seed.into_iter().take(DEFAULT_CHALLENGE_SIZE).collect() // Or full seed if preferred
    }

    fn internal_generate_user_id_bytes(&self) -> Vec<u8> {
        let seed = env::random_seed(); // Use a different part or full seed if possible to differentiate from challenge
                                      // For simplicity, using the same method but could be a slice or different hash.
        seed.into_iter().take(DEFAULT_USER_ID_SIZE).collect()
    }

    pub fn generate_registration_options(
        &mut self,
        rp_name: String,
        rp_id: String,
        user_name: String,
        user_id: Option<Vec<u8>>,
        challenge: Option<Vec<u8>>,
        user_display_name: Option<String>,
        timeout: Option<u64>,
        attestation_type: Option<String>, // JS uses 'direct' | 'enterprise' | 'none'
        exclude_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        extensions: Option<AuthenticationExtensionsClientInputsJSON>,
        supported_algorithm_ids: Option<Vec<i32>>,
        preferred_authenticator_type: Option<String>, // e.g., "securityKey", "localDevice"
    ) -> RegistrationOptionsWithDerpIdJSON {

        let final_challenge_bytes = challenge.unwrap_or_else(|| self.internal_generate_challenge_bytes());
        let final_user_id_bytes = user_id.unwrap_or_else(|| self.internal_generate_user_id_bytes());

        let final_challenge_b64url = BASE64_URL_ENGINE.encode(&final_challenge_bytes);
        // self.current_challenge = Some(final_challenge_b64url.clone());

        let final_user_id_b64url = BASE64_URL_ENGINE.encode(&final_user_id_bytes);

        let final_user_display_name = user_display_name.unwrap_or_else(|| "".to_string());
        let final_timeout = timeout.unwrap_or(60000);
        let final_attestation_type = attestation_type.unwrap_or_else(|| "none".to_string());
        let final_exclude_credentials = exclude_credentials.unwrap_or_else(Vec::new);

        let mut final_authenticator_selection = authenticator_selection.unwrap_or_default();

        // Replicate JS logic for residentKey and requireResidentKey
        if final_authenticator_selection.resident_key.is_none() {
            if final_authenticator_selection.require_resident_key == Some(true) {
                final_authenticator_selection.resident_key = Some("required".to_string());
            } else {
                // JS comments out 'discouraged' for FIDO conformance, so we can leave it None or set to preferred if that was the actual JS default base
                // Sticking to JS default if not set: residentKey: 'preferred' which our Default impl provides
            }
        } else {
            final_authenticator_selection.require_resident_key = Some(
                final_authenticator_selection.resident_key == Some("required".to_string())
            );
        }

        let mut final_extensions = extensions.unwrap_or_default();
        final_extensions.cred_props = Some(true); // JS always sets/overrides this

        let final_supported_algorithm_ids = supported_algorithm_ids.unwrap_or_else(|| vec![-8, -7, -257]);

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
                    final_authenticator_selection.authenticator_attachment = Some("cross-platform".to_string());
                }
                "localDevice" => {
                    current_hints.push("client-device".to_string());
                    final_authenticator_selection.authenticator_attachment = Some("platform".to_string());
                }
                "remoteDevice" => { // JS uses 'hybrid' for hint, maps to cross-platform
                    current_hints.push("hybrid".to_string());
                    final_authenticator_selection.authenticator_attachment = Some("cross-platform".to_string());
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
}


#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{VMContextBuilder, accounts};
    use near_sdk::{testing_env};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
    use base64::Engine as TestEngine;

    // Helper to get a VMContext, random_seed is still useful for internal challenge/userID generation
    fn get_context_with_seed(random_byte_val: u8) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let seed: Vec<u8> = (0..32).map(|_| random_byte_val).collect(); // Create a seed with all same byte for predictability
        builder
            .current_account_id(accounts(0))
            .signer_account_id(accounts(1))
            .predecessor_account_id(accounts(1))
            .is_view(false)
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

        // Calling with all optional params as None to test internal defaults
        let result = contract.generate_registration_options(
            rp_name.clone(),
            rp_id.clone(),
            user_name.clone(),
            None, // userID
            None, // challenge
            None, // userDisplayName
            None, // timeout
            None, // attestationType
            None, // excludeCredentials
            None, // authenticatorSelection
            None, // extensions
            None, // supportedAlgorithmIDs
            None, // preferredAuthenticatorType
        );
        let options = result.options;

        // Assertions based on JS default behaviors
        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 1).collect();
        assert_eq!(options.challenge, TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes));
        assert_eq!(contract.current_challenge, Some(TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes)));

        let expected_user_id_bytes: Vec<u8> = (0..DEFAULT_USER_ID_SIZE).map(|_| 1).collect();
        assert_eq!(options.user.id, TEST_BASE64_URL_ENGINE.encode(&expected_user_id_bytes));
        assert_eq!(options.user.name, user_name);
        assert_eq!(options.user.display_name, ""); // JS default

        assert_eq!(options.rp.name, rp_name);
        assert_eq!(options.rp.id, rp_id.clone());

        assert_eq!(options.pub_key_cred_params.len(), 3);
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -8));
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -7));
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -257));

        assert_eq!(options.timeout, 60000); // JS default
        assert_eq!(options.attestation, "none"); // JS default
        assert_eq!(options.exclude_credentials, Vec::new()); // JS default

        // JS default authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }
        // Our Default impl for AuthenticatorSelectionCriteria matches this for residentKey & userVerification
        // requireResidentKey logic: if residentKey is 'preferred' (and not 'required'), requireResidentKey should be false.
        let expected_auth_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: Some("preferred".to_string()),
            require_resident_key: Some(false), // Based on JS logic for 'preferred' residentKey
            user_verification: Some("preferred".to_string()),
        };
        assert_eq!(options.authenticator_selection, expected_auth_selection);

        assert_eq!(options.extensions.cred_props, Some(true)); // JS sets this
        assert!(options.hints.is_none()); // No preferredAuthenticatorType provided

        let expected_derp_id = format!("{}.{}", user_name, rp_id);
        assert_eq!(result.derp_account_id, Some(expected_derp_id));
    }

    #[test]
    fn test_generate_registration_options_with_specific_overrides() {
        let context = get_context_with_seed(2);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        let user_id_bytes = vec![1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
        let challenge_bytes = vec![10,20,30,40,50,60,70,80,90,100,110,120,130,140,150,160];
        let custom_display_name = "Custom Name".to_string();
        let custom_timeout = 120000u64;
        let custom_attestation = "direct".to_string();
        let custom_exclude = vec![PublicKeyCredentialDescriptorJSON {
            id: TEST_BASE64_URL_ENGINE.encode(b"cred-id-123"),
            type_: "public-key".to_string(),
            transports: Some(vec![AuthenticatorTransport::Usb])
        }];
        let custom_auth_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: Some("platform".to_string()),
            resident_key: Some("required".to_string()),
            require_resident_key: None, // Let logic derive this to true
            user_verification: Some("required".to_string()),
        };
        let custom_extensions = AuthenticationExtensionsClientInputsJSON { cred_props: Some(false) }; // Test if cred_props gets overridden to true
        let custom_alg_ids = vec![-7, -36];
        let custom_pref_auth_type = "securityKey".to_string();

        let result = contract.generate_registration_options(
            "RP".to_string(),
            "rp.example".to_string(),
            "user".to_string(),
            Some(user_id_bytes.clone()),
            Some(challenge_bytes.clone()),
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

        assert_eq!(options.challenge, TEST_BASE64_URL_ENGINE.encode(&challenge_bytes));
        assert_eq!(options.user.id, TEST_BASE64_URL_ENGINE.encode(&user_id_bytes));
        assert_eq!(options.user.display_name, custom_display_name);
        assert_eq!(options.timeout, custom_timeout);
        assert_eq!(options.attestation, custom_attestation);
        assert_eq!(options.exclude_credentials, custom_exclude);

        let mut expected_auth_sel = custom_auth_selection.clone();
        expected_auth_sel.require_resident_key = Some(true); // residentKey is 'required'
        expected_auth_sel.authenticator_attachment = Some("cross-platform".to_string()); // Due to preferredAuthenticatorType 'securityKey'
        assert_eq!(options.authenticator_selection, expected_auth_sel);

        assert_eq!(options.extensions.cred_props, Some(true)); // Should be overridden to true
        assert_eq!(options.pub_key_cred_params.len(), 2);
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -7));
        assert!(options.pub_key_cred_params.iter().any(|p| p.alg == -36));
        assert_eq!(options.hints, Some(vec!["security-key".to_string()]));
    }
}
