use super::{WebAuthnContract, WebAuthnContractExt};

use crate::generate_registration_options::{
    AuthenticationExtensionsClientInputs,
    PublicKeyCredentialDescriptorJSON,
    AuthenticatorTransport,
    UserVerificationRequirement,
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{log, near};


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

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// Generate authentication options for WebAuthn authentication
    /// Equivalent to @simplewebauthn/server's generateAuthenticationOptions function
    pub fn generate_authentication_options(
        &mut self,
        rp_id: Option<String>,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
        challenge: Option<String>,
        timeout: Option<u64>,
        user_verification: Option<UserVerificationRequirement>,
        extensions: Option<AuthenticationExtensionsClientInputs>,
    ) -> String {
        log!("Generating authentication options");

        // 1. Generate or use provided challenge
        let challenge_b64url = match challenge {
            Some(c) => {
                // Validate that it's valid base64url
                match BASE64_URL_ENGINE.decode(&c) {
                    Ok(_) => c,
                    Err(_) => {
                        log!("Invalid challenge format provided, generating new one");
                        let bytes = self.generate_challenge_bytes();
                        BASE64_URL_ENGINE.encode(&bytes)
                    }
                }
            }
            None => {
                let bytes = self.generate_challenge_bytes();
                BASE64_URL_ENGINE.encode(&bytes)
            }
        };

        // 2. Set defaults and validate parameters
        let final_timeout = timeout.unwrap_or(60000); // Default 60 seconds
        let final_user_verification = user_verification.unwrap_or_default(); // Default is "preferred"
        let final_extensions = extensions.unwrap_or_default();
        let final_rp_id = rp_id.unwrap_or_else(|| {
            // Extract from contract name if not provided
            // This assumes contract_name is in format "subdomain.domain.tld"
            if self.contract_name.contains('.') {
                self.contract_name.clone()
            } else {
                format!("{}.testnet", self.contract_name)
            }
        });

        // 3. Build the PublicKeyCredentialRequestOptionsJSON
        let options = PublicKeyCredentialRequestOptionsJSON {
            challenge: challenge_b64url.clone(),
            timeout: Some(final_timeout),
            rp_id: Some(final_rp_id),
            allow_credentials,
            user_verification: Some(final_user_verification),
            extensions: Some(final_extensions),
        };

        log!("Generated authentication options with challenge: {}", challenge_b64url);

        // 4. Return the options as JSON string
        serde_json::to_string(&options).expect("Failed to serialize authentication options")
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
    use base64::Engine as TestEngine;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use serde_cbor::Value as CborValue;
    use std::collections::BTreeMap;

    use crate::generate_registration_options::DEFAULT_CHALLENGE_SIZE;

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
    fn test_generate_authentication_options_defaults() {
        let context = get_context_with_seed(20);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        let result_json = contract.generate_authentication_options(
            None, // rp_id
            None, // allow_credentials
            None, // challenge -> contract generates
            None, // timeout
            None, // user_verification
            None, // extensions
        );

        // Parse the JSON response
        let result: PublicKeyCredentialRequestOptionsJSON = serde_json::from_str(&result_json)
            .expect("Failed to parse authentication options JSON");

        // Verify defaults
        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 20).collect();
        let expected_challenge_b64url = TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes);
        assert_eq!(result.challenge, expected_challenge_b64url);

        assert_eq!(result.timeout, Some(60000));
        assert_eq!(result.rp_id, Some("webauthn-contract.testnet".to_string()));
        assert_eq!(result.allow_credentials, None);
        assert_eq!(result.user_verification, Some(UserVerificationRequirement::Preferred));
        assert!(result.extensions.is_some());
        let extensions = result.extensions.unwrap();
        assert_eq!(extensions.appid, None);
        assert_eq!(extensions.cred_props, None);
        assert_eq!(extensions.hmac_create_secret, None);
        assert_eq!(extensions.min_pin_length, None);
    }

    #[test]
    fn test_generate_authentication_options_with_overrides() {
        let context = get_context_with_seed(21);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        let custom_challenge = "Y3VzdG9tX2NoYWxsZW5nZV8xMjM0NQ"; // "custom_challenge_12345" base64url encoded
        let custom_timeout = 30000u64;
        let custom_rp_id = "custom.example.com";
        let custom_allow_credentials = vec![
            PublicKeyCredentialDescriptorJSON {
                id: TEST_BASE64_URL_ENGINE.encode(b"credential-1"),
                type_: "public-key".to_string(),
                transports: Some(vec![AuthenticatorTransport::Usb, AuthenticatorTransport::Nfc]),
            },
            PublicKeyCredentialDescriptorJSON {
                id: TEST_BASE64_URL_ENGINE.encode(b"credential-2"),
                type_: "public-key".to_string(),
                transports: Some(vec![AuthenticatorTransport::Internal]),
            },
        ];
        let custom_extensions = AuthenticationExtensionsClientInputs {
            appid: Some("https://legacy.example.com".to_string()),
            cred_props: Some(true),
            hmac_create_secret: Some(true),
            min_pin_length: Some(false),
        };

        let result_json = contract.generate_authentication_options(
            Some(custom_rp_id.to_string()),
            Some(custom_allow_credentials.clone()),
            Some(custom_challenge.to_string()),
            Some(custom_timeout),
            Some(UserVerificationRequirement::Required),
            Some(custom_extensions.clone()),
        );

        // Parse the JSON response
        let result: PublicKeyCredentialRequestOptionsJSON = serde_json::from_str(&result_json)
            .expect("Failed to parse authentication options JSON");

        // Verify all custom values
        assert_eq!(result.challenge, custom_challenge);
        assert_eq!(result.timeout, Some(custom_timeout));
        assert_eq!(result.rp_id, Some(custom_rp_id.to_string()));
        assert_eq!(result.allow_credentials, Some(custom_allow_credentials));
        assert_eq!(result.user_verification, Some(UserVerificationRequirement::Required));
        assert_eq!(result.extensions, Some(custom_extensions));
    }

    #[test]
    fn test_generate_authentication_options_invalid_challenge() {
        let context = get_context_with_seed(22);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::default();

        // Provide an invalid base64url challenge
        let invalid_challenge = "invalid base64url!!";

        let result_json = contract.generate_authentication_options(
            None,
            None,
            Some(invalid_challenge.to_string()),
            None,
            None,
            None,
        );

        // Parse the JSON response
        let result: PublicKeyCredentialRequestOptionsJSON = serde_json::from_str(&result_json)
            .expect("Failed to parse authentication options JSON");

        // Should have generated a new challenge instead of using the invalid one
        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 22).collect();
        let expected_challenge_b64url = TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes);
        assert_eq!(result.challenge, expected_challenge_b64url);
        assert_ne!(result.challenge, invalid_challenge);
    }

}
