use super::{WebAuthnContract, WebAuthnContractExt};

use crate::generate_registration_options::{
    AuthenticationExtensionsClientInputs,
    PublicKeyCredentialDescriptorJSON,
    AuthenticatorTransport,
    UserVerificationRequirement,
};
use crate::verify_authentication_response::{
    YieldedAuthenticationData,
    AuthenticatorDevice,
};
use crate::UserIdYieldId;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near, Gas, GasWeight, NearToken};
use serde_json;

pub const DEFAULT_CHALLENGE_SIZE: u64 = 16;
pub const DATA_REGISTER_ID: u64 = 0;


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

#[near_sdk::near(serializers = [json])]
#[derive(Debug)]
pub struct AuthenticationOptionsJSON {
    pub options: PublicKeyCredentialRequestOptionsJSON,
    #[serde(rename = "commitmentId")]
    pub commitment_id: Option<String>,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// Generate authentication options for WebAuthn authentication with yield-resume
    /// Equivalent to @simplewebauthn/server's generateAuthenticationOptions function
    pub fn generate_authentication_options(
        &mut self,
        rp_id: Option<String>,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptorJSON>>,
        challenge: Option<String>,
        timeout: Option<u64>,
        user_verification: Option<UserVerificationRequirement>,
        extensions: Option<AuthenticationExtensionsClientInputs>,
        authenticator: AuthenticatorDevice, // The authenticator device to use for verification
    ) -> AuthenticationOptionsJSON {

        log!("Generating authentication options with yield-resume");
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

        // 3. Set defaults and validate parameters
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

        // 4. Determine expected origin and require_user_verification
        let expected_origin = format!("https://{}", final_rp_id);
        let require_user_verification = final_user_verification == UserVerificationRequirement::Required;

        // 5. Build the PublicKeyCredentialRequestOptionsJSON
        let options = PublicKeyCredentialRequestOptionsJSON {
            challenge: challenge_b64url.clone(),
            timeout: Some(final_timeout),
            rp_id: Some(final_rp_id.clone()),
            allow_credentials,
            user_verification: Some(final_user_verification),
            extensions: Some(final_extensions),
        };

        let yield_data = YieldedAuthenticationData {
            authenticator,
            commitment_b64url,
            expected_origin,
            original_challenge_b64url: challenge_b64url,
            rp_id: final_rp_id,
            require_user_verification,
            salt_b64url,
        };

        // NEW: Store commitment data in a LookupMap
        let commitment_id = BASE64_URL_ENGINE.encode(&env::random_seed()[..16]);
        self.pending_authentications.insert(commitment_id.clone(), yield_data);

        log!("Stored authentication commitment with id: {}", commitment_id);

        // Yield a promise to prune this commitment later if it's not used
        env::promise_yield_create(
            "prune_auth_commitment_callback",
            &serde_json::json!({ "commitment_id": commitment_id }).to_string().into_bytes(),
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
                yield_resume_id: yield_resume_id_bytes,
            }
        );

        // 8. Return the options with commitment_id
        let response = AuthenticationOptionsJSON {
            options,
            commitment_id: Some(commitment_id),
        };

        response
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
    use base64::Engine as TestEngine;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    use crate::contract_helpers::DEFAULT_CHALLENGE_SIZE;

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
        let mut contract = WebAuthnContract::init("test-contract".to_string());

        let result = contract.generate_authentication_options(
            None, // rp_id
            None, // allow_credentials
            None, // challenge -> contract generates
            None, // timeout
            None, // user_verification
            None, // extensions
            AuthenticatorDevice::default(),
        );

        // Verify defaults
        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 20).collect();
        let expected_challenge_b64url = TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes);
        assert_eq!(result.options.challenge, expected_challenge_b64url);

        assert_eq!(result.options.timeout, Some(60000));
        assert_eq!(result.options.rp_id, Some("test-contract.testnet".to_string()));
        assert_eq!(result.options.allow_credentials, None);
        assert_eq!(result.options.user_verification, Some(UserVerificationRequirement::Preferred));
        assert!(result.options.extensions.is_some());
        let extensions = result.options.extensions.unwrap();
        assert_eq!(extensions.appid, None);
        assert_eq!(extensions.cred_props, None);
        assert_eq!(extensions.hmac_create_secret, None);
        assert_eq!(extensions.min_pin_length, None);
    }

    #[test]
    fn test_generate_authentication_options_with_overrides() {
        let context = get_context_with_seed(21);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::init("test-contract".to_string());

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

        let result = contract.generate_authentication_options(
            Some(custom_rp_id.to_string()),
            Some(custom_allow_credentials.clone()),
            Some(custom_challenge.to_string()),
            Some(custom_timeout),
            Some(UserVerificationRequirement::Required),
            Some(custom_extensions.clone()),
            AuthenticatorDevice::default(),
        );

        // Verify all custom values
        assert_eq!(result.options.challenge, custom_challenge);
        assert_eq!(result.options.timeout, Some(custom_timeout));
        assert_eq!(result.options.rp_id, Some(custom_rp_id.to_string()));
        assert_eq!(result.options.allow_credentials, Some(custom_allow_credentials));
        assert_eq!(result.options.user_verification, Some(UserVerificationRequirement::Required));
        assert_eq!(result.options.extensions, Some(custom_extensions));
    }

    #[test]
    fn test_generate_authentication_options_invalid_challenge() {
        let context = get_context_with_seed(22);
        testing_env!(context.build());
        let mut contract = WebAuthnContract::init("test-contract".to_string());

        // Provide an invalid base64url challenge
        let invalid_challenge = "invalid base64url!!";

        let result = contract.generate_authentication_options(
            None,
            None,
            Some(invalid_challenge.to_string()),
            None,
            None,
            None,
            AuthenticatorDevice::default(),
        );

        // Should have generated a new challenge instead of using the invalid one
        let expected_challenge_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 22).collect();
        let expected_challenge_b64url = TEST_BASE64_URL_ENGINE.encode(&expected_challenge_bytes);
        assert_eq!(result.options.challenge, expected_challenge_b64url);
        assert_ne!(result.options.challenge, invalid_challenge);
    }

}
