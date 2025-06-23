use super::{WebAuthnContract, WebAuthnContractExt};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::{env, log, near};

pub const DEFAULT_CHALLENGE_SIZE: usize = 16;

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    #[private]
    pub fn generate_challenge_bytes(&self) -> Vec<u8> {
        let seed = env::random_seed();
        seed.into_iter().take(DEFAULT_CHALLENGE_SIZE).collect()
    }

    #[private]
    pub fn decode_or_generate_new_challenge(&self, challenge: Option<String>) -> (Vec<u8>, String) {
        if let Some(c) = challenge {
            if !c.is_empty() {
                if let Ok(bytes) = BASE64_URL_ENGINE.decode(&c) {
                    // Also check that the decoded challenge is not empty
                    if !bytes.is_empty() {
                        return (bytes, c);
                    }
                }
            }
            log!("Invalid challenge format provided, generating new one");
        };
        let bytes = self.generate_challenge_bytes();
        let b64url = BASE64_URL_ENGINE.encode(&bytes);
        (bytes, b64url)
    }

    #[private]
    pub fn generate_yield_resume_salt(&self) -> (Vec<u8>, String) {
        let salt_bytes = env::random_seed().iter().copied().take(16).collect::<Vec<u8>>();
        let salt_b64url = BASE64_URL_ENGINE.encode(&salt_bytes);
        (salt_bytes, salt_b64url)
    }

    // Generate a random register ID to avoid conflicts with concurrent operations
    #[private]
    pub fn generate_yield_resume_id(&self) -> u64 {
        // Use random seed to generate a unique register ID
        let seed = env::random_seed();
        // Take first 8 bytes and convert to u64
        let bytes: [u8; 8] = seed[0..8].try_into().unwrap_or([0u8; 8]);
        u64::from_le_bytes(bytes)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE;
    use base64::Engine as TestEngine;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    // Helper to get a VMContext with a specific seed for predictable randomness
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

    #[test]
    fn test_generate_challenge_bytes() {
        let context = get_context_with_seed(42);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        let challenge_bytes = contract.generate_challenge_bytes();

        // Should generate the correct length
        assert_eq!(challenge_bytes.len(), DEFAULT_CHALLENGE_SIZE);

        // Should be deterministic with the same seed
        let challenge_bytes_2 = contract.generate_challenge_bytes();
        assert_eq!(challenge_bytes, challenge_bytes_2);

        // With the predictable seed (42), all bytes should be 42
        let expected_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 42).collect();
        assert_eq!(challenge_bytes, expected_bytes);
    }

    #[test]
    fn test_generate_challenge_bytes_different_seeds() {
        // Test with different seeds to ensure different challenges
        let context1 = get_context_with_seed(10);
        testing_env!(context1.build());
        let contract1 = WebAuthnContract::init("test-contract".to_string());
        let challenge1 = contract1.generate_challenge_bytes();

        let context2 = get_context_with_seed(20);
        testing_env!(context2.build());
        let contract2 = WebAuthnContract::init("test-contract".to_string());
        let challenge2 = contract2.generate_challenge_bytes();

        // Should be different with different seeds
        assert_ne!(challenge1, challenge2);
        assert_eq!(challenge1.len(), DEFAULT_CHALLENGE_SIZE);
        assert_eq!(challenge2.len(), DEFAULT_CHALLENGE_SIZE);
    }

    #[test]
    fn test_validate_or_generate_challenge_bytes_valid_challenge() {
        let context = get_context_with_seed(30);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        // Test with a valid base64url challenge
        let valid_challenge = "dGVzdF9jaGFsbGVuZ2VfMTIzNDU"; // "test_challenge_12345" in base64url
        let (bytes, b64url) = contract.decode_or_generate_new_challenge(Some(valid_challenge.to_string()));

        // Should return the original challenge
        assert_eq!(b64url, valid_challenge);
        assert_eq!(bytes, TEST_BASE64_URL_ENGINE.decode(valid_challenge).unwrap());
    }

    #[test]
    fn test_validate_or_generate_challenge_bytes_invalid_challenge() {
        let context = get_context_with_seed(31);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        // Test with an invalid base64url challenge (contains spaces)
        let invalid_challenge = "invalid base64url!!";
        let (bytes, b64url) = contract.decode_or_generate_new_challenge(Some(invalid_challenge.to_string()));

        // Should generate a new challenge
        assert_ne!(b64url, invalid_challenge);
        assert_eq!(bytes.len(), DEFAULT_CHALLENGE_SIZE);

        // Should be able to decode the generated challenge
        let decoded = TEST_BASE64_URL_ENGINE.decode(&b64url).unwrap();
        assert_eq!(decoded, bytes);

        // With seed 31, should be predictable
        let expected_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 31).collect();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_validate_or_generate_challenge_bytes_none_challenge() {
        let context = get_context_with_seed(32);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        // Test with None
        let (bytes, b64url) = contract.decode_or_generate_new_challenge(None);

        // Should generate a new challenge
        assert_eq!(bytes.len(), DEFAULT_CHALLENGE_SIZE);

        // Should be able to decode the generated challenge
        let decoded = TEST_BASE64_URL_ENGINE.decode(&b64url).unwrap();
        assert_eq!(decoded, bytes);

        // With seed 32, should be predictable
        let expected_bytes: Vec<u8> = (0..DEFAULT_CHALLENGE_SIZE).map(|_| 32).collect();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_generate_yield_resume_salt() {
        let context = get_context_with_seed(40);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        let (salt_bytes, salt_b64url) = contract.generate_yield_resume_salt();

        // Should generate 16 bytes of salt
        assert_eq!(salt_bytes.len(), 16);

        // Should be valid base64url
        let decoded = TEST_BASE64_URL_ENGINE.decode(&salt_b64url).unwrap();
        assert_eq!(decoded, salt_bytes);

        // With seed 40, should be predictable
        let expected_bytes: Vec<u8> = (0..16).map(|_| 40).collect();
        assert_eq!(salt_bytes, expected_bytes);
    }

    #[test]
    fn test_generate_yield_resume_salt_different_seeds() {
        // Test with different seeds to ensure different salts
        let context1 = get_context_with_seed(50);
        testing_env!(context1.build());
        let contract1 = WebAuthnContract::init("test-contract".to_string());
        let (salt1, salt1_b64) = contract1.generate_yield_resume_salt();

        let context2 = get_context_with_seed(60);
        testing_env!(context2.build());
        let contract2 = WebAuthnContract::init("test-contract".to_string());
        let (salt2, salt2_b64) = contract2.generate_yield_resume_salt();

        // Should be different with different seeds
        assert_ne!(salt1, salt2);
        assert_ne!(salt1_b64, salt2_b64);
        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
    }

    #[test]
    fn test_generate_yield_resume_id() {
        let context = get_context_with_seed(70);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        let id1 = contract.generate_yield_resume_id();
        let id2 = contract.generate_yield_resume_id();

        // Should generate the same ID with the same seed (deterministic)
        assert_eq!(id1, id2);

        // With seed 70, should generate a specific value
        // First 8 bytes of seed [70,70,70,70,70,70,70,70] as little-endian u64
        let expected_bytes = [70u8; 8];
        let expected_id = u64::from_le_bytes(expected_bytes);
        assert_eq!(id1, expected_id);
    }

    #[test]
    fn test_generate_yield_resume_id_different_seeds() {
        // Test with different seeds to ensure different IDs
        let context1 = get_context_with_seed(80);
        testing_env!(context1.build());
        let contract1 = WebAuthnContract::init("test-contract".to_string());
        let id1 = contract1.generate_yield_resume_id();

        let context2 = get_context_with_seed(90);
        testing_env!(context2.build());
        let contract2 = WebAuthnContract::init("test-contract".to_string());
        let id2 = contract2.generate_yield_resume_id();

        // Should be different with different seeds
        assert_ne!(id1, id2);

        // Verify the expected values
        let expected_id1 = u64::from_le_bytes([80u8; 8]);
        let expected_id2 = u64::from_le_bytes([90u8; 8]);
        assert_eq!(id1, expected_id1);
        assert_eq!(id2, expected_id2);
    }

    #[test]
    fn test_validate_or_generate_challenge_bytes_empty_string() {
        let context = get_context_with_seed(33);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        // Test with empty string (should be treated as invalid)
        let (bytes, b64url) = contract.decode_or_generate_new_challenge(Some("".to_string()));

        // Should generate a new challenge since empty string decodes to empty bytes
        // but we want a proper challenge
        assert_ne!(b64url, "");
        assert_eq!(bytes.len(), DEFAULT_CHALLENGE_SIZE);

        // Should be able to decode the generated challenge
        let decoded = TEST_BASE64_URL_ENGINE.decode(&b64url).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_validate_or_generate_challenge_bytes_special_characters() {
        let context = get_context_with_seed(34);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        // Test with base64url that contains invalid characters for base64url
        let invalid_challenge = "hello+world/with=padding"; // Contains +, /, = which are not base64url
        let (bytes, b64url) = contract.decode_or_generate_new_challenge(Some(invalid_challenge.to_string()));

        // Should generate a new challenge
        assert_ne!(b64url, invalid_challenge);
        assert_eq!(bytes.len(), DEFAULT_CHALLENGE_SIZE);
    }

    #[test]
    fn test_salt_and_id_independence() {
        let context = get_context_with_seed(100);
        testing_env!(context.build());
        let contract = WebAuthnContract::init("test-contract".to_string());

        // Generate salt and ID multiple times to ensure they use independent randomness
        let (salt1, _) = contract.generate_yield_resume_salt();
        let id1 = contract.generate_yield_resume_id();
        let (salt2, _) = contract.generate_yield_resume_salt();
        let id2 = contract.generate_yield_resume_id();

        // With the same seed, they should be the same (deterministic)
        assert_eq!(salt1, salt2);
        assert_eq!(id1, id2);

        // But salt and ID should be using different portions/transformations of the seed
        // Salt uses first 16 bytes, ID uses first 8 bytes as u64
        assert_eq!(salt1.len(), 16);
        assert_ne!(salt1[0] as u64, id1); // They shouldn't be the same value
    }
}
