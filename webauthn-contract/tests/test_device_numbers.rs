#[cfg(test)]
mod device_number_tests {
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, AccountId};
    use webauthn_contract::{WebAuthnContract, StoredAuthenticator};
    use near_sdk::bs58;

    fn get_context(predecessor: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder.predecessor_account_id(predecessor);
        builder
    }

    #[test]
    fn test_device_number_assignment() {
        let account: AccountId = accounts(0);
        let context = get_context(account.clone());
        testing_env!(context.build());

        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test that first device gets device number 1
        let device_num_1 = 1u8;
        let stored_auth_1 = StoredAuthenticator {
            credential_public_key: vec![1, 2, 3],
            transports: None,
            registered: "2024-01-01".to_string(),
            vrf_public_keys: vec![vec![4, 5, 6]],
            device_number: device_num_1,
        };

        // Store first authenticator
        let success = contract.store_authenticator(
            account.clone(),
            "credential_1".to_string(),
            vec![1, 2, 3],
            None,
            "2024-01-01".to_string(),
            vec![vec![4, 5, 6]],
            device_num_1,
        );
        assert!(success, "First authenticator should be stored successfully");

        // Test that we can retrieve all authenticators with device numbers
        let all_auths = contract.get_authenticators_by_user(account.clone());
        assert_eq!(all_auths.len(), 1, "Should have one authenticator");
        assert_eq!(all_auths[0].1.device_number, 1, "First device should have device number 1");

        // Test device linking counter increment
        let valid_ed25519_key = "ed25519:".to_string() + &bs58::encode(&[0u8; 32]).into_string();
        contract.store_device_linking_mapping(
            valid_ed25519_key.clone(),
            account.clone(),
        );

        // Check that device counter was incremented for next device
        let linking_result = contract.get_device_linking_account(valid_ed25519_key);
        assert!(linking_result.is_some(), "Device linking should exist");
        if let Some((linked_account, device_number)) = linking_result {
            assert_eq!(linked_account, account, "Account should match");
            assert_eq!(device_number, 2, "Second device should get device number 2");
        }
    }

    #[test]
    fn test_device_counter_initialization() {
        let account: AccountId = accounts(0);
        let context = get_context(account.clone());
        testing_env!(context.build());

        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test device linking when no devices exist yet
        let valid_key = "ed25519:".to_string() + &bs58::encode(&[1u8; 32]).into_string();
        contract.store_device_linking_mapping(
            valid_key.clone(),
            account.clone(),
        );

        let result = contract.get_device_linking_account(valid_key);
        assert!(result.is_some(), "Device mapping should exist");

        if let Some((_, device_num)) = result {
            assert_eq!(device_num, 2, "First linked device should get device number 2 (device 1 is the original)");
        }
    }

    #[test]
    fn test_1_indexed_device_numbers() {
        let account: AccountId = accounts(0);
        let context = get_context(account.clone());
        testing_env!(context.build());

        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test that device numbers are 1-indexed for better UX

        // First device should be device number 1
        let success = contract.store_authenticator(
            account.clone(),
            "credential_device_1".to_string(),
            vec![1, 2, 3],
            None,
            "2024-01-01".to_string(),
            vec![vec![4, 5, 6]],
            1u8, // First device is device 1
        );
        assert!(success, "First device should be stored successfully");

        // Second device through linking should be device number 2
        let device2_key = "ed25519:".to_string() + &bs58::encode(&[2u8; 32]).into_string();
        contract.store_device_linking_mapping(
            device2_key.clone(),
            account.clone(),
        );

        let linking_result = contract.get_device_linking_account(device2_key);
        if let Some((_, device_number)) = linking_result {
            assert_eq!(device_number, 2, "Second device should be device number 2 (1-indexed)");
        }

        // Third device should be device number 3
        let device3_key = "ed25519:".to_string() + &bs58::encode(&[3u8; 32]).into_string();
        contract.store_device_linking_mapping(
            device3_key.clone(),
            account.clone(),
        );

        let linking_result_3 = contract.get_device_linking_account(device3_key);
        if let Some((_, device_number)) = linking_result_3 {
            assert_eq!(device_number, 3, "Third device should be device number 3 (1-indexed)");
        }
    }
}