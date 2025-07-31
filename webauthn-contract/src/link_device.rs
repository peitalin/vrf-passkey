use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{
    log, near, env, serde_json, require,
    AccountId, Gas, PublicKey, CryptoHash, GasWeight
};

// Simple enum for access key permission (kept for potential future use)
#[derive(Clone, Debug, PartialEq)]
#[near_sdk::near(serializers = [json, borsh])]
pub enum AccessKeyPermission {
    FunctionCall,
    FullAccess,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {
    /// Store device linking mapping for Device2 polling
    /// Device1 calls this after directly adding Device2's key to their own account
    /// This enables Device2 to discover which account it was linked to and get assigned a device number
    pub fn store_device_linking_mapping(
        &mut self,
        device_public_key: String,
        target_account_id: AccountId,
    ) -> CryptoHash {
        let caller = env::predecessor_account_id();
        require!(caller == target_account_id, "Caller must be the target account");

        log!(
            "Storing device linking mapping: {} -> {} by {}",
            device_public_key,
            target_account_id,
            caller
        );

        // Parse the public key to validate format
        let _parsed_key = match device_public_key.parse::<PublicKey>() {
            Ok(key) => key,
            Err(e) => {
                env::panic_str(&format!("Invalid public key format: {}", e));
            }
        };

        // Get next device number for this account (1-indexed for UX)
        let current_counter = self.device_numbers
            .get(&target_account_id)
            .copied()
            .unwrap_or(1); // device numbering starts on 1

        let device_number = current_counter;

        // Store temporary mapping for Device2 to poll (account ID and assigned device number)
        self.device_linking_map.insert(
            device_public_key.clone(),
            (target_account_id.clone(), device_number)
        );

        // Emit structured log event that Device2 can poll
        log!(
            "DEVICE_KEY_MAPPED:{}:{}:{}:{}",
            device_public_key,
            target_account_id,
            device_number,
            env::block_timestamp()
        );

        // Initiate automatic cleanup after 200 blocks using yield-resume pattern
        let data_id = self.initiate_cleanup(device_public_key.clone());
        // Initiate automatic key cleanup in 200 blocks if device linking process fails
        let key_cleanup_data_id = self.initiate_key_cleanup(
            device_public_key.clone(),
            target_account_id.clone()
        );

        log!(
            "Device linking mapping stored successfully for account {} with device number {}",
            target_account_id,
            device_number
        );
        log!(
            "Automatic cleanup scheduled: mapping cleanup (data_id: {:?}), key cleanup (data_id: {:?})",
            data_id,
            key_cleanup_data_id
        );
        data_id
    }

    /// View function for Device2 to query which account it will be linked to and get its assigned device number
    /// Device2 calls this with its public key to discover Device1's account ID and its assigned device number
    pub fn get_device_linking_account(&self, device_public_key: String) -> Option<(AccountId, u8)> {
        self.device_linking_map.get(&device_public_key)
            .map(|(account_id, device_number)| (account_id.clone(), *device_number))
    }

    /// Get the current device counter for an account (useful for debugging)
    pub fn get_device_counter(&self, account_id: AccountId) -> u8 {
        self.device_numbers.get(&account_id).copied().unwrap_or(0)
    }

    /// Initiate automatic cleanup using yield-resume pattern (executes after 200 blocks)
    pub fn initiate_cleanup(&mut self, device_public_key: String) -> CryptoHash {
        let data_id_register = 0;

        // Create yield promise for cleanup_device_linking
        env::promise_yield_create(
            "cleanup_device_linking",
            serde_json::to_vec(&serde_json::json!({
                "device_public_key": device_public_key
            })).unwrap().as_slice(),
            Gas::from_tgas(10),
            GasWeight(0),
            data_id_register
        );

        // Retrieve data_id for later resume
        let data_id: CryptoHash = env::read_register(data_id_register)
            .expect("Failed to read data_id")
            .try_into()
            .expect("Failed to convert to CryptoHash");

        data_id
    }

    /// Resume cleanup execution with custom payload
    pub fn resume_cleanup(&self, data_id: CryptoHash, result_data: String) -> bool {
        // Resume execution with custom payload
        env::promise_yield_resume(
            &data_id,
            serde_json::to_vec(&serde_json::json!({
                "status": "completed",
                "result": result_data
            })).unwrap().as_slice()
        )
    }

    /// Clean up temporary device linking mapping after successful registration
    /// This should be called after Device2 completes link_device_register_user
    /// OR automatically called by the yield-resume pattern after 200 blocks
    pub fn cleanup_device_linking(&mut self, device_public_key: String) {
        self.device_linking_map.remove(&device_public_key);
        log!("Cleaned up device linking mapping for key: {}", device_public_key);
    }

    /// Initiate automatic key cleanup using yield-resume pattern (executes after 200 blocks)
    /// This removes the temporary NEAR key if device linking process fails
    /// Only the target account can initiate cleanup for their own keys (security check)
    pub fn initiate_key_cleanup(&mut self, device_public_key: String, target_account_id: AccountId) -> CryptoHash {
        // Security check: Only the target account can schedule key deletion for themselves
        let caller = env::predecessor_account_id();
        require!(caller == target_account_id, "Can only delete keys for your own account");

        let data_id_register = 1; // Use different register to avoid conflicts

        // Create yield promise for cleanup_temporary_key
        env::promise_yield_create(
            "cleanup_temporary_key",
            serde_json::to_vec(&serde_json::json!({
                "device_public_key": device_public_key,
                "target_account_id": target_account_id
            })).unwrap().as_slice(),
            Gas::from_tgas(15), // Slightly more gas for key operations
            GasWeight(0),
            data_id_register
        );

        // Retrieve data_id for later resume
        let data_id: CryptoHash = env::read_register(data_id_register)
            .expect("Failed to read data_id")
            .try_into()
            .expect("Failed to convert to CryptoHash");

        log!("Initiated automatic key cleanup for device key: {} on account: {}", device_public_key, target_account_id);
        data_id
    }

    /// Resume key cleanup execution with custom payload
    pub fn resume_key_cleanup(&self, data_id: CryptoHash, result_data: String) -> bool {
        // Resume execution with custom payload
        env::promise_yield_resume(
            &data_id,
            serde_json::to_vec(&serde_json::json!({
                "status": "completed",
                "result": result_data
            })).unwrap().as_slice()
        )
    }

    /// Clean up temporary NEAR key after device linking process
    /// This should be called after Device2 completes link_device_register_user successfully
    /// OR automatically called by the yield-resume pattern after 200 blocks if process fails
    /// This method creates a promise batch targeting the user's account (e.g., bob.near) to delete the key
    pub fn cleanup_temporary_key(&mut self, device_public_key: String, target_account_id: AccountId) {
        // Parse the public key
        let public_key = match device_public_key.parse::<PublicKey>() {
            Ok(key) => key,
            Err(e) => {
                log!("Failed to parse public key for cleanup: {}", e);
                return;
            }
        };

        // Create promise batch for the TARGET account (e.g., bob.near), not the contract
        let promise_index = env::promise_batch_create(&target_account_id);

        // Delete the temporary key from the target account
        env::promise_batch_action_delete_key(promise_index, &public_key);

        // Return the promise
        env::promise_return(promise_index);

        log!("Cleaned up temporary NEAR key: {} from account: {}", device_public_key, target_account_id);
    }

    /// Cancel automatic key cleanup when device linking succeeds
    /// This should be called after Device2 successfully completes the device linking process
    /// to prevent the temporary key from being automatically deleted
    pub fn cancel_key_cleanup(&mut self, device_public_key: String, target_account_id: AccountId) {
        // Note: In the current NEAR SDK, there's no direct way to cancel a yield promise
        // This method serves as a marker that the cleanup should be skipped
        // The actual cancellation would need to be handled in the cleanup_temporary_key method
        // by checking if the device linking was successful

        log!("Key cleanup cancellation requested for device key: {} on account: {}", device_public_key, target_account_id);
        log!("Note: Manual cancellation of yield promises is not supported in current NEAR SDK");
        log!("The cleanup_temporary_key method should check if device linking was successful before deleting the key");
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use near_sdk::{AccountId, PublicKey};
    use std::str::FromStr;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_store_device_linking_mapping_invalid_public_key() {
        let alice = AccountId::from_str("alice.testnet").unwrap();
        let bob = AccountId::from_str("bob.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test invalid public key format
        let invalid_key = "invalid_public_key_format".to_string();

        // This should panic due to invalid public key format
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.store_device_linking_mapping(invalid_key, bob.clone());
        })).expect_err("Should panic with invalid public key format");
    }

    #[test]
    fn test_store_device_linking_mapping_valid_format() {
        let alice = AccountId::from_str("alice.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test valid device public key
        let device_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

        // This stores the mapping without creating a Promise
        // We're just verifying the function doesn't panic with valid input
        // Alice can only create device linking mappings for her own account
        contract.store_device_linking_mapping(device_public_key, alice.clone());

        // The function should complete without panicking
        // In a real blockchain environment, this would:
        // 1. Store the device linking mapping for Device2 to poll
        // 2. Emit the DEVICE_KEY_MAPPED log event
    }

    #[test]
    fn test_initiate_key_cleanup() {
        let alice = AccountId::from_str("alice.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test valid device public key
        let device_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

        // Test initiating key cleanup (Alice calling for her own account - should succeed)
        let data_id = contract.initiate_key_cleanup(device_public_key.clone(), alice.clone());

        // The function should complete without panicking
        // In a real blockchain environment, this would:
        // 1. Create a yield promise for automatic key cleanup after 200 blocks
        // 2. Return a data_id for later resume
        log!("Key cleanup initiated with data_id: {:?}", data_id);
    }

    #[test]
    fn test_initiate_key_cleanup_security_check() {
        let alice = AccountId::from_str("alice.testnet").unwrap();
        let bob = AccountId::from_str("bob.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test valid device public key
        let device_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

        // Test security check: Alice trying to delete keys for Bob's account should fail
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.initiate_key_cleanup(device_public_key.clone(), bob.clone());
        })).expect_err("Should panic when Alice tries to delete keys for Bob's account");
    }

    #[test]
    fn test_cleanup_temporary_key() {
        let alice = AccountId::from_str("alice.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test valid device public key
        let device_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

        // Test cleanup temporary key
        // Note: This would create a promise batch in a real blockchain environment
        contract.cleanup_temporary_key(device_public_key.clone(), alice.clone());

        // The function should complete without panicking
        // In a real blockchain environment, this would:
        // 1. Parse the public key
        // 2. Create a promise batch for the target account
        // 3. Add a delete key action to the batch
        // 4. Return the promise
        log!("Temporary key cleanup completed for key: {}", device_public_key);
    }
}
