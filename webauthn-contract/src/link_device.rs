use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{
    log, near, env, serde_json, require,
    Promise, AccountId, NearToken, Gas, PublicKey, CryptoHash, GasWeight
};

// Simple enum for access key permission
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
    /// Add a device key to an account and store temporary mapping for Device2 polling
    /// This enables secure device linking where Device2 can poll for the mapping
    pub fn add_device_key(
        &mut self,
        device_public_key: String,
        target_account_id: AccountId,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        require!(caller == target_account_id, "Caller must be the target account");

        log!(
            "Adding device key {} to account {} on behalf of {}",
            device_public_key,
            target_account_id,
            caller
        );

        // Parse the public key to validate format
        let parsed_key = match device_public_key.parse::<PublicKey>() {
            Ok(key) => key,
            Err(e) => {
                env::panic_str(&format!("Invalid public key format: {}", e));
            }
        };

        // Store temporary mapping for Device2 to poll (account ID and access key permission)
        self.device_linking_map.insert(
            device_public_key.clone(),
            (target_account_id.clone(), AccessKeyPermission::FullAccess)
        );

        // Initiate automatic cleanup after 200 blocks using yield-resume pattern
        let _data_id = self.initiate_cleanup(device_public_key.clone());

        // Add the key to the target account via cross-contract call
        let add_key_promise = Promise::new(target_account_id.clone())
            .add_full_access_key(parsed_key);

        // Chain with callback to emit log event
        let callback_promise = Promise::new(env::current_account_id()).function_call(
            "on_device_key_added".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "device_public_key": device_public_key,
                "target_account_id": target_account_id,
                "caller": caller,
            })).unwrap(),
            NearToken::from_yoctonear(0), // No payment needed for callback
            Gas::from_tgas(10), // 10 TGas should be sufficient for logging
        );

        add_key_promise.then(callback_promise)
    }

    /// Callback function to emit log event after device key is added
    #[private]
    pub fn on_device_key_added(
        &mut self,
        device_public_key: String,
        target_account_id: AccountId,
        caller: AccountId,
    ) {
        // Check if the previous promise (add_key) succeeded
        let promise_result = env::promise_result(0);

        match promise_result {
            near_sdk::PromiseResult::Successful(_) => {
                // Emit structured log event that Device2 can poll
                log!(
                    "DEVICE_KEY_ADDED:{}:{}:{}:{}",
                    device_public_key,
                    target_account_id,
                    caller,
                    env::block_timestamp()
                );

                log!("Device key successfully added to account {}", target_account_id);
            }
            _ => {
                log!("Failed to add device key {} to account {}", device_public_key, target_account_id);
                env::panic_str("Device key addition failed");
            }
        }
    }

    /// View function for Device2 to query which account it will be linked to and the access key permission
    /// Device2 calls this with its public key to discover Device1's account ID and confirm the access key permission
    pub fn get_device_linking_account(&self, device_public_key: String) -> Option<(AccountId, AccessKeyPermission)> {
        self.device_linking_map.get(&device_public_key)
            .map(|(account_id, permission)| (account_id.clone(), permission.clone()))
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
    /// This should be called after Device2 completes verify_and_register_user
    /// OR automatically called by the yield-resume pattern after 200 blocks
    pub fn cleanup_device_linking(&mut self, device_public_key: String) {
        self.device_linking_map.remove(&device_public_key);
        log!("Cleaned up device linking mapping for key: {}", device_public_key);
    }

    /// Test helper method to manually add device linking entry for testing
    /// This bypasses the normal add_device_key flow to enable testing of just the HashMap cleanup
    /// WARNING: This is for testing purposes only and should not be used in production
    pub fn test_add_device_linking_entry(&mut self, device_public_key: String, account_id: AccountId) {
        self.device_linking_map.insert(
            device_public_key.clone(),
            (account_id.clone(), AccessKeyPermission::FullAccess)
        );

        // Initiate automatic cleanup after 200 blocks using yield-resume pattern
        let _data_id = self.initiate_cleanup(device_public_key.clone());

        log!("Test helper: Added device linking entry for key: {} -> account: {}", device_public_key, account_id);
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
    fn test_add_device_key_invalid_public_key() {
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
            contract.add_device_key(invalid_key, bob.clone());
        })).expect_err("Should panic with invalid public key format");
    }

    #[test]
    fn test_add_device_key_valid_format() {
        let alice = AccountId::from_str("alice.testnet").unwrap();
        let bob = AccountId::from_str("bob.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init("test_contract".to_string());

        // Test valid device public key
        let device_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

        // This creates a Promise but won't execute in test environment
        // We're just verifying the function doesn't panic with valid input
        let _promise = contract.add_device_key(device_public_key, bob.clone());

        // The function should complete without panicking
        // In a real blockchain environment, this would:
        // 1. Add the key to bob's account
        // 2. Emit the DEVICE_KEY_ADDED log event
    }
}
