# Device Linking: Automatic Cleanup of Stale Keys

## Problem

During device linking, temporary NEAR keys are added to user accounts (e.g., `serp149.web3-authn-v2.testnet`). If the device linking process fails, these keys remain on the account indefinitely (although the key is immediately discard on the client if not used).

The direct approach of having the contract (`web3-authn-v2.testnet`) delete keys from user accounts fails with:

```json
{
  "ActionError": {
    "kind": {
      "ActorNoPermission": {
        "actorId": "web3-authn-v2.testnet",
        "accountId": "serp149.web3-authn-v2.testnet"
      }
    },
    "index": "0"
  }
}
```

## Solutions:
Either we:
1. Pre-sign a DeleteKey transaction on Device1, and broadcast it when the user closes the QR Scanner:
- The issue is that the user could accidentally close the QR scanner on device1 before device2 polling detects the added key (and performs the rest of the link device flow), so we have a minor race condition.

2. We could try delegate temporary access key to the contract so that the contract can execute the DeleteKey action via a schedule yield-resume call (auto cleanup in 200 blocks) if device2 doesn't execute the swap key action.


## Solution 2: Temporary Access Key Approach

Since direct delegation isn't possible, we use a temporary access key approach:

1. **Grant Temporary Access**: User grants contract a limited access key
2. **Scheduled Deletion**: Contract uses yield-resume to delete the target key after timeout
3. **Cleanup**: Contract removes its own temporary access key

Flow Diagram
```
User Account (serp149.web3-authn-v2.testnet)
    ↓ (grants temp access)
Contract (web3-authn-v2.testnet)
    ↓ (after 200 blocks via yield-resume)
User Account (delete device key + temp access key)
```

## Implementation

### Step 1: Grant Temporary Access Key

```rust
#[near]
impl Web3AuthnContract {
    /// Called by user to grant temporary key deletion access to the contract
    pub fn grant_temporary_key_access(
        &mut self,
        target_account: AccountId,
        device_key_to_delete: PublicKey,
        temp_access_key: PublicKey
    ) -> Promise {
        // Verify caller is the target account
        assert_eq!(
            env::predecessor_account_id(),
            target_account,
            "Only account owner can grant access"
        );

        // Store which specific key can be deleted (security measure)
        self.authorized_deletions.insert(&target_account, &device_key_to_delete);

        // Grant contract limited access to the user's account
        Promise::new(target_account.clone())
            .add_access_key_allowance(
                temp_access_key,
                Allowance::Limited(NearToken::from_near(1).try_into().unwrap()),
                env::current_account_id(), // Contract can be called
                "delete_authorized_key".to_string() // Only this method
            )
    }
}
```

### Step 2: Authorized Key Deletion

```rust
#[near]
impl Web3AuthnContract {
    /// Deletes only pre-authorized keys using temporary access
    pub fn delete_authorized_key(&mut self, target_account: AccountId) -> Promise {
        // Get the authorized key for this account
        let device_key = self.authorized_deletions.get(&target_account)
            .expect("No authorized deletion for this account");

        // Delete the specific authorized key
        Promise::new(target_account.clone())
            .delete_key(device_key)
            .then(
                // Chain cleanup of authorization record
                Self::ext(env::current_account_id())
                    .cleanup_authorization(target_account)
            )
    }

    #[private]
    pub fn cleanup_authorization(&mut self, target_account: AccountId) {
        self.authorized_deletions.remove(&target_account);
    }
}
```

### Step 3: Yield-Resume Integration

```rust
#[near]
impl Web3AuthnContract {
    pub fn initiate_key_cleanup_with_temp_access(
        &mut self,
        target_account: AccountId,
        device_key: PublicKey,
        temp_access_key: PublicKey
    ) -> PromiseIndex {
        let args = serde_json::json!({
            "target_account": target_account,
            "device_key": device_key,
            "temp_access_key": temp_access_key
        }).to_string().into_bytes();

        promise_yield_create(
            "resume_key_cleanup_with_temp_access",
            &args,
            Gas::from_tgas(30),
            GasWeight(0),
            0
        )
    }

    #[private]
    pub fn resume_key_cleanup_with_temp_access(
        &mut self,
        target_account: AccountId,
        device_key: PublicKey,
        temp_access_key: PublicKey
    ) {
        // Use temporary access to delete the device key
        let delete_promise = env::promise_batch_create(&target_account);
        env::promise_batch_action_delete_key(delete_promise, &device_key);

        // Chain cleanup of the temporary access key
        let cleanup_promise = env::promise_batch_then(delete_promise, &target_account);
        env::promise_batch_action_delete_key(cleanup_promise, &temp_access_key);

        // Remove authorization record
        self.authorized_deletions.remove(&target_account);

        env::promise_return(cleanup_promise);
    }
}
```

### Step 4: Integration with Device Linking

```rust
pub fn store_device_linking_mapping(
    &mut self,
    device_public_key: PublicKey,
    target_account_id: AccountId,
) -> u32 {
    // ... existing logic ...

    // Generate temporary access key for cleanup
    let temp_access_key = self.generate_temp_access_key();

    // Schedule both mapping and key cleanup
    self.initiate_cleanup(device_public_key.clone());
    self.initiate_key_cleanup_with_temp_access(
        target_account_id.clone(),
        device_public_key,
        temp_access_key
    );

    // ... rest of logic ...
}
```

## Gas Cost Analysis

### Access Key Approach Operations

**Grant temporary access key** `promise.rs:350-364`
- `add_access_key_allowance`: ~5-10 TGas
- Cross-contract call overhead: ~2-5 TGas
- **Total**: ~7-15 TGas

**Delete target key using temp access** `env.rs:1449-1457`
- `promise_batch_action_delete_key`: ~2-5 TGas
- Promise batch creation: ~1-2 TGas
- **Total**: ~3-7 TGas

**Cleanup temporary key** (same delete operation)
- Another `promise_batch_action_delete_key`: ~2-5 TGas
- **Total**: ~2-5 TGas

**Yield-resume overhead** `env.rs:1588-1597`
- `promise_yield_create`: ~3-5 TGas
- `promise_yield_resume`: ~2-3 TGas
- **Total**: ~5-8 TGas

### Total Estimated Cost
- **Complete automated flow**: ~17-35 TGas

### Manual Alternative Cost
- **Manual key deletion by user**: ~2-5 TGas

