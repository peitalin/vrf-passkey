# Signer Smart Contract for Passkey-Controlled NEAR Account

This document outlines the features, state, and methods for a NEAR smart contract designed to enable account control via passkeys, mediated by a trusted backend server.

**Smart Contract Name Suggestion:** `PasskeyControlledAccount`

**Assumed Architecture:**
The contract itself is deployed on the user's account (e.g., `username.your-app.near`). A trusted backend server, acting as a relayer, verifies WebAuthn assertions from the user and then calls methods on this contract to manage passkey associations and execute transactions.

## I. State (Storage)

The contract needs to store the following:

1.  `trusted_relayer_account_id: AccountId`
    *   **Purpose:** Stores the Account ID of your backend server's relayer. This is the only account authorized to call privileged methods.
    *   **Type (Rust):** `near_sdk::AccountId`
    *   **Mutability:** Set at initialization, potentially updatable by an owner/admin.

2.  `registered_passkey_pks: UnorderedSet<PublicKey>`
    *   **Purpose:** Stores the set of *derived NEAR Ed25519 public keys* that are authorized to "control" this account through the `trusted_relayer_account_id`. These public keys are derived by the server from the user's passkey COSE keys.
    *   **Type (Rust):** `near_sdk::store::UnorderedSet<near_sdk::PublicKey>` (using `near_sdk::PublicKey` for NEAR Ed25519 public keys).
    *   **Mutability:** Managed by methods callable by the `trusted_relayer_account_id`.

3.  `owner_id: AccountId` (Optional, but recommended for admin)
    *   **Purpose:** Stores the Account ID that has administrative rights over this contract instance, primarily for setting/updating the `trusted_relayer_account_id`.
    *   **Type (Rust):** `near_sdk::AccountId`
    *   **Mutability:** Set at initialization.

## II. Methods (Interface)

### 1. Initialization & Admin Methods

*   **`new(trusted_relayer_account_id: AccountId, owner_id: AccountId, initial_passkey_pks: Option<Vec<PublicKey>>)`**
    *   **Purpose:** Constructor for the contract. Marked with `#[init]`.
    *   **Parameters:**
        *   `trusted_relayer_account_id: AccountId`: The account ID of your server's relayer.
        *   `owner_id: AccountId`: The account ID that will own/administer this contract instance.
        *   `initial_passkey_pks: Option<Vec<PublicKey>>`: (Optional) A list of derived NEAR public keys to register immediately.
    *   **Logic:**
        *   Initializes `self.trusted_relayer_account_id`.
        *   Initializes `self.owner_id`.
        *   Initializes `self.registered_passkey_pks`, adding any `initial_passkey_pks`.
    *   **Example (Conceptual Rust):**
        ```rust
        use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
        use near_sdk::collections::UnorderedSet;
        use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault, PublicKey}; // near_sdk::PublicKey
        use std::collections::HashSet; // Only if converting Vec to Set manually

        #[near_bindgen]
        #[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
        pub struct PasskeyControlledAccount {
            trusted_relayer_account_id: AccountId,
            owner_id: AccountId,
            registered_passkey_pks: UnorderedSet<PublicKey>,
        }

        #[near_bindgen]
        impl PasskeyControlledAccount {
            #[init]
            pub fn new(
                trusted_relayer_account_id: AccountId,
                owner_id: AccountId,
                initial_passkey_pks: Option<Vec<PublicKey>>,
            ) -> Self {
                assert!(!env::state_exists(), "Already initialized");
                let mut pk_set = UnorderedSet::new(b"p".to_vec());
                if let Some(keys) = initial_passkey_pks {
                    for key in keys {
                        pk_set.insert(&key);
                    }
                }
                Self {
                    trusted_relayer_account_id,
                    owner_id,
                    registered_passkey_pks: pk_set,
                }
            }
            // ... other methods ...
        }
        ```

*   **`set_trusted_relayer(&mut self, account_id: AccountId)`**
    *   **Purpose:** Allows the `owner_id` to update the `trusted_relayer_account_id`.
    *   **Security:** Asserts that `env::predecessor_account_id() == self.owner_id`.
    *   **Logic:** Updates `self.trusted_relayer_account_id`.
    *   **Example (Conceptual Rust):**
        ```rust
        // In impl PasskeyControlledAccount
        pub fn set_trusted_relayer(&mut self, account_id: AccountId) {
            assert_eq!(
                env::predecessor_account_id(),
                self.owner_id,
                "Only owner can set trusted relayer"
            );
            self.trusted_relayer_account_id = account_id;
        }
        ```

*   **`get_trusted_relayer(&self) -> AccountId`**
    *   **Purpose:** View method to retrieve the current `trusted_relayer_account_id`.
    *   **Example (Conceptual Rust):**
        ```rust
        // In impl PasskeyControlledAccount
        pub fn get_trusted_relayer(&self) -> AccountId {
            self.trusted_relayer_account_id.clone()
        }
        ```

*   **`get_owner_id(&self) -> AccountId`**
    *   **Purpose:** View method to retrieve the `owner_id`.
    *   **Example (Conceptual Rust):**
        ```rust
        // In impl PasskeyControlledAccount
        pub fn get_owner_id(&self) -> AccountId {
            self.owner_id.clone()
        }
        ```

### 2. Passkey Public Key Management Methods (Callable by Trusted Relayer)

*   **`add_passkey_pk(&mut self, passkey_pk: PublicKey)`**
    *   **Purpose:** Registers a new derived NEAR public key (from a passkey) as an authorized key for this account.
    *   **Security:** Asserts that `env::predecessor_account_id() == self.trusted_relayer_account_id`.
    *   **Logic:** Adds `passkey_pk` to `self.registered_passkey_pks`.
    *   **Returns:** (Optional) `bool` for success, or emits an event.
    *   **Example (Conceptual Rust):**
        ```rust
        // In impl PasskeyControlledAccount
        pub fn add_passkey_pk(&mut self, passkey_pk: PublicKey) -> bool {
            assert_eq!(
                env::predecessor_account_id(),
                self.trusted_relayer_account_id,
                "Only trusted relayer can add passkey PKs"
            );
            self.registered_passkey_pks.insert(&passkey_pk)
        }
        ```

*   **`remove_passkey_pk(&mut self, passkey_pk: PublicKey)`**
    *   **Purpose:** De-registers a derived NEAR public key.
    *   **Security:** Asserts that `env::predecessor_account_id() == self.trusted_relayer_account_id`.
    *   **Logic:** Removes `passkey_pk` from `self.registered_passkey_pks`.
    *   **Returns:** (Optional) `bool` for success, or emits an event.
    *   **Example (Conceptual Rust):**
        ```rust
        // In impl PasskeyControlledAccount
        pub fn remove_passkey_pk(&mut self, passkey_pk: PublicKey) -> bool {
            assert_eq!(
                env::predecessor_account_id(),
                self.trusted_relayer_account_id,
                "Only trusted relayer can remove passkey PKs"
            );
            self.registered_passkey_pks.remove(&passkey_pk)
        }
        ```

*   **`is_passkey_pk_registered(&self, passkey_pk: PublicKey) -> bool`**
    *   **Purpose:** View method to check if a specific derived NEAR public key is registered.
    *   **Logic:** Returns `self.registered_passkey_pks.contains(&passkey_pk)`.
    *   **Example (Conceptual Rust):**
        ```rust
        // In impl PasskeyControlledAccount
        pub fn is_passkey_pk_registered(&self, passkey_pk: PublicKey) -> bool {
            self.registered_passkey_pks.contains(&passkey_pk)
        }
        ```

### 3. Transaction Execution Method (Callable by Trusted Relayer)

*   **`execute_actions(&mut self, passkey_pk_used: PublicKey, actions_to_execute: Vec<SerializableAction>)`**
    *   **Purpose:** The core method that executes NEAR actions on behalf of this account (`env::current_account_id()`), authorized by a passkey (whose use was verified by the server).
    *   **Parameters:**
        *   `passkey_pk_used: PublicKey`: The derived NEAR public key corresponding to the passkey the user authenticated with.
        *   `actions_to_execute: Vec<SerializableAction>`: A vector of `SerializableAction` structs (defined in section III) describing the actions to perform.
    *   **Security:**
        *   Asserts `env::predecessor_account_id() == self.trusted_relayer_account_id`.
        *   Asserts `self.registered_passkey_pks.contains(&passkey_pk_used)`, ensuring the passkey (identified by its derived public key) is known and authorized.
    *   **Logic:**
        *   Iterates through `actions_to_execute`.
        *   For each `SerializableAction`, constructs and dispatches the appropriate `near_sdk::Promise`.
    *   **Example (Conceptual Rust):**
        ```rust
        use near_sdk::{Promise, Gas};
        use near_sdk::json_types::{U128, Base64VecU8};
        // Assuming SerializableAction and ActionType are defined as in section III

        // In impl PasskeyControlledAccount
        pub fn execute_actions(
            &mut self,
            passkey_pk_used: PublicKey,
            actions_to_execute: Vec<SerializableAction>,
        ) {
            assert_eq!(
                env::predecessor_account_id(),
                self.trusted_relayer_account_id,
                "Only trusted relayer can execute actions"
            );
            assert!(
                self.registered_passkey_pks.contains(&passkey_pk_used),
                "Passkey PK not registered for this account"
            );

            for s_action in actions_to_execute {
                // Note: For batched actions to the SAME receiver, you'd build up one Promise.
                // This simplified example creates a new promise for each action descriptor.
                let mut promise = Promise::new(s_action.receiver_id.clone());
                match s_action.action_type {
                    ActionType::Transfer => {
                        promise = promise.transfer(s_action.amount.expect("Amount missing for transfer").0);
                    }
                    ActionType::FunctionCall => {
                        promise = promise.function_call(
                            s_action.method_name.expect("Method name missing for function call"),
                            s_action.args.unwrap_or_else(|| Base64VecU8(vec![])).0, // Default to empty args if None
                            s_action.deposit.unwrap_or(U128(0)).0,
                            s_action.gas.expect("Gas missing for function call"),
                        );
                    }
                    // Add other action types like AddKey, DeleteKey etc. as needed
                }
            }
            // Promises are automatically dispatched at the end of the function execution.
            // If you need to chain them or handle results, you'd use .then()
        }
        ```

## III. Serializable Action Struct (Helper for `execute_actions`)

To pass complex actions as parameters from the server (likely as JSON) to the smart contract, you'll need a helper struct that can be serialized and deserialized (e.g., with Borsh for storage/internal and Serde for JSON).

```rust
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, Balance, Gas, PublicKey}; // near_sdk::PublicKey for internal use
use near_sdk::json_types::{U128, Base64VecU8}; // For JSON args compatibility

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub enum ActionType {
    Transfer,
    FunctionCall,
    // Future considerations: AddKey, DeleteKey, DeployContract, Stake, DeleteAccount.
    // For AddKey/DeleteKey, you'd need serializable AccessKey and PublicKey structs.
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct SerializableAction {
    pub action_type: ActionType,
    pub receiver_id: AccountId, // Target account for the action

    // --- Transfer specific ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U128>, // For Transfer action_type

    // --- FunctionCall specific ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Base64VecU8>, // Arguments for the function call, base64 encoded (usually from a JSON string)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<Gas>,          // Gas for the function call
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit: Option<U128>,     // Attached deposit for the function call
}
```

## Summary of Contract Operational Flow

1.  **Deployment:**
    *   The `PasskeyControlledAccount` contract code is deployed to a new user account (e.g., `alice.your-app.near`).
    *   It's initialized with your server's `trusted_relayer_account_id` and an `owner_id`.

2.  **Passkey Registration (User Onboarding):**
    *   User registers a passkey on your frontend application.
    *   Frontend sends the COSE public key to your backend server.
    *   Server validates the COSE key, derives a NEAR-compatible Ed25519 public key (`derived_near_pk_alice`).
    *   Server (acting as `trusted_relayer_account_id`) calls the `add_passkey_pk` method on `alice.your-app.near`, passing `derived_near_pk_alice`.

3.  **Transaction Execution (User Action):**
    *   User initiates an action on your frontend (e.g., "send 0.1 NEAR to `bob.near`").
    *   Frontend prepares the transaction details and obtains a WebAuthn assertion from the user for this specific intent (challenge should be tied to transaction details).
    *   Frontend sends the WebAuthn assertion and the `SerializableAction` (e.g., `{ type: Transfer, receiver: "bob.near", amount: "100000000000000000000000" }` for 0.1 NEAR) to the server.
    *   Server verifies the WebAuthn assertion against the stored COSE public key for the user.
    *   If valid, the server (as `trusted_relayer_account_id`) calls the `execute_actions` method on `alice.your-app.near`.
        *   Parameters: `passkey_pk_used = derived_near_pk_alice`, `actions_to_execute = [the_serializable_action_for_transfer]`.
    *   The `execute_actions` method on `alice.your-app.near` contract:
        *   Verifies the caller is the `trusted_relayer_account_id`.
        *   Verifies `derived_near_pk_alice` is in its `registered_passkey_pks`.
        *   Constructs and dispatches a NEAR promise: `Promise::new("bob.near").transfer(0.1 NEAR_equivalent_in_yoctoNEAR)`.
        *   The actual sender of this transfer is `alice.your-app.near` (the contract's own account ID).

This detailed outline should provide a strong starting point for developing your `PasskeyControlledAccount` smart contract.