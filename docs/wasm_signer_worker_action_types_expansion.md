# WASM Signer Worker Action Types Expansion Plan

## Overview

This document outlines the plan to refactor and expand the WASM signer worker (`packages/passkey/src/wasm_signer_worker`) to support all NEAR action types, not just `FunctionCall`. The current implementation is hardcoded to only handle function calls, but NEAR supports 8 different action types.

## Current State Analysis

### Existing Implementation
- **Location**: `packages/passkey/src/wasm_signer_worker/src/lib.rs`
- **Current Support**: Only `FunctionCall` actions
- **Entry Points**:
  - `sign_near_transaction_with_prf()` - hardcoded to FunctionCall
  - `decrypt_and_sign_transaction_with_prf()` - wrapper for the above
  - `sign_transaction_with_encrypted_key()` - worker interface

### Current Limitations
1. **Hardcoded Action Type**: All transactions assume FunctionCall actions
2. **Monolithic Structure**: Transaction building logic is embedded in signing functions
3. **Limited Worker Interface**: Worker request types don't specify action types
4. **No Action Validation**: No validation for action-specific parameters

## Target Action Types

```rust
pub enum ActionType {
    CreateAccount,
    DeployContract,
    FunctionCall,
    Transfer,
    Stake,
    AddKey,
    DeleteKey,
    DeleteAccount,
}
```

## Phase 1: Refactoring for Modularity

### 1.1 Extract Action Building Logic

**Goal**: Separate action creation from transaction signing

**Changes**:
```rust
// New action builder module
mod action_builder {
    pub fn build_function_call_action(
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
        deposit: Balance,
    ) -> Action;

    pub fn build_transfer_action(deposit: Balance) -> Action;

    pub fn build_create_account_action() -> Action;

    // ... other action builders
}
```

### 1.2 Create Action Handler Trait

**Goal**: Standardize action handling with a common interface

```rust
pub trait ActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String>;
    fn build_action(&self, params: &ActionParams) -> Result<Action, String>;
    fn get_action_type(&self) -> ActionType;
}
```

### 1.3 Refactor Transaction Builder

**Goal**: Make transaction building action-agnostic

```rust
pub struct TransactionBuilder {
    signer_id: AccountId,
    receiver_id: AccountId,
    nonce: u64,
    block_hash: CryptoHash,
    public_key: PublicKey,
}

impl TransactionBuilder {
    pub fn add_action(&mut self, action: Action) -> &mut Self;
    pub fn build(self) -> Transaction;
}
```

## Phase 2: Worker Interface Updates

### 2.1 Enhanced Request Types

**File**: `packages/passkey/src/core/types/worker.ts`

```typescript
export interface ActionParams {
  actionType: ActionType;
  // Union type for all action-specific parameters
  functionCall?: {
    methodName: string;
    args: Record<string, any>;
    gas: string;
    deposit: string;
  };
  transfer?: {
    deposit: string;
  };
  createAccount?: {};
  // ... other action types
}

export interface DecryptAndSignTransactionWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF;
  payload: {
    nearAccountId: string;
    prfOutput: string;
    receiverId: string;
    actions: ActionParams[]; // Support multiple actions
    nonce: string;
    blockHashBytes: number[];
  };
}
```

### 2.2 Worker Message Validation

Add validation for action-specific parameters before sending to WASM:

```typescript
function validateActionParams(actionParams: ActionParams): void {
  switch (actionParams.actionType) {
    case ActionType.FunctionCall:
      if (!actionParams.functionCall?.methodName) {
        throw new Error('methodName required for FunctionCall');
      }
      break;
    case ActionType.Transfer:
      if (!actionParams.transfer?.deposit) {
        throw new Error('deposit required for Transfer');
      }
      break;
    // ... other validations
  }
}
```

## Phase 3: WASM Implementation - Transfer Action

### 3.1 Action Handler Implementation

**File**: `packages/passkey/src/wasm_signer_worker/src/lib.rs`

```rust
pub struct TransferActionHandler;

impl ActionHandler for TransferActionHandler {
    fn validate_params(&self, params: &ActionParams) -> Result<(), String> {
        match params {
            ActionParams::Transfer { deposit } => {
                if deposit.is_empty() {
                    return Err("Transfer deposit cannot be empty".to_string());
                }
                deposit.parse::<Balance>()
                    .map_err(|_| "Invalid deposit amount".to_string())?;
                Ok(())
            }
            _ => Err("Invalid params for Transfer action".to_string())
        }
    }

    fn build_action(&self, params: &ActionParams) -> Result<Action, String> {
        match params {
            ActionParams::Transfer { deposit } => {
                let deposit_amount = deposit.parse::<Balance>()
                    .map_err(|e| format!("Failed to parse deposit: {}", e))?;
                Ok(Action::Transfer { deposit: deposit_amount })
            }
            _ => Err("Invalid params for Transfer action".to_string())
        }
    }

    fn get_action_type(&self) -> ActionType {
        ActionType::Transfer
    }
}
```

### 3.2 Action Parameters Enum

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "actionType")]
pub enum ActionParams {
    CreateAccount,
    DeployContract { code: Vec<u8> },
    FunctionCall {
        method_name: String,
        args: String, // JSON string
        gas: String,
        deposit: String,
    },
    Transfer {
        deposit: String,
    },
    Stake {
        stake: String,
        public_key: String, // NEAR format public key
    },
    AddKey {
        public_key: String,
        access_key: String, // JSON serialized AccessKey
    },
    DeleteKey {
        public_key: String,
    },
    DeleteAccount {
        beneficiary_id: String,
    },
}
```

### 3.3 Refactored Signing Function

```rust
#[wasm_bindgen]
pub fn sign_near_transaction_with_actions(
    // Authentication
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,

    // Transaction details
    signer_account_id: &str,
    receiver_account_id: &str,
    nonce: u64,
    block_hash_bytes: &[u8],
    actions_json: &str, // JSON array of ActionParams
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting NEAR transaction signing with multiple actions");

    // 1. Decrypt private key using PRF
    let private_key = decrypt_private_key_with_prf_internal(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
    )?;

    // 2. Parse actions
    let action_params: Vec<ActionParams> = serde_json::from_str(actions_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse actions: {}", e)))?;

    // 3. Build actions using handlers
    let mut actions = Vec::new();
    for params in action_params {
        let handler = get_action_handler(&params)?;
        handler.validate_params(&params)?;
        let action = handler.build_action(&params)?;
        actions.push(action);
    }

    // 4. Build and sign transaction
    let transaction = build_transaction(
        signer_account_id,
        receiver_account_id,
        nonce,
        block_hash_bytes,
        &private_key,
        actions,
    )?;

    sign_transaction(transaction, private_key)
}

fn get_action_handler(params: &ActionParams) -> Result<Box<dyn ActionHandler>, String> {
    match params {
        ActionParams::FunctionCall { .. } => Ok(Box::new(FunctionCallActionHandler)),
        ActionParams::Transfer { .. } => Ok(Box::new(TransferActionHandler)),
        ActionParams::CreateAccount => Ok(Box::new(CreateAccountActionHandler)),
        // ... other handlers
        _ => Err("Unsupported action type".to_string()),
    }
}
```

## Phase 4: Integration Points

### 4.1 WebAuthnWorkers Updates

**File**: `packages/passkey/src/core/WebAuthnManager/webauthn-workers.ts`

Update `secureTransactionSigningWithPrf` to support action arrays:

```typescript
async secureTransactionSigningWithPrf(
  nearAccountId: string,
  prfOutput: ArrayBuffer,
  payload: {
    nearAccountId: string;
    receiverId: string;
    actions: ActionParams[];
    nonce: string;
    blockHashBytes: number[];
  }
): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
  // ... existing PRF validation logic

  const workerPayload = {
    nearAccountId: payload.nearAccountId,
    prfOutput: bufferEncode(prfOutput),
    receiverId: payload.receiverId,
    actions: payload.actions, // Pass actions array
    nonce: payload.nonce,
    blockHashBytes: payload.blockHashBytes
  };

  // ... rest of implementation
}
```

### 4.2 PasskeyManager Updates

**File**: `packages/passkey/src/core/PasskeyManager/actions.ts`

```typescript
export async function signTransferTransaction(
  nearAccountId: string,
  receiverId: string,
  depositAmount: string,
  options?: {
    nonce?: string;
    blockHash?: string;
  }
): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
  const actions: ActionParams[] = [{
    actionType: ActionType.Transfer,
    transfer: {
      deposit: depositAmount
    }
  }];

  return signTransaction(nearAccountId, receiverId, actions, options);
}

async function signTransaction(
  nearAccountId: string,
  receiverId: string,
  actions: ActionParams[],
  options?: {
    nonce?: string;
    blockHash?: string;
  }
): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
  // ... existing authentication and network call logic
  // Updated to pass actions array instead of individual action parameters
}
```

## Phase 5: Testing Strategy

### 5.1 NEAR Libraries for Test Validation

**Important**: `near-primitives` and `near-api-rs` are not WASM-compatible but can be used as `dev-dependencies` for testing.

**File**: `packages/passkey/src/wasm_signer_worker/Cargo.toml`

```toml
[dev-dependencies]
near-primitives = "0.30"
near-crypto = "0.30"
near-sdk = "5.13"
near-api = "0.6"
```

This allows us to:
1. Cross-validate our WASM transaction building against official NEAR libraries
2. Test that our Borsh serialization matches NEAR's expected format
3. Verify transaction hashes and signatures match reference implementations

### 5.2 Unit Tests (Rust)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Use near-primitives for reference validation in tests
    #[cfg(test)]
    use near_primitives::{
        transaction::{Transaction as NearTransaction, Action as NearAction, TransferAction},
        types::{AccountId as NearAccountId, Balance as NearBalance},
        hash::CryptoHash as NearCryptoHash,
    };

    #[test]
    fn test_transfer_action_handler() {
        let handler = TransferActionHandler;
        let params = ActionParams::Transfer {
            deposit: "1000000000000000000000000".to_string(),
        };

        assert!(handler.validate_params(&params).is_ok());
        let action = handler.build_action(&params).unwrap();

        match action {
            Action::Transfer { deposit } => {
                assert_eq!(deposit, 1000000000000000000000000u128);
            }
            _ => panic!("Expected Transfer action"),
        }
    }

    #[test]
    fn test_transaction_compatibility_with_near_primitives() {
        // Test that our WASM transaction matches near-primitives transaction
        let our_transaction = build_test_transaction();
        let near_transaction = build_reference_near_transaction();

        // Serialize both and compare
        let our_serialized = borsh::to_vec(&our_transaction).unwrap();
        let near_serialized = borsh::to_vec(&near_transaction).unwrap();

        assert_eq!(our_serialized, near_serialized, "Transaction serialization must match NEAR reference");
    }

    #[test]
    fn test_multi_action_transaction_signing() {
        // Test transaction with multiple actions against near-primitives reference
    }

    #[test]
    fn test_signature_verification_with_near_crypto() {
        // Use near-crypto to verify our signatures are valid
    }
}
```

### 5.3 Integration Tests (TypeScript)

```typescript
describe('Clean Action-Based Transaction Signing', () => {
  test('should sign transfer transaction with clean API', async () => {
    const transferResult = await passkeyManager.signTransferTransaction({
      nearAccountId: 'test.testnet',
      receiverId: 'receiver.testnet',
      deposit: '1000000000000000000000000'
    });

    expect(transferResult.signedTransactionBorsh).toBeDefined();
    expect(transferResult.nearAccountId).toBe('test.testnet');
  });

  test('should sign function call transaction with clean API', async () => {
    const functionCallResult = await passkeyManager.signFunctionCallTransaction({
      nearAccountId: 'test.testnet',
      receiverId: 'contract.testnet',
      methodName: 'set_greeting',
      args: { greeting: 'Hello World' },
      gas: '30000000000000',
      deposit: '0'
    });

    expect(functionCallResult.signedTransactionBorsh).toBeDefined();
  });

  test('should sign multi-action transaction', async () => {
    const actions: ActionParams[] = [
      {
        actionType: ActionType.Transfer,
        transfer: { deposit: '1000000000000000000000000' }
      },
      {
        actionType: ActionType.FunctionCall,
        functionCall: {
          methodName: 'set_greeting',
          args: { greeting: 'Hello' },
          gas: '30000000000000',
          deposit: '0'
        }
      }
    ];

    const result = await passkeyManager.signMultiActionTransaction({
      nearAccountId: 'test.testnet',
      receiverId: 'receiver.testnet',
      actions
    });

    expect(result.signedTransactionBorsh).toBeDefined();
  });

  test('should validate against near-primitives in Node.js tests', async () => {
    // This test can use near-primitives since it runs in Node.js, not WASM
    const { SignedTransaction } = await import('near-primitives');

    const result = await passkeyManager.signTransferTransaction({
      nearAccountId: 'test.testnet',
      receiverId: 'receiver.testnet',
      deposit: '1000000000000000000000000'
    });

    // Deserialize our signed transaction using near-primitives
    const signedTx = SignedTransaction.decode(Buffer.from(result.signedTransactionBorsh));
    expect(signedTx.transaction.actions).toHaveLength(1);
    expect(signedTx.transaction.actions[0]).toHaveProperty('Transfer');
  });
});
```

## Phase 6: Implementation Timeline

### Week 1: Core Refactoring
- [ ] Extract action building logic from signing functions
- [ ] Create ActionHandler trait and base infrastructure
- [ ] Update Rust transaction building to be action-agnostic
- [ ] Add comprehensive unit tests for refactored code

### Week 2: Transfer Action Implementation
- [ ] Implement TransferActionHandler
- [ ] Update worker request/response types
- [ ] Add Transfer action validation
- [ ] Create `signTransferTransaction` in PasskeyManager
- [ ] Add integration tests for Transfer actions

### Week 3: Multi-Action Support
- [ ] Update worker interface to support action arrays
- [ ] Implement multi-action transaction building
- [ ] Add validation for action combinations
- [ ] Update WebAuthnWorkers for multi-action support

### Week 4: Documentation and Testing
- [ ] Add basic documentation for new action system
- [ ] Create basic examples for each action type
- [ ] Integration testing with frontend components

## Phase 7: Future Action Types

After Transfer is successfully implemented, the remaining action types can be added following the same pattern:

### Priority Order:
1. **Transfer** ✓ (Phase 3)
2. **AddKey** - Important for account management
3. **DeleteKey** - Pairs with AddKey
4. **CreateAccount** - Simple action, no parameters
5. **DeleteAccount** - Destructive action, needs extra safety
6. **Stake** - Requires staking-specific validation
7. **DeployContract** - More complex, requires contract bytecode (do this later)

### Implementation Pattern:
For each new action type:
1. Create `{ActionType}ActionHandler` struct
2. Implement `ActionHandler` trait
3. Add to `get_action_handler()` function
4. Add corresponding TypeScript interface
5. Create helper function in PasskeyManager
6. Add unit and integration tests

## Clean API Design (No Legacy Support)

### New Action-Based API

The new API will be clean and action-focused without backward compatibility concerns:

```typescript
// Clean action-based interface
interface PasskeyTransactionSigner {
  // Single action transactions
  signTransferTransaction(params: TransferParams): Promise<SignedTransaction>;
  signFunctionCallTransaction(params: FunctionCallParams): Promise<SignedTransaction>;
  signCreateAccountTransaction(params: CreateAccountParams): Promise<SignedTransaction>;

  // Multi-action transactions
  signMultiActionTransaction(params: MultiActionParams): Promise<SignedTransaction>;
}

interface TransferParams {
  nearAccountId: string;
  receiverId: string;
  deposit: string;
  nonce?: string;
  blockHash?: string;
}

interface MultiActionParams {
  nearAccountId: string;
  receiverId: string;
  actions: ActionParams[];
  nonce?: string;
  blockHash?: string;
}
```

### Implementation Benefits
1. **Type Safety**: Each action type has specific parameters
2. **Clear Intent**: Method names clearly indicate the action being performed
3. **Extensibility**: Easy to add new action types without breaking existing code
4. **Multi-Action Support**: Single transaction can contain multiple actions
5. **Validation**: Action-specific validation at both TypeScript and Rust levels

## Success Metrics

1. **NEAR Compatibility**: All transactions validate against official `near-primitives` in tests
2. **Code Coverage**: 90%+ test coverage for new action handlers
3. **Performance**: No regression in transaction signing speed
4. **Developer Experience**: Clean, type-safe API for each action type
5. **Documentation**: Complete examples for all supported action types
6. **Cross-Validation**: Borsh serialization matches NEAR reference implementations
7. **Signature Verification**: All signatures validate with `near-crypto` in tests

## Additional Considerations

### WASM Compatibility Constraints
- **Custom Types**: All NEAR transaction types must be implemented in WASM-compatible Rust
- **No Dependencies**: Cannot use `near-primitives` or `near-api-rs` in runtime WASM code (you can try, but we ran into compatibility issues before, hence we reimplemented functionCall TX signing in the wasm worker ourselves)
- **Test Validation**: Use official NEAR libraries in `dev-dependencies` for cross-validation
- **Borsh Serialization**: Must match exact format expected by NEAR protocol

### Development Workflow
1. Implement action handlers in WASM-compatible Rust
2. Cross-validate against `near-primitives` in unit tests
3. Verify Borsh serialization format matches exactly
4. Test signatures with `near-crypto` validation
5. Integration test with actual NEAR networks

This plan provides a structured approach to expanding the WASM signer worker while ensuring full compatibility with NEAR protocol standards without legacy constraints.