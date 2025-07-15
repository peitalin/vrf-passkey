# create_account_and_verify() Integration Plan

## Overview

The `create_account_and_verify()` function in the WebAuthn contract provides atomic account creation with WebAuthn registration. This needs to be integrated into the passkey SDK, but only when using the relay-server (not the testnet faucet).

## Current State

- ✅ Contract function `create_account_and_verify()` is implemented
- ✅ Atomic transaction combines VRF proof + WebAuthn verification + account creation + NEAR transfer
- ❌ SDK integration is missing
- ❌ Relay-server detection logic is missing

## Implementation Requirements

### 1. Relay-Server Detection Logic

The SDK needs to detect when it's configured to use the relay-server vs direct testnet faucet:

```typescript
// In PasskeyManager configuration
interface PasskeyConfig {
  relayServerUrl?: string;
  initialUseRelayer: boolean;
  // ... other config
}

// Detection logic
const shouldUseAtomicRegistration = config.initialUseRelayer && config.relayServerUrl;
```

### 2. Registration Flow Modification

**Current Flow (Testnet Faucet):**
1. Generate WebAuthn credentials
2. Call testnet faucet directly
3. Register credentials with contract

**New Flow (Relay-Server with Atomic Registration):**
1. Generate WebAuthn credentials
2. Call `create_account_and_verify()` directly
3. Handle atomic transaction response

### 3. SDK Integration Points

#### 3.1 Registration Function Updates

Update `packages/passkey/src/core/PasskeyManager/registration.ts`:

```typescript
export async function registerWithAtomic(
  accountId: string,
  credential: WebAuthnCredential,
  vrfProof: VRFProof,
  contractId: string
): Promise<RegistrationResult> {
  // Call create_account_and_verify() instead of separate registration
  const result = await contractCalls.createAccountAndVerify({
    accountId,
    credential,
    vrfProof,
    initialBalance: "0.1" // or from config
  });

  return result;
}
```

#### 3.2 Contract Calls Integration

Update `packages/passkey/src/core/WebAuthnManager/contract-calls.ts`:

```typescript
class WebAuthnContractCalls {
  async createAccountAndVerify(params: {
    accountId: string;
    credential: WebAuthnCredential;
    vrfProof: VRFProof;
    initialBalance?: string;
  }): Promise<AtomicRegistrationResult> {
    // Implementation for atomic registration
  }
}
```

#### 3.3 Configuration Updates

Update configuration types in `packages/passkey/src/core/types/passkeyManager.ts`:

```typescript
interface PasskeyManagerConfig {
  // ... existing config
  useAtomicRegistration?: boolean; // Auto-detect based on relay-server usage
}
```

## Implementation Flow

### Phase 1: Detection Logic
- Add relay-server detection in configuration
- Create feature flag for atomic registration
- Update config validation

### Phase 2: Contract Integration
- Implement `createAccountAndVerify()` contract call
- Add proper error handling for atomic transactions
- Test atomic transaction flow

### Phase 3: Registration Flow Update
- Modify registration logic to use atomic flow when appropriate
- Implement fallback to traditional flow
- Update error handling and user feedback

### Phase 4: Testing & Documentation
- Add E2E tests for atomic registration
- Update registration flow documentation
- Test both relay-server and faucet flows

## Error Handling Strategy

### Atomic Transaction Failures
- **VRF Verification Fails**: Show VRF error, retry with new challenge
- **WebAuthn Verification Fails**: Show WebAuthn error, retry registration
- **Account Creation Fails**: Show account creation error, suggest different username
- **NEAR Transfer Fails**: Show balance error, retry with lower amount

### Fallback Mechanism
If atomic registration fails unexpectedly:
1. Log the error for debugging
2. Fall back to traditional registration flow
3. Show user appropriate error message

## Testing Considerations

### Unit Tests
- Test relay-server detection logic
- Test atomic transaction handling
- Test error scenarios and fallbacks

### E2E Tests
- Test full atomic registration flow
- Test fallback to traditional flow
- Test both relay-server and faucet configurations

## Configuration Examples

### Relay-Server Configuration (Uses Atomic Registration)
```typescript
const config: PasskeyManagerConfig = {
  relayServerUrl: 'https://relay.example.com',
  initialUseRelayer: true,
  // useAtomicRegistration: true (auto-detected)
};
```

### Testnet Faucet Configuration (Uses Traditional Registration)
```typescript
const config: PasskeyManagerConfig = {
  relayServerUrl: undefined,
  initialUseRelayer: false,
  // useAtomicRegistration: false (auto-detected)
};
```

## Migration Strategy

1. **Backward Compatibility**: Keep existing registration flow as default
2. **Feature Flag**: Use configuration-based detection for atomic registration
3. **Gradual Rollout**: Test with relay-server first, then expand usage
4. **Monitoring**: Add logging to track atomic vs traditional registration success rates

## Benefits of Atomic Registration

1. **Reduced Complexity**: Single transaction instead of multiple steps
2. **Better UX**: Faster registration with fewer potential failure points
3. **Atomicity**: Either complete success or complete failure (no partial states)
4. **Cost Efficiency**: Single transaction reduces gas costs

## Next Steps

1. Implement relay-server detection logic
2. Add atomic registration contract calls
3. Update registration flow switching
4. Add comprehensive error handling
5. Test both flows thoroughly
6. Update documentation