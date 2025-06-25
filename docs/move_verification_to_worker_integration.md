# VRF Verification Worker Integration Plan

## Overview

This document outlines the plan to move VRF authentication verification from the main thread into the WASM signer worker. This architectural change enhances security by ensuring that VRF verification happens atomically with transaction signing, eliminating potential Time-of-Check-to-Time-of-Use (TOCTOU) vulnerabilities.

## Current Architecture Analysis

### Current Flow (Security Gap)
```
Main Thread                          WASM Worker
-----------                          -----------
1. Generate VRF challenge
2. WebAuthn authentication
3. ✅ verifyVrfAuthentication() ──RPC call──▶ Contract
4. [SECURITY GAP: PRF could be modified here]
5. Send PRF to worker ──────────────▶ 6. Decrypt private key
                                     7. Sign transaction
```

### Current Implementation Locations
- **VRF Generation**: `VRFManager` (Service Worker)
- **WebAuthn Authentication**: Main thread (`PasskeyManager/actions.ts`)
- **Contract Verification**: Main thread (`WebAuthnManager/contract-calls.ts`)
- **Transaction Signing**: WASM Worker (`web3authn-signer.worker.ts`)

### Security Vulnerabilities
1. **Time-of-Check-to-Time-of-Use (TOCTOU)**: PRF data could theoretically be modified between verification and signing
2. **Attack Surface**: Multiple thread hops create opportunities for data tampering
3. **Trust Boundaries**: Verification and signing happen in different execution contexts

## Proposed Architecture

### New Flow (Atomic Security)
```
Main Thread                          WASM Worker
-----------                          -----------
1. Generate VRF challenge
2. WebAuthn authentication
3. Send VRF + credential + PRF ─────▶ 4. ✅ verifyVrfAuthentication() ──RPC call──▶ Contract
                                     5. ✅ IF verified: Decrypt private key
                                     6. ✅ IF verified: Sign transaction
                                     7. ❌ IF failed: Terminate immediately
```

### Security Benefits
- **Atomic Operations**: Verification and signing happen in same isolated context
- **Fail-Fast Security**: PRF never touches private key operations unless verification passes
- **Reduced Attack Surface**: Single worker handles complete secure workflow
- **Cryptographic Integrity**: All operations happen after proof validation

## Implementation Phases

### Phase 1: Data Structure Updates
**Duration**: 1-2 days

#### 1.1 Update Worker Request Types
**File**: `packages/passkey/src/core/types/worker.ts`

Add VRF verification data to existing request interfaces:
```typescript
export interface SignTransactionWithActionsRequest extends BaseWorkerRequest {
  payload: {
    // ... existing fields ...

    // === VRF VERIFICATION DATA ===
    vrfVerification?: {
      vrfChallengeData: {
        vrfInput: string;
        vrfOutput: string;
        vrfProof: string;
        vrfPublicKey: string;
        userId: string;
        rpId: string;
        blockHeight: number;
        blockHash: string;
      };
      webauthnCredential: {
        id: string;
        rawId: string;
        response: {
          clientDataJSON: string;
          authenticatorData: string;
          signature: string;
          userHandle?: string | null;
        };
        authenticatorAttachment?: string | null;
        type: 'public-key';
        clientExtensionResults?: Record<string, any>;
      };
      contractConfig: {
        contractId: string;
        rpcUrl: string;
        debugMode?: boolean;
      };
    };
  };
}
```

#### 1.2 Create VRF Verification Response Types
```typescript
export interface VrfVerificationResult {
  verified: boolean;
  error?: string;
  contractResponse?: any;
}

export enum WorkerResponseType {
  // ... existing types ...
  VRF_VERIFICATION_SUCCESS = 'VRF_VERIFICATION_SUCCESS',
  VRF_VERIFICATION_FAILURE = 'VRF_VERIFICATION_FAILURE',
}
```

### Phase 2: Worker Implementation
**Duration**: 2-3 days

#### 2.1 Add VRF Verification to Worker
**File**: `packages/passkey/src/core/web3authn-signer.worker.ts`

```typescript
// === VRF VERIFICATION FUNCTIONS ===

/**
 * Verify VRF authentication with contract before signing
 */
async function verifyVrfAuthentication(
  vrfChallengeData: VrfChallengeData,
  webauthnCredential: WebAuthnCredentialData,
  contractConfig: ContractConfig
): Promise<VrfVerificationResult> {
  try {
    console.log('WORKER: Starting atomic VRF verification before signing');

    // 1. Construct contract call data
    const contractArgs = buildContractVerificationArgs(vrfChallengeData, webauthnCredential);

    // 2. Make RPC call to contract
    const contractResponse = await callContractVerification(contractConfig, contractArgs);

    // 3. Parse and validate response
    return parseVerificationResponse(contractResponse);

  } catch (error: any) {
    console.error('WORKER: VRF verification failed:', error);
    return { verified: false, error: error.message };
  }
}

/**
 * Enhanced signing handler with VRF verification
 */
async function handleSignTransactionWithVrfVerification(
  payload: SignTransactionWithActionsRequest['payload']
): Promise<void> {
  try {
    const { vrfVerification, ...signingPayload } = payload;

    // 1. SECURITY GATE: Verify VRF if verification data provided
    if (vrfVerification) {
      console.log('WORKER: Performing VRF verification before signing');

      const verificationResult = await verifyVrfAuthentication(
        vrfVerification.vrfChallengeData,
        vrfVerification.webauthnCredential,
        vrfVerification.contractConfig
      );

      if (!verificationResult.verified) {
        throw new Error(`VRF verification failed: ${verificationResult.error}`);
      }

      console.log('WORKER: ✅ VRF verification passed - proceeding with signing');
    }

    // 2. Proceed with transaction signing only after verification
    await handleSignTransactionWithActions(signingPayload);

  } catch (error: any) {
    console.error('WORKER: VRF-verified signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message }
    });
  }
}
```

#### 2.2 HTTP Client for Contract Calls
```typescript
/**
 * Make contract verification call from worker
 */
async function callContractVerification(
  contractConfig: ContractConfig,
  contractArgs: any
): Promise<any> {
  const response = await fetch(contractConfig.rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'vrf-verify-worker',
      method: 'query',
      params: {
        request_type: 'call_function',
        account_id: contractConfig.contractId,
        method_name: 'verify_authentication_response',
        args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
        finality: 'optimistic'
      }
    })
  });

  if (!response.ok) {
    throw new Error(`Contract verification RPC failed: ${response.status}`);
  }

  return await response.json();
}
```

### Phase 3: Main Thread Integration
**Duration**: 2-3 days

#### 3.1 Update WebAuthnWorkers
**File**: `packages/passkey/src/core/WebAuthnManager/webauthn-workers.ts`

```typescript
/**
 * Enhanced multi-action signing with optional VRF verification
 */
async signMultiActionTransactionWithPrf(
  nearAccountId: string,
  prfOutput: ArrayBuffer,
  payload: {
    // ... existing fields ...
    vrfVerification?: VrfVerificationData;
  }
): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {

  const workerPayload = {
    // ... existing payload ...
    vrfVerification: payload.vrfVerification // Pass verification data to worker
  };

  const response = await this.executeWorkerOperation(worker, {
    type: WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS,
    payload: workerPayload
  });

  // ... handle response ...
}
```

#### 3.2 Update PasskeyManager Actions
**File**: `packages/passkey/src/core/PasskeyManager/actions.ts`

```typescript
/**
 * Enhanced transaction signing with worker-based VRF verification
 */
async function signTransaction(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  actionArgs: SerializableActionArgs,
  authContext: AuthContext,
  eventOptions: EventOptions
): Promise<any> {
  const { onEvent } = eventOptions;
  const webAuthnManager = passkeyManager.getWebAuthnManager();

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'signing',
      message: 'Verifying authentication and signing transaction in secure worker...'
    }
  });

  // Prepare VRF verification data for worker
  const vrfVerification = {
    vrfChallengeData: authContext.vrfChallengeData,
    webauthnCredential: extractWebAuthnCredentialData(authContext.credential),
    contractConfig: {
      contractId: passkeyManager.getConfig().contractId,
      rpcUrl: passkeyManager.getConfig().rpcUrl,
      debugMode: passkeyManager.getConfig().debugMode
    }
  };

  if (actionArgs.action_type === 'Transfer') {
    const transferPayload = {
      // ... existing payload ...
      vrfVerification // Send verification data to worker
    };

    return await webAuthnManager.signTransferTransactionWithPrf(
      nearAccountId,
      authContext.prfOutput,
      transferPayload
    );
  }

  // ... handle other action types ...
}

/**
 * Extract WebAuthn credential data for worker consumption
 */
function extractWebAuthnCredentialData(credential: PublicKeyCredential): WebAuthnCredentialData {
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: base64UrlEncode(new Uint8Array(credential.rawId)),
    response: {
      clientDataJSON: base64UrlEncode(new Uint8Array(response.clientDataJSON)),
      authenticatorData: base64UrlEncode(new Uint8Array(response.authenticatorData)),
      signature: base64UrlEncode(new Uint8Array(response.signature)),
      userHandle: response.userHandle ? base64UrlEncode(new Uint8Array(response.userHandle)) : null,
    },
    authenticatorAttachment: (credential as any).authenticatorAttachment,
    type: 'public-key',
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
```

### Phase 4: Remove Main Thread Verification
**Duration**: 1 day

#### 4.1 Cleanup Contract Calls
Remove the main thread verification since it now happens in worker:

```typescript
// REMOVE from performVRFAuthentication():
const contractVerificationResult = await webAuthnManager.verifyVrfAuthentication(
  nearRpcProvider,
  passkeyManager.getConfig().contractId,
  vrfChallengeData,
  credential,
  passkeyManager.getConfig().debugMode ?? false
);
```

#### 4.2 Simplify Auth Context
```typescript
interface AuthContext extends ValidationContext {
  vrfChallengeData: any;
  credential: PublicKeyCredential;
  prfOutput: ArrayBuffer;
  // REMOVE: contractVerificationResult - now handled in worker
}
```

## Data Flow Changes

### Current Data Flow
```
1. Main Thread: Generate VRF challenge
2. Main Thread: WebAuthn authentication
3. Main Thread: Contract verification (RPC call)
4. Main Thread: Send PRF to worker
5. Worker: Decrypt private key
6. Worker: Sign transaction
```

### New Data Flow
```
1. Main Thread: Generate VRF challenge
2. Main Thread: WebAuthn authentication
3. Main Thread: Send VRF data + credential + PRF to worker
4. Worker: Contract verification (RPC call)
5. Worker: IF verified → Decrypt private key
6. Worker: IF verified → Sign transaction
7. Worker: IF failed → Terminate with error
```

## Security Improvements

### 1. Atomic Verification + Signing
- **Before**: Verification and signing separated by thread boundaries
- **After**: Verification and signing happen atomically in worker context

### 2. Fail-Fast Security
- **Before**: PRF reaches private key operations regardless of verification
- **After**: PRF never touches private key unless verification passes first

### 3. Reduced Attack Surface
- **Before**: Multiple thread hops create attack opportunities
- **After**: Single worker handles complete secure workflow

### 4. Tamper-Proof Flow
- **Before**: PRF data could theoretically be modified between verification and signing
- **After**: No opportunity for data modification between verification and signing

## Testing Strategy

### Unit Tests (Rust - WASM Worker)
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_verification_success() {
        // Test successful VRF verification before signing
    }

    #[test]
    fn test_vrf_verification_failure_blocks_signing() {
        // Test that failed verification prevents signing
    }

    #[test]
    fn test_contract_rpc_error_handling() {
        // Test contract call error scenarios
    }

    #[test]
    fn test_atomic_verify_and_sign() {
        // Test complete atomic workflow
    }
}
```

### Integration Tests (TypeScript)
```typescript
describe('Worker VRF Verification Integration', () => {
  test('should verify VRF before signing transaction', async () => {
    // Test complete flow with valid VRF data
  });

  test('should fail transaction if VRF verification fails', async () => {
    // Test that invalid VRF data blocks signing
  });

  test('should handle contract RPC errors gracefully', async () => {
    // Test error handling for contract communication
  });

  test('should maintain backward compatibility for non-VRF flows', async () => {
    // Test that existing flows still work
  });
});
```

### Security Tests
```typescript
describe('Security Improvements', () => {
  test('should prevent TOCTOU attacks', async () => {
    // Test that PRF cannot be modified between verification and signing
  });

  test('should terminate worker on verification failure', async () => {
    // Test fail-fast behavior
  });

  test('should not decrypt private key on verification failure', async () => {
    // Test that failed verification prevents key operations
  });
});
```

## Migration Strategy

### Backward Compatibility
- Keep existing worker interfaces functional during transition
- Add VRF verification as optional feature initially
- Gradual migration of flows to use worker verification

### Feature Flags
```typescript
interface WorkerConfig {
  enableWorkerVrfVerification: boolean; // Feature flag for gradual rollout
  contractConfig?: ContractConfig; // Only needed when verification enabled
}
```

### Rollout Phases
1. **Phase 1**: Implement worker verification as optional feature
2. **Phase 2**: Enable for new transaction types (Transfer, multi-action)
3. **Phase 3**: Migrate existing FunctionCall transactions
4. **Phase 4**: Remove main thread verification entirely

## Performance Considerations

### Network Calls from Worker
- **Impact**: Additional RPC call from worker context
- **Mitigation**: Use optimistic finality for faster responses
- **Benefit**: Eliminates main thread RPC call, so net neutral

### Worker Initialization
- **Impact**: Worker needs access to RPC configuration
- **Mitigation**: Pass config in worker payload
- **Benefit**: Self-contained security verification

### Error Handling
- **Impact**: Need robust error handling for worker RPC calls
- **Mitigation**: Comprehensive error types and fallback strategies
- **Benefit**: Better error boundaries and security guarantees

## Risk Analysis

### Low Risk
- **Backward Compatibility**: Existing interfaces remain functional
- **Performance**: Net neutral network calls
- **Testing**: Comprehensive test coverage planned

### Medium Risk
- **Worker Complexity**: Worker becomes more complex with RPC logic
- **Error Handling**: Need robust handling of network failures
- **Migration**: Gradual migration prevents breaking changes

### High Risk
- **Security Regression**: Any bugs in verification logic could be serious
- **Mitigation**: Extensive security testing and gradual rollout

## Success Metrics

### Security Metrics
- [ ] Zero TOCTOU vulnerabilities in signing flow
- [ ] 100% verification coverage before private key operations
- [ ] Fail-fast behavior on all verification failures

### Performance Metrics
- [ ] No regression in transaction signing speed
- [ ] ≤ 100ms additional latency for contract verification
- [ ] Worker initialization time remains < 2s

### Reliability Metrics
- [ ] 99.9% success rate for VRF verification calls
- [ ] Graceful degradation on contract RPC failures
- [ ] No worker memory leaks or crashes

## Implementation Timeline

### Week 1: Foundation (Phase 1)
- [ ] Update worker request/response types
- [ ] Add VRF verification data structures
- [ ] Create worker HTTP client for contract calls

### Week 2: Core Implementation (Phase 2)
- [ ] Implement VRF verification in worker
- [ ] Add atomic verify-then-sign logic
- [ ] Comprehensive error handling

### Week 3: Integration (Phase 3)
- [ ] Update WebAuthnWorkers to pass VRF data
- [ ] Update PasskeyManager to prepare verification data
- [ ] Remove main thread verification

### Week 4: Testing & Validation (Phase 4)
- [ ] Unit tests for worker verification
- [ ] Integration tests for complete flow
- [ ] Security testing for TOCTOU prevention
- [ ] Performance testing and optimization

## Future Enhancements

### Enhanced Security Features
- **Certificate Pinning**: Pin contract SSL certificates in worker
- **Request Signing**: Sign contract verification requests with VRF key
- **Rate Limiting**: Implement worker-level rate limiting for contract calls

### Performance Optimizations
- **Connection Pooling**: Reuse HTTP connections for contract calls
- **Caching**: Cache successful verifications for short periods
- **Batching**: Batch multiple verifications in single contract call

### Monitoring & Observability
- **Metrics**: Track verification success rates and latencies
- **Logging**: Comprehensive security audit logs
- **Alerting**: Alert on verification failure spikes

## Conclusion

Moving VRF verification into the WASM worker provides significant security benefits by eliminating TOCTOU vulnerabilities and ensuring atomic verification + signing operations. The implementation plan provides a structured approach with comprehensive testing and gradual migration to minimize risks while maximizing security improvements.

The key insight is that this architectural change transforms the security model from "trust but verify" to "verify then operate" - ensuring that cryptographic operations only happen on verified, authenticated data.