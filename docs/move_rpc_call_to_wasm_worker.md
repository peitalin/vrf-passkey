# Moving RPC Contract Verification to WASM Worker

## Overview

This document outlines the implementation plan for moving WebAuthn contract verification from the main JavaScript thread into the WASM signer worker. This enhancement reduces trust boundaries and improves security by ensuring both verification and signing operations occur within the same isolated context.

## Security Motivation

### Current Architecture Risk
```
Main Thread (Untrusted) → Contract RPC (Verification) → WASM Worker (PRF Usage)
                      ↑
                 Trust Boundary Risk
```

**Risk**: Malicious code in main thread could bypass contract verification and send unverified PRF to worker.

### Enhanced Architecture
```
Main Thread → WASM Worker → Contract RPC (Verification) → PRF Usage (Same Context)
                        ↑
                 Single Trusted Context
```

**Benefit**: Verification and PRF usage happen atomically within isolated worker context.

## Implementation Steps

### Phase 1: Extend Worker Message Types

#### File: `packages/passkey/src/core/types/worker.ts`

Add new request/response types:

```typescript
export enum WorkerRequestType {
  // ... existing types ...
  VERIFY_AND_SIGN_WITH_WEBAUTHN = 'VERIFY_AND_SIGN_WITH_WEBAUTHN',
}

export interface VerifyAndSignWithWebAuthnRequest {
  type: WorkerRequestType.VERIFY_AND_SIGN_WITH_WEBAUTHN;
  payload: {
    // PRF data
    prfOutput: string;

    // WebAuthn assertion data
    authenticatorData: string; // base64url
    clientDataJSON: string;    // base64url
    signature: string;         // base64url
    credentialId: string;      // base64url

    // Transaction data
    nearAccountId: string;
    receiverId: string;
    actions: ActionParams[];
    nonce: string;
    blockHashBytes: number[];

    // RPC configuration
    rpcEndpoint: string;
    contractAccountId: string;

    // VRF data for contract verification
    vrfData: {
      vrf_input_data: number[];
      vrf_output: number[];
      vrf_proof: number[];
      public_key: number[];
      user_id: string;
      rp_id: string;
      block_height: number;
      block_hash: number[];
    };
  };
}
```

### Phase 2: Add Contract RPC Client to WASM Worker

#### File: `packages/passkey/src/core/web3authn-signer.worker.ts`

Add RPC functionality:

```typescript
// === CONTRACT RPC CLIENT ===

interface ContractRPCConfig {
  endpoint: string;
  contractAccountId: string;
}

interface WebAuthnVerificationRequest {
  vrf_data: any;
  webauthn_authentication: {
    id: string;
    rawId: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
      userHandle?: string;
    };
    authenticatorAttachment?: string;
    type: string;
  };
}

async function verifyWebAuthnWithContract(
  config: ContractRPCConfig,
  verificationRequest: WebAuthnVerificationRequest
): Promise<{ verified: boolean; authentication_info?: any }> {
  try {
    console.log('WORKER: Making contract RPC call for WebAuthn verification');

    const response = await fetch(config.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'webauthn-verification',
        method: 'query',
        params: {
          request_type: 'call_function',
          finality: 'final',
          account_id: config.contractAccountId,
          method_name: 'verify_authentication_response',
          args_base64: btoa(JSON.stringify(verificationRequest))
        }
      })
    });

    if (!response.ok) {
      throw new Error(`RPC call failed: ${response.status} ${response.statusText}`);
    }

    const rpcResult = await response.json();

    if (rpcResult.error) {
      throw new Error(`Contract error: ${JSON.stringify(rpcResult.error)}`);
    }

    // Parse contract response
    const resultBytes = new Uint8Array(rpcResult.result.result);
    const resultString = new TextDecoder().decode(resultBytes);
    const verificationResult = JSON.parse(resultString);

    console.log('WORKER: Contract verification result:', verificationResult.verified);
    return verificationResult;

  } catch (error: any) {
    console.error('WORKER: Contract verification failed:', error);
    throw new Error(`Contract verification failed: ${error.message}`);
  }
}
```

### Phase 3: Add Combined Verification + Signing Handler

#### File: `packages/passkey/src/core/web3authn-signer.worker.ts`

Add the main handler:

```typescript
/**
 * Handle WebAuthn verification + transaction signing in single atomic operation
 */
async function handleVerifyAndSignWithWebAuthn(
  payload: VerifyAndSignWithWebAuthnRequest['payload']
): Promise<void> {
  try {
    console.log('WORKER: Starting atomic WebAuthn verification + transaction signing');

    // 1. Prepare contract RPC configuration
    const rpcConfig: ContractRPCConfig = {
      endpoint: payload.rpcEndpoint,
      contractAccountId: payload.contractAccountId
    };

    // 2. Prepare WebAuthn verification request
    const verificationRequest: WebAuthnVerificationRequest = {
      vrf_data: payload.vrfData,
      webauthn_authentication: {
        id: payload.credentialId,
        rawId: payload.credentialId, // Same as id for our use case
        response: {
          clientDataJSON: payload.clientDataJSON,
          authenticatorData: payload.authenticatorData,
          signature: payload.signature
        },
        type: 'public-key'
      }
    };

    // 3. Call contract to verify WebAuthn assertion (CRITICAL SECURITY STEP)
    console.log('WORKER: Verifying WebAuthn assertion with contract...');
    const verificationResult = await verifyWebAuthnWithContract(rpcConfig, verificationRequest);

    if (!verificationResult.verified) {
      throw new Error('WebAuthn assertion verification failed - authentication invalid');
    }

    console.log('WORKER: WebAuthn verification successful - PRF can be trusted');

    // 4. Now that verification passed, we can trust the PRF output for decryption
    console.log('WORKER: Getting encrypted key data...');
    const encryptedKeyData = await getEncryptedKey(payload.nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${payload.nearAccountId}`);
    }

    // 5. Sign transaction using verified PRF
    console.log('WORKER: Signing transaction with verified PRF...');
    const signedTransactionBorsh = sign_near_transaction_with_actions(
      payload.prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      payload.nearAccountId,
      payload.receiverId,
      BigInt(payload.nonce),
      new Uint8Array(payload.blockHashBytes),
      JSON.stringify(payload.actions)
    );

    console.log('WORKER: Atomic verification + signing completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(signedTransactionBorsh),
        nearAccountId: payload.nearAccountId,
        verificationInfo: verificationResult.authentication_info
      }
    });

  } catch (error: any) {
    console.error('WORKER: Atomic verification + signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Atomic verification + signing failed' }
    });
  }
}
```

Update the main message handler:

```typescript
// In the main onmessage handler
switch (type) {
  // ... existing cases ...

  case WorkerRequestType.VERIFY_AND_SIGN_WITH_WEBAUTHN:
    await handleVerifyAndSignWithWebAuthn(payload);
    break;
}
```

### Phase 4: Add WebAuthn Workers Method

#### File: `packages/passkey/src/core/WebAuthnManager/webauthn-workers.ts`

Add method to WebAuthnWorkers class:

```typescript
/**
 * Atomic WebAuthn verification + transaction signing
 * Enhanced security: Both verification and signing happen in same worker context
 */
async verifyAndSignWithWebAuthn(
  payload: {
    // PRF output from WebAuthn ceremony
    prfOutput: ArrayBuffer;

    // WebAuthn assertion data
    webauthnAssertion: {
      authenticatorData: string;
      clientDataJSON: string;
      signature: string;
      credentialId: string;
    };

    // Transaction details
    nearAccountId: string;
    receiverId: string;
    actions: ActionParams[];
    nonce: string;
    blockHashBytes: number[];

    // VRF data
    vrfData: any;

    // RPC config
    rpcEndpoint: string;
    contractAccountId: string;
  }
): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string; verificationInfo?: any }> {
  try {
    console.log('WebAuthnManager: Starting atomic WebAuthn verification + signing');

    const worker = this.createSecureWorker();

    const workerPayload = {
      prfOutput: bufferEncode(payload.prfOutput),
      authenticatorData: payload.webauthnAssertion.authenticatorData,
      clientDataJSON: payload.webauthnAssertion.clientDataJSON,
      signature: payload.webauthnAssertion.signature,
      credentialId: payload.webauthnAssertion.credentialId,
      nearAccountId: payload.nearAccountId,
      receiverId: payload.receiverId,
      actions: payload.actions,
      nonce: payload.nonce,
      blockHashBytes: payload.blockHashBytes,
      rpcEndpoint: payload.rpcEndpoint,
      contractAccountId: payload.contractAccountId,
      vrfData: payload.vrfData
    };

    const response = await this.executeWorkerOperation(worker, {
      type: WorkerRequestType.VERIFY_AND_SIGN_WITH_WEBAUTHN,
      payload: workerPayload
    });

    if (response.type === 'SIGNATURE_SUCCESS' && response.payload?.signedTransactionBorsh) {
      console.log('WebAuthnManager: Atomic verification + signing successful');
      return {
        signedTransactionBorsh: response.payload.signedTransactionBorsh,
        nearAccountId: payload.nearAccountId,
        verificationInfo: response.payload.verificationInfo
      };
    } else {
      console.error('WebAuthnManager: Atomic verification + signing failed:', response);
      throw new Error('Atomic verification + signing failed');
    }

  } catch (error: any) {
    console.error('WebAuthnManager: Atomic verification + signing error:', error);
    throw error;
  }
}
```

### Phase 5: Update Client Integration

#### File: `packages/passkey/src/core/PasskeyManager/actions.ts`

Modify the signing methods to use the new atomic approach:

```typescript
// Add method to use enhanced security flow
async signTransactionWithAtomicVerification(
  nearAccountId: string,
  actions: ActionParams[],
  options: {
    rpcEndpoint: string;
    contractAccountId: string;
  }
): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
  try {
    // 1. Get fresh block data
    const { nonce, blockHash, blockHashBytes } = await this.networkManager.getFreshBlockData(nearAccountId);

    // 2. Generate VRF challenge data
    const vrfChallengeData = await this.webauthnManager.vrfManager.generateVRFChallengeForAuthentication(
      nearAccountId,
      options.rpcEndpoint // RP ID extracted from RPC endpoint
    );

    // 3. Perform WebAuthn authentication with PRF
    const webauthnResult = await this.webauthnManager.performWebAuthnAuthenticationWithPrf(
      vrfChallengeData.challenge_b64url,
      nearAccountId
    );

    // 4. Use atomic verification + signing (ENHANCED SECURITY)
    const result = await this.webauthnManager.webauthnWorkers.verifyAndSignWithWebAuthn({
      prfOutput: webauthnResult.prfOutput,
      webauthnAssertion: {
        authenticatorData: webauthnResult.credential.response.authenticatorData,
        clientDataJSON: webauthnResult.credential.response.clientDataJSON,
        signature: webauthnResult.credential.response.signature,
        credentialId: webauthnResult.credential.id
      },
      nearAccountId,
      receiverId: actions[0]?.functionCall?.receiverId || nearAccountId, // Extract from actions
      actions,
      nonce: nonce.toString(),
      blockHashBytes,
      vrfData: vrfChallengeData.vrf_data,
      rpcEndpoint: options.rpcEndpoint,
      contractAccountId: options.contractAccountId
    });

    return result;

  } catch (error: any) {
    console.error('PasskeyManager: Atomic verification + signing failed:', error);
    throw error;
  }
}
```

## Migration Strategy

### Phase A: Parallel Implementation
1. Implement new atomic method alongside existing separate verification
2. Add feature flag to control which approach is used
3. Test thoroughly in development environment

### Phase B: Gradual Rollout
1. Enable atomic verification for beta users
2. Monitor error rates and performance
3. Gather security audit feedback

### Phase C: Full Migration
1. Switch default to atomic verification
2. Deprecate separate verification methods
3. Remove old code paths after transition period

## Security Benefits Summary

1. **Eliminates Trust Boundary**: Main thread can no longer bypass verification
2. **Atomic Operations**: Verification and signing happen atomically in same context
3. **Reduced Attack Surface**: Fewer points where malicious code can interfere
4. **Better Isolation**: All sensitive operations confined to worker context
5. **Enhanced Auditability**: Single code path for both verification and signing

## Performance Considerations

- **Network Latency**: RPC calls from worker may have slightly different latency characteristics
- **Worker Complexity**: Increased worker code size and initialization time
- **Error Recovery**: More complex error handling for network failures within worker
- **Debugging**: Network calls from workers may require additional debugging tools

## Testing Requirements

1. **Unit Tests**: Test RPC client functionality within worker
2. **Integration Tests**: End-to-end atomic verification + signing flows
3. **Security Tests**: Verify that verification cannot be bypassed
4. **Network Tests**: Handle various network failure scenarios
5. **Performance Tests**: Compare latency vs. current approach
