# Moving RPC Contract Verification to WASM Worker

## Overview

This document outlines the implementation plan for moving WebAuthn contract verification from the main JavaScript thread into the WASM signer worker. This enhancement reduces trust boundaries and improves security by ensuring both verification and signing operations occur within the same isolated context.


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
3. Send VRF + credential + PRF ────▶ 4. ✅ verifyVrfAuthentication() ──RPC call──▶ Contract
                                     5. ✅ IF verified: Decrypt private key
                                     6. ✅ IF verified: Sign transaction
                                     7. ❌ IF failed: Terminate immediately
```

### Benefits
1. **Atomic Operation**: Verification and signing in same execution context
2. **Eliminated TOCTOU**: No time gap between verification and PRF usage
3. **Reduced Attack Surface**: Single secure worker handles all cryptographic operations
4. **Performance**: Reduced thread communication overhead

## Streaming Worker Implementation (Multiple Messages)

### Worker-to-Main Thread Communication Pattern

Similar to Server-Sent Events (SSE), the worker can send multiple progress messages for a single request:

```typescript
// Worker sends multiple messages for one request:
// 1. Verification progress
// 2. Verification complete
// 3. Signing progress
// 4. Signing complete (final)

// Main thread usage example:
const result = await signerWorkerManager.signTransactionWithVerificationAndProgress(
  prfOutput,
  {
    nearAccountId,
    receiverId,
    actions,
    nonce,
    blockHashBytes,
    contractId,
    vrfChallengeData,
    webauthnCredential,
    nearRpcProvider
  },
  // Progress callback - receives multiple updates
  (progress) => {
    console.log(`Step: ${progress.step}`);
    console.log(`Message: ${progress.message}`);
    if (progress.logs) {
      console.log('Contract logs:', progress.logs);
    }
  }
);
```

### Worker Implementation Pattern

```typescript
// Worker sends progressive responses without terminating
function sendProgress(response: WorkerResponse): void {
  self.postMessage(response);  // Send but don't terminate
}

// Worker sends final response and terminates
function sendFinalResponseAndTerminate(response: WorkerResponse): void {
  self.postMessage(response);
  self.close();  // Now terminate
}

// Example worker flow:
async function handleEnhancedSigning(payload) {
  // Step 1: Send progress
  sendProgress({
    type: 'VERIFICATION_PROGRESS',
    payload: { step: 'contract_verification', message: 'Verifying...' }
  });

  // Step 2: Perform RPC call
  const verificationResult = await callContract();

  // Step 3: Send verification complete
  sendProgress({
    type: 'VERIFICATION_COMPLETE',
    payload: { success: true, logs: verificationResult.logs }
  });

  // Step 4: Send signing progress
  sendProgress({
    type: 'SIGNING_PROGRESS',
    payload: { step: 'transaction_signing', message: 'Signing...' }
  });

  // Step 5: Sign transaction
  const signature = await signTransaction();

  // Step 6: Send final result and terminate
  sendFinalResponseAndTerminate({
    type: 'SIGNING_COMPLETE',
    payload: { success: true, data: { signature, logs } }
  });
}
```

### Benefits

1. **Real-time Feedback**: User sees contract verification logs immediately
2. **Better UX**: Progress indicators during long operations
3. **Debugging**: Contract logs available for troubleshooting
4. **Error Handling**: Can fail fast after verification without waiting for signing
5. **Separation of Concerns**: Clear distinction between verification and signing steps

This pattern enables the security benefits of moving RPC calls to the worker while providing excellent user experience through real-time progress updates.

## Implementation Plan

### Phase 1: Extend Worker Request Types

#### 1.1 New Worker Request Type
**File**: `packages/passkey/src/core/types/worker.ts`

```typescript
export enum WorkerRequestType {
  // ... existing types
  VERIFY_AND_SIGN_TRANSACTION_WITH_ACTIONS = 'VERIFY_AND_SIGN_TRANSACTION_WITH_ACTIONS',
  VERIFY_AND_SIGN_TRANSFER_TRANSACTION = 'VERIFY_AND_SIGN_TRANSFER_TRANSACTION',
}

export interface VerifyAndSignTransactionWithActionsRequest extends BaseWorkerRequest {
  type: WorkerRequestType.VERIFY_AND_SIGN_TRANSACTION_WITH_ACTIONS;
  payload: {
    // Transaction data
    nearAccountId: string;
    prfOutput: string;
    receiverId: string;
    actions: ActionParams[];
    nonce: string;
    blockHashBytes: number[];

    // Contract verification data
    contractId: string;
    rpcProviderUrl: string;

    // VRF challenge data
    vrfChallenge: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      userId: string;
      rpId: string;
      blockHeight: number;
      blockHash: string;
    };

    // WebAuthn credential data (for verification)
    webauthnCredential: {
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

    debugMode?: boolean;
  };
}

export interface VerifyAndSignTransferTransactionRequest extends BaseWorkerRequest {
  type: WorkerRequestType.VERIFY_AND_SIGN_TRANSFER_TRANSACTION;
  payload: {
    // Transaction data
    nearAccountId: string;
    prfOutput: string;
    receiverId: string;
    depositAmount: string;
    nonce: string;
    blockHashBytes: number[];

    // Contract verification data
    contractId: string;
    rpcProviderUrl: string;

    // VRF challenge data
    vrfChallenge: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      userId: string;
      rpId: string;
      blockHeight: number;
      blockHash: string;
    };

    // WebAuthn credential data (for verification)
    webauthnCredential: {
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

    debugMode?: boolean;
  };
}
```

#### 1.2 Response Types
```typescript
export enum WorkerResponseType {
  // ... existing types
  VERIFY_AND_SIGN_SUCCESS = 'VERIFY_AND_SIGN_SUCCESS',
  VERIFY_AND_SIGN_FAILURE = 'VERIFY_AND_SIGN_FAILURE',
  CONTRACT_VERIFICATION_FAILURE = 'CONTRACT_VERIFICATION_FAILURE',
}

export interface VerifyAndSignSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.VERIFY_AND_SIGN_SUCCESS;
  payload: {
    signedTransactionBorsh: number[];
    nearAccountId: string;
    verificationResult: {
      verified: true;
      contractCallDuration: number;
    };
  };
}

export interface VerifyAndSignFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.VERIFY_AND_SIGN_FAILURE;
  payload: {
    error: string;
    errorCode?: WorkerErrorCode;
    verificationResult?: {
      verified: false;
      error: string;
      contractCallDuration?: number;
    };
  };
}

export interface ContractVerificationFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.CONTRACT_VERIFICATION_FAILURE;
  payload: {
    error: string;
    errorCode?: WorkerErrorCode;
    contractError?: string;
    phase: 'pre-verification' | 'contract-call' | 'response-parsing';
  };
}
```

### Phase 2: WASM Worker Implementation

#### 2.1 Add NEAR RPC Support to Worker
**File**: `packages/passkey/src/wasm_signer_worker/src/lib.rs`

```rust
// Add serde_json for RPC calls
use serde_json;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // Add fetch API binding for RPC calls
    #[wasm_bindgen(catch, js_name = "fetch")]
    async fn fetch_with_str(url: &str, opts: &JsValue) -> Result<JsValue, JsValue>;
}

// Contract verification structures
#[derive(Serialize, Deserialize, Debug)]
struct VrfData {
    vrf_input_data: Vec<u8>,
    vrf_output: Vec<u8>,
    vrf_proof: Vec<u8>,
    public_key: Vec<u8>,
    user_id: String,
    rp_id: String,
    block_height: u64,
    block_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct WebAuthnAuthenticationResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct WebAuthnAuthentication {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    response: WebAuthnAuthenticationResponse,
    #[serde(rename = "authenticatorAttachment")]
    authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    credential_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContractArgs {
    vrf_data: VrfData,
    webauthn_authentication: WebAuthnAuthentication,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcQuery {
    request_type: String,
    account_id: String,
    method_name: String,
    args_base64: String,
    finality: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: RpcQuery,
}
```

#### 2.2 Contract Verification Function
```rust
async fn verify_vrf_authentication_internal(
    contract_id: &str,
    rpc_provider_url: &str,
    vrf_challenge_data: &serde_json::Value,
    webauthn_credential: &serde_json::Value,
    debug_mode: bool,
) -> Result<bool, String> {
    console_log!("RUST: Starting VRF authentication verification with contract");

    // Parse VRF challenge data
    let vrf_input = base64_url_decode(
        vrf_challenge_data["vrfInput"].as_str()
            .ok_or("Missing vrfInput in VRF challenge data")?
    )?;
    let vrf_output = base64_url_decode(
        vrf_challenge_data["vrfOutput"].as_str()
            .ok_or("Missing vrfOutput in VRF challenge data")?
    )?;
    let vrf_proof = base64_url_decode(
        vrf_challenge_data["vrfProof"].as_str()
            .ok_or("Missing vrfProof in VRF challenge data")?
    )?;
    let vrf_public_key = base64_url_decode(
        vrf_challenge_data["vrfPublicKey"].as_str()
            .ok_or("Missing vrfPublicKey in VRF challenge data")?
    )?;
    let block_hash = base64_url_decode(
        vrf_challenge_data["blockHash"].as_str()
            .ok_or("Missing blockHash in VRF challenge data")?
    )?;

    // Construct VRF data
    let vrf_data = VrfData {
        vrf_input_data: vrf_input,
        vrf_output: vrf_output,
        vrf_proof: vrf_proof,
        public_key: vrf_public_key,
        user_id: vrf_challenge_data["userId"].as_str()
            .ok_or("Missing userId in VRF challenge data")?.to_string(),
        rp_id: vrf_challenge_data["rpId"].as_str()
            .ok_or("Missing rpId in VRF challenge data")?.to_string(),
        block_height: vrf_challenge_data["blockHeight"].as_u64()
            .ok_or("Missing blockHeight in VRF challenge data")?,
        block_hash: block_hash,
    };

    // Construct WebAuthn authentication data
    let webauthn_auth = WebAuthnAuthentication {
        id: webauthn_credential["id"].as_str()
            .ok_or("Missing id in WebAuthn credential")?.to_string(),
        raw_id: webauthn_credential["rawId"].as_str()
            .ok_or("Missing rawId in WebAuthn credential")?.to_string(),
        response: WebAuthnAuthenticationResponse {
            client_data_json: webauthn_credential["response"]["clientDataJSON"].as_str()
                .ok_or("Missing clientDataJSON in WebAuthn response")?.to_string(),
            authenticator_data: webauthn_credential["response"]["authenticatorData"].as_str()
                .ok_or("Missing authenticatorData in WebAuthn response")?.to_string(),
            signature: webauthn_credential["response"]["signature"].as_str()
                .ok_or("Missing signature in WebAuthn response")?.to_string(),
            user_handle: webauthn_credential["response"]["userHandle"].as_str()
                .map(|s| s.to_string()),
        },
        authenticator_attachment: webauthn_credential["authenticatorAttachment"].as_str()
            .map(|s| s.to_string()),
        credential_type: "public-key".to_string(),
    };

    // Construct contract args
    let contract_args = ContractArgs {
        vrf_data: vrf_data,
        webauthn_authentication: webauthn_auth,
    };

    // Make RPC call
    let args_json = serde_json::to_string(&contract_args)
        .map_err(|e| format!("Failed to serialize contract args: {}", e))?;
    let args_base64 = base64::encode(args_json.as_bytes());

    let rpc_query = RpcQuery {
        request_type: "call_function".to_string(),
        account_id: contract_id.to_string(),
        method_name: "verify_authentication_response".to_string(),
        args_base64: args_base64,
        finality: "optimistic".to_string(),
    };

    let rpc_request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: "verify_auth".to_string(),
        method: "query".to_string(),
        params: rpc_query,
    };

    if debug_mode {
        console_log!("RUST: Making RPC call to contract...");
        console_log!(&format!("RUST: Contract ID: {}", contract_id));
        console_log!(&format!("RUST: RPC URL: {}", rpc_provider_url));
    }

    // Make the fetch call
    let response = make_rpc_call(rpc_provider_url, &rpc_request).await?;

    // Parse verification result
    let verified = response["result"]["result"]
        .as_array()
        .and_then(|arr| arr.get(0))
        .and_then(|v| v.as_u64())
        .map(|b| b == 1) // Assuming contract returns 1 for verified, 0 for not verified
        .unwrap_or(false);

    console_log!(&format!("RUST: Contract verification result: {}", verified));
    Ok(verified)
}

async fn make_rpc_call(
    rpc_url: &str,
    request: &RpcRequest,
) -> Result<serde_json::Value, String> {
    let request_body = serde_json::to_string(request)
        .map_err(|e| format!("Failed to serialize RPC request: {}", e))?;

    // Create fetch options
    let mut opts = web_sys::RequestInit::new();
    opts.method("POST");
    opts.body(Some(&JsValue::from_str(&request_body)));

    let headers = web_sys::Headers::new()
        .map_err(|e| format!("Failed to create headers: {:?}", e))?;
    headers.set("Content-Type", "application/json")
        .map_err(|e| format!("Failed to set Content-Type header: {:?}", e))?;
    opts.headers(&headers);

    let response = fetch_with_str(rpc_url, &opts.into())
        .await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;

    let response: web_sys::Response = response.dyn_into()
        .map_err(|e| format!("Failed to cast response: {:?}", e))?;

    if !response.ok() {
        return Err(format!("HTTP error: {}", response.status()));
    }

    let text = wasm_bindgen_futures::JsFuture::from(response.text()
        .map_err(|e| format!("Failed to get response text: {:?}", e))?)
        .await
        .map_err(|e| format!("Failed to read response text: {:?}", e))?;

    let response_str = text.as_string()
        .ok_or("Response is not a string")?;

    let json_response: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

    if let Some(error) = json_response.get("error") {
        return Err(format!("RPC error: {}", error));
    }

    Ok(json_response)
}
```

#### 2.3 Main Signing Functions with Verification
```rust
#[wasm_bindgen]
pub fn verify_and_sign_transaction_with_actions(
    // Transaction data
    near_account_id: &str,
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
    receiver_id: &str,
    actions_json: &str,
    nonce: u64,
    block_hash_bytes: &[u8],

    // Contract verification data
    contract_id: &str,
    rpc_provider_url: &str,

    // VRF and WebAuthn data (as JSON strings)
    vrf_challenge_json: &str,
    webauthn_credential_json: &str,

    debug_mode: bool,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting atomic verify-and-sign operation");

    // Parse VRF challenge and WebAuthn credential
    let vrf_challenge_data: serde_json::Value = serde_json::from_str(vrf_challenge_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse VRF challenge: {}", e)))?;
    let webauthn_credential: serde_json::Value = serde_json::from_str(webauthn_credential_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse WebAuthn credential: {}", e)))?;

    // Step 1: Verify VRF authentication with contract
    console_log!("RUST: Step 1 - Verifying VRF authentication with contract");
    let verification_start = js_sys::Date::now();

    let verification_result = wasm_bindgen_futures::spawn_local(async move {
        verify_vrf_authentication_internal(
            contract_id,
            rpc_provider_url,
            &vrf_challenge_data,
            &webauthn_credential,
            debug_mode,
        ).await
    });

    // Wait for verification to complete
    let verified = verification_result
        .map_err(|e| JsValue::from_str(&format!("Contract verification failed: {:?}", e)))?;

    let verification_duration = js_sys::Date::now() - verification_start;
    console_log!(&format!("RUST: Contract verification completed in {}ms", verification_duration));

    if !verified {
        console_log!("RUST: ❌ Contract verification failed - terminating operation");
        return Err(JsValue::from_str("VRF authentication verification failed"));
    }

    console_log!("RUST: ✅ Contract verification successful - proceeding with transaction signing");

    // Step 2: Sign transaction (only if verification succeeded)
    console_log!("RUST: Step 2 - Signing transaction with verified PRF");
    sign_near_transaction_with_actions(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
        near_account_id,
        receiver_id,
        nonce,
        block_hash_bytes,
        actions_json,
    )
}

#[wasm_bindgen]
pub fn verify_and_sign_transfer_transaction(
    // Transaction data
    near_account_id: &str,
    prf_output_base64: &str,
    encrypted_private_key_data: &str,
    encrypted_private_key_iv: &str,
    receiver_id: &str,
    deposit_amount: &str,
    nonce: u64,
    block_hash_bytes: &[u8],

    // Contract verification data
    contract_id: &str,
    rpc_provider_url: &str,

    // VRF and WebAuthn data (as JSON strings)
    vrf_challenge_json: &str,
    webauthn_credential_json: &str,

    debug_mode: bool,
) -> Result<Vec<u8>, JsValue> {
    console_log!("RUST: Starting atomic verify-and-sign transfer operation");

    // Parse VRF challenge and WebAuthn credential
    let vrf_challenge_data: serde_json::Value = serde_json::from_str(vrf_challenge_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse VRF challenge: {}", e)))?;
    let webauthn_credential: serde_json::Value = serde_json::from_str(webauthn_credential_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse WebAuthn credential: {}", e)))?;

    // Step 1: Verify VRF authentication with contract
    console_log!("RUST: Step 1 - Verifying VRF authentication with contract");
    let verification_start = js_sys::Date::now();

    let verified = wasm_bindgen_futures::spawn_local(async move {
        verify_vrf_authentication_internal(
            contract_id,
            rpc_provider_url,
            &vrf_challenge_data,
            &webauthn_credential,
            debug_mode,
        ).await
    }).map_err(|e| JsValue::from_str(&format!("Contract verification failed: {:?}", e)))?;

    let verification_duration = js_sys::Date::now() - verification_start;
    console_log!(&format!("RUST: Contract verification completed in {}ms", verification_duration));

    if !verified {
        console_log!("RUST: ❌ Contract verification failed - terminating operation");
        return Err(JsValue::from_str("VRF authentication verification failed"));
    }

    console_log!("RUST: ✅ Contract verification successful - proceeding with transaction signing");

    // Step 2: Sign transaction (only if verification succeeded)
    console_log!("RUST: Step 2 - Signing transfer transaction with verified PRF");
    sign_near_transfer_transaction(
        prf_output_base64,
        encrypted_private_key_data,
        encrypted_private_key_iv,
        near_account_id,
        receiver_id,
        deposit_amount,
        nonce,
        block_hash_bytes,
    )
}
```

### Phase 3: Update SignerWorkerManager

Replace existing methods with atomic verify-and-sign methods:

**File**: `packages/passkey/src/core/WebAuthnManager/signerWorkerManager.ts`

```typescript
export class SignerWorkerManager {
  // Replace signTransactionWithActions with atomic version
  async signTransactionWithActions(
    prfOutput: ArrayBuffer,
    payload: {
      nearAccountId: string;
      receiverId: string;
      actions: ActionParams[];
      nonce: string;
      blockHashBytes: number[];
      contractId: string;
      rpcProviderUrl: string;
      vrfChallenge: any;
      webauthnCredential: PublicKeyCredential;
      debugMode?: boolean;
    }
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string; verificationResult: any }> {
    try {
      console.log('WebAuthnManager: Starting atomic verify-and-sign with actions');

      // Validate all actions
      payload.actions.forEach((action, index) => {
        try {
          validateActionParams(action);
        } catch (error) {
          throw new Error(`Action ${index} validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      // Serialize WebAuthn credential data for worker
      const response = payload.webauthnCredential.response as AuthenticatorAssertionResponse;
      const serializedCredential = {
        id: payload.webauthnCredential.id,
        rawId: base64UrlEncode(new Uint8Array(payload.webauthnCredential.rawId)),
        response: {
          clientDataJSON: base64UrlEncode(new Uint8Array(response.clientDataJSON)),
          authenticatorData: base64UrlEncode(new Uint8Array(response.authenticatorData)),
          signature: base64UrlEncode(new Uint8Array(response.signature)),
          userHandle: response.userHandle ? base64UrlEncode(new Uint8Array(response.userHandle)) : undefined,
        },
        authenticatorAttachment: (payload.webauthnCredential as any).authenticatorAttachment || undefined,
        type: 'public-key',
      };

      const worker = this.createSecureWorker();

      const response = await this.executeWorkerOperation(worker, {
        type: WorkerRequestType.VERIFY_AND_SIGN_TRANSACTION_WITH_ACTIONS,
        payload: {
          nearAccountId: payload.nearAccountId,
          prfOutput: bufferEncode(prfOutput),
          receiverId: payload.receiverId,
          actions: payload.actions,
          nonce: payload.nonce,
          blockHashBytes: payload.blockHashBytes,
          contractId: payload.contractId,
          rpcProviderUrl: payload.rpcProviderUrl,
          vrfChallenge: payload.vrfChallenge,
          webauthnCredential: serializedCredential,
          debugMode: payload.debugMode || false,
        }
      });

      if (response.type === 'VERIFY_AND_SIGN_SUCCESS' && response.payload?.signedTransactionBorsh) {
        console.log('WebAuthnManager: Atomic verify-and-sign successful');
        return {
          signedTransactionBorsh: response.payload.signedTransactionBorsh,
          nearAccountId: payload.nearAccountId,
          verificationResult: response.payload.verificationResult,
        };
      } else {
        console.error('WebAuthnManager: Atomic verify-and-sign failed:', response);
        throw new Error('Atomic verify-and-sign failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: Atomic verify-and-sign error:', error);
      throw error;
    }
  }

  // Replace signTransferTransaction with atomic version
  async signTransferTransaction(
    prfOutput: ArrayBuffer,
    payload: {
      nearAccountId: string;
      receiverId: string;
      depositAmount: string;
      nonce: string;
      blockHashBytes: number[];
      contractId: string;
      rpcProviderUrl: string;
      vrfChallenge: any;
      webauthnCredential: PublicKeyCredential;
      debugMode?: boolean;
    }
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string; verificationResult: any }> {
    // Implementation similar to signTransactionWithActions but for transfer
    // ... (similar structure, calling VERIFY_AND_SIGN_TRANSFER_TRANSACTION)
  }
}
```

### Phase 4: Update PasskeyManager Actions

**File**: `packages/passkey/src/core/PasskeyManager/actions.ts`

Replace the separate verification and signing with atomic operation:

```typescript
async function verifyVrfAuthAndSignTransaction(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  validationContext: ValidationContext,
  actionArgs: SerializableActionArgs,
  eventOptions: EventOptions
): Promise<AuthContext> {
  const { onEvent, onError, hooks } = eventOptions;
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const nearRpcProvider = passkeyManager.getNearRpcProvider();

  // ... existing VRF challenge generation code ...

  console.log('[Direct Action] Using atomic verify-and-sign flow');

  // Handle different action types with atomic verification
  let signingResult: any;

  if (actionArgs.action_type === 'Transfer') {
    signingResult = await webAuthnManager.signTransferTransaction(
      prfOutput,
      {
        nearAccountId: nearAccountId,
        receiverId: actionArgs.receiver_id!,
        depositAmount: actionArgs.amount!,
        nonce: validationContext.nonce.toString(),
        blockHashBytes: validationContext.transactionBlockHashBytes,
        contractId: passkeyManager.getConfig().contractId,
        rpcProviderUrl: nearRpcProvider.getUrl(),
        vrfChallenge: vrfChallenge,
        webauthnCredential: credential,
        debugMode: passkeyManager.getConfig().debugMode || false,
      }
    );

  } else if (actionArgs.action_type === 'FunctionCall') {
    const functionCallAction: ActionParams = {
      actionType: ActionType.FunctionCall,
      method_name: actionArgs.method_name!,
      args: actionArgs.args!,
      gas: actionArgs.gas || DEFAULT_GAS_STRING,
      deposit: actionArgs.deposit || "0"
    };

    signingResult = await webAuthnManager.signTransactionWithActions(
      prfOutput,
      {
        nearAccountId: nearAccountId,
        receiverId: actionArgs.receiver_id!,
        actions: [functionCallAction],
        nonce: validationContext.nonce.toString(),
        blockHashBytes: validationContext.transactionBlockHashBytes,
        contractId: passkeyManager.getConfig().contractId,
        rpcProviderUrl: nearRpcProvider.getUrl(),
        vrfChallenge: vrfChallenge,
        webauthnCredential: credential,
        debugMode: passkeyManager.getConfig().debugMode || false,
      }
    );
  }

  console.log('✅ Atomic verify-and-sign completed successfully');
  console.log(`   - Contract verification: ${signingResult.verificationResult.verified}`);
  console.log(`   - Transaction signed: ${!!signingResult.signedTransactionBorsh}`);

  return signingResult;
}
```

## Implementation Timeline

### Week 1: WASM Foundation
- [ ] Add NEAR RPC support to WASM worker (fetch bindings, Rust structures)
- [ ] Implement contract verification function in Rust
- [ ] Add base atomic verify-and-sign functions

### Week 2: TypeScript Integration
- [ ] Update worker request/response types
- [ ] Add TypeScript worker handlers for atomic operations
- [ ] Update SignerWorkerManager with atomic methods

### Week 3: PasskeyManager Integration
- [ ] Replace separate verification flow with atomic operations
- [ ] Update PasskeyManager actions to use new flow
- [ ] Remove old verifyVrfAuthentication method

### Week 4: Testing & Finalization
- [ ] Unit tests for WASM contract verification
- [ ] Integration tests for atomic operations
- [ ] Performance testing and optimization
- [ ] Documentation updates

## Success Metrics

1. **Security**: Elimination of TOCTOU vulnerabilities
2. **Performance**: Reduced thread communication overhead
3. **Reliability**: Atomic success/failure of verification+signing
4. **Test Coverage**: 90%+ coverage for new atomic operations

This implementation provides a clean, atomic solution that eliminates the trust boundary between verification and signing operations.