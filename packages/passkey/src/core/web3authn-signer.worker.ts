// WASM-only transaction signing worker
// This worker handles all NEAR transaction operations using WASM functions

// Import WASM binary directly
import init, * as wasmModule from '../wasm_signer_worker/wasm_signer_worker.js';
import {
  WorkerRequestType,
  WorkerResponseType,
  type WorkerRequest,
  type WorkerResponse,
  type SignTransactionWithActionsRequest,
  type SignTransferTransactionRequest,
  type DeriveNearKeypairAndEncryptRequest,
  type RecoverKeypairFromPasskeyRequest,
  type DecryptPrivateKeyWithPrfRequest,
  type CheckCanRegisterUserRequest,
  type SignVerifyAndRegisterUserRequest,
  type ExtractCosePublicKeyRequest,
  type ProgressMessageParams,
  type WorkerProgressMessage,
  ProgressMessageType,
  ProgressStep,
  AddKeyWithPrfRequest,
  DeleteKeyWithPrfRequest,
  takeAesPrfOutput,
} from './types/signer-worker.js';
import type { onProgressEvents } from './types/webauthn.js';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from './IndexedDBManager/passkeyNearKeysDB.js';
import { base64UrlEncode } from '../utils/encoders.js';

// Buffer polyfill for Web Workers
// Workers don't inherit main thread polyfills, they run in an isolated environment
// Manual polyfill is required for NEAR crypto operations that depend on Buffer.
import { Buffer } from 'buffer';
globalThis.Buffer = Buffer;

// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('./wasm_signer_worker_bg.wasm', import.meta.url);
const WASM_CACHE_NAME = 'web3authn-signer-worker-v1';

// Create database manager instance
const nearKeysDB = new PasskeyNearKeysDBManager();

/////////////////////////////////////
// === WASM MODULE FUNCTIONS ===
/////////////////////////////////////

const {
  // Dual PRF functions (structured)
  derive_and_encrypt_keypair,
  DualPrfOutputs,
  // Registration (structured)
  check_can_register_user,
  sign_verify_and_register_user,
  // Key exports/decryption (structured)
  decrypt_private_key_with_prf,
  DecryptPrivateKeyRequest,
  // Transaction signing: combined verification + signing (structured)
  verify_and_sign_near_transaction_with_actions,
  verify_and_sign_near_transfer_transaction,
  // New action-specific functions (structured)
  add_key_with_prf,
  delete_key_with_prf,
  // Recover keypair from passkey (structured)
  recover_keypair_from_passkey,
  // Structured types
  WebAuthnRegistrationCredentialStruct,
  WebAuthnAuthenticationCredentialStruct,
  VrfChallengeStruct,
  TransactionSigningRequest,
  TransferTransactionRequest,
  RegistrationCheckRequest,
  RegistrationRequest,
  AddKeyRequest,
  DeleteKeyRequest,
  // Grouped parameter structures
  Decryption,
  TxData,
  TransferTxData,
  RegistrationTxData,
  AddKeyTxData,
  DeleteKeyTxData,
  Verification,
  RecoverKeypairResult,
  DecryptPrivateKeyResult,
  TransactionSignResult,
  KeyActionResult,
  RegistrationCheckResult,
  RegistrationResult,
  // COSE keys
  extract_cose_public_key_from_attestation,
} = wasmModule;

/**
 * Initialize WASM module with caching support
 */
async function initializeWasmWithCache(): Promise<void> {
  try {
    console.debug('[signer-worker]: Starting WASM initialization...', {
      wasmUrl: wasmUrl.href,
      userAgent: navigator.userAgent,
      currentUrl: self.location.href
    });

    const cache = await caches.open(WASM_CACHE_NAME);
    const cachedResponse = await cache.match(wasmUrl.href);
    if (cachedResponse) {
      const wasmModule = await WebAssembly.compileStreaming(cachedResponse.clone());
      await init({ module: wasmModule });
      console.debug('[signer-worker]: WASM initialized successfully from cache');
      return;
    }

    console.debug('[signer-worker]: Fetching fresh WASM module from:', wasmUrl.href);
    const response = await fetch(wasmUrl.href);

    if (!response.ok) {
      throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`);
    }

    // console.log('[signer-worker]: WASM fetch successful, content-type:', response.headers.get('content-type'));
    const responseToCache = response.clone();
    const wasmModule = await WebAssembly.compileStreaming(response);

    await cache.put(wasmUrl.href, responseToCache);
    await init({ module: wasmModule });
  } catch (error: any) {
    console.error('[signer-worker]: WASM initialization failed, using fallback:', error);
    console.error('[signer-worker]: Error details:', {
      name: error?.name,
      message: error?.message,
      stack: error?.stack
    });

    try {
      console.debug('[signer-worker]: Attempting fallback WASM initialization...');
      await init();
    } catch (fallbackError: any) {
      console.error('[signer-worker]: Fallback WASM initialization also failed:', fallbackError);
      throw new Error(`WASM initialization failed: ${error?.message || 'Unknown error'}. Fallback also failed: ${fallbackError?.message || 'Unknown fallback error'}`);
    }
  }
}

// === PROGRESS MESSAGING ===

/**
 * Function called by WASM to send progress messages
 * This is imported into the WASM module as sendProgressMessage
 *
 * Enhanced version that supports logs and creates consistent onProgressEvents output
 *
 * @param messageType - Type of message (e.g., 'VERIFICATION_PROGRESS', 'SIGNING_COMPLETE')
 * @param step - Step identifier (e.g., 'contract_verification', 'transaction_signing')
 * @param message - Human-readable progress message
 * @param data - JSON string containing structured data
 * @param logs - Optional JSON string containing array of log messages
 */
function sendProgressMessage(
  messageType: ProgressMessageType | string,
  step: ProgressStep | string,
  message: string,
  data: string,
  logs?: string
): void {
  console.log(`[wasm-progress]: ${messageType} - ${step}: ${message}`);

  // Parse data if provided
  let parsedData: any = undefined;
  let parsedLogs: string[] = [];

  try {
    if (data) {
      parsedData = JSON.parse(data);
      // Extract logs from data if present (for backward compatibility)
      if (parsedData && Array.isArray(parsedData.logs)) {
        parsedLogs = parsedData.logs;
      }
    }
  } catch (e) {
    console.warn('[wasm-progress]: Failed to parse data as JSON:', data);
    parsedData = data; // Fallback to raw string
  }

  // Parse logs parameter if provided (takes precedence over logs in data)
  if (logs) {
    try {
      const logsArray = JSON.parse(logs);
      if (Array.isArray(logsArray)) {
        parsedLogs = logsArray;
      } else {
        parsedLogs = [logs]; // Single log message
      }
    } catch (e) {
      parsedLogs = [logs]; // Fallback to single string
    }
  }

  // Map step strings to numbers for consistency with BaseSSEActionEvent
  const stepMap: Record<ProgressStep | string, number> = {
    [ProgressStep.PREPARATION]: 1,
    [ProgressStep.AUTHENTICATION]: 2,
    [ProgressStep.CONTRACT_VERIFICATION]: 3,
    [ProgressStep.TRANSACTION_SIGNING]: 4,
    [ProgressStep.BROADCASTING]: 5,
    [ProgressStep.VERIFICATION_COMPLETE]: 3,
    [ProgressStep.SIGNING_COMPLETE]: 6,
  };

  // Map step strings to phase names
  const phaseMap: Record<ProgressStep | string, onProgressEvents['phase']> = {
    [ProgressStep.PREPARATION]: 'preparation',
    [ProgressStep.AUTHENTICATION]: 'authentication',
    [ProgressStep.CONTRACT_VERIFICATION]: 'contract-verification',
    [ProgressStep.TRANSACTION_SIGNING]: 'transaction-signing',
    [ProgressStep.BROADCASTING]: 'broadcasting',
    [ProgressStep.VERIFICATION_COMPLETE]: 'contract-verification',
    [ProgressStep.SIGNING_COMPLETE]: 'action-complete',
  };

  // Determine status from messageType
  let status: 'progress' | 'success' | 'error' = 'progress';
  if (messageType.includes('COMPLETE')) {
    status = parsedData?.success === false ? 'error' : 'success';
  } else if (messageType.includes('ERROR') || messageType.includes('FAILURE')) {
    status = 'error';
  }

  // Create consolidated payload that works for both new and legacy callers
  const payload: any = {
    // New onProgressEvents-compatible fields
    step: stepMap[step] || 1,
    phase: phaseMap[step] || 'preparation',
    status,
    message: message,
    data: parsedData,
    logs: parsedLogs.length > 0 ? parsedLogs : undefined
  };

  // Handle specific message types
  if (messageType === 'VERIFICATION_COMPLETE' && parsedData) {
    payload.success = parsedData.success;
    payload.error = parsedData.error;
  } else if (messageType === 'SIGNING_COMPLETE') {
    payload.success = true;
    payload.data = parsedData;
  }

  // Send single consolidated message
  self.postMessage({
    type: messageType,
    payload: payload
  });

  // Auto-terminate worker on completion messages
  if (messageType === 'SIGNING_COMPLETE' || messageType === 'REGISTRATION_COMPLETE') {
    console.log(`[wasm-progress]: Auto-terminating worker after ${messageType}`);
    self.close();
  }
}

//////////////////////////////////////////////////////////////
// Make sendProgressMessage available globally for WASM imports
(globalThis as any).sendProgressMessage = sendProgressMessage;
//////////////////////////////////////////////////////////////

// Send response message and terminate worker
const sendResponseAndTerminate = (response: WorkerResponse): void => {
  self.postMessage(response);
  self.close();
}

// === ERROR HANDLING ===

const createErrorResponse = (error: string): WorkerResponse => {
  return {
    type: WorkerResponseType.ERROR,
    payload: { error }
  };
}

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[signer-worker]: Global error:', {
    message: typeof message === 'string' ? message : 'Unknown error',
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: error
  });
  console.error('[signer-worker]: Error stack:', error?.stack);
};

self.onunhandledrejection = (event) => {
  console.error('[signer-worker]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
};

let messageProcessed = false;

self.onmessage = async (event: MessageEvent<WorkerRequest>): Promise<void> => {
  if (messageProcessed) {
    sendResponseAndTerminate(createErrorResponse('Worker has already processed a message'));
    return;
  }

  messageProcessed = true;
  const { type, payload } = event.data;
  console.log('[signer-worker]: Received message:', { type, payload: { ...payload, prfOutput: '[REDACTED]' } });

  try {
    console.log('[signer-worker]: Starting WASM initialization...');
    await initializeWasmWithCache();
    console.log('[signer-worker]: WASM initialization completed, processing message...');

    switch (type) {
      case WorkerRequestType.DERIVE_NEAR_KEYPAIR_AND_ENCRYPT:
        await handleDeriveNearKeypairAndEncrypt(payload);
        break;

      case WorkerRequestType.RECOVER_KEYPAIR_FROM_PASSKEY:
        await handleRecoverKeypairFromPasskey(payload);
        break;

      case WorkerRequestType.CHECK_CAN_REGISTER_USER:
        await handleCheckCanRegisterUser(payload);
        break;

      case WorkerRequestType.SIGN_VERIFY_AND_REGISTER_USER:
        await handleSignVerifyAndRegisterUser(payload);
        break;

      case WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF:
        await handleDecryptPrivateKeyWithPrf(payload);
        break;

      case WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS:
        await handleVerifyAndSignNearTransactionWithActions(payload);
        break;

      case WorkerRequestType.SIGN_TRANSFER_TRANSACTION:
        await handleSignTransferTransaction(payload);
        break;

      case WorkerRequestType.ADD_KEY_WITH_PRF:
        await handleAddKeyWithPrf(payload);
        break;

      case WorkerRequestType.DELETE_KEY_WITH_PRF:
        await handleDeleteKeyWithPrf(payload);
        break;

      case WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY:
        await handleExtractCosePublicKey(payload);
        break;

      default:
        sendResponseAndTerminate(createErrorResponse(`Unknown message type: ${type}`));
    }
  } catch (error: any) {
    console.error('[signer-worker]: Message processing failed:', {
      error: error?.message || 'Unknown error',
      stack: error?.stack,
      name: error?.name,
      type,
      workerLocation: self.location.href
    });
    sendResponseAndTerminate(createErrorResponse(error?.message || 'Unknown error occurred'));
  }
};

/////////////////////////////////////
// === MESSAGE HANDLERS ===
/////////////////////////////////////

/**
 * Derives an AES-256-GCM symmetric key from the first PRF output,
 * Then derives NEAR ed25519 keypairs using HKDF from the second PRF output,
 * then encrypts the NEAR private key with the AES-256-GCM symmetric key.
 *
 * @param payload - The request payload containing:
 *   @param {string} payload.prfOutput - Base64-encoded PRF output from WebAuthn assertion
 *   @param {string} payload.nearAccountId - NEAR account ID for HKDF context and keypair association
 *   @param {string} payload.attestationObjectBase64url - Base64URL-encoded WebAuthn attestation object (used for verification only)
 */
async function handleDeriveNearKeypairAndEncrypt(
  payload: DeriveNearKeypairAndEncryptRequest['payload']
): Promise<void> {
  try {
    const { dualPrfOutputs, nearAccountId } = payload;

    const dualPrfOutputsStruct = new DualPrfOutputs(
      dualPrfOutputs.aesPrfOutput,
      dualPrfOutputs.ed25519PrfOutput
    );

    const encryptionResult = derive_and_encrypt_keypair(
      dualPrfOutputsStruct,
      nearAccountId
    );

    console.log('[signer-worker]: WASM encryption result:', {
      encrypted_data_length: encryptionResult.encrypted_data?.length,
      iv_field: encryptionResult.iv,
      iv_length: encryptionResult.iv?.length,
      public_key: encryptionResult.public_key,
      near_account_id: encryptionResult.near_account_id
    });

    // The result is now a structured object, not JSON
    const encryptedData = encryptionResult.encrypted_data;
    const iv = encryptionResult.iv;

    // Store the encrypted key in IndexedDB using flexible field names
    if (!encryptedData || !iv) {
      throw new Error(`Missing encrypted data or IV in WASM result. Available fields: encrypted_data, iv, public_key, near_account_id, stored`);
    }

    const keyData: EncryptedKeyData = {
      nearAccountId: nearAccountId,
      encryptedData: encryptedData,
      iv: iv,
      timestamp: Date.now()
    };
    await nearKeysDB.storeEncryptedKey(keyData);

    const verified = await nearKeysDB.verifyKeyStorage(nearAccountId);
    if (!verified) {
      throw new Error('Key storage verification failed');
    }

    sendResponseAndTerminate({
      type: WorkerResponseType.ENCRYPTION_SUCCESS,
      payload: {
        nearAccountId,
        publicKey: encryptionResult.public_key,
        stored: true
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: ENCRYPTION - Dual PRF key derivation failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.DERIVE_NEAR_KEY_FAILURE,
      payload: { error: error.message || 'Dual PRF key derivation failed' }
    });
  }
}

/**
 * Handle deterministic keypair derivation from passkey for account recovery using PRF
 * @param payload - The request payload containing registration credential with PRF outputs and optional account hint
 */
async function handleRecoverKeypairFromPasskey(
  payload: RecoverKeypairFromPasskeyRequest['payload']
): Promise<void> {
  try {
    const { credential, accountIdHint } = payload;
    console.log('[signer-worker]: Deriving deterministic keypair from passkey using PRF outputs for recovery');

    // Verify that PRF outputs are available in the credential
    if (!credential.clientExtensionResults?.prf?.results?.second) {
      throw new Error('Ed25519 PRF output (second) missing from credential - required for PRF-based key derivation');
    }

    console.log('[signer-worker]: PRF outputs confirmed in credential, proceeding with recovery');

    // Create structured credential object
    const credentialStruct = new WebAuthnRegistrationCredentialStruct(
      credential.id,
      credential.rawId,
      credential.type,
      credential.authenticatorAttachment,
      credential.response.clientDataJSON,
      credential.response.attestationObject,
      credential.response.transports,
      credential.clientExtensionResults?.prf?.results?.second || null // Ed25519 PRF output
    );

    console.log('[signer-worker]: Calling WASM recover_keypair_from_passkey with structured types');
    const result = await recover_keypair_from_passkey(credentialStruct, accountIdHint);

    // Result is now a structured object
    const publicKey = result.public_key;
    console.log('[signer-worker]: PRF-based keypair derivation successful');

    sendResponseAndTerminate({
      type: WorkerResponseType.RECOVER_KEYPAIR_SUCCESS,
      payload: {
        publicKey,
        accountIdHint
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: PRF-based keypair derivation failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.RECOVER_KEYPAIR_FAILURE,
      payload: { error: error.message || 'PRF-based keypair derivation failed' }
    });
  }
}

////////////////////////////////////////////
// === KEY EXPORT AND DECRYPTION HANDLER ===
////////////////////////////////////////////

/**
 * Handle private key decryption with PRF
 * @param payload - The decryption request payload
 * @param payload.nearAccountId - NEAR account ID associated with the key
 * @param payload.prfOutput - Base64-encoded PRF output from WebAuthn assertion
 * @returns Promise that resolves when decryption is complete
 */
async function handleDecryptPrivateKeyWithPrf(
  payload: DecryptPrivateKeyWithPrfRequest['payload']
): Promise<void> {
  try {
    const { nearAccountId, prfOutput } = payload;

    console.log('[signer-worker]: Decrypting for account:', nearAccountId);
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    console.log('[signer-worker]: Retrieved encrypted data:', {
      nearAccountId,
      encryptedDataLength: encryptedKeyData.encryptedData.length,
      ivLength: encryptedKeyData.iv.length,
      ivValue: encryptedKeyData.iv,
      timestamp: encryptedKeyData.timestamp
    });

    // Debug: Try to decode the IV to see if it's valid base64
    try {
      const ivBytes = atob(encryptedKeyData.iv.replace(/-/g, '+').replace(/_/g, '/'));
      console.log('[signer-worker]: IV as base64 decodes to length:', ivBytes.length);
    } catch (e) {
      console.log('[signer-worker]: IV is not valid base64:', e);
    }

    // Create structured request
    const request = new DecryptPrivateKeyRequest(
      nearAccountId,                  // 1st: near_account_id
      prfOutput,                      // 2nd: aes_prf_output
      encryptedKeyData.encryptedData, // 3rd: encrypted_private_key_data
      encryptedKeyData.iv             // 4th: encrypted_private_key_iv
    );

    console.log('[signer-worker]: Calling WASM decrypt_private_key_with_prf...');
    const result = await decrypt_private_key_with_prf(request);

    const decryptedPrivateKey = result.private_key;

    sendResponseAndTerminate({
      type: WorkerResponseType.DECRYPTION_SUCCESS,
      payload: {
        decryptedPrivateKey,
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: Decryption failed:', error);
    const errorMessage = error?.message || error?.toString() || String(error) || 'PRF decryption failed';
    sendResponseAndTerminate({
      type: WorkerResponseType.DECRYPTION_FAILURE,
      payload: { error: errorMessage }
    });
  }
}

/**
 * Handle checking if user can register (view function)
 * Calls check_can_register_user on the contract to check eligibility
 */
async function handleCheckCanRegisterUser(
  payload: CheckCanRegisterUserRequest['payload']
): Promise<void> {
  try {
    console.log('[signer-worker]: Starting registration check with enhanced verification');

    // Convert to structured types
    const vrfChallengeStruct = new VrfChallengeStruct(
      payload.vrfChallenge.vrfInput,
      payload.vrfChallenge.vrfOutput,
      payload.vrfChallenge.vrfProof,
      payload.vrfChallenge.vrfPublicKey,
      payload.vrfChallenge.userId,
      payload.vrfChallenge.rpId,
      BigInt(payload.vrfChallenge.blockHeight),
      payload.vrfChallenge.blockHash,
    );

    const credentialStruct = new WebAuthnRegistrationCredentialStruct(
      payload.credential.id,
      payload.credential.rawId,
      payload.credential.type,
      payload.credential.authenticatorAttachment,
      payload.credential.response.clientDataJSON,
      payload.credential.response.attestationObject,
      payload.credential.response.transports || null,
      payload.credential.clientExtensionResults?.prf?.results?.second || null, // Ed25519 PRF for recovery
    );

    const requestStruct = new RegistrationCheckRequest(
      payload.contractId,
      payload.nearRpcUrl
    );

    // Call the structured function
    const checkResult = await check_can_register_user(vrfChallengeStruct, credentialStruct, requestStruct);

    // Result is now a structured object, not JSON
    console.log('[signer-worker]: Registration check completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: checkResult.verified,
        registrationInfo: checkResult.registration_info ? {
          credential_id: Array.from(checkResult.registration_info.credential_id),
          credential_public_key: Array.from(checkResult.registration_info.credential_public_key),
          user_id: checkResult.registration_info.user_id,
          vrf_public_key: checkResult.registration_info.vrf_public_key ? Array.from(checkResult.registration_info.vrf_public_key) : undefined,
        } : undefined,
        logs: checkResult.logs,
      },
      operationId: payload.contractId,
      timestamp: Date.now()
    });

  } catch (error: any) {
    console.error('[signer-worker]: Registration check failed:', error);
    sendResponseAndTerminate(createErrorResponse(`Registration check failed: ${error.message}`));
  }
}

/**
 * Handle actual user registration (state-changing function)
 * Calls sign_verify_and_register_user on the contract via send_tx to actually register
 */
async function handleSignVerifyAndRegisterUser(
  payload: SignVerifyAndRegisterUserRequest['payload']
): Promise<void> {
  try {
    const {
      vrfChallenge,
      credential,
      contractId,
      signerAccountId,
      nearAccountId,
      nonce,
      blockHashBytes
    } = payload;

    console.log('[signer-worker]: Starting user registration with full verification');

    // Get PRF output from serialized credential
    const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure signing');
    }

    // Get encrypted key data
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Convert TypeScript types to WASM struct types
    const vrfChallengeStruct = new VrfChallengeStruct(
      vrfChallenge.vrfInput,
      vrfChallenge.vrfOutput,
      vrfChallenge.vrfProof,
      vrfChallenge.vrfPublicKey,
      vrfChallenge.userId,
      vrfChallenge.rpId,
      BigInt(vrfChallenge.blockHeight),
      vrfChallenge.blockHash
    );

    const credentialStruct = new WebAuthnRegistrationCredentialStruct(
      credential.id,
      credential.rawId,
      credential.type,
      credential.authenticatorAttachment,
      credential.response.clientDataJSON,
      credential.response.attestationObject,
      credential.response.transports,
      credential.clientExtensionResults?.prf?.results?.second || null
    );

    // Create grouped parameter structures
    const decryption = new Decryption(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv
    );
    const transaction = new RegistrationTxData(
      signerAccountId,
      BigInt(nonce),
      new Uint8Array(blockHashBytes)
    );
    const verification = new Verification(
      contractId,
      contractId // Use contractId as fallback for nearRpcUrl
    );
    const registrationRequest = new RegistrationRequest(
      verification,
      decryption,
      transaction
    );

    // Call the structured WASM function
    const registrationResult = await sign_verify_and_register_user(
      vrfChallengeStruct,
      credentialStruct,
      registrationRequest
    );

    if (!registrationResult.verified) {
      sendResponseAndTerminate({
        type: WorkerResponseType.REGISTRATION_FAILURE,
        payload: { error: registrationResult.error || 'Registration verification failed' }
      });
      return;
    }

    // Create signedTransaction objects for response (without functions - they can't be serialized)
    const signedTransaction = registrationResult.signed_transaction ? {
      transaction: JSON.parse(registrationResult.signed_transaction.transaction_json),
      signature: JSON.parse(registrationResult.signed_transaction.signature_json),
      borsh_bytes: Array.from(registrationResult.signed_transaction.borsh_bytes || new Uint8Array())
    } : {
      transaction: {},
      signature: {},
      borsh_bytes: []
    };

    const preSignedDeleteTransaction = registrationResult.pre_signed_delete_transaction ? {
      transaction: JSON.parse(registrationResult.pre_signed_delete_transaction.transaction_json),
      signature: JSON.parse(registrationResult.pre_signed_delete_transaction.signature_json),
      borsh_bytes: Array.from(registrationResult.pre_signed_delete_transaction.borsh_bytes || new Uint8Array())
    } : {
      transaction: {},
      signature: {},
      borsh_bytes: []
    };

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: registrationResult.verified,
        registrationInfo: registrationResult.registration_info ? {
          credential_id: Array.from(registrationResult.registration_info.credential_id),
          credential_public_key: Array.from(registrationResult.registration_info.credential_public_key),
          user_id: registrationResult.registration_info.user_id,
          vrf_public_key: registrationResult.registration_info.vrf_public_key ? Array.from(registrationResult.registration_info.vrf_public_key) : undefined
        } : {
          credential_id: [],
          credential_public_key: [],
          user_id: nearAccountId,
          vrf_public_key: undefined
        },
        logs: registrationResult.logs,
        signedTransaction,
        preSignedDeleteTransaction
      }
    });

  } catch (error: any) {
    console.error('[signer-worker]: User registration failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_FAILURE,
      payload: { error: error.message || 'User registration failed' }
    });
  }
}

/**
 * Enhanced transaction signing with RPC verification and progress updates
 * NOTE: PRF output is extracted from credential in worker for security
 * Sends multiple messages: verification progress, verification complete, signing progress, signing complete
 */
async function handleVerifyAndSignNearTransactionWithActions(
  payload: SignTransactionWithActionsRequest['payload']
): Promise<void> {
  try {
    const {
      nearAccountId,
      receiverId,
      actions,
      nonce,
      blockHashBytes,
      contractId,
      vrfChallenge,
      credential,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting transaction signing with actions');

    const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('PRF output missing from credential.clientExtensionResults: required for secure key decryption');
    }

    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Convert to structured WASM types
    const vrfChallengeStruct = new VrfChallengeStruct(
      vrfChallenge.vrfInput,
      vrfChallenge.vrfOutput,
      vrfChallenge.vrfProof,
      vrfChallenge.vrfPublicKey,
      vrfChallenge.userId,
      vrfChallenge.rpId,
      BigInt(vrfChallenge.blockHeight),
      vrfChallenge.blockHash
    );

    const credentialStruct = new WebAuthnAuthenticationCredentialStruct(
      credential.id,
      credential.rawId,
      credential.type,
      credential.authenticatorAttachment,
      credential.response.clientDataJSON,
      credential.response.authenticatorData,
      credential.response.signature,
      credential.response.userHandle
    );

    // Create grouped parameters for the structured WASM request
    const decryption = new Decryption(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv
    );
    const transaction = new TxData(
      nearAccountId,
      receiverId,
      BigInt(nonce),
      new Uint8Array(blockHashBytes),
      actions
    );
    const verification = new Verification(
      contractId,
      nearRpcUrl
    );
    const requestStruct = new TransactionSigningRequest(
      verification,
      decryption,
      transaction
    );

    const signedTransactionResult = await verify_and_sign_near_transaction_with_actions(
      vrfChallengeStruct,
      credentialStruct,
      requestStruct
    );

    console.log('[signer-worker]: Pure WASM verify and sign completed successfully');

    // Check if signed transaction is available
    if (!signedTransactionResult.signed_transaction) {
      throw new Error('Signed transaction missing from WASM result');
    }

    // Send completion response to main thread
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNING_COMPLETE,
      payload: {
        success: true,
        data: {
          signed_transaction: {
            transaction: JSON.parse(signedTransactionResult.signed_transaction.transaction_json),
            signature: JSON.parse(signedTransactionResult.signed_transaction.signature_json),
            borsh_bytes: Array.from(signedTransactionResult.signed_transaction.borsh_bytes || new Uint8Array())
          },
          near_account_id: nearAccountId,
          verification_logs: signedTransactionResult.logs || []
        },
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: Enhanced verify and sign failed:', error);
    sendResponseAndTerminate(createErrorResponse(
      `Enhanced verify and sign failed: ${error.message}`
    ));
  }
}

/**
 * Handle Transfer transaction signing with PRF extracted from credential in worker
 * Enhanced mode with contract verification (PRF extracted in worker for security)
 */
async function handleSignTransferTransaction(
  payload: SignTransferTransactionRequest['payload']
): Promise<void> {
  try {
    const {
      nearAccountId,
      receiverId,
      depositAmount,
      nonce,
      blockHashBytes,
      contractId,
      vrfChallenge,
      credential,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting Transfer transaction signing');

    const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure key decryption');
    }

    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Convert to structured WASM types
    const vrfChallengeStruct = new VrfChallengeStruct(
      vrfChallenge.vrfInput,
      vrfChallenge.vrfOutput,
      vrfChallenge.vrfProof,
      vrfChallenge.vrfPublicKey,
      vrfChallenge.userId,
      vrfChallenge.rpId,
      BigInt(vrfChallenge.blockHeight),
      vrfChallenge.blockHash
    );

    const credentialStruct = new WebAuthnAuthenticationCredentialStruct(
      credential.id,
      credential.rawId,
      credential.type,
      credential.authenticatorAttachment,
      credential.response.clientDataJSON,
      credential.response.authenticatorData,
      credential.response.signature,
      credential.response.userHandle
    );

    const decryption = new Decryption(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv
    );
    const transaction = new TransferTxData(
      nearAccountId,
      receiverId,
      BigInt(nonce),
      new Uint8Array(blockHashBytes),
      depositAmount
    );
    const verification = new Verification(
      contractId,
      nearRpcUrl
    );
    const requestStruct = new TransferTransactionRequest(
      verification,
      decryption,
      transaction
    );

    const signedTransactionResult = await verify_and_sign_near_transfer_transaction(
      vrfChallengeStruct,
      credentialStruct,
      requestStruct
    );

    console.log('[signer-worker]: Enhanced Transfer transaction signing completed successfully');

    // Check if signed transaction is available
    if (!signedTransactionResult.signed_transaction) {
      throw new Error('Signed transaction missing from WASM result');
    }

    // Send completion response to main thread (cast to any to avoid type conflicts)
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNING_COMPLETE,
      payload: {
        success: true,
        data: {
          signed_transaction: {
            transaction: JSON.parse(signedTransactionResult.signed_transaction.transaction_json),
            signature: JSON.parse(signedTransactionResult.signed_transaction.signature_json),
            borsh_bytes: Array.from(signedTransactionResult.signed_transaction.borsh_bytes || new Uint8Array())
          },
          near_account_id: nearAccountId,
          verification_logs: signedTransactionResult.logs || []
        }
      }
    });

  } catch (error: any) {
    console.error('[signer-worker]: Transfer transaction signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Transfer transaction signing failed' }
    });
  }
}

/**
 * Handle AddKey transaction with PRF authentication
 */
async function handleAddKeyWithPrf(
  payload: AddKeyWithPrfRequest['payload']
): Promise<void> {
  try {
    console.log('[signer-worker]: Starting AddKey with PRF authentication');

    const {
      prfOutput,
      encryptedPrivateKeyData,
      encryptedPrivateKeyIv,
      signerAccountId,
      newPublicKey,
      accessKeyJson,
      nonce,
      blockHashBytes,
      contractId,
      vrfChallenge,
      credential,
      nearRpcUrl
    } = payload;

    // Convert to structured WASM types
    const vrfChallengeStruct = new VrfChallengeStruct(
      vrfChallenge.vrfInput,
      vrfChallenge.vrfOutput,
      vrfChallenge.vrfProof,
      vrfChallenge.vrfPublicKey,
      vrfChallenge.userId,
      vrfChallenge.rpId,
      BigInt(vrfChallenge.blockHeight),
      vrfChallenge.blockHash
    );

    const credentialStruct = new WebAuthnAuthenticationCredentialStruct(
      credential.id,
      credential.rawId,
      credential.type,
      credential.authenticatorAttachment,
      credential.response.clientDataJSON,
      credential.response.authenticatorData,
      credential.response.signature,
      credential.response.userHandle
    );

    // Create grouped parameter structures
    const decryption = new Decryption(
      prfOutput,
      encryptedPrivateKeyData,
      encryptedPrivateKeyIv
    );

    // Create transaction data for AddKey action
    const transaction = new AddKeyTxData(
      signerAccountId,
      newPublicKey,
      accessKeyJson,
      BigInt(nonce),
      new Uint8Array(blockHashBytes)
    );
    const verification = new Verification(
      contractId,
      nearRpcUrl
    );
    const requestStruct = new AddKeyRequest(
      verification,
      decryption,
      transaction
    );

    const result = await add_key_with_prf(
      vrfChallengeStruct,
      credentialStruct,
      requestStruct
    );

    console.log('[signer-worker]: Add key with PRF completed successfully');
  } catch (error: any) {
    console.error('[signer-worker]: Add key with PRF failed:', error);
    sendResponseAndTerminate(createErrorResponse(`Add key failed: ${error.message}`));
  }
}

/**
 * Handle DeleteKey transaction with PRF authentication
 */
async function handleDeleteKeyWithPrf(
  payload: DeleteKeyWithPrfRequest['payload']
): Promise<void> {
  try {
    console.log('[signer-worker]: Starting DeleteKey with PRF authentication');

    const {
      prfOutput,
      encryptedPrivateKeyData,
      encryptedPrivateKeyIv,
      signerAccountId,
      publicKeyToDelete,
      nonce,
      blockHashBytes,
      contractId,
      vrfChallenge,
      credential,
      nearRpcUrl
    } = payload;

    // Convert to structured WASM types
    const vrfChallengeStruct = new VrfChallengeStruct(
      vrfChallenge.vrfInput,
      vrfChallenge.vrfOutput,
      vrfChallenge.vrfProof,
      vrfChallenge.vrfPublicKey,
      vrfChallenge.userId,
      vrfChallenge.rpId,
      BigInt(vrfChallenge.blockHeight),
      vrfChallenge.blockHash
    );

    const credentialStruct = new WebAuthnAuthenticationCredentialStruct(
      credential.id,
      credential.rawId,
      credential.type,
      credential.authenticatorAttachment,
      credential.response.clientDataJSON,
      credential.response.authenticatorData,
      credential.response.signature,
      credential.response.userHandle
    );

    // Create grouped parameter structures
    const decryption = new Decryption(
      prfOutput,
      encryptedPrivateKeyData,
      encryptedPrivateKeyIv
    );

    // Create actions JSON for DeleteKey action
    const deleteKeyAction = {
      actionType: 'DeleteKey',
      public_key: publicKeyToDelete
    };
    const actionsJson = JSON.stringify([deleteKeyAction]);

    const transaction = new TxData(
      signerAccountId,
      signerAccountId, // receiver_id is same as signer for delete key
      BigInt(nonce),
      new Uint8Array(blockHashBytes),
      actionsJson
    );
    const verification = new Verification(
      contractId,
      nearRpcUrl
    );
    const requestStruct = new TransactionSigningRequest(
      verification,
      decryption,
      transaction
    );

    await verify_and_sign_near_transaction_with_actions(
      vrfChallengeStruct,
      credentialStruct,
      requestStruct
    );

    console.log('[signer-worker]: Delete key with PRF completed successfully');
  } catch (error: any) {
    console.error('[signer-worker]: Delete key with PRF failed:', error);
    sendResponseAndTerminate(createErrorResponse(`Delete key failed: ${error.message}`));
  }
}

/**
 * Handle ExtractCosePublicKey operation - extracts COSE public key from attestation object
 */
async function handleExtractCosePublicKey(
  payload: ExtractCosePublicKeyRequest['payload']
): Promise<void> {
  try {
    console.log('[signer-worker]: Starting COSE public key extraction from attestation object');

    // Call the WASM function to extract COSE public key
    const cosePublicKeyBytes = await extract_cose_public_key_from_attestation(payload.attestationObjectBase64url);

    console.log('[signer-worker]: COSE public key extraction successful, bytes length:', cosePublicKeyBytes.length);

    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_EXTRACTION_SUCCESS,
      payload: {
        cosePublicKeyBytes
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: COSE public key extraction failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_EXTRACTION_FAILURE,
      payload: { error: error.message || 'COSE public key extraction failed' }
    });
  }
}

// === EXPORTS ===
export type {
  WorkerRequest,
  WorkerResponse,
  DeriveNearKeypairAndEncryptRequest,
  DecryptPrivateKeyWithPrfRequest
};