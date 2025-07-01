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
  type DecryptPrivateKeyWithPrfRequest,
  type ExtractCosePublicKeyRequest,
  type ValidateCoseKeyRequest,
  type CheckCanRegisterUserRequest,
  type SignVerifyAndRegisterUserRequest,
  SerializableWebAuthnCredential,
  takePrfOutputFromCredential,
  ProgressMessageType,
  ProgressStep,
  type ProgressMessageParams,
  type WorkerProgressMessage,
  DeleteKeyWithPrfRequest,
  RollbackFailedRegistrationWithPrfRequest,
} from './types/signer-worker.js';
import type { onProgressEvents } from './types/webauthn.js';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from './IndexedDBManager/passkeyNearKeysDB.js';
import { bufferEncode } from '../utils/encoders.js';

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
  // Registration
  derive_near_keypair_from_cose_and_encrypt_with_prf,
  check_can_register_user,
  sign_verify_and_register_user,
  // Key exports/decryption
  decrypt_private_key_with_prf_as_string,
  // Transaction signing: combined verification + signing
  verify_and_sign_near_transaction_with_actions,
  verify_and_sign_near_transfer_transaction,
  // New action-specific functions (will be available after WASM rebuild)
  add_key_with_prf,
  delete_key_with_prf,
  rollback_failed_registration_with_prf,
  // COSE keys
  extract_cose_public_key_from_attestation,
  validate_cose_key_format,
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

/////////////////////////////////////
// === MAIN MESSAGE HANDLER ===
/////////////////////////////////////

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

      case WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY:
        await handleExtractCosePublicKey(payload);
        break;

      case WorkerRequestType.VALIDATE_COSE_KEY:
        await handleValidateCoseKey(payload);
        break;

      case WorkerRequestType.ADD_KEY_WITH_PRF:
        await handleAddKeyWithPrf(payload);
        break;

      case WorkerRequestType.DELETE_KEY_WITH_PRF:
        await handleDeleteKeyWithPrf(payload);
        break;

      case WorkerRequestType.ROLLBACK_FAILED_REGISTRATION_WITH_PRF:
        await handleRollbackFailedRegistrationWithPrf(payload);
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

// === NEAR KEY DERIVATION AND ENCRYPTION HANDLER ===

/**
 * Derives NEAR ed25519 keypairs from the WebAuthn P-256 COSE keys,
 * then derives an AES-256-GCM symmetric key from the WebAuthn PRF output,
 * then encrypts the NEAR private key with the AES-256-GCM symmetric key.
 *
 * @param payload - The request payload containing:
 *   @param {string} payload.prfOutput - Base64-encoded PRF output from WebAuthn assertion
 *   @param {string} payload.nearAccountId - NEAR account ID to associate with the keypair
 *   @param {string} payload.attestationObjectBase64url - Base64URL-encoded WebAuthn attestation object (includes COSE P-256 keys)
 */
async function handleDeriveNearKeypairAndEncrypt(
  payload: DeriveNearKeypairAndEncryptRequest['payload']
): Promise<void> {
  try {
    const { prfOutput, nearAccountId, attestationObjectBase64url } = payload;
    console.log('[signer-worker]: Using deterministic key derivation from COSE P-256 credential');

    const resultJson = derive_near_keypair_from_cose_and_encrypt_with_prf(
      attestationObjectBase64url,
      prfOutput
    );

    const { publicKey, encryptedPrivateKey } = parseWasmResult(resultJson);
    console.log('[signer-worker]: Deterministic parseWasmResult output:');
    console.log('  - publicKey value:', publicKey);
    console.log('  - encryptedPrivateKey type:', typeof encryptedPrivateKey);

    const keyData: EncryptedKeyData = {
      nearAccountId: nearAccountId,
      encryptedData: encryptedPrivateKey.encrypted_near_key_data_b64u,
      iv: encryptedPrivateKey.aes_gcm_nonce_b64u,
      timestamp: Date.now()
    };

    console.log('[signer-worker]: Deterministic key derivation successful - NEAR keypair bound to WebAuthn credential');
    await nearKeysDB.storeEncryptedKey(keyData);

    const verified = await nearKeysDB.verifyKeyStorage(nearAccountId);
    if (!verified) {
      throw new Error('Key storage verification failed');
    }

    sendResponseAndTerminate({
      type: WorkerResponseType.ENCRYPTION_SUCCESS,
      payload: {
        nearAccountId,
        publicKey,
        stored: true,
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: Encryption failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.DERIVE_NEAR_KEY_FAILURE,
      payload: { error: error.message || 'PRF encryption failed' }
    });
  }
}

/////////////////////////////////////
// === KEY EXPORT AND DECRYPTION HANDLER ===
/////////////////////////////////////

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

    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Encrypted data is already raw base64, no prefix stripping needed
    const decryptedPrivateKey = decrypt_private_key_with_prf_as_string(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv
    );

    sendResponseAndTerminate({
      type: WorkerResponseType.DECRYPTION_SUCCESS,
      payload: {
        decryptedPrivateKey,
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: Decryption failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.DECRYPTION_FAILURE,
      payload: { error: error.message || 'PRF decryption failed' }
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
    const {
      vrfChallenge,
      credential,
      contractId,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting check if user can register (view function)');

    // Validate required parameters
    if (!vrfChallenge || !credential || !contractId || !nearRpcUrl) {
      throw new Error('Missing required parameters for registration check: vrfChallenge, credential, contractId, nearRpcUrl');
    }

    const { credentialWithoutPrf } = takePrfOutputFromCredential(credential);
    console.log('[signer-worker]: Calling check_can_register_user function');

    // Call the WASM function that handles registration eligibility check
    const checkResultJson = await check_can_register_user(
      contractId,
      JSON.stringify(vrfChallenge),
      JSON.stringify(credentialWithoutPrf),
      nearRpcUrl
    );

    // Parse the result
    const checkResult = JSON.parse(checkResultJson);
    console.log('[signer-worker]: Registration check result:', {
      verified: checkResult.verified,
      hasRegistrationInfo: !!checkResult.registration_info,
      signedTransactionBorsh: checkResult.signed_transaction_borsh
    });

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: checkResult.verified,
        registrationInfo: checkResult.registration_info,
        logs: checkResult.logs,
        signedTransactionBorsh: checkResult.signed_transaction_borsh
      }
    });

  } catch (error: any) {
    console.error('[signer-worker]: Check registration eligibility failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_FAILURE,
      payload: { error: error.message || 'Check registration eligibility failed' }
    });
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

    console.log('[signer-worker]: Starting actual user registration (state-changing function)');

    // Validate required parameters
    if (!vrfChallenge || !credential || !contractId || !signerAccountId || !nearAccountId || !nonce || !blockHashBytes) {
      throw new Error('Missing required parameters for actual registration: vrfChallenge, credential, contractId, nearRpcUrl, signerAccountId, nearAccountId, nonce, blockHashBytes');
    }

    // Get encrypted key data for the account
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Extract PRF output from credential
    const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure registration');
    }

    console.log('[signer-worker]: Calling sign_verify_and_register_user function with transaction metadata');
    const { credentialWithoutPrf } = takePrfOutputFromCredential(credential);

    // Call the WASM function that handles actual registration (send_tx)
    const registrationResultJson = await sign_verify_and_register_user(
      contractId,
      JSON.stringify(vrfChallenge),
      JSON.stringify(credentialWithoutPrf),
      signerAccountId,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      prfOutput,
      BigInt(nonce),
      new Uint8Array(blockHashBytes)
    );

    // Parse the result
    const registrationResult = JSON.parse(registrationResultJson);
    console.log('[signer-worker]: Actual registration result:', {
      verified: registrationResult.verified,
      hasRegistrationInfo: !!registrationResult.registration_info,
      signedTransactionBorsh: registrationResult.signed_transaction_borsh
    });

    if (!registrationResult.verified) {
      throw new Error('Actual registration verification failed');
    }

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: registrationResult.verified,
        registrationInfo: registrationResult.registration_info,
        logs: registrationResult.logs,
        signedTransactionBorsh: registrationResult.signed_transaction_borsh,
        preSignedDeleteTransaction: registrationResult.pre_signed_delete_transaction
      }
    });

  } catch (error: any) {
    console.error('[signer-worker]: Actual user registration failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_FAILURE,
      payload: { error: error.message || 'Actual user registration failed' }
    });
  }
}

// === NEW ACTION-BASED TRANSACTION SIGNING HANDLERS ===

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

    console.log('[signer-worker]: Starting enhanced verify and sign with pure WASM implementation');

    // Validate required parameters
    if (!nearAccountId || !receiverId || !actions || !nonce || !blockHashBytes) {
      throw new Error('Missing required transaction parameters');
    }
    if (!contractId || !vrfChallenge || !credential || !nearRpcUrl) {
      throw new Error('Missing required verification parameters');
    }

    // Get encrypted key data for the account
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Extract PRF output using the method you wanted
    if (!credential.clientExtensionResults?.prf?.results?.first) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure key decryption');
    }
    console.log('[signer-worker]: PRF output extracted via getClientExtensionResults()');

    let { credentialWithoutPrf, prfOutput } = takePrfOutputFromCredential(credential);

    // Call the pure WASM function that handles verification + signing with progress messages
    const _signedTransactionBorsh = await verify_and_sign_near_transaction_with_actions(
      // Authentication
      prfOutput, // Keep as base64 string - will be converted by WASM internally
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,

      // Transaction details
      nearAccountId,
      receiverId,
      BigInt(nonce),
      new Uint8Array(blockHashBytes),
      actions, // JSON string from signerWorkerManager

      // Verification parameters
      contractId,
      JSON.stringify(vrfChallenge),
      JSON.stringify(credentialWithoutPrf),
      nearRpcUrl
    );

    console.log('[signer-worker]: Pure WASM verify and sign completed successfully');
    // WASM handles ALL messaging including the final SIGNING_COMPLETE message
    // The function sends::
    // - VERIFICATION_PROGRESS,
    // - VERIFICATION_COMPLETE,
    // - SIGNING_PROGRESS, and
    // - SIGNING_COMPLETE with the final result: _signedTransactionBorsh
    //
    // Do not send any additional messages to avoid duplication
    // The worker will be terminated by the caller after receiving SIGNING_COMPLETE
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
      // Verification parameters for enhanced mode (all required)
      contractId,
      vrfChallenge,
      credential,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting Transfer transaction signing');

    // Validate all required parameters
    const requiredFields = ['nearAccountId', 'receiverId', 'depositAmount', 'nonce'];
    const missingFields = requiredFields.filter(field => !payload[field as keyof typeof payload]);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields for transfer transaction signing: ${missingFields.join(', ')}`);
    }
    if (!blockHashBytes || blockHashBytes.length === 0) {
      throw new Error('blockHashBytes is required and cannot be empty');
    }
    // All verification parameters are required
    if (!contractId || !vrfChallenge || !credential || !nearRpcUrl) {
      throw new Error('All verification parameters are required: contractId, vrfChallenge, credential, nearRpcUrl');
    }

    // Get PRF output from serialized credential (extracted in main thread with minimal exposure)
    console.log('[signer-worker]: Getting PRF output from serialized credential');
    const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure key decryption');
    }
    console.log('[signer-worker]: PRF output available for secure signing');

    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    console.log('[signer-worker]: Using enhanced mode with contract verification');

      // Use the transfer-specific verify+sign WASM function
      const _signedTransactionBorsh = await verify_and_sign_near_transfer_transaction(
        // Authentication
        prfOutput, // Keep as base64 string - WASM function expects string
        encryptedKeyData.encryptedData,
        encryptedKeyData.iv,

        // Transaction details
        nearAccountId,
        receiverId,
        depositAmount,
        BigInt(nonce),
        new Uint8Array(blockHashBytes),

        // Verification parameters
        contractId,
        JSON.stringify(vrfChallenge),
        JSON.stringify(credential),
        nearRpcUrl
      );

      console.log('[signer-worker]: Enhanced Transfer transaction signing completed successfully');

      // WASM handles ALL messaging including the final SIGNING_COMPLETE message
      // which contains the `signedTransactionBorsh` result
      // We should not send any additional messages to avoid duplication

  } catch (error: any) {
    console.error('[signer-worker]: Transfer transaction signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Transfer transaction signing failed' }
    });
  }
}

// === COSE KEY EXTRACTION WORKFLOW ===

/**
 * Handle COSE public key extraction from attestation object
 * @param payload - The request payload
 * @param payload.attestationObjectBase64url - Base64URL-encoded WebAuthn attestation object containing the COSE key
 */
async function handleExtractCosePublicKey(
  payload: ExtractCosePublicKeyRequest['payload']
): Promise<void> {
  try {
    const { attestationObjectBase64url } = payload;
    console.log('[signer-worker]: Extracting COSE public key from attestation object');

    // Call the WASM function to extract COSE public key
    const cosePublicKeyBytes = extract_cose_public_key_from_attestation(attestationObjectBase64url);
    console.log('[signer-worker]: Successfully extracted COSE public key:', cosePublicKeyBytes.length, 'bytes');

    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_KEY_SUCCESS,
      payload: {
        cosePublicKeyBytes: Array.from(cosePublicKeyBytes)
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: COSE key extraction failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_KEY_FAILURE,
      payload: { error: error.message || 'COSE key extraction failed' }
    });
  }
}

/**
 * Handle COSE key format validation
 * @param payload - The validation request payload
 * @param payload.coseKeyBytes - Array of bytes containing the COSE key to validate
 */
async function handleValidateCoseKey(
  payload: ValidateCoseKeyRequest['payload']
): Promise<void> {
  try {
    const { coseKeyBytes } = payload;
    // Call the WASM function to validate COSE key format
    const validationResult = validate_cose_key_format(new Uint8Array(coseKeyBytes));
    const validationInfo = JSON.parse(validationResult);
    console.log('[signer-worker]: COSE key validation result:', validationInfo);

    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_VALIDATION_SUCCESS,
      payload: {
        valid: validationInfo.valid,
        info: validationInfo
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: COSE key validation failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_VALIDATION_FAILURE,
      payload: { error: error.message || 'COSE key validation failed' }
    });
  }
}

/////////////////////////////////////
// === PROGRESS MESSAGING ===
/////////////////////////////////////

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

  // Add legacy fields for backward compatibility
  if (messageType === 'VERIFICATION_COMPLETE' && parsedData) {
    // Legacy callers expect: payload.success, payload.error
    payload.success = parsedData.success;
    payload.error = parsedData.error;
  } else if (messageType === 'SIGNING_COMPLETE') {
    // Legacy callers expect: payload.success = true
    payload.success = true;
  }

  // Send single consolidated message
  self.postMessage({
    type: messageType,
    payload: payload
  });
}

//////////////////////////////////////////////////////////////
// Make sendProgressMessage available globally for WASM imports
(globalThis as any).sendProgressMessage = sendProgressMessage;
//////////////////////////////////////////////////////////////

// Send response message and terminate worker
function sendResponseAndTerminate(response: WorkerResponse): void {
  self.postMessage(response);
  self.close();
}

interface WasmResult {
  publicKey: string;
  encryptedPrivateKey: any;
}

function parseWasmResult(resultJson: string | object): WasmResult {
  const result = typeof resultJson === 'string' ? JSON.parse(resultJson) : resultJson;
  const encryptedPrivateKey = typeof result.encryptedPrivateKey === 'string'
    ? JSON.parse(result.encryptedPrivateKey)
    : result.encryptedPrivateKey;

  const finalResult = {
    publicKey: result.publicKey,
    encryptedPrivateKey
  };
  // console.log('[signer-worker]: parseWasmResult - Final result:', finalResult);
  return finalResult;
}

/////////////////////////////////////
// === ERROR HANDLING ===
/////////////////////////////////////

function createErrorResponse(error: string): WorkerResponse {
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

// === EXPORTS ===
export type {
  WorkerRequest,
  WorkerResponse,
  DeriveNearKeypairAndEncryptRequest,
  DecryptPrivateKeyWithPrfRequest,
  ExtractCosePublicKeyRequest,
  ValidateCoseKeyRequest
};

/**
 * Handle AddKey transaction with PRF authentication
 */
async function handleAddKeyWithPrf(
  payload: any // TODO: Type properly once AddKeyWithPrfRequest is imported
): Promise<void> {
  try {
    console.log('[signer-worker]: AddKey with PRF - WASM function not yet available');

    const result = await add_key_with_prf(
      payload.prfOutput,
      payload.encryptedPrivateKeyData,
      payload.encryptedPrivateKeyIv,
      payload.signerAccountId,
      payload.newPublicKey,
      payload.accessKeyJson,
      BigInt(payload.nonce),
      new Uint8Array(payload.blockHashBytes),
      payload.contractId,
      JSON.stringify(payload.vrfChallenge),
      JSON.stringify(payload.credential),
      payload.nearRpcUrl
    );

    // For now, use the general action-based function as a fallback
    const actions = JSON.stringify([{
      actionType: 'AddKey',
      public_key: payload.newPublicKey,
      access_key: payload.accessKeyJson
    }]);

    await verify_and_sign_near_transaction_with_actions(
      payload.prfOutput,
      payload.encryptedPrivateKeyData,
      payload.encryptedPrivateKeyIv,
      payload.signerAccountId,
      payload.signerAccountId, // receiver same as signer for AddKey
      BigInt(payload.nonce),
      new Uint8Array(payload.blockHashBytes),
      actions,
      payload.contractId,
      JSON.stringify(payload.vrfChallenge),
      JSON.stringify(payload.credential),
      payload.nearRpcUrl
    );

  } catch (error: any) {
    console.error('[signer-worker]: AddKey with PRF failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'AddKey transaction failed' }
    });
  }
}

/**
 * Handle DeleteKey transaction with PRF authentication
 */
async function handleDeleteKeyWithPrf(
  payload: DeleteKeyWithPrfRequest['payload']
): Promise<void> {
  try {
    console.log('[signer-worker]: DeleteKey with PRF - WASM function not yet available');

    const result = await delete_key_with_prf(
      payload.prfOutput,
      payload.encryptedPrivateKeyData,
      payload.encryptedPrivateKeyIv,
      payload.signerAccountId,
      payload.publicKeyToDelete,
      BigInt(payload.nonce),
      new Uint8Array(payload.blockHashBytes),
      payload.contractId,
      JSON.stringify(payload.vrfChallenge),
      JSON.stringify(payload.credential),
      payload.nearRpcUrl
    );

    // For now, use the general action-based function as a fallback
    const actions = JSON.stringify([{
      actionType: 'DeleteKey',
      public_key: payload.publicKeyToDelete
    }]);

    await verify_and_sign_near_transaction_with_actions(
      payload.prfOutput,
      payload.encryptedPrivateKeyData,
      payload.encryptedPrivateKeyIv,
      payload.signerAccountId,
      payload.signerAccountId, // receiver same as signer for DeleteKey
      BigInt(payload.nonce),
      new Uint8Array(payload.blockHashBytes),
      actions,
      payload.contractId,
      JSON.stringify(payload.vrfChallenge),
      JSON.stringify(payload.credential),
      payload.nearRpcUrl
    );

  } catch (error: any) {
    console.error('[signer-worker]: DeleteKey with PRF failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'DeleteKey transaction failed' }
    });
  }
}

/**
 * Handle registration rollback with DeleteAccount (context-restricted)
 */
async function handleRollbackFailedRegistrationWithPrf(
  payload: RollbackFailedRegistrationWithPrfRequest['payload']
): Promise<void> {
  try {
    console.log('[signer-worker]: Registration rollback with DeleteAccount - validating caller');

    // SECURITY: Use the caller function name passed from main thread
    // This prevents arbitrary calls to DeleteAccount
    const callerFunction = payload.callerFunction;

    if (!callerFunction || callerFunction === 'unknown') {
      throw new Error('SECURITY: Invalid or missing caller function for DeleteAccount operation');
    }

    console.log(`[signer-worker]: DeleteAccount requested by caller: ${callerFunction}`);

    const result = await (rollback_failed_registration_with_prf as any)(
      payload.prfOutput,
      payload.encryptedPrivateKeyData,
      payload.encryptedPrivateKeyIv,
      payload.signerAccountId,
      payload.beneficiaryAccountId,
      BigInt(payload.nonce),
      new Uint8Array(payload.blockHashBytes),
      payload.contractId,
      JSON.stringify(payload.vrfChallenge),
      JSON.stringify(payload.credential),
      payload.nearRpcUrl,
      callerFunction // Pass actual caller function for security validation
    );

    // The WASM function handles all messaging including SIGNING_COMPLETE
    console.log('[signer-worker]: Registration rollback completed successfully');

  } catch (error: any) {
    console.error('[signer-worker]: Registration rollback failed:', error);

    // Log security violations with more detail
    if (error.message?.includes('SECURITY VIOLATION')) {
      console.error('[signer-worker]: Unauthorized DeleteAccount attempt:', {
        callerFunction: payload.callerFunction,
        signerAccountId: payload.signerAccountId,
        error: error.message
      });
    }

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Registration rollback failed' }
    });
  }
}

/**
 * Extract the calling function name from JavaScript stack trace
 * This is used for security validation in context-restricted functions
 */
function extractCallerFunctionName(): string {
  try {
    const stack = new Error().stack;
    if (!stack) return 'unknown';

    // Parse stack trace to find the actual calling function
    // Stack format: "at functionName (file:line:col)" or "at file:line:col"
    const lines = stack.split('\n');

    // Skip the first few lines which are internal calls
    // Look for the first line that contains a recognizable function name
    for (let i = 3; i < Math.min(lines.length, 10); i++) {
      const line = lines[i];
      if (line && line.includes('at ')) {
        // Extract function name from "at functionName (" pattern
        const match = line.match(/at\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/);
        if (match && match[1] &&
            !match[1].startsWith('handle') && // Skip worker handlers
            !match[1].startsWith('execute') && // Skip generic execution functions
            !match[1].includes('Worker')) { // Skip worker-related functions
          return match[1];
        }
      }
    }
    return 'unknown';
  } catch (error) {
    console.warn('[security]: Failed to extract caller function name:', error);
    return 'unknown';
  }
}