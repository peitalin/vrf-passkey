// WASM-only transaction signing worker
// This worker handles all NEAR transaction operations using WASM functions only.

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
  type RegisterWithPrfRequest,
  SerializableWebAuthnCredential,
  takePrfOutputFromCredential,
} from './types/worker.js';
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

// === WASM MODULE FUNCTIONS ===
const {
  // Registration
  derive_near_keypair_from_cose_and_encrypt_with_prf,
  register_with_prf,
  check_can_register_user,
  verify_and_register_user,
  // Key exports/decryption
  decrypt_private_key_with_prf_as_string,
  // Transaction signing: combined verification + signing
  verify_and_sign_near_transaction_with_actions,
  verify_and_sign_near_transfer_transaction,
  // COSE keys
  extract_cose_public_key_from_attestation,
  validate_cose_key_format,
} = wasmModule;

// === WASM IMPORTED FUNCTIONS ===
// These functions will be imported by WASM and called during execution

/**
 * Function called by WASM to send progress messages
 * This is imported into the WASM module as sendProgressMessage
 */
function sendProgressMessage(messageType: string, step: string, message: string, data: string): void {
  console.log(`[wasm-progress]: ${messageType} - ${step}: ${message}`);

  // Parse data if provided
  const parsedData = data ? JSON.parse(data) : undefined;

  // Create the base payload
  const payload: any = {
    step: step,
    message: message,
    data: parsedData
  };

  // Handle specific message type payload formats to match caller expectations
  if (messageType === 'VERIFICATION_COMPLETE' && parsedData) {
    // Caller expects: payload.success, payload.logs, payload.error
    payload.success = parsedData.success;
    payload.logs = parsedData.logs;
    payload.error = parsedData.error;
  } else if (messageType === 'SIGNING_COMPLETE') {
    // Caller expects: payload.success = true, payload.data = { signedTransactionBorsh, verificationLogs }
    payload.success = true;
  }

  // Send progress message to main thread
  self.postMessage({
    type: messageType,
    payload: payload
  });
}

// Make sendProgressMessage available globally for WASM imports
(globalThis as any).sendProgressMessage = sendProgressMessage;


// Create database manager instance
const nearKeysDB = new PasskeyNearKeysDBManager();


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

// Send response message and terminate worker
function sendResponseAndTerminate(response: WorkerResponse): void {
  self.postMessage(response);
  self.close();
}

// Send progress message without terminating
function sendProgress(response: WorkerResponse): void {
  self.postMessage(response);
}

function createErrorResponse(error: string): WorkerResponse {
  return {
    type: WorkerResponseType.ERROR,
    payload: { error }
  };
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

// === MAIN MESSAGE HANDLER ===

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

      case WorkerRequestType.REGISTER_WITH_PRF:
        await handleRegisterWithPrf(payload);
        break;

      case WorkerRequestType.CHECK_CAN_REGISTER_USER:
        await handleCheckCanRegisterUser(payload);
        break;

      case WorkerRequestType.VERIFY_AND_REGISTER_USER:
        await handleVerifyAndRegisterUser(payload);
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

// === KEY EXPORT AND DECRYPTION HANDLER ===

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
 * Handle WebAuthn registration with VRF verification
 * Calls verify_registration_response on the contract to register a new credential
 */
async function handleRegisterWithPrf(
  payload: RegisterWithPrfRequest['payload']
): Promise<void> {
  try {
    const {
      vrfChallenge,
      webauthnCredential,
      contractId,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting WebAuthn registration with VRF verification');

    // Validate required parameters
    if (!vrfChallenge || !webauthnCredential || !contractId || !nearRpcUrl) {
      throw new Error('Missing required parameters for registration: vrfChallenge, webauthnCredential, contractId, nearRpcUrl');
    }

    console.log('[signer-worker]: Calling register_with_prf WASM function');

    // Call the WASM function that handles registration verification
    const registrationResultJson = await register_with_prf(
      JSON.stringify(vrfChallenge),
      JSON.stringify(webauthnCredential),
      contractId,
      nearRpcUrl
    );

    // Parse the result
    const registrationResult = JSON.parse(registrationResultJson);
    console.log('[signer-worker]: Registration result:', {
      verified: registrationResult.verified,
      hasRegistrationInfo: !!registrationResult.registration_info
    });

    if (!registrationResult.verified) {
      throw new Error('Registration verification failed');
    }

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: registrationResult.verified,
        registrationInfo: registrationResult.registration_info,
        logs: registrationResult.logs
      }
    });

  } catch (error: any) {
    console.error('[signer-worker]: Registration with PRF failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_FAILURE,
      payload: { error: error.message || 'Registration with PRF failed' }
    });
  }
}

/**
 * Handle checking if user can register (view function)
 * Calls verify_can_register_user on the contract to check eligibility
 */
async function handleCheckCanRegisterUser(
  payload: any // CheckCanRegisterUserRequest['payload']
): Promise<void> {
  try {
    const {
      vrfChallenge,
      webauthnCredential,
      contractId,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting check if user can register (view function)');

    // Validate required parameters
    if (!vrfChallenge || !webauthnCredential || !contractId || !nearRpcUrl) {
      throw new Error('Missing required parameters for registration check: vrfChallenge, webauthnCredential, contractId, nearRpcUrl');
    }

    console.log('[signer-worker]: Calling check_can_register_user function');

    // Call the WASM function that handles registration eligibility check
    const checkResultJson = await check_can_register_user(
      contractId,
      JSON.stringify(vrfChallenge),
      JSON.stringify(webauthnCredential),
      nearRpcUrl
    );

    // Parse the result
    const checkResult = JSON.parse(checkResultJson);
    console.log('[signer-worker]: Registration check result:', {
      verified: checkResult.verified,
      hasRegistrationInfo: !!checkResult.registration_info
    });

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: checkResult.verified,
        registrationInfo: checkResult.registration_info,
        logs: checkResult.logs
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
 * Calls verify_and_register_user on the contract via send_tx to actually register
 */
async function handleVerifyAndRegisterUser(
  payload: any // VerifyAndRegisterUserRequest['payload']
): Promise<void> {
  try {
    const {
      vrfChallenge,
      webauthnCredential,
      contractId,
      nearRpcUrl,
      signerAccountId,
      nearAccountId,
      nonce,
      blockHashBytes
    } = payload;

    console.log('[signer-worker]: Starting actual user registration (state-changing function)');

    // Validate required parameters
    if (!vrfChallenge || !webauthnCredential || !contractId || !nearRpcUrl || !signerAccountId || !nearAccountId || !nonce || !blockHashBytes) {
      throw new Error('Missing required parameters for actual registration: vrfChallenge, webauthnCredential, contractId, nearRpcUrl, signerAccountId, nearAccountId, nonce, blockHashBytes');
    }

    // Get encrypted key data for the account
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Extract PRF output from credential
    const prfOutput = webauthnCredential.clientExtensionResults?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure registration');
    }

    console.log('[signer-worker]: Calling verify_and_register_user function with transaction metadata');

    // Call the WASM function that handles actual registration (send_tx)
    const registrationResultJson = await verify_and_register_user(
      contractId,
      JSON.stringify(vrfChallenge),
      JSON.stringify(webauthnCredential),
      nearRpcUrl,
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
      hasRegistrationInfo: !!registrationResult.registration_info
    });

    if (!registrationResult.verified) {
      throw new Error('Actual registration verification failed');
    }

    sendResponseAndTerminate({
      type: WorkerResponseType.REGISTRATION_SUCCESS,
      payload: {
        verified: registrationResult.verified,
        registrationInfo: registrationResult.registration_info,
        logs: registrationResult.logs
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
      webauthnCredential,
      nearRpcUrl
    } = payload;

    console.log('[signer-worker]: Starting enhanced verify and sign with pure WASM implementation');

    // Validate required parameters
    if (!nearAccountId || !receiverId || !actions || !nonce || !blockHashBytes) {
      throw new Error('Missing required transaction parameters');
    }
    if (!contractId || !vrfChallenge || !webauthnCredential || !nearRpcUrl) {
      throw new Error('Missing required verification parameters');
    }

    // Get encrypted key data for the account
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Extract PRF output using the method you wanted
    if (!webauthnCredential.clientExtensionResults?.prf?.results?.first) {
      throw new Error('PRF output missing from credential.extensionResults: required for secure key decryption');
    }
    console.log('[signer-worker]: PRF output extracted via getClientExtensionResults()');

    let { credentialWithoutPrf, prfOutput } = takePrfOutputFromCredential(webauthnCredential);

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
      webauthnCredential,
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
    if (!contractId || !vrfChallenge || !webauthnCredential || !nearRpcUrl) {
      throw new Error('All verification parameters are required: contractId, vrfChallenge, webauthnCredential, nearRpcUrl');
    }

    // Get PRF output from serialized credential (extracted in main thread with minimal exposure)
    console.log('[signer-worker]: Getting PRF output from serialized credential');
    const prfOutput = webauthnCredential.clientExtensionResults?.prf?.results?.first;
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
        JSON.stringify(webauthnCredential),
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

// === ERROR HANDLING ===
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