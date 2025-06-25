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
  type ValidateCoseKeyRequest
} from './types/worker.js';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from './IndexedDBManager/passkeyNearKeysDB.js';

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
  // Key exports/decryption
  decrypt_private_key_with_prf_as_string,
  // Transaction signing
  sign_near_transaction_with_actions,
  sign_near_transfer_transaction,
  // COSE keys
  extract_cose_public_key_from_attestation,
  validate_cose_key_format,
} = wasmModule;

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

      case WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF:
        await handleDecryptPrivateKeyWithPrf(payload);
        break;

      case WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS:
        await handleSignTransactionWithActions(payload);
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

// === NEW ACTION-BASED TRANSACTION SIGNING HANDLERS ===

/**
 * Handle signing a NEAR transaction with multiple actions
 * @param payload - The transaction signing request payload
 * @param payload.nearAccountId - NEAR account ID whose key should be used for signing
 * @param payload.prfOutput - Base64-encoded PRF output from WebAuthn assertion
 * @param payload.receiverId - Receiver account ID for the transaction
 * @param payload.actions - Array of actions to include in the transaction
 * @param payload.nonce - Transaction nonce as string
 * @param payload.blockHashBytes - Block hash bytes for the transaction
 * @returns Promise that resolves when signing is complete
 */
async function handleSignTransactionWithActions(
  payload: SignTransactionWithActionsRequest['payload']
): Promise<void> {
  try {
    const { nearAccountId, prfOutput, receiverId, actions, nonce, blockHashBytes } = payload;

    // actions comes as a JSON string from webauthn-workers.ts
    const actionsStr = typeof actions === 'string' ? actions : JSON.stringify(actions);

    console.log('[signer-worker]: Starting multi-action transaction signing');
    console.log('[signer-worker]: Actions to process:', actionsStr);

    // Validate all required parameters are defined
    const requiredFields = ['nearAccountId', 'receiverId', 'actions', 'nonce'];
    const missingFields = requiredFields.filter(field => !payload[field as keyof typeof payload]);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields for multi-action transaction signing: ${missingFields.join(', ')}`);
    }
    if (!blockHashBytes || blockHashBytes.length === 0) {
      throw new Error('blockHashBytes is required and cannot be empty');
    }
    if (!prfOutput || prfOutput.length === 0) {
      throw new Error('PRF output is required and cannot be empty');
    }

    console.log('[signer-worker]: Getting encrypted key data for account:', nearAccountId);
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    console.log('[signer-worker]: Using new multi-action WASM function');
    // Call the new WASM function for multi-action signing
    const signedTransactionBorsh = sign_near_transaction_with_actions(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      nearAccountId,
      receiverId,
      BigInt(nonce),
      new Uint8Array(blockHashBytes),
      actionsStr // actions as JSON string
    );

    console.log('[signer-worker]: Multi-action transaction signing completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(signedTransactionBorsh),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('[signer-worker]: Multi-action transaction signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Multi-action transaction signing failed' }
    });
  }
}

/**
 * Handle Transfer transaction signing with PRF
 * @param payload - The transaction signing request payload
 * @param payload.nearAccountId - NEAR account ID whose key should be used for signing
 * @param payload.prfOutput - Base64-encoded PRF output from WebAuthn assertion
 * @param payload.receiverId - Receiver account ID for the transaction
 * @param payload.depositAmount - Deposit amount in string format
 * @param payload.nonce - Transaction nonce as string
 * @param payload.blockHashBytes - Block hash bytes for the transaction
 * @returns Promise that resolves when signing is complete
 */
async function handleSignTransferTransaction(
  payload: SignTransferTransactionRequest['payload']
): Promise<void> {
  try {
    const { nearAccountId, prfOutput, receiverId, depositAmount, nonce, blockHashBytes } = payload;
    console.log('[signer-worker]: Starting Transfer transaction signing');
    console.log('[signer-worker]: Transfer amount:', depositAmount);

    // Validate all required parameters
    const requiredFields = ['nearAccountId', 'receiverId', 'depositAmount', 'nonce'];
    const missingFields = requiredFields.filter(field => !payload[field as keyof typeof payload]);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields for transfer transaction signing: ${missingFields.join(', ')}`);
    }
    if (!blockHashBytes || blockHashBytes.length === 0) {
      throw new Error('blockHashBytes is required and cannot be empty');
    }
    if (!prfOutput || prfOutput.length === 0) {
      throw new Error('PRF output is required and cannot be empty');
    }

    console.log('[signer-worker]: Getting encrypted key data for account:', nearAccountId);
    const encryptedKeyData = await nearKeysDB.getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    console.log('[signer-worker]: Using new transfer WASM function');
    // Call the new WASM function for transfer signing
    const signedTransactionBorsh = sign_near_transfer_transaction(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      nearAccountId,
      receiverId,
      depositAmount,
      BigInt(nonce),
      new Uint8Array(blockHashBytes)
    );

    console.log('[signer-worker]: Transfer transaction signing completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(signedTransactionBorsh),
        nearAccountId
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

// === EXPORTS ===
export type {
  WorkerRequest,
  WorkerResponse,
  DeriveNearKeypairAndEncryptRequest,
  DecryptPrivateKeyWithPrfRequest,
  ExtractCosePublicKeyRequest,
  ValidateCoseKeyRequest
};