// WASM-only transaction signing worker
// This worker handles all NEAR transaction operations using WASM functions only.

// Import WASM binary directly
import init, * as wasmModule from '../wasm_signer_worker/wasm_signer_worker.js';

import {
  WorkerRequestType,
  WorkerResponseType,
  type WorkerRequest,
  type WorkerResponse,
  type EncryptPrivateKeyWithPrfRequest,
  type DecryptAndSignTransactionWithPrfRequest,
  type DecryptPrivateKeyWithPrfRequest,
  type ExtractCosePublicKeyRequest,
  type ValidateCoseKeyRequest
} from './types/worker.js';

// Buffer polyfill for Web Workers
// Workers don't inherit main thread polyfills - they run in an isolated environment
// without access to Node.js globals like Buffer that bundlers typically provide.
// Manual polyfill is required for NEAR crypto operations that depend on Buffer.
import { Buffer } from 'buffer';
// @ts-ignore
globalThis.Buffer = Buffer;

// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('./wasm_signer_worker_bg.wasm', import.meta.url);

// === CONSTANTS ===
const WASM_CACHE_NAME = 'passkey-wasm-v1';
const DB_NAME = 'PasskeyNearKeys';
const DB_VERSION = 1;
const STORE_NAME = 'encryptedKeys';

// === WASM MODULE FUNCTIONS ===
const {
  encrypt_data_aes_gcm,
  decrypt_data_aes_gcm,
  derive_encryption_key_from_prf,
  generate_and_encrypt_near_keypair_with_prf,
  extract_cose_public_key_from_attestation,
  validate_cose_key_format,
  sign_near_transaction_with_actions,
  sign_transfer_transaction_with_prf,
  sign_transaction_with_encrypted_key, // Legacy transaction signing function
  decrypt_private_key_with_prf_as_string // New WASM function for private key decryption
} = wasmModule;

// === UTILITY FUNCTIONS ===

/**
 * Initialize WASM module with caching support
 */
async function initializeWasmWithCache(): Promise<void> {
  try {
    console.log('WORKER: Starting WASM initialization...', {
      wasmUrl: wasmUrl.href,
      userAgent: navigator.userAgent,
      currentUrl: self.location.href
    });

    const cache = await caches.open(WASM_CACHE_NAME);
    const cachedResponse = await cache.match(wasmUrl.href);

    if (cachedResponse) {
      console.log('WORKER: Using cached WASM module');
      const wasmModule = await WebAssembly.compileStreaming(cachedResponse.clone());
      await init({ module: wasmModule });
      console.log('WORKER: WASM initialized successfully from cache');
      return;
    }

    console.log('WORKER: Fetching fresh WASM module from:', wasmUrl.href);
    const response = await fetch(wasmUrl.href);

    if (!response.ok) {
      throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`);
    }

    console.log('WORKER: WASM fetch successful, content-type:', response.headers.get('content-type'));
    const responseToCache = response.clone();
    const wasmModule = await WebAssembly.compileStreaming(response);

    await cache.put(wasmUrl.href, responseToCache);
    await init({ module: wasmModule });
    console.log('WORKER: WASM initialized successfully from fresh fetch');
  } catch (error: any) {
    console.error('WORKER: WASM initialization failed, using fallback:', error);
    console.error('WORKER: Error details:', {
      name: error?.name,
      message: error?.message,
      stack: error?.stack
    });

    try {
      console.log('WORKER: Attempting fallback WASM initialization...');
    await init();
      console.log('WORKER: Fallback WASM initialization successful');
    } catch (fallbackError: any) {
      console.error('WORKER: Fallback WASM initialization also failed:', fallbackError);
      throw new Error(`WASM initialization failed: ${error?.message || 'Unknown error'}. Fallback also failed: ${fallbackError?.message || 'Unknown fallback error'}`);
    }
  }
}

/**
 * Send response message and terminate worker
 */
function sendResponseAndTerminate(response: WorkerResponse): void {
  self.postMessage(response);
  self.close();
}

/**
 * Create error response
 */
function createErrorResponse(error: string): WorkerResponse {
  return {
    type: WorkerResponseType.ERROR,
    payload: { error }
  };
}

/**
 * Parse WASM result with proper typing
 */
function parseWasmResult(resultJson: string | object): WasmResult {
  console.log('WORKER: parseWasmResult - Input type:', typeof resultJson);
  console.log('WORKER: parseWasmResult - Input value:', resultJson);

  const result = typeof resultJson === 'string' ? JSON.parse(resultJson) : resultJson;
  console.log('WORKER: parseWasmResult - Parsed result:', result);
  console.log('WORKER: parseWasmResult - Parsed result keys:', result ? Object.keys(result) : 'undefined');

  const encryptedPrivateKey = typeof result.encryptedPrivateKey === 'string'
    ? JSON.parse(result.encryptedPrivateKey)
    : result.encryptedPrivateKey;

  console.log('WORKER: parseWasmResult - encryptedPrivateKey processing:');
  console.log('  - result.encryptedPrivateKey type:', typeof result.encryptedPrivateKey);
  console.log('  - result.encryptedPrivateKey value:', result.encryptedPrivateKey);
  console.log('  - Final encryptedPrivateKey:', encryptedPrivateKey);
  console.log('  - Final encryptedPrivateKey keys:', encryptedPrivateKey ? Object.keys(encryptedPrivateKey) : 'undefined');

  const finalResult = {
    publicKey: result.publicKey,
    encryptedPrivateKey
  };

  console.log('WORKER: parseWasmResult - Final result:', finalResult);

  return finalResult;
}

// === TYPE DEFINITIONS ===

interface EncryptedKeyData {
  nearAccountId: string;
  encryptedData: string;
  iv: string;
  timestamp: number;
}

interface WasmResult {
  publicKey: string;
  encryptedPrivateKey: any;
}

// === INDEXEDDB OPERATIONS ===

const KEY_PATH = 'nearAccountId';

/**
 * Open IndexedDB connection
 */
async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: KEY_PATH });
      }
    };
  });
}

/**
 * Store encrypted key data
 */
async function storeEncryptedKey(data: EncryptedKeyData): Promise<void> {
  const db = await openDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.put(data);

    request.onsuccess = () => {
      db.close();
      resolve();
    };

    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/**
 * Retrieve encrypted key data
 */
async function getEncryptedKey(nearAccountId: string): Promise<EncryptedKeyData | null> {
  console.log('WORKER: getEncryptedKey - Retrieving for account:', nearAccountId);

  const db = await openDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.get(nearAccountId);

    request.onsuccess = () => {
      const result = request.result;
      console.log('WORKER: getEncryptedKey - Raw result:', result);
      console.log('WORKER: getEncryptedKey - Result type:', typeof result);

      if (result) {
        console.log('WORKER: getEncryptedKey - Result keys:', Object.keys(result));
        console.log('WORKER: getEncryptedKey - encryptedData type:', typeof result.encryptedData);
        console.log('WORKER: getEncryptedKey - encryptedData value:', result.encryptedData);
        console.log('WORKER: getEncryptedKey - iv type:', typeof result.iv);
        console.log('WORKER: getEncryptedKey - iv value:', result.iv);
      } else {
        console.log('WORKER: getEncryptedKey - No result found');
      }

      db.close();
      resolve(result || null);
    };

    request.onerror = () => {
      console.error('WORKER: getEncryptedKey - Error:', request.error);
      db.close();
      reject(request.error);
    };
  });
}

/**
 * Verify key storage by attempting retrieval
 */
async function verifyKeyStorage(nearAccountId: string): Promise<boolean> {
  try {
    const retrievedKey = await getEncryptedKey(nearAccountId);
    return !!retrievedKey;
  } catch {
    return false;
  }
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

  console.log('WORKER: Received message:', { type, payload: { ...payload, prfOutput: '[REDACTED]' } });

  try {
    console.log('WORKER: Starting WASM initialization...');
    await initializeWasmWithCache();
    console.log('WORKER: WASM initialization completed, processing message...');

    switch (type) {
      case WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF:
        await handleEncryptPrivateKeyWithPrf(payload);
        break;

      case WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF:
        await handleDecryptAndSignTransactionWithPrf(payload);
        break;

      case WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF:
        await handleDecryptPrivateKeyWithPrf(payload);
        break;

      case WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY:
        await handleExtractCosePublicKey(payload);
        break;

      case WorkerRequestType.VALIDATE_COSE_KEY:
        await handleValidateCoseKey(payload);
        break;

      case WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS:
        await handleSignTransactionWithActions(payload);
        break;

      case WorkerRequestType.SIGN_TRANSFER_TRANSACTION:
        await handleSignTransferTransaction(payload);
        break;

      default:
        sendResponseAndTerminate(createErrorResponse(`Unknown message type: ${type}`));
    }
  } catch (error: any) {
    console.error('WORKER: Message processing failed:', {
      error: error?.message || 'Unknown error',
      stack: error?.stack,
      name: error?.name,
      type,
      workerLocation: self.location.href
    });
    sendResponseAndTerminate(createErrorResponse(error?.message || 'Unknown error occurred'));
  }
};

// === ENCRYPTION WORKFLOW ===

/**
 * Generate and encrypt NEAR keypair using PRF
 */
async function generateAndEncryptKeypair(
  prfOutput: string,
  nearAccountId: string
): Promise<{ publicKey: string; keyData: EncryptedKeyData }> {
  console.log('WORKER: generateAndEncryptKeypair - Starting...');
  console.log('WORKER: prfOutput type:', typeof prfOutput);
  console.log('WORKER: nearAccountId:', nearAccountId);

  const resultJson = generate_and_encrypt_near_keypair_with_prf(prfOutput);
  console.log('WORKER: WASM result type:', typeof resultJson);
  console.log('WORKER: WASM result raw:', resultJson);

  const { publicKey, encryptedPrivateKey } = parseWasmResult(resultJson);
  console.log('WORKER: parseWasmResult output:');
  console.log('  - publicKey type:', typeof publicKey);
  console.log('  - publicKey value:', publicKey);
  console.log('  - encryptedPrivateKey type:', typeof encryptedPrivateKey);
  console.log('  - encryptedPrivateKey keys:', encryptedPrivateKey ? Object.keys(encryptedPrivateKey) : 'undefined');
  console.log('  - encryptedPrivateKey.encrypted_near_key_data_b64u:', encryptedPrivateKey?.encrypted_near_key_data_b64u);
  console.log('  - encryptedPrivateKey.aes_gcm_nonce_b64u:', encryptedPrivateKey?.aes_gcm_nonce_b64u);

  const keyData: EncryptedKeyData = {
    nearAccountId,
    encryptedData: encryptedPrivateKey.encrypted_near_key_data_b64u,
    iv: encryptedPrivateKey.aes_gcm_nonce_b64u,
    timestamp: Date.now()
  };

  console.log('WORKER: Final keyData being stored:');
  console.log('  - nearAccountId:', keyData.nearAccountId);
  console.log('  - encryptedData type:', typeof keyData.encryptedData);
  console.log('  - encryptedData value:', keyData.encryptedData);
  console.log('  - iv type:', typeof keyData.iv);
  console.log('  - iv value:', keyData.iv);

  return { publicKey, keyData };
}

/**
 * Handle private key encryption with PRF
 */
async function handleEncryptPrivateKeyWithPrf(
  payload: EncryptPrivateKeyWithPrfRequest['payload']
): Promise<void> {
  try {
    const { prfOutput, nearAccountId } = payload;
    const { publicKey, keyData } = await generateAndEncryptKeypair(prfOutput, nearAccountId);

    await storeEncryptedKey(keyData);

    const verified = await verifyKeyStorage(nearAccountId);
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
    console.error('WORKER: Encryption failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.ENCRYPTION_FAILURE,
      payload: { error: error.message || 'PRF encryption failed' }
    });
  }
}

// === DECRYPTION AND SIGNING WORKFLOW ===

/**
 * Decrypt private key from stored data and return as string
 * NOTE: This is kept for the DECRYPT_PRIVATE_KEY_WITH_PRF operation only
 */
function decryptPrivateKeyString(
  encryptedKeyData: EncryptedKeyData,
  prfOutput: string
): string {
  console.log('WORKER: decryptPrivateKeyString - Starting...');
  console.log('WORKER: encryptedKeyData keys:', Object.keys(encryptedKeyData));
  console.log('WORKER: encryptedKeyData.encryptedData type:', typeof encryptedKeyData.encryptedData);
  console.log('WORKER: encryptedKeyData.iv type:', typeof encryptedKeyData.iv);
  console.log('WORKER: prfOutput type:', typeof prfOutput);

  // Use WASM function for decryption - handles all key derivation and formatting
  try {
    const decryptedKey = decrypt_private_key_with_prf_as_string(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv
    );
    console.log('WORKER: WASM decryption successful, type:', typeof decryptedKey);
    return decryptedKey;
  } catch (error) {
    console.error('WORKER: WASM decryption failed:', error);
    throw new Error(`Private key decryption failed: ${error}`);
  }
}

/**
 * Handle transaction decryption and signing with PRF using WASM-only implementation
 */
async function handleDecryptAndSignTransactionWithPrf(
  payload: DecryptAndSignTransactionWithPrfRequest['payload']
): Promise<void> {
  try {
    const {
      nearAccountId,
      prfOutput,
      receiverId,
      contractMethodName,
      contractArgs,
      gasAmount,
      depositAmount,
      nonce,
      blockHashBytes
    } = payload;

    // Validate payload data before processing
    console.log('WORKER: Validating payload data...');
    console.log('WORKER: Payload keys:', Object.keys(payload));
    console.log('WORKER: blockHashBytes type:', typeof blockHashBytes);
    console.log('WORKER: blockHashBytes length:', blockHashBytes?.length);

    // Validate required fields
    const requiredFields = ['nearAccountId', 'prfOutput', 'receiverId', 'contractMethodName', 'contractArgs', 'gasAmount', 'depositAmount', 'nonce', 'blockHashBytes'];
    const missingFields = requiredFields.filter(field => !payload[field as keyof typeof payload]);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields in worker payload: ${missingFields.join(', ')}`);
    }

    // Specifically validate blockHashBytes
    if (!payload.blockHashBytes || !Array.isArray(payload.blockHashBytes) || payload.blockHashBytes.length === 0) {
      throw new Error(`Invalid blockHashBytes in worker payload: ${typeof payload.blockHashBytes}, length: ${payload.blockHashBytes?.length}`);
    }

    console.log('WORKER: Payload validation successful');

    console.log('WORKER: Getting encrypted key data...');
    const encryptedKeyData = await getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }
    console.log('WORKER: Encrypted key data retrieved');

    // Prepare encrypted key data as JSON for WASM function
    const encryptedKeyJson = JSON.stringify({
      encrypted_near_key_data_b64u: encryptedKeyData.encryptedData,
      aes_gcm_nonce_b64u: encryptedKeyData.iv
    });

    console.log('WORKER: Using WASM-only transaction signing...');
    // Use WASM function directly - handles decryption, transaction creation, and signing
    const signedTransactionBorsh = sign_transaction_with_encrypted_key(
      prfOutput, // PRF output for decryption
      encryptedKeyJson, // Encrypted key data as JSON
      nearAccountId, // Signer account ID
      receiverId, // Receiver account ID
      contractMethodName, // Contract method name
      JSON.stringify(contractArgs), // Contract arguments as JSON string
      gasAmount, // Gas amount as string
      depositAmount, // Deposit amount as string
      BigInt(nonce), // Nonce as number
      new Uint8Array(blockHashBytes) // Block hash as Uint8Array
    );

    console.log('WORKER: WASM transaction signing completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(signedTransactionBorsh),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: WASM signing failed:', error.message);
    console.error('WORKER: Error stack:', error.stack);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'WASM transaction signing failed' }
    });
  }
}

/**
 * Handle private key decryption with PRF
 */
async function handleDecryptPrivateKeyWithPrf(
  payload: DecryptPrivateKeyWithPrfRequest['payload']
): Promise<void> {
  try {
    const { nearAccountId, prfOutput } = payload;

    const encryptedKeyData = await getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    // Encrypted data is already raw base64, no prefix stripping needed
    const decryptedPrivateKey = decryptPrivateKeyString(encryptedKeyData, prfOutput);

    sendResponseAndTerminate({
      type: WorkerResponseType.DECRYPTION_SUCCESS,
      payload: {
        decryptedPrivateKey,
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: Decryption failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.DECRYPTION_FAILURE,
      payload: { error: error.message || 'PRF decryption failed' }
    });
  }
}

// === COSE KEY EXTRACTION WORKFLOW ===

/**
 * Handle COSE public key extraction from attestation object
 */
async function handleExtractCosePublicKey(
  payload: ExtractCosePublicKeyRequest['payload']
): Promise<void> {
  try {
    const { attestationObjectBase64url } = payload;

    console.log('WORKER: Extracting COSE public key from attestation object');

    // Call the WASM function to extract COSE public key
    const cosePublicKeyBytes = extract_cose_public_key_from_attestation(attestationObjectBase64url);

    console.log('WORKER: Successfully extracted COSE public key:', cosePublicKeyBytes.length, 'bytes');

    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_KEY_SUCCESS,
      payload: {
        cosePublicKeyBytes: Array.from(cosePublicKeyBytes)
      }
    });
  } catch (error: any) {
    console.error('WORKER: COSE key extraction failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_KEY_FAILURE,
      payload: { error: error.message || 'COSE key extraction failed' }
    });
  }
}

/**
 * Handle COSE key format validation
 */
async function handleValidateCoseKey(
  payload: ValidateCoseKeyRequest['payload']
): Promise<void> {
  try {
    const { coseKeyBytes } = payload;

    console.log('WORKER: Validating COSE key format for key bytes:', coseKeyBytes.length);

    // Call the WASM function to validate COSE key format
    const validationResult = validate_cose_key_format(new Uint8Array(coseKeyBytes));
    const validationInfo = JSON.parse(validationResult);

    console.log('WORKER: COSE key validation result:', validationInfo);

    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_VALIDATION_SUCCESS,
      payload: {
        valid: validationInfo.valid,
        info: validationInfo
      }
    });
  } catch (error: any) {
    console.error('WORKER: COSE key validation failed:', error.message);
    sendResponseAndTerminate({
      type: WorkerResponseType.COSE_VALIDATION_FAILURE,
      payload: { error: error.message || 'COSE key validation failed' }
    });
  }
}

// === NEW ACTION-BASED SIGNING HANDLERS ===

/**
 * Handle multi-action transaction signing with PRF
 */
async function handleSignTransactionWithActions(
  payload: any // SignTransactionWithActionsRequest['payload'] - using any to avoid circular imports
): Promise<void> {
  try {
    const { nearAccountId, prfOutput, receiverId, actions, nonce, blockHashBytes } = payload;

    console.log('WORKER: Starting multi-action transaction signing');
    console.log('WORKER: Actions to process:', actions);

    // Validate all required parameters are defined
    const requiredFields = ['nearAccountId', 'receiverId', 'actions', 'nonce'];
    const missingFields = requiredFields.filter(field => !payload[field]);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields for multi-action transaction signing: ${missingFields.join(', ')}`);
    }

    if (!blockHashBytes || blockHashBytes.length === 0) {
      throw new Error('blockHashBytes is required and cannot be empty');
    }

    if (!prfOutput || prfOutput.length === 0) {
      throw new Error('PRF output is required and cannot be empty');
    }

    console.log('WORKER: Getting encrypted key data for account:', nearAccountId);
    const encryptedKeyData = await getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    console.log('WORKER: Using new multi-action WASM function');
    // Call the new WASM function for multi-action signing
    const signedTransactionBorsh = sign_near_transaction_with_actions(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      nearAccountId,
      receiverId,
      BigInt(nonce),
      new Uint8Array(blockHashBytes),
      actions // actions JSON string
    );

    console.log('WORKER: Multi-action transaction signing completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(signedTransactionBorsh),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: Multi-action transaction signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Multi-action transaction signing failed' }
    });
  }
}

/**
 * Handle Transfer transaction signing with PRF
 */
async function handleSignTransferTransaction(
  payload: any // SignTransferTransactionRequest['payload'] - using any to avoid circular imports
): Promise<void> {
  try {
    const { nearAccountId, prfOutput, receiverId, depositAmount, nonce, blockHashBytes } = payload;

    console.log('WORKER: Starting Transfer transaction signing');
    console.log('WORKER: Transfer amount:', depositAmount);

    // Validate all required parameters
    const requiredFields = ['nearAccountId', 'receiverId', 'depositAmount', 'nonce'];
    const missingFields = requiredFields.filter(field => !payload[field]);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields for transfer transaction signing: ${missingFields.join(', ')}`);
    }

    if (!blockHashBytes || blockHashBytes.length === 0) {
      throw new Error('blockHashBytes is required and cannot be empty');
    }

    if (!prfOutput || prfOutput.length === 0) {
      throw new Error('PRF output is required and cannot be empty');
    }

    console.log('WORKER: Getting encrypted key data for account:', nearAccountId);
    const encryptedKeyData = await getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    console.log('WORKER: Using new transfer WASM function');
    // Call the new WASM function for transfer signing
    const signedTransactionBorsh = sign_transfer_transaction_with_prf(
      prfOutput,
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      nearAccountId,
      receiverId,
      depositAmount,
      BigInt(nonce),
      new Uint8Array(blockHashBytes)
    );

    console.log('WORKER: Transfer transaction signing completed successfully');

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(signedTransactionBorsh),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: Transfer transaction signing failed:', error);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'Transfer transaction signing failed' }
    });
  }
}

// === EXPORTS ===
export type {
  WorkerRequest,
  WorkerResponse,
  EncryptPrivateKeyWithPrfRequest,
  DecryptAndSignTransactionWithPrfRequest,
  DecryptPrivateKeyWithPrfRequest,
  ExtractCosePublicKeyRequest,
  ValidateCoseKeyRequest
};