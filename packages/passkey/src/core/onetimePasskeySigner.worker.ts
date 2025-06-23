import { KeyPair, type KeyPairString } from '@near-js/crypto';
import { serialize } from 'borsh';
import {
  SCHEMA,
  SignedTransaction,
  createTransaction,
  Action,
  Signature
} from '@near-js/transactions';
import { sha256 } from 'js-sha256';

// Import WASM binary directly
import init, * as wasmModule from '../wasm-signer-worker/web3authn_passkey_worker.js';

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
} from './types/worker';

// Buffer polyfill for Web Workers
// Workers don't inherit main thread polyfills - they run in an isolated environment
// without access to Node.js globals like Buffer that bundlers typically provide.
// Manual polyfill is required for NEAR crypto operations that depend on Buffer.
import { Buffer } from 'buffer';
// @ts-ignore
globalThis.Buffer = Buffer;

// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('./web3authn_passkey_worker_bg.wasm', import.meta.url);

// === CONSTANTS ===
const WASM_CACHE_NAME = 'passkey-wasm-v1';
const DB_NAME = 'PasskeyNearKeys';
const DB_VERSION = 1;
const STORE_NAME = 'encryptedKeys';
const HKDF_INFO = 'near-key-encryption';
const HKDF_SALT = '';

// === WASM MODULE FUNCTIONS ===
const {
  encrypt_data_aes_gcm,
  decrypt_data_aes_gcm,
  derive_encryption_key_from_prf,
  generate_and_encrypt_near_keypair_with_prf,
  extract_cose_public_key_from_attestation,
  validate_cose_key_format
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

  const decryptionKey = derive_encryption_key_from_prf(prfOutput, HKDF_INFO, HKDF_SALT);
  console.log('WORKER: decryptionKey derived, type:', typeof decryptionKey);

  const decryptedKey = decrypt_data_aes_gcm(
    encryptedKeyData.encryptedData,
    encryptedKeyData.iv,
    decryptionKey
  );
  console.log('WORKER: decryptedKey result, type:', typeof decryptedKey);

  // Handle both cases: full "ed25519:..." format or just base58
  if (decryptedKey.startsWith('ed25519:')) {
    console.log('WORKER: Key already has ed25519 prefix');
    return decryptedKey; // Already has the prefix
  } else {
    console.log('WORKER: Adding ed25519 prefix to key');
    return `ed25519:${decryptedKey}`; // Add the prefix
  }
}

/**
 * Decrypt private key from stored data and return as KeyPair
 */
function decryptPrivateKey(
  encryptedKeyData: EncryptedKeyData,
  prfOutput: string
): KeyPair {
  console.log('WORKER: decryptPrivateKey - Starting...');
  const decryptedPrivateKeyString = decryptPrivateKeyString(encryptedKeyData, prfOutput);
  console.log('WORKER: decryptedPrivateKeyString result, type:', typeof decryptedPrivateKeyString);
  console.log('WORKER: decryptedPrivateKeyString length:', decryptedPrivateKeyString?.length);

  console.log('WORKER: Creating KeyPair from string...');
  const keyPair = KeyPair.fromString(decryptedPrivateKeyString as KeyPairString);
  console.log('WORKER: KeyPair created successfully, type:', typeof keyPair);

  return keyPair;
}

/**
 * Create NEAR transaction from parameters
 */
function createNearTransaction(
  nearAccountId: string,
  keyPair: KeyPair,
  payload: DecryptAndSignTransactionWithPrfRequest['payload']
): any {
  const { receiverId, contractMethodName, contractArgs, gasAmount, depositAmount, nonce, blockHashBytes } = payload;

  console.log('WORKER: Creating NEAR transaction with blockHashBytes:', {
    type: typeof blockHashBytes,
    isArray: Array.isArray(blockHashBytes),
    length: blockHashBytes?.length,
    sample: blockHashBytes?.slice(0, 5) // Show first 5 bytes for debugging
  });

  // Defensive validation of blockHashBytes before Buffer.from()
  if (!blockHashBytes || !Array.isArray(blockHashBytes) || blockHashBytes.length === 0) {
    throw new Error(`Invalid blockHashBytes for transaction creation: ${typeof blockHashBytes}, length: ${blockHashBytes?.length}`);
  }

  const actions: Action[] = [
    ({
      functionCall: {
        methodName: contractMethodName,
        args: Buffer.from(JSON.stringify(contractArgs)),
        gas: BigInt(gasAmount),
        deposit: BigInt(depositAmount)
      }
    } as any)
  ];

  try {
    const blockHashBuffer = Buffer.from(blockHashBytes);
    console.log('WORKER: Block hash buffer created successfully:', blockHashBuffer.length, 'bytes');

    return createTransaction(
      nearAccountId,
      keyPair.getPublicKey(),
      receiverId,
      BigInt(nonce),
      actions,
      blockHashBuffer
    );
  } catch (error: any) {
    console.error('WORKER: Failed to create block hash buffer:', error);
    throw new Error(`Failed to create block hash buffer: ${error.message}`);
  }
}

/**
 * Sign transaction and create signed transaction
 */
function signTransaction(transaction: any, keyPair: KeyPair): Uint8Array {
  const serializedTx = serialize(SCHEMA.Transaction, transaction);
  const hash = new Uint8Array(sha256.array(serializedTx));
  const signatureFromKeyPair = keyPair.sign(hash);

  const nearSignature = new Signature({
    keyType: keyPair.getPublicKey().keyType,
    data: signatureFromKeyPair.signature
  });

  const signedTransaction = new SignedTransaction({
    transaction,
    signature: nearSignature
  });

  return serialize(SCHEMA.SignedTransaction, signedTransaction);
}

/**
 * Handle transaction decryption and signing with PRF
 */
async function handleDecryptAndSignTransactionWithPrf(
  payload: DecryptAndSignTransactionWithPrfRequest['payload']
): Promise<void> {
  try {
    const { nearAccountId, prfOutput } = payload;

    // Validate payload data before processing
    console.log('WORKER: Validating payload data...');
    console.log('WORKER: Payload keys:', Object.keys(payload));
    console.log('WORKER: blockHashBytes type:', typeof payload.blockHashBytes);
    console.log('WORKER: blockHashBytes length:', payload.blockHashBytes?.length);
    console.log('WORKER: blockHashBytes value:', payload.blockHashBytes);

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

    console.log('WORKER: Step 1 - Getting encrypted key data...');
    const encryptedKeyData = await getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }
    console.log('WORKER: Step 1 completed - Encrypted key data retrieved');

    console.log('WORKER: Step 2 - Decrypting private key...');
    const keyPair = decryptPrivateKey(encryptedKeyData, prfOutput);
    console.log('WORKER: Step 2 completed - Private key decrypted, keyPair type:', typeof keyPair);

    console.log('WORKER: Step 3 - Creating NEAR transaction...');
    const transaction = createNearTransaction(nearAccountId, keyPair, payload);
    console.log('WORKER: Step 3 completed - Transaction created, transaction type:', typeof transaction);

    console.log('WORKER: Step 4 - Signing transaction...');
    const serializedSignedTx = signTransaction(transaction, keyPair);
    console.log('WORKER: Step 4 completed - Transaction signed, serialized length:', serializedSignedTx.length);

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(serializedSignedTx),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: Signing failed:', error.message);
    console.error('WORKER: Error stack:', error.stack);
    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_FAILURE,
      payload: { error: error.message || 'PRF decryption/signing failed' }
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