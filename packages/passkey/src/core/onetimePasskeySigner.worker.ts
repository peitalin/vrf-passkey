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
import init, * as wasmModule from '../wasm-worker/passkey_crypto_worker.js';

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
const wasmUrl = new URL('./passkey_crypto_worker_bg.wasm', import.meta.url);

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
  const result = typeof resultJson === 'string' ? JSON.parse(resultJson) : resultJson;

  const encryptedPrivateKey = typeof result.encryptedPrivateKey === 'string'
    ? JSON.parse(result.encryptedPrivateKey)
    : result.encryptedPrivateKey;

  return {
    publicKey: result.publicKey,
    encryptedPrivateKey
  };
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
  const db = await openDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.get(nearAccountId);

    request.onsuccess = () => {
      db.close();
      resolve(request.result || null);
    };

    request.onerror = () => {
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
  const resultJson = generate_and_encrypt_near_keypair_with_prf(prfOutput);
  const { publicKey, encryptedPrivateKey } = parseWasmResult(resultJson);

  const keyData: EncryptedKeyData = {
    nearAccountId,
    encryptedData: encryptedPrivateKey.encrypted_data_b64u,
    iv: encryptedPrivateKey.iv_b64u,
    timestamp: Date.now()
  };

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
  const decryptionKey = derive_encryption_key_from_prf(prfOutput, HKDF_INFO, HKDF_SALT);
  const decryptedKey = decrypt_data_aes_gcm(
    encryptedKeyData.encryptedData,
    encryptedKeyData.iv,
    decryptionKey
  );

  // Handle both cases: full "ed25519:..." format or just base58
  if (decryptedKey.startsWith('ed25519:')) {
    return decryptedKey; // Already has the prefix
  } else {
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
  const decryptedPrivateKeyString = decryptPrivateKeyString(encryptedKeyData, prfOutput);
  return KeyPair.fromString(decryptedPrivateKeyString as KeyPairString);
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

  return createTransaction(
    nearAccountId,
    keyPair.getPublicKey(),
    receiverId,
    BigInt(nonce),
    actions,
    Buffer.from(blockHashBytes)
  );
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

    const encryptedKeyData = await getEncryptedKey(nearAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${nearAccountId}`);
    }

    const keyPair = decryptPrivateKey(encryptedKeyData, prfOutput);
    const transaction = createNearTransaction(nearAccountId, keyPair, payload);
    const serializedSignedTx = signTransaction(transaction, keyPair);

    sendResponseAndTerminate({
      type: WorkerResponseType.SIGNATURE_SUCCESS,
      payload: {
        signedTransactionBorsh: Array.from(serializedSignedTx),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: Signing failed:', error.message);
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