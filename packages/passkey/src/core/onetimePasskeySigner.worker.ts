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

// Import WASM binary directly as URL
// @ts-ignore - WASM module types
import init, * as wasmModule from '../wasm-worker/passkey_crypto_worker.js';
// @ts-ignore - WASM binary import
import wasmUrl from '../wasm-worker/passkey_crypto_worker_bg.wasm?url';

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
  generate_and_encrypt_near_keypair_with_prf
} = wasmModule;

// === UTILITY FUNCTIONS ===

/**
 * Initialize WASM module with caching support
 */
async function initializeWasmWithCache(): Promise<void> {
  try {
    const cache = await caches.open(WASM_CACHE_NAME);
    const cachedResponse = await cache.match(wasmUrl);

    if (cachedResponse) {
      const wasmModule = await WebAssembly.compileStreaming(cachedResponse.clone());
      await init({ module: wasmModule });
      return;
    }

    const response = await fetch(wasmUrl);
    const responseToCache = response.clone();
    const wasmModule = await WebAssembly.compileStreaming(response);

    await cache.put(wasmUrl, responseToCache);
    await init({ module: wasmModule });
  } catch (error) {
    console.error('WORKER: WASM initialization failed, using fallback:', error);
    await init();
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
    type: 'ERROR',
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

interface WorkerResponse {
  type: string;
  payload: any;
}

interface WasmResult {
  publicKey: string;
  encryptedPrivateKey: any;
}

// === INDEXEDDB OPERATIONS ===

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
        db.createObjectStore(STORE_NAME, { keyPath: 'nearAccountId' });
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

interface EncryptPrivateKeyWithPrfMessage {
  type: 'ENCRYPT_PRIVATE_KEY_WITH_PRF';
  payload: {
    prfOutput: string; // Base64-encoded PRF output
    nearAccountId: string;
  };
}

interface DecryptAndSignTransactionWithPrfMessage {
  type: 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF';
  payload: {
    nearAccountId: string;
    prfOutput: string; // Base64-encoded PRF output
    receiverId: string;
    contractMethodName: string;
    contractArgs: any;
    gasAmount: string;
    depositAmount: string;
    nonce: string;
    blockHashBytes: number[];
  };
}

type WorkerMessage = EncryptPrivateKeyWithPrfMessage | DecryptAndSignTransactionWithPrfMessage;

// === MAIN MESSAGE HANDLER ===

let messageProcessed = false;

self.onmessage = async (event: MessageEvent<WorkerMessage>): Promise<void> => {
  if (messageProcessed) {
    sendResponseAndTerminate(createErrorResponse('Worker has already processed a message'));
    return;
  }

  messageProcessed = true;
  const { type, payload } = event.data;

  try {
    await initializeWasmWithCache();

    switch (type) {
      case 'ENCRYPT_PRIVATE_KEY_WITH_PRF':
        await handleEncryptPrivateKeyWithPrf(payload);
        break;

      case 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF':
        await handleDecryptAndSignTransactionWithPrf(payload);
        break;

      default:
        sendResponseAndTerminate(createErrorResponse(`Unknown message type: ${type}`));
    }
  } catch (error: any) {
    console.error('WORKER: Message processing failed:', error.message);
    sendResponseAndTerminate(createErrorResponse(error.message || 'Unknown error occurred'));
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
  payload: EncryptPrivateKeyWithPrfMessage['payload']
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
      type: 'ENCRYPTION_SUCCESS',
      payload: {
        nearAccountId,
        publicKey,
        stored: true,
      }
    });
  } catch (error: any) {
    console.error('WORKER: Encryption failed:', error.message);
    sendResponseAndTerminate({
      type: 'ENCRYPTION_FAILURE',
      payload: { error: error.message || 'PRF encryption failed' }
    });
  }
}

// === DECRYPTION AND SIGNING WORKFLOW ===

/**
 * Decrypt private key from stored data
 */
function decryptPrivateKey(
  encryptedKeyData: EncryptedKeyData,
  prfOutput: string
): KeyPair {
  const decryptionKey = derive_encryption_key_from_prf(prfOutput, HKDF_INFO, HKDF_SALT);
  const decryptedPrivateKeyString = decrypt_data_aes_gcm(
    encryptedKeyData.encryptedData,
    encryptedKeyData.iv,
    decryptionKey
  );

  return KeyPair.fromString(decryptedPrivateKeyString as KeyPairString);
}

/**
 * Create NEAR transaction from parameters
 */
function createNearTransaction(
  nearAccountId: string,
  keyPair: KeyPair,
  payload: DecryptAndSignTransactionWithPrfMessage['payload']
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
  payload: DecryptAndSignTransactionWithPrfMessage['payload']
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
      type: 'SIGNATURE_SUCCESS',
      payload: {
        signedTransactionBorsh: Array.from(serializedSignedTx),
        nearAccountId
      }
    });
  } catch (error: any) {
    console.error('WORKER: Signing failed:', error.message);
    sendResponseAndTerminate({
      type: 'SIGNATURE_FAILURE',
      payload: { error: error.message || 'PRF decryption/signing failed' }
    });
  }
}

// === EXPORTS ===
export type {
  WorkerMessage,
  EncryptPrivateKeyWithPrfMessage,
  DecryptAndSignTransactionWithPrfMessage
};