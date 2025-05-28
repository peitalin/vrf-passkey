import { KeyPair, PublicKey, type KeyPairString } from '@near-js/crypto';
import { serialize } from 'borsh';
import {
  SCHEMA,
  SignedTransaction,
  createTransaction,
  Action,
  Signature,
} from '@near-js/transactions';
import nearApiJs from "near-api-js";
import { sha256 } from 'js-sha256';

// Import WASM binary directly as URL
// @ts-ignore - WASM module types
import init, * as wasmModule from '../../wasm-worker/pkg/passkey_crypto_worker.js';
// @ts-ignore - WASM binary import
import wasmUrl from '../../wasm-worker/pkg/passkey_crypto_worker_bg.wasm?url';
// ?url: lets Vite treat WASM file as a URL asset, which it serves with the correct MIME type

const {
  derive_encryption_key_from_webauthn_js,
  encrypt_data_aes_gcm,
  decrypt_data_aes_gcm,
  generate_and_encrypt_near_keypair
} = wasmModule;

// Cache name for WASM module
const WASM_CACHE_NAME = 'passkey-wasm-v1';

// Initialize WASM module with caching
async function initializeWasmWithCache() {
  console.log('WORKER: Initializing WASM module with cache support');

  try {
    // Try to get the WASM module from cache
    const cache = await caches.open(WASM_CACHE_NAME);
    const cachedResponse = await cache.match(wasmUrl);

    if (cachedResponse) {
      console.log('WORKER: Loading WASM from cache');
      const wasmModule = await WebAssembly.compileStreaming(cachedResponse.clone());
      await init({ module: wasmModule });
      console.log('WORKER: WASM module initialized from cache');
      return;
    }

    // If not in cache, fetch and cache it
    console.log('WORKER: WASM not in cache, fetching...');
    const response = await fetch(wasmUrl);

    // Clone the response before using it
    const responseToCache = response.clone();

    // Compile the module
    const wasmModule = await WebAssembly.compileStreaming(response);

    // Cache the response for future use
    await cache.put(wasmUrl, responseToCache);
    console.log('WORKER: WASM module cached');

    // Initialize with the compiled module using modern object syntax
    await init({ module: wasmModule });
    console.log('WORKER: WASM module initialized');

  } catch (error) {
    console.error('WORKER: Failed to initialize WASM with cache, falling back to default init:', error);
    // Fallback to default initialization (no parameters needed for default)
    await init();
  }
}

// IndexedDB helper functions
const DB_NAME = 'PasskeyNearKeys';
const DB_VERSION = 1;
const STORE_NAME = 'encryptedKeys';

interface EncryptedKeyData {
  derpAccountId: string;
  encryptedData: string;
  iv: string;
  timestamp: number;
}

async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'derpAccountId' });
      }
    };
  });
}

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

async function getEncryptedKey(derpAccountId: string): Promise<EncryptedKeyData | null> {
  const db = await openDB();
  const transaction = db.transaction([STORE_NAME], 'readonly');
  const store = transaction.objectStore(STORE_NAME);

  return new Promise((resolve, reject) => {
    const request = store.get(derpAccountId);
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

// Message types
interface EncryptPrivateKeyMessage {
  type: 'ENCRYPT_PRIVATE_KEY';
  payload: {
    passkeyAttestationResponse: any; // publicKeyCredentialToJSON output
    derpAccountId: string;
  };
}

interface DecryptAndSignTransactionMessage {
  type: 'DECRYPT_AND_SIGN_TRANSACTION';
  payload: {
    derpAccountId: string;
    passkeyAssertionResponse: any; // publicKeyCredentialToJSON output
    receiverId: string;
    contractMethodName: string;
    contractArgs: any;
    gasAmount: string;
    depositAmount: string;
    nonce: string;
    blockHash: string; // base64 string
  };
}

type WorkerMessage = EncryptPrivateKeyMessage | DecryptAndSignTransactionMessage;

// Track if we've processed a message
let messageProcessed = false;

// Main message handler - ONE TIME USE
self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
  // Ensure we only process one message
  if (messageProcessed) {
    console.warn('WORKER: Attempted to process multiple messages in one-time worker');
    self.postMessage({
      type: 'ERROR',
      payload: { error: 'Worker has already processed a message' }
    });
    return;
  }

  messageProcessed = true;
  const { type, payload } = event.data;

  try {
    // Initialize WASM with caching
    await initializeWasmWithCache();

    switch (type) {
      case 'ENCRYPT_PRIVATE_KEY':
        await handleEncryptPrivateKey(payload);
        break;

      case 'DECRYPT_AND_SIGN_TRANSACTION':
        await handleDecryptAndSignTransaction(payload);
        break;

      default:
        self.postMessage({
          type: 'ERROR',
          payload: { error: `Unknown message type: ${type}` }
        });
    }
  } catch (error: any) {
    console.error('WORKER: Error processing message:', error);
    self.postMessage({
      type: 'ERROR',
      payload: { error: error.message || 'Unknown error occurred' }
    });
  } finally {
    // Self-terminate after processing
    console.log('WORKER: Self-terminating after processing message');
    self.close();
  }
};

async function handleEncryptPrivateKey(payload: EncryptPrivateKeyMessage['payload']) {
  const { passkeyAttestationResponse, derpAccountId } = payload;

  try {

    if (!passkeyAttestationResponse.response) {
      throw new Error('Invalid attestation response structure - missing response property');
    }

    // Transform field names to match WASM expectations (clientDataJSON -> clientDataJson)
    const wasmCompatibleResponse = {
      clientDataJson: passkeyAttestationResponse.response.clientDataJSON,
      attestationObject: passkeyAttestationResponse.response.attestationObject,
    };

    // Generate NEAR key pair and encrypt it in WASM
    const resultJson = generate_and_encrypt_near_keypair(
      JSON.stringify(wasmCompatibleResponse),
      'registration'
    );

    console.log('WORKER: WASM function returned:', typeof resultJson, resultJson);

    // Check if resultJson is already an object or a string
    let result;
    if (typeof resultJson === 'string') {
      result = JSON.parse(resultJson);
    } else {
      // If it's already an object, use it directly
      result = resultJson;
    }

    console.log('WORKER: Parsed result:', result);

    // result.encryptedPrivateKey should be a JSON string from WASM, parse it
    let encryptedPrivateKey;
    if (typeof result.encryptedPrivateKey === 'string') {
      encryptedPrivateKey = JSON.parse(result.encryptedPrivateKey);
    } else {
      // If it's already an object, use it directly
      encryptedPrivateKey = result.encryptedPrivateKey;
    }

    console.log('WORKER: Encrypted private key:', encryptedPrivateKey);

    // Store in IndexedDB
    await storeEncryptedKey({
      derpAccountId,
      encryptedData: encryptedPrivateKey.encrypted_data_b64u,
      iv: encryptedPrivateKey.iv_b64u,
      timestamp: Date.now()
    });

    self.postMessage({
      type: 'ENCRYPTION_SUCCESS',
      payload: {
        derpAccountId,
        publicKey: result.publicKey,
        stored: true
      }
    });

  } catch (error: any) {
    console.error('WORKER: Encryption failed:', error);
    self.postMessage({
      type: 'ENCRYPTION_FAILURE',
      payload: { error: error.message || 'Encryption failed' }
    });
  }
}

async function handleDecryptAndSignTransaction(payload: DecryptAndSignTransactionMessage['payload']) {
  const {
    derpAccountId,
    passkeyAssertionResponse,
    receiverId,
    contractMethodName,
    contractArgs,
    gasAmount,
    depositAmount,
    nonce,
    blockHash
  } = payload;

  try {
    // Retrieve encrypted key from IndexedDB
    const encryptedKeyData = await getEncryptedKey(derpAccountId);
    if (!encryptedKeyData) {
      throw new Error(`No encrypted key found for account: ${derpAccountId}`);
    }

    // The passkeyAssertionResponse from publicKeyCredentialToJSON has this structure:
    // { id, rawId, response: { clientDataJSON, signature, authenticatorData, ... }, type }
    // We need to pass just the response object to the WASM function

    if (!passkeyAssertionResponse.response) {
      throw new Error('Invalid assertion response structure - missing response property');
    }

    // Transform field names to match WASM expectations (clientDataJSON -> clientDataJson)
    const wasmCompatibleResponse = {
      clientDataJson: passkeyAssertionResponse.response.clientDataJSON,
      signature: passkeyAssertionResponse.response.signature,
      authenticatorData: passkeyAssertionResponse.response.authenticatorData,
      userHandle: passkeyAssertionResponse.response.userHandle,
    };

    // Derive decryption key from WebAuthn response
    const decryptionKey = derive_encryption_key_from_webauthn_js(
      JSON.stringify(wasmCompatibleResponse),
      'authentication'
    );

    // Decrypt the NEAR private key
    const decryptedPrivateKeyString = decrypt_data_aes_gcm(
      encryptedKeyData.encryptedData,
      encryptedKeyData.iv,
      decryptionKey
    );

    // Create KeyPair from decrypted private key
    const keyPair = KeyPair.fromString(decryptedPrivateKeyString as KeyPairString);
    const publicKey = keyPair.getPublicKey();

    // Construct the action(s) for the transaction
    const actions: Action[] = [
      nearApiJs.transactions.functionCall(
        contractMethodName,
        Buffer.from(JSON.stringify(contractArgs)),
        BigInt(gasAmount),
        BigInt(depositAmount)
      )
    ];

    // Create the transaction
    const transaction = nearApiJs.transactions.createTransaction(
      derpAccountId,     // Signer
      publicKey,         // Signer's public key
      receiverId,        // Receiver of this transaction
      BigInt(nonce),     // Nonce must be BigInt
      actions,           // Array of Action objects
      Buffer.from(blockHash, 'base64') // Decoded block hash bytes
    );

    // Serialize and sign the transaction
    const serializedTx = serialize(SCHEMA.Transaction, transaction);
    const hash = new Uint8Array(sha256.array(serializedTx));
    const signatureFromKeyPair = keyPair.sign(hash);

    // Create the signed transaction
    const nearSignature = new Signature({
      keyType: publicKey.keyType,
      data: signatureFromKeyPair.signature
    });

    const signedTransaction = new SignedTransaction({
      transaction: transaction,
      signature: nearSignature
    });

    // Serialize the signed transaction
    const serializedSignedTx = serialize(SCHEMA.SignedTransaction, signedTransaction);

    self.postMessage({
      type: 'SIGNATURE_SUCCESS',
      payload: {
        signedTransactionBorsh: Array.from(serializedSignedTx),
        derpAccountId
      }
    });

  } catch (error: any) {
    console.error('WORKER: Decryption/signing failed:', error);
    self.postMessage({
      type: 'SIGNATURE_FAILURE',
      payload: { error: error.message || 'Decryption/signing failed' }
    });
  }
}

// Export types for use in main thread
export type {
  WorkerMessage,
  EncryptPrivateKeyMessage,
  DecryptAndSignTransactionMessage
};