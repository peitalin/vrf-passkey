// frontend/src/passkeyCrypto.worker.ts
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

// Import WASM module
// @ts-ignore - WASM module types
import init, {
  derive_encryption_key_from_webauthn_js,
  encrypt_data_aes_gcm,
  decrypt_data_aes_gcm
} from '../wasm-worker/pkg/passkey_crypto_worker.js';

// Initialize WASM module once
let wasmInitialized = false;

async function ensureWasmInitialized() {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;
    console.log('WORKER: WASM module initialized');
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
    nearPrivateKeyString: string;
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

// Main message handler
self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
  const { type, payload } = event.data;

  try {
    await ensureWasmInitialized();

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
  }
};

async function handleEncryptPrivateKey(payload: EncryptPrivateKeyMessage['payload']) {
  const { passkeyAttestationResponse, nearPrivateKeyString, derpAccountId } = payload;

  try {
    // The passkeyAttestationResponse from publicKeyCredentialToJSON has this structure:
    // { id, rawId, response: { clientDataJSON, attestationObject, ... }, type }
    // We need to pass just the response object to the WASM function

    if (!passkeyAttestationResponse.response) {
      throw new Error('Invalid attestation response structure - missing response property');
    }

    // Transform field names to match WASM expectations (clientDataJSON -> clientDataJson)
    const wasmCompatibleResponse = {
      clientDataJson: passkeyAttestationResponse.response.clientDataJSON,
      attestationObject: passkeyAttestationResponse.response.attestationObject,
    };

    // Derive encryption key from WebAuthn response
    const encryptionKey = derive_encryption_key_from_webauthn_js(
      JSON.stringify(wasmCompatibleResponse),
      'registration'
    );

    // Encrypt the NEAR private key
    const encryptedJson = encrypt_data_aes_gcm(nearPrivateKeyString, encryptionKey);
    const encrypted = JSON.parse(encryptedJson);

    // Store in IndexedDB
    await storeEncryptedKey({
      derpAccountId,
      encryptedData: encrypted.encrypted_data_b64u,
      iv: encrypted.iv_b64u,
      timestamp: Date.now()
    });

    self.postMessage({
      type: 'ENCRYPTION_SUCCESS',
      payload: {
        derpAccountId,
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