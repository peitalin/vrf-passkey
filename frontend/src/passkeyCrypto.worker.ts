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

// Helper to convert base64url to ArrayBuffer (used by Web Crypto API)
function base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to convert ArrayBuffer to base64url string
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// PLACEHOLDER: Securely derive encryption key from WebAuthn response
// This function should be robust enough for both attestation and assertion if inputs are handled carefully.
async function deriveEncryptionKeyFromWebAuthnResponse(webAuthnResponse: any, operationContext: 'registration' | 'authentication'): Promise<CryptoKey> {
  console.warn(`WORKER: Using insecure key derivation for demo (${operationContext}). IMPLEMENT SECURE KDF.`);
  // IMPORTANT: This derivation is NOT secure for production.
  // Use clientDataJSON.challenge and parts of attestationObject (for registration)
  // or authenticatorData/signature (for assertion) in a strong KDF (e.g., HKDF).

  // webAuthnResponse is the object from publicKeyCredentialToJSON(),
  // so webAuthnResponse.response.clientDataJSON is a base64url STRING.
  const b64ClientData = webAuthnResponse.response.clientDataJSON;
  if (typeof b64ClientData !== 'string') {
    throw new Error('WORKER: Expected clientDataJSON to be a base64url string from publicKeyCredentialToJSON.');
  }

  let clientDataJSONStr;
  try {
      clientDataJSONStr = new TextDecoder().decode(base64UrlToArrayBuffer(b64ClientData));
  } catch (e) {
      console.error("WORKER: Failed to decode base64url clientDataJSON string:", b64ClientData, e);
      throw new Error("WORKER: Could not decode clientDataJSON string.");
  }

  const clientData = JSON.parse(clientDataJSONStr);
  const challenge = clientData.challenge;

  const encoder = new TextEncoder();
  // DEMO ONLY: This input must be cryptographically strong and unique per operation/user.
  const saltSuffix = operationContext === 'registration' ? "_REG_SALT_DEMO" : "_AUTH_SALT_DEMO";
  const simplisticInputForKeyMaterial = encoder.encode(challenge.slice(0, 16) + saltSuffix);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    simplisticInputForKeyMaterial,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: encoder.encode('worker-kdf-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// Encrypts data (e.g., a NEAR private key string)
async function encryptData(plainTextData: string, encryptionKey: CryptoKey): Promise<{ encryptedData: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommended IV size
  const encodedData = new TextEncoder().encode(plainTextData);
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    encryptionKey,
    encodedData
  );
  return {
    encryptedData: arrayBufferToBase64Url(encryptedBuffer),
    iv: arrayBufferToBase64Url(iv.buffer),
  };
}

// Decrypts data (e.g., a NEAR private key string)
async function decryptData(encryptedDataB64: string, ivB64: string, encryptionKey: CryptoKey): Promise<string> {
  const encryptedData = base64UrlToArrayBuffer(encryptedDataB64);
  const iv = base64UrlToArrayBuffer(ivB64);
  const decryptedDataBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    encryptionKey,
    encryptedData
  );
  return new TextDecoder().decode(decryptedDataBuffer);
}

self.onmessage = async (event: MessageEvent) => {
  const { type, payload } = event.data;

  if (!crypto || !crypto.subtle || !TextEncoder || !TextDecoder || typeof atob === 'undefined' || typeof btoa === 'undefined') {
    self.postMessage({ type: 'CRYPTO_ERROR', payload: { error: 'Essential crypto/encoding APIs not available in worker.' }});
    return;
  }

  if (type === 'ENCRYPT_PRIVATE_KEY_WITH_ATTESTATION') {
    try {
      const {
        passkeyAttestationResponse, // Raw AuthenticatorAttestationResponse from navigator.credentials.create()
        nearPrivateKeyString,       // Plaintext NEAR private key string to encrypt
      } = payload;

      if (!passkeyAttestationResponse || !nearPrivateKeyString) {
        throw new Error('WORKER: Missing attestation response or private key string for encryption.');
      }

      const encryptionKey = await deriveEncryptionKeyFromWebAuthnResponse(passkeyAttestationResponse, 'registration');
      const encryptedKeyInfo = await encryptData(nearPrivateKeyString, encryptionKey);

      self.postMessage({
        type: 'ENCRYPTION_SUCCESS',
        payload: encryptedKeyInfo, // { encryptedData: string (base64url), iv: string (base64url) }
      });

    } catch (error: any) {
      console.error('WORKER: Error encrypting private key:', error);
      self.postMessage({ type: 'ENCRYPTION_FAILURE', payload: { error: error.message || 'Encryption error' } });
    }

  } else if (type === 'DECRYPT_AND_SIGN_TRANSACTION') { // New message type for full signing
    try {
      const {
        encryptedNearPrivateKeyInfo,
        passkeyAssertionResponse,
        derpAccountId,
        receiverId,
        contractMethodName, // Renamed for clarity from contractMethodForPasskeyController
        contractArgs,       // Renamed for clarity from contractArgsForPasskeyController
        gasAmount,          // Renamed for clarity from actionGas
        depositAmount,      // Renamed for clarity from actionDeposit
        nonce,
        blockHash,        // base64 string of block hash bytes (from main thread's access key query)
      } = payload;

      if (!encryptedNearPrivateKeyInfo || !passkeyAssertionResponse || !derpAccountId || !receiverId || !contractMethodName || !contractArgs || typeof nonce === 'undefined' || !blockHash || typeof gasAmount === 'undefined' || typeof depositAmount === 'undefined') {
        throw new Error('WORKER: Missing critical data for decryption and signing.');
      }

      const encryptionKey = await deriveEncryptionKeyFromWebAuthnResponse(passkeyAssertionResponse, 'authentication');
      const decryptedPrivateKeyString = await decryptData(
        encryptedNearPrivateKeyInfo.encryptedData,
        encryptedNearPrivateKeyInfo.iv,
        encryptionKey
      );

      // Ensure decryptedPrivateKeyString is in "ed25519:BASE58_PV_KEY" format for KeyPair.fromString
      const keyPair = KeyPair.fromString(decryptedPrivateKeyString as KeyPairString);
      const publicKey = keyPair.getPublicKey();

      // Construct the action(s) for the transaction
      // Here, we are calling a method on the PasskeyController (receiverId)
      const actions: Action[] = [
        nearApiJs.transactions.functionCall(
          contractMethodName,
          Buffer.from(JSON.stringify(contractArgs)),
          BigInt(gasAmount),
          BigInt(depositAmount)
        )
      ];

      // Use nearApiJs.transactions.createTransaction if it's preferred due to main import
      const transaction = nearApiJs.transactions.createTransaction(
        derpAccountId, // Signer
        publicKey,     // Signer's public key
        receiverId,    // Receiver of this transaction (PasskeyController)
        BigInt(nonce), // Nonce must be BigInt
        actions,       // Array of Action objects
        Buffer.from(blockHash, 'base64') // Decoded block hash bytes
      );

      // Access schema via nearApiJs.transactions if available, or specific class static property
      const schemaToUse = nearApiJs.transactions.SCHEMA; // Assuming SCHEMA is re-exported here
      if (!schemaToUse || !schemaToUse.Transaction || !schemaToUse.SignedTransaction) {
          // Fallback or error if SCHEMA structure isn't as expected
          // This might happen if nearApiJs.transactions.SCHEMA is not the collection of schemas
          // or if Transaction/SignedTransaction are not direct keys.
          // For now, we'll assume the direct SCHEMA import from @near-js/transactions was more direct.
          // Re-importing it specifically for serialize if nearApiJs.transactions.SCHEMA is problematic.
          console.warn("Using direct SCHEMA import for serialization as nearApiJs.transactions.SCHEMA seems incomplete.")
          const { SCHEMA: directSchema } = await import('@near-js/transactions'); // Dynamic import for schema
          const serializedTx = serialize(directSchema.Transaction, transaction);
          const hash = new Uint8Array(sha256.array(serializedTx));
          const signatureFromKeyPair = keyPair.sign(hash);
          const nearSignature = new Signature({ keyType: publicKey.keyType, data: signatureFromKeyPair.signature });
          const signedTransaction = new SignedTransaction({ transaction: transaction, signature: nearSignature });
          const serializedSignedTx = serialize(directSchema.SignedTransaction, signedTransaction);

          self.postMessage({
            type: 'SIGNATURE_SUCCESS',
            payload: {
              signedTransactionBorsh: Array.from(serializedSignedTx),
            },
          });
          return; // Exit after this path
      }

      const serializedTx = serialize(schemaToUse.Transaction, transaction);
      const hash = new Uint8Array(sha256.array(serializedTx));
      const signatureFromKeyPair = keyPair.sign(hash);

      const nearSignature = new Signature({
        keyType: publicKey.keyType,
        data: signatureFromKeyPair.signature
      });

      const signedTransaction = new SignedTransaction({
        transaction: transaction,
        signature: nearSignature
      });

      const serializedSignedTx = serialize(schemaToUse.SignedTransaction, signedTransaction);

      self.postMessage({
        type: 'SIGNATURE_SUCCESS',
        payload: {
          signedTransactionBorsh: Array.from(serializedSignedTx),
        },
      });

    } catch (error: any) {
      console.error('WORKER: Error decrypting/signing transaction:', error);
      self.postMessage({ type: 'SIGNATURE_FAILURE', payload: { error: error.message || 'Decryption/Signing error' } });
    }
  } else {
    console.warn('WORKER: Received unknown message type:', type);
    self.postMessage({ type: 'UNKNOWN_MESSAGE_TYPE', payload: { receivedType: type } });
  }
};