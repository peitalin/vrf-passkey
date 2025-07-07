import type { NearClient } from '../NearClient';
import { SignedTransaction } from "../NearClient";
import { base64UrlEncode, base58Decode } from '../../utils/encoders';
import type {
  WorkerResponse,
  ActionParams,
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
  RecoverKeypairSuccessResponse,
  ErrorResponse,
  CompletionResponse,
  ProgressResponse,
  SignatureSuccessResponse,
  WasmEncryptionResult,
  WasmRegistrationResult,
  WasmTransactionSignResult,
  WasmRecoverKeypairResult,
} from '../types/signer-worker';
import {
  WorkerRequestType,
  WorkerResponseType,
  isEncryptionSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isCheckRegistrationSuccess,
  isRegistrationSuccess,
  validateActionParams,
  serializeCredentialWithPRF,
  extractDualPrfOutputs,
  isCoseExtractionSuccess,
  isRecoverKeypairSuccess,
  isWorkerError,
  isWorkerSuccess,
  takeAesPrfOutput
} from '../types/signer-worker';
import { ActionType } from '../types/actions';
import { ClientAuthenticatorData } from '../IndexedDBManager';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from '../IndexedDBManager/passkeyNearKeysDB';
import { TouchIdPrompt } from "./touchIdPrompt";
import { VRFChallenge } from '../types/webauthn';
import type { onProgressEvents } from '../types/webauthn';

// === CONFIGURATION ===
const CONFIG = {
  TIMEOUTS: {
    DEFAULT: 20_000,      // 20s
    TRANSACTION: 60_000,  // 60s for contract verification + signing
    REGISTRATION: 60_000, // 60s for registration operations
  },
  WORKER: {
    URL: '/workers/web3authn-signer.worker.js',
    TYPE: 'module' as const,
    NAME: 'Web3AuthnSignerWorker',
  },
  RETRY: {
    MAX_ATTEMPTS: 3,
    BACKOFF_MS: 1000,
  }
} as const;

// === IMPORT AUTO-GENERATED WASM TYPES ===
// WASM-generated types now correctly match runtime data with js_name attributes
import * as wasmModule from '../../wasm_signer_worker/wasm_signer_worker.js';

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: Challenge store removed as VRF provides cryptographic freshness
 * without needing centralized challenge management
 */
export class SignerWorkerManager {

  private nearKeysDB: PasskeyNearKeysDBManager;

  constructor() {
    this.nearKeysDB = new PasskeyNearKeysDBManager();
  }

  createSecureWorker(): Worker {
    // Simple path resolution - build:all copies worker files to /workers/
    const workerUrl = new URL(CONFIG.WORKER.URL, window.location.origin);
    console.log('Creating secure worker from:', workerUrl.href);

    try {
      const worker = new Worker(workerUrl, {
        type: CONFIG.WORKER.TYPE,
        name: CONFIG.WORKER.NAME
      });

      // Add error handling
      worker.onerror = (event) => {
        console.error('Worker error:', event);
      };

      return worker;
    } catch (error) {
      console.error('Failed to create worker:', error);
      throw new Error(`Failed to create secure worker: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * === EXECUTE WORKER OPERATION METHOD ===
   * Execute worker operation with optional progress updates (handles both single and multiple response patterns)
   *
   * FEATURES:
   * - Single-response operations (traditional request-response)
   * - Multi-response operations with progress updates (streaming SSE-like pattern)
   * - Consistent error handling and timeouts
   * - Strong WASM-generated types for all responses
   */
  private async executeWorkerOperation({
    message,
    onEvent,
    timeoutMs = CONFIG.TIMEOUTS.DEFAULT // 20s
  }: {
    message: Record<string, any>,
    onEvent?: (update: onProgressEvents) => void,
    timeoutMs?: number
  }): Promise<WorkerResponse> {

    const worker = this.createSecureWorker();

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Worker operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const responses: WorkerResponse[] = [];

      worker.onmessage = (event) => {
        // Use strong typing from WASM-generated types
        const response = event.data as WorkerResponse;
        responses.push(response);

        // Handle progress updates using WASM-generated numeric enum values
        if (response.type === WorkerResponseType.VerificationProgress ||
            response.type === WorkerResponseType.SigningProgress ||
            response.type === WorkerResponseType.RegistrationProgress) {
          const progressResponse = response as ProgressResponse;
          onEvent?.(progressResponse.payload as onProgressEvents);
          return; // Continue listening for more messages
        }

        // Handle completion messages using WASM-generated numeric enum values
        if (response.type === WorkerResponseType.SigningComplete ||
            response.type === WorkerResponseType.RegistrationComplete ||
            response.type === WorkerResponseType.VerificationComplete) {
          const completionResponse = response as CompletionResponse;
          onEvent?.(completionResponse.payload as onProgressEvents);

          clearTimeout(timeoutId);
          worker.terminate();

          if (completionResponse.payload.status === 'success') {
            resolve(completionResponse);
          } else {
            reject(new Error(completionResponse.payload.message || 'Operation failed'));
          }
          return;
        }

        // Handle errors using WASM-generated enum
        if (response.type === WorkerResponseType.Error) {
          clearTimeout(timeoutId);
          worker.terminate();
          const errorResponse = response as ErrorResponse;
          reject(new Error(errorResponse.payload.error));
          return;
        }

        // Handle successful completion types using strong typing
        if (isWorkerSuccess(response)) {
          clearTimeout(timeoutId);
          worker.terminate();
          resolve(response);
        }
      };

      worker.onerror = (event) => {
        clearTimeout(timeoutId);
        worker.terminate();
        const errorMessage = event.error?.message || event.message || 'Unknown worker error';
        console.error('Worker error details (progress):', {
          message: errorMessage,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          error: event.error
        });
        reject(new Error(`Worker error: ${errorMessage}`));
      };

      // Format message for Rust SignerWorkerMessage structure using WASM types
      const formattedMessage = {
        type: message.type, // Numeric enum value from WorkerRequestType
        payload: message.payload,
      };

      worker.postMessage(formattedMessage);
    });
  }

  // === PRF OPERATIONS ===

  /**
   * Secure registration flow with dual PRF: WebAuthn + WASM worker encryption using dual PRF
   */
  async deriveNearKeypairAndEncrypt(
    credential: PublicKeyCredential,
    nearAccountId: string,
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    try {
      console.log('WebAuthnManager: Starting secure registration with dual PRF using deterministic derivation');

      // Serialize credential first to ensure consistent PRF extraction with decryption phase
      const serializedCredential = serializeCredentialWithPRF<WebAuthnRegistrationCredential>(credential);

      // Extract dual PRF outputs from serialized credential (same as decryption phase)
      const dualPrfOutputs = {
        aesPrfOutput: serializedCredential.clientExtensionResults?.prf?.results?.first!,
        ed25519PrfOutput: serializedCredential.clientExtensionResults?.prf?.results?.second!
      };

      if (!dualPrfOutputs.aesPrfOutput || !dualPrfOutputs.ed25519PrfOutput) {
        throw new Error('Dual PRF outputs missing from serialized credential');
      }

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.DeriveNearKeypairAndEncrypt,
          payload: {
            dualPrfOutputs,
            nearAccountId: nearAccountId,
          }
        }
      });

      if (isEncryptionSuccess(response)) {
        console.log('WebAuthnManager: Dual PRF registration successful with deterministic derivation');

        const wasmResult = response.payload as WasmEncryptionResult;

        // Store the encrypted key in IndexedDB using the manager
        const keyData: EncryptedKeyData = {
          nearAccountId: nearAccountId,
          encryptedData: wasmResult.encryptedData,
          iv: wasmResult.iv,
          timestamp: Date.now()
        };

        await this.nearKeysDB.storeEncryptedKey(keyData);

        // Verify storage
        const verified = await this.nearKeysDB.verifyKeyStorage(nearAccountId);
        if (!verified) {
          throw new Error('Key storage verification failed');
        }
        console.log('WebAuthnManager: Encrypted key stored and verified in IndexedDB');

        return {
          success: true,
          nearAccountId: wasmResult.nearAccountId,
          publicKey: wasmResult.publicKey
        };
      } else {
        console.error('WebAuthnManager: Dual PRF registration failed:', response);
        return {
          success: false,
          nearAccountId: nearAccountId,
          publicKey: ''
        };
      }
    } catch (error: any) {
      console.error('WebAuthnManager: Dual PRF registration error:', error);
      return {
        success: false,
        nearAccountId: nearAccountId,
        publicKey: ''
      };
    }
  }

  /**
   * Secure private key decryption with dual PRF
   *
   * For local private key export, we're just decrypting locally stored encrypted private keys
   *    - No network communication with servers
   *    - No transaction signing or blockchain interaction
   *    - No replay attack surface since nothing is transmitted
   *    - Security comes from device possession + biometrics
   *    - This is equivalent to: "If you can unlock your phone, you can access your local keychain"
   *
   * DUAL PRF DETERMINISTIC KEY DERIVATION: WebAuthn dual PRF provides cryptographic guarantees
   *    - Same SALT + same authenticator = same PRF output (deterministic)
   *    - Different SALT + same authenticator = different PRF output
   *    - Use account-specific salts for both AES and Ed25519 PRF derivation
   *    - Impossible to derive PRF output without the physical authenticator
   */
  async decryptPrivateKeyWithPrf(
    touchIdPrompt: TouchIdPrompt,
    nearAccountId: string,
    authenticators: ClientAuthenticatorData[],
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    try {
      console.log('WebAuthnManager: Starting private key decryption with dual PRF (local operation)');

      // Retrieve encrypted key data from IndexedDB in main thread
      console.log('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', nearAccountId);
      const encryptedKeyData = await this.nearKeysDB.getEncryptedKey(nearAccountId);
      if (!encryptedKeyData) {
        throw new Error(`No encrypted key found for account: ${nearAccountId}`);
      }

      // For private key export, no VRF challenge is needed.
      // we can use local random challenge for WebAuthn authentication.
      // Security comes from device possession + biometrics, not challenge validation
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      // TouchID prompt
      const credential = await touchIdPrompt.getCredentials({
        nearAccountId,
        challenge,
        authenticators,
      });

      // Extract dual PRF outputs and use the AES one for decryption
      const dualPrfOutputs = extractDualPrfOutputs(credential);
      console.log('WebAuthnManager: Extracted dual PRF outputs, using AES PRF for decryption');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.DecryptPrivateKeyWithPrf,
          payload: {
            nearAccountId: nearAccountId,
            prfOutput: dualPrfOutputs.aesPrfOutput, // Use AES PRF output for decryption
            encryptedPrivateKeyData: encryptedKeyData.encryptedData,
            encryptedPrivateKeyIv: encryptedKeyData.iv
          }
        }
      });

      if (isDecryptionSuccess(response)) {
        console.log('WebAuthnManager: Dual PRF private key decryption successful');
        const wasmResult = response.payload as wasmModule.DecryptPrivateKeyResult;
        return {
          decryptedPrivateKey: wasmResult.privateKey,
          nearAccountId: wasmResult.nearAccountId
        };
      } else {
        console.error('WebAuthnManager: Dual PRF private key decryption failed:', response);
        throw new Error('Private key decryption failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: Dual PRF private key decryption error:', error);
      throw error;
    }
  }

  async checkCanRegisterUser({
    vrfChallenge,
    credential,
    contractId,
    nearRpcUrl,
    onEvent,
  }: {
    vrfChallenge: VRFChallenge,
    credential: PublicKeyCredential,
    contractId: string;
    nearRpcUrl: string;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    success: boolean;
    verified?: boolean;
    registrationInfo?: any;
    logs?: string[];
    signedTransactionBorsh?: number[];
    error?: string;
  }> {
    try {
      console.log('WebAuthnManager: Checking if user can be registered on-chain');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.CheckCanRegisterUser,
          payload: {
            vrfChallenge,
            credential: serializeCredentialWithPRF(credential),
            contractId,
            nearRpcUrl
          }
        },
        onEvent,
        timeoutMs: CONFIG.TIMEOUTS.TRANSACTION
      });

      if (isCheckRegistrationSuccess(response)) {
        console.log('WebAuthnManager: User can be registered on-chain');
        const wasmResult = response.payload as wasmModule.RegistrationCheckResult;
        return {
          success: true,
          verified: wasmResult.verified,
          registrationInfo: wasmResult.registrationInfo,
          logs: wasmResult.logs,
        };
      } else {
        console.error('WebAuthnManager: User cannot be registered on-chain:', response);
        return {
          success: false,
          error: 'User cannot be registered - registration check failed'
        };
      }
    } catch (error: any) {
      console.error('WebAuthnManager: User cannot be registered on-chain:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Actually register user on-chain with transaction (STATE-CHANGING)
   * This function performs the complete registration transaction including:
   * 1. Get transaction metadata (nonce, block hash)
   * 2. Decrypt NEAR keys with PRF
   * 3. Build and sign registration transaction
   * 4. Return signed transaction for main thread to dispatch
   */
  async signVerifyAndRegisterUser({
    vrfChallenge,
    credential,
    contractId,
    signerAccountId,
    nearAccountId,
    publicKeyStr,
    nearClient,
    onEvent,
  }: {
    vrfChallenge: VRFChallenge,
    credential: PublicKeyCredential,
    contractId: string;
    signerAccountId: string;
    nearAccountId: string;
    publicKeyStr: string; // NEAR public key for nonce retrieval
    nearClient: NearClient; // NEAR RPC client for getting transaction metadata
    onEvent?: (update: onProgressEvents) => void
  }): Promise<{
    verified: boolean;
    registrationInfo?: any;
    logs?: string[];
    signedTransaction: SignedTransaction;
    preSignedDeleteTransaction: SignedTransaction;
  }> {
    try {
      console.log('WebAuthnManager: Starting on-chain user registration with transaction');

      // Step 1: Get transaction metadata
      onEvent?.({
        step: 1,
        phase: 'preparation',
        status: 'progress',
        message: 'Preparing transaction metadata...',
      });

      if (!publicKeyStr) {
        throw new Error('Client NEAR public key not provided - cannot get access key nonce');
      }

      // Retrieve encrypted key data from IndexedDB in main thread
      console.log('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', nearAccountId);
      const encryptedKeyData = await this.nearKeysDB.getEncryptedKey(nearAccountId);
      if (!encryptedKeyData) {
        throw new Error(`No encrypted key found for account: ${nearAccountId}`);
      }

      // Extract PRF output from credential
      const dualPrfOutputs = extractDualPrfOutputs(credential);

      // Get access key and transaction block info concurrently
      const [accessKeyInfo, transactionBlockInfo] = await Promise.all([
        nearClient.viewAccessKey(signerAccountId, publicKeyStr),
        nearClient.viewBlock({ finality: 'final' })
      ]);

      console.log('WebAuthnManager: Access key info received:', {
        signerAccountId,
        publicKeyStr,
        accessKeyInfo,
        hasNonce: accessKeyInfo?.nonce !== undefined,
        nonceValue: accessKeyInfo?.nonce,
        nonceType: typeof accessKeyInfo?.nonce
      });

      if (!accessKeyInfo || accessKeyInfo.nonce === undefined) {
        throw new Error(`Access key not found or invalid for account ${signerAccountId} with public key ${publicKeyStr}. Response: ${JSON.stringify(accessKeyInfo)}`);
      }

      const nonce = BigInt(accessKeyInfo.nonce) + BigInt(1);
      const blockHashString = transactionBlockInfo.header.hash;
      // Convert base58 block hash to bytes for WASM
      const transactionBlockHashBytes = Array.from(base58Decode(blockHashString));

      console.log('WebAuthnManager: Transaction metadata prepared', {
        nonce: nonce.toString(),
        blockHash: blockHashString,
        blockHashBytesLength: transactionBlockHashBytes.length
      });

      // Step 2: Execute registration transaction via WASM
      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SignVerifyAndRegisterUser,
          payload: {
            vrfChallenge,
            credential: serializeCredentialWithPRF(credential),
            contractId,
            signerAccountId,
            nearAccountId,
            nonce: nonce.toString(),
            blockHashBytes: transactionBlockHashBytes,
            // Pass encrypted key data from IndexedDB
            encryptedPrivateKeyData: encryptedKeyData.encryptedData,
            encryptedPrivateKeyIv: encryptedKeyData.iv,
            prfOutput: dualPrfOutputs.aesPrfOutput
          }
        },
        onEvent,
        timeoutMs: CONFIG.TIMEOUTS.TRANSACTION
      });

      if (isRegistrationSuccess(response)) {
        console.log('WebAuthnManager: On-chain user registration transaction successful');
        const wasmResult = response.payload as wasmModule.RegistrationResult;
        return {
          verified: wasmResult.verified,
          registrationInfo: wasmResult.registrationInfo,
          logs: wasmResult.logs,
          signedTransaction: new SignedTransaction({
            transaction: JSON.parse(wasmResult.signedTransaction?.transactionJson || '{}'),
            signature: JSON.parse(wasmResult.signedTransaction?.signatureJson || '{}'),
            borsh_bytes: Array.from(wasmResult.signedTransaction?.borshBytes || [])
          }),
          preSignedDeleteTransaction: new SignedTransaction({
            transaction: JSON.parse(wasmResult.preSignedDeleteTransaction?.transactionJson || '{}'),
            signature: JSON.parse(wasmResult.preSignedDeleteTransaction?.signatureJson || '{}'),
            borsh_bytes: Array.from(wasmResult.preSignedDeleteTransaction?.borshBytes || [])
          })
        };
      } else {
        console.error('WebAuthnManager: On-chain user registration transaction failed:', response);
        throw new Error('On-chain user registration transaction failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: On-chain user registration error:', error);
      throw error;
    }
  }

  // === ACTION-BASED SIGNING METHODS ===

  /**
   * Enhanced transaction signing with contract verification and progress updates
   * Demonstrates the "streaming" worker pattern similar to SSE
   */
  async signTransactionWithActions(
    payload: {
      nearAccountId: string;
      receiverId: string;
      actions: ActionParams[];
      nonce: string;
      blockHashBytes: number[];
      // Additional parameters for contract verification
      contractId: string;
      vrfChallenge: VRFChallenge;
      credential: PublicKeyCredential;
      nearRpcUrl: string;
    },
    onEvent?: (update: onProgressEvents) => void
  ): Promise<{
    signedTransaction: SignedTransaction;
    nearAccountId: string;
    logs?: string[]
  }> {
    try {
      console.log('WebAuthnManager: Starting enhanced transaction signing with verification');

      payload.actions.forEach((action, index) => {
        try {
          validateActionParams(action);
        } catch (error) {
          throw new Error(`Action ${index} validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      // Retrieve encrypted key data from IndexedDB in main thread
      console.log('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', payload.nearAccountId);
      const encryptedKeyData = await this.nearKeysDB.getEncryptedKey(payload.nearAccountId);
      if (!encryptedKeyData) {
        throw new Error(`No encrypted key found for account: ${payload.nearAccountId}`);
      }

      // Extract PRF output from credential
      const dualPrfOutputs = extractDualPrfOutputs(payload.credential);

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SignTransactionWithActions,
          payload: {
            nearAccountId: payload.nearAccountId,
            receiverId: payload.receiverId,
            actions: JSON.stringify(payload.actions), // Convert actions array to JSON string
            nonce: payload.nonce,
            blockHashBytes: payload.blockHashBytes,
            // Contract verification parameters
            contractId: payload.contractId,
            vrfChallenge: payload.vrfChallenge,
            // Serialize credential right before sending - minimal exposure time
            credential: serializeCredentialWithPRF(payload.credential),
            nearRpcUrl: payload.nearRpcUrl,
            // Pass encrypted key data from IndexedDB
            encryptedPrivateKeyData: encryptedKeyData.encryptedData,
            encryptedPrivateKeyIv: encryptedKeyData.iv,
            prfOutput: dualPrfOutputs.aesPrfOutput
          }
        },
        onEvent, // onEvent callback for wasm-worker events
        timeoutMs: CONFIG.TIMEOUTS.TRANSACTION
      });
      console.log(">>>>>> WASM RESPONSE", response);

      if (isSignatureSuccess(response)) {
        console.log('WebAuthnManager: Enhanced transaction signing successful with verification logs');
        const wasmResult = response.payload as WasmTransactionSignResult;

        if (!wasmResult.signedTransaction || !wasmResult.signedTransaction.transactionJson || !wasmResult.signedTransaction.signatureJson) {
          throw new Error('Incomplete signed transaction data received from worker');
        }

        return {
          signedTransaction: new SignedTransaction({
            transaction: JSON.parse(wasmResult.signedTransaction.transactionJson),
            signature: JSON.parse(wasmResult.signedTransaction.signatureJson),
            borsh_bytes: Array.from(wasmResult.signedTransaction.borshBytes || [])
          }),
          nearAccountId: payload.nearAccountId
        };
      } else {
        console.error('WebAuthnManager: Enhanced transaction signing failed:', response);
        throw new Error('Enhanced transaction signing failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: Enhanced transaction signing error:', error);
      throw error;
    }
  }

  /**
   * Enhanced Transfer transaction signing with contract verification and progress updates
   * Uses the new verify+sign WASM function for secure, efficient transaction processing
   */
  async signTransferTransaction(
    payload: {
      nearAccountId: string;
      receiverId: string;
      depositAmount: string;
      nonce: string;
      blockHashBytes: number[];
      // Additional parameters for contract verification
      contractId: string;
      vrfChallenge: VRFChallenge;
      credential: PublicKeyCredential;
      nearRpcUrl: string;
    },
    onEvent?: (update: onProgressEvents) => void
  ): Promise<{
    signedTransaction: SignedTransaction;
    nearAccountId: string;
    logs?: string[]
  }> {
    try {
      console.log('WebAuthnManager: Starting enhanced transfer transaction signing with verification');

      const transferAction: ActionParams = {
        actionType: ActionType.Transfer,
        deposit: payload.depositAmount
      };
      validateActionParams(transferAction);

      // Retrieve encrypted key data from IndexedDB in main thread
      console.log('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', payload.nearAccountId);
      const encryptedKeyData = await this.nearKeysDB.getEncryptedKey(payload.nearAccountId);
      if (!encryptedKeyData) {
        throw new Error(`No encrypted key found for account: ${payload.nearAccountId}`);
      }

      // Extract PRF output from credential
      const dualPrfOutputs = extractDualPrfOutputs(payload.credential);

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SignTransferTransaction,
          payload: {
            nearAccountId: payload.nearAccountId,
            receiverId: payload.receiverId,
            depositAmount: payload.depositAmount,
            nonce: payload.nonce,
            blockHashBytes: payload.blockHashBytes,
            // Contract verification parameters
            contractId: payload.contractId,
            vrfChallenge: payload.vrfChallenge,
            // Serialize credential right before sending - minimal exposure time
            credential: serializeCredentialWithPRF(payload.credential),
            nearRpcUrl: payload.nearRpcUrl,
            // Pass encrypted key data from IndexedDB
            encryptedPrivateKeyData: encryptedKeyData.encryptedData,
            encryptedPrivateKeyIv: encryptedKeyData.iv,
            prfOutput: dualPrfOutputs.aesPrfOutput
          }
        },
        onEvent, // onEvent callback for wasm-worker events
        timeoutMs: CONFIG.TIMEOUTS.TRANSACTION
      });

      if (isSignatureSuccess(response)) {
        console.log('WebAuthnManager: Enhanced transfer transaction signing successful with verification logs');
        const wasmResult = response.payload as WasmTransactionSignResult;

        if (!wasmResult.signedTransaction || !wasmResult.signedTransaction.transactionJson || !wasmResult.signedTransaction.signatureJson) {
          throw new Error('Incomplete signed transaction data received from worker');
        }

        return {
          signedTransaction: new SignedTransaction({
            transaction: JSON.parse(wasmResult.signedTransaction.transactionJson),
            signature: JSON.parse(wasmResult.signedTransaction.signatureJson),
            borsh_bytes: Array.from(wasmResult.signedTransaction.borshBytes || [])
          }),
          nearAccountId: payload.nearAccountId,
          logs: wasmResult.logs || []
        };
      } else {
        console.error('WebAuthnManager: Enhanced transfer transaction signing failed:', response);
        throw new Error('Enhanced transfer transaction signing failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: Enhanced transfer transaction signing error:', error);
      throw error;
    }
  }

  /**
   * Recover keypair from authentication credential for account recovery
   * Uses dual PRF-based Ed25519 key derivation with account-specific HKDF and AES encryption
   */
  async recoverKeypairFromPasskey(
    credential: PublicKeyCredential,
    challenge: string,
    accountIdHint?: string
  ): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    iv: string;
    accountIdHint?: string;
  }> {
    try {
      console.log('SignerWorkerManager: Starting dual PRF-based keypair recovery from authentication credential');

      // Serialize the authentication credential for the worker (includes dual PRF outputs)
      const serializedCredential = serializeCredentialWithPRF<WebAuthnAuthenticationCredential>(
        credential
      );

      // Verify dual PRF outputs are available
      if (!serializedCredential.clientExtensionResults?.prf?.results?.first ||
          !serializedCredential.clientExtensionResults?.prf?.results?.second) {
        throw new Error('Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available');
      }

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.RecoverKeypairFromPasskey,
          payload: {
            credential: serializedCredential,
            accountIdHint
          }
        }
      });

      if (isRecoverKeypairSuccess(response)) {
        console.log('SignerWorkerManager: Dual PRF keypair recovery successful');
        const wasmResult = response.payload as wasmModule.RecoverKeypairResult;
        return {
          publicKey: wasmResult.publicKey,
          encryptedPrivateKey: wasmResult.encryptedData,
          iv: wasmResult.iv,
          accountIdHint: wasmResult.accountIdHint
        };
      } else {
        console.error('SignerWorkerManager: Dual PRF-based keypair recovery failed:', response);
        throw new Error('Dual PRF keypair recovery failed in WASM worker');
      }
    } catch (error: any) {
      console.error('SignerWorkerManager: Dual PRF keypair recovery error:', error);
      throw error;
    }
  }

  /**
   * Extract COSE public key from WebAuthn attestation object
   * Simple operation that doesn't require TouchID or progress updates
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    try {
      console.log('SignerWorkerManager: Starting COSE public key extraction');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.ExtractCosePublicKey,
          payload: {
            attestationObjectBase64url
          }
        }
      });

      if (isCoseExtractionSuccess(response)) {
        console.log('SignerWorkerManager: COSE public key extraction successful');
        return response.payload.cosePublicKeyBytes;
      } else {
        console.error('SignerWorkerManager: COSE public key extraction failed:', response);
        throw new Error('COSE public key extraction failed in WASM worker');
      }
    } catch (error: any) {
      console.error('SignerWorkerManager: COSE public key extraction error:', error);
      throw error;
    }
  }

}