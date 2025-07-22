import type { NearClient } from '../NearClient';
import { getNonceBlockHashAndHeight } from "../PasskeyManager/actions";
import { SignedTransaction } from "../NearClient";
import { base64UrlEncode, base64UrlDecode, base58Decode } from '../../utils/encoders';
import type {
  ActionParams,
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
  WasmEncryptionResult,
  WasmRegistrationResult,
  WasmTransactionSignResult,
  WasmRecoverKeypairResult,
  WorkerResponseForRequest,
  SuccessPayloadForRequest,
  EncryptionResponse,
  RecoveryResponse,
  CheckRegistrationResponse,
  RegistrationResponse,
  TransactionResponse,
  DecryptionResponse,
  CoseExtractionResponse,
  WorkerErrorResponse,
  WorkerProgressResponse,
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
  isWorkerProgress,
  takeAesPrfOutput,
  extractEncryptionResult,
  extractTransactionResult,
  extractRegistrationResult,
  extractRecoveryResult,
} from '../types/signer-worker';
import { ClientAuthenticatorData } from '../IndexedDBManager';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from '../IndexedDBManager/passkeyNearKeysDB';
import { TouchIdPrompt } from "./touchIdPrompt";
import { VRFChallenge } from '../types/webauthn';
import type { onProgressEvents } from '../types/webauthn';
import { jsonTryParse } from '../../utils';
import { BUILD_PATHS } from '../../../build-paths.js';
import { AccountId, validateBaseAccountId } from "../types/accountIds";

// === CONFIGURATION ===
const CONFIG = {
  TIMEOUTS: {
    DEFAULT: 20_000,      // 20s
    TRANSACTION: 60_000,  // 60s for contract verification + signing
    REGISTRATION: 60_000, // 60s for registration operations
  },
  WORKER: {
    URL: BUILD_PATHS.RUNTIME.SIGNER_WORKER,
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
    console.debug('Creating secure worker from:', workerUrl.href);

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
   * - Generic typing based on request type for better type safety
   */
  private async executeWorkerOperation<T extends WorkerRequestType>({
    message,
    onEvent,
    timeoutMs = CONFIG.TIMEOUTS.DEFAULT // 20s
  }: {
    message: { type: T } & Record<string, any>,
    onEvent?: (update: onProgressEvents) => void,
    timeoutMs?: number
  }): Promise<WorkerResponseForRequest<T>> {

    const worker = this.createSecureWorker();

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Worker operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const responses: WorkerResponseForRequest<T>[] = [];

      worker.onmessage = (event) => {
        // Use strong typing from WASM-generated types
        const response = event.data as WorkerResponseForRequest<T>;
        responses.push(response);

        // Handle progress updates using WASM-generated numeric enum values
        if (
          response.type === WorkerResponseType.VerificationProgress ||
          response.type === WorkerResponseType.SigningProgress ||
          response.type === WorkerResponseType.RegistrationProgress ||
          response.type === WorkerResponseType.VerificationComplete || // Treat as progress, not final completion
          response.type === WorkerResponseType.SigningComplete ||      // Treat as progress, not final completion
          response.type === WorkerResponseType.RegistrationComplete    // Treat as progress, not final completion
        ) {
          const progressResponse = response as WorkerProgressResponse;
          onEvent?.(progressResponse.payload as onProgressEvents);
          return; // Continue listening for more messages
        }

        // Handle errors using WASM-generated enum
        if (response.type === WorkerResponseType.Error) {
          clearTimeout(timeoutId);
          worker.terminate();
          const errorResponse = response as WorkerErrorResponse;
          reject(new Error(errorResponse.payload.error));
          return;
        }

        // Handle successful completion types using strong typing
        if (isWorkerSuccess(response)) {
          clearTimeout(timeoutId);
          worker.terminate();
          resolve(response as WorkerResponseForRequest<T>);
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
   * Optionally signs a verify_and_register_user transaction if VRF data is provided
   */
  async deriveNearKeypairAndEncrypt(
    credential: PublicKeyCredential,
    nearAccountId: AccountId,
    options?: {
      vrfChallenge?: VRFChallenge;
      contractId?: string;
      nearRpcUrl?: string;
      nonce?: string;
      blockHashBytes?: number[];
    }
  ): Promise<{
    success: boolean;
    nearAccountId: AccountId;
    publicKey: string;
    signedTransaction?: SignedTransaction;
  }> {
    try {
      console.info('WebAuthnManager: Starting secure registration with dual PRF using deterministic derivation');

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

      // Use generic executeWorkerOperation with specific request type for better type safety
      const response = await this.executeWorkerOperation<typeof WorkerRequestType.DeriveNearKeypairAndEncrypt>({
        message: {
          type: WorkerRequestType.DeriveNearKeypairAndEncrypt,
          payload: {
            dualPrfOutputs,
            nearAccountId: nearAccountId,
            // Optional device linking registration transaction
            registrationTransaction: (options?.vrfChallenge && options?.contractId && options?.nonce && options?.blockHashBytes) ? {
              vrfChallenge: options.vrfChallenge,
              contractId: options.contractId,
              nonce: options.nonce,
              blockHashBytes: options.blockHashBytes,
            } : undefined,
          }
        }
      });

      // Response is specifically EncryptionSuccessResponse | EncryptionFailureResponse
      if (!isEncryptionSuccess(response)) {
        throw new Error('Dual PRF registration failed');
      }

      console.debug('WebAuthnManager: Dual PRF registration successful with deterministic derivation');
      // response.payload is a WasmEncryptionResult with proper WASM types
      const wasmResult = response.payload;
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
      console.info('WebAuthnManager: Encrypted key stored and verified in IndexedDB');

      // Convert optional WASM signed transaction to SignedTransaction object
      let signedTransaction: SignedTransaction | undefined = undefined;
      if (wasmResult.signedTransaction) {
        signedTransaction = new SignedTransaction({
          transaction: jsonTryParse(wasmResult.signedTransaction.transactionJson),
          signature: jsonTryParse(wasmResult.signedTransaction.signatureJson),
          borsh_bytes: Array.from(wasmResult.signedTransaction.borshBytes || [])
        });
      }

      return {
        success: true,
        nearAccountId: validateBaseAccountId(wasmResult.nearAccountId),
        publicKey: wasmResult.publicKey,
        signedTransaction
      };
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
   *    - Equivalent to: "If you can unlock your phone, you can access your local keychain"
   *
   * DUAL PRF DETERMINISTIC KEY DERIVATION: WebAuthn dual PRF provides cryptographic guarantees
   *    - Same SALT + same authenticator = same PRF output (deterministic)
   *    - Different SALT + same authenticator = different PRF output
   *    - Use account-specific salts for both AES and Ed25519 PRF derivation
   *    - Impossible to derive PRF output without the physical authenticator
   */
  async decryptPrivateKeyWithPrf(
    touchIdPrompt: TouchIdPrompt,
    nearAccountId: AccountId,
    authenticators: ClientAuthenticatorData[],
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: AccountId }> {
    try {
      console.info('WebAuthnManager: Starting private key decryption with dual PRF (local operation)');

      // Retrieve encrypted key data from IndexedDB in main thread
      console.debug('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', nearAccountId);
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
      console.debug('WebAuthnManager: Extracted dual PRF outputs, using AES PRF for decryption');

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

      if (!isDecryptionSuccess(response)) {
        console.error('WebAuthnManager: Dual PRF private key decryption failed:', response);
        throw new Error('Private key decryption failed');
      }
      console.info('WebAuthnManager: Dual PRF private key decryption successful');
      const wasmResult = response.payload as wasmModule.DecryptPrivateKeyResult;
      return {
        decryptedPrivateKey: wasmResult.privateKey,
        nearAccountId: validateBaseAccountId(wasmResult.nearAccountId)
      };
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
      console.info('WebAuthnManager: Checking if user can be registered on-chain');

      const response = await this.executeWorkerOperation<typeof WorkerRequestType.CheckCanRegisterUser>({
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

      if (!isCheckRegistrationSuccess(response)) {
        throw Error("isCheckRegistrationSuccess failed")
      }

      console.info('WebAuthnManager: User can be registered on-chain');
      const wasmResult = response.payload as wasmModule.RegistrationCheckResult;
      return {
        success: true,
        verified: wasmResult.verified,
        registrationInfo: wasmResult.registrationInfo,
        logs: wasmResult.logs,
      };
    } catch (error: any) {
      console.error('WebAuthnManager: User cannot be registered on-chain:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Actually register user on-chain with transaction
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
    deterministicVrfPublicKey,
    signerAccountId,
    nearAccountId,
    nearPublicKeyStr,
    nearClient,
    nearRpcUrl,
    deviceNumber = 1, // Default to device number 1 for first device (1-indexed)
    onEvent,
  }: {
    vrfChallenge: VRFChallenge,
    credential: PublicKeyCredential,
    contractId: string;
    deterministicVrfPublicKey?: string; // Optional deterministic VRF key for dual registration
    signerAccountId: string;
    nearAccountId: AccountId;
    nearPublicKeyStr: string;
    nearClient: NearClient; // NEAR RPC client for getting transaction metadata
    nearRpcUrl: string; // NEAR RPC URL for contract verification
    deviceNumber?: number; // Device number for multi-device support (defaults to 1)
    onEvent?: (update: onProgressEvents) => void
  }): Promise<{
    verified: boolean;
    registrationInfo?: any;
    logs?: string[];
    signedTransaction: SignedTransaction;
    preSignedDeleteTransaction: SignedTransaction;
  }> {
    try {
      console.info('WebAuthnManager: Starting on-chain user registration with transaction');

      if (!nearPublicKeyStr) {
        throw new Error('Client NEAR public key not provided - cannot get access key nonce');
      }

      // Step 1: Get transaction metadata
      onEvent?.({
        step: 1,
        phase: 'preparation',
        status: 'progress',
        message: 'Preparing transaction metadata...',
      });

      // Retrieve encrypted key data from IndexedDB in main thread
      console.debug('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', nearAccountId);
      const encryptedKeyData = await this.nearKeysDB.getEncryptedKey(nearAccountId);
      if (!encryptedKeyData) {
        throw new Error(`No encrypted key found for account: ${nearAccountId}`);
      }

      // Extract PRF output from credential
      const dualPrfOutputs = extractDualPrfOutputs(credential);

      const {
        accessKeyInfo,
        nextNonce,
        txBlockHashBytes,
        txBlockHeight,
      } = await getNonceBlockHashAndHeight({ nearClient, nearPublicKeyStr, nearAccountId });

      console.debug('WebAuthnManager: Access key info received:', {
        signerAccountId,
        nearPublicKeyStr,
        accessKeyInfo,
        hasNonce: accessKeyInfo?.nonce !== undefined,
        nonceValue: accessKeyInfo?.nonce,
        nonceType: typeof accessKeyInfo?.nonce
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
            nonce: nextNonce,
            blockHashBytes: txBlockHashBytes,
            // Pass encrypted key data from IndexedDB
            encryptedPrivateKeyData: encryptedKeyData.encryptedData,
            encryptedPrivateKeyIv: encryptedKeyData.iv,
            prfOutput: dualPrfOutputs.aesPrfOutput,
            // Add missing nearRpcUrl field
            nearRpcUrl,
            deterministicVrfPublicKey,
            deviceNumber, // Pass device number for multi-device support
          }
        },
        onEvent,
        timeoutMs: CONFIG.TIMEOUTS.TRANSACTION
      });

      if (isRegistrationSuccess(response)) {
        console.debug('WebAuthnManager: On-chain user registration transaction successful');
        const wasmResult = response.payload;
        return {
          verified: wasmResult.verified,
          registrationInfo: wasmResult.registrationInfo,
          logs: wasmResult.logs,
          signedTransaction: new SignedTransaction({
            transaction: jsonTryParse(wasmResult.signedTransaction?.transactionJson),
            signature: jsonTryParse(wasmResult.signedTransaction?.signatureJson),
            borsh_bytes: Array.from(wasmResult.signedTransaction?.borshBytes || [])
          }),
          preSignedDeleteTransaction: new SignedTransaction({
            transaction: jsonTryParse(wasmResult.preSignedDeleteTransaction?.transactionJson),
            signature: jsonTryParse(wasmResult.preSignedDeleteTransaction?.signatureJson),
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
   * Sign multiple transactions with shared VRF challenge and credential
   * Efficiently processes multiple transactions with one PRF authentication
   */
  async signTransactionsWithActions({
    transactions,
    blockHashBytes,
    contractId,
    vrfChallenge,
    credential,
    nearRpcUrl,
    onEvent
  }: {
    transactions: Array<{
      nearAccountId: AccountId;
      receiverId: string;
      actions: ActionParams[];
      nonce: string;
    }>;
    blockHashBytes: number[];
    contractId: string;
    vrfChallenge: VRFChallenge;
    credential: PublicKeyCredential;
    nearRpcUrl: string;
    onEvent?: (update: onProgressEvents) => void
  }): Promise<Array<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[]
  }>> {
    try {
      console.info(`WebAuthnManager: Starting batch transaction signing for ${transactions.length} transactions`);

      if (transactions.length === 0) {
        throw new Error('No transactions provided for batch signing');
      }

      // Validate all actions in all payloads
      transactions.forEach((txPayload, txIndex) => {
        txPayload.actions.forEach((action, actionIndex) => {
          try {
            validateActionParams(action);
          } catch (error) {
            throw new Error(`Transaction ${txIndex}, Action ${actionIndex} validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        });
      });

      // All transactions should use the same account for signing
      const nearAccountId = transactions[0].nearAccountId;

      // Verify all payloads use the same account
      for (const tx of transactions) {
        if (tx.nearAccountId !== nearAccountId) {
          throw new Error('All transactions must be signed by the same account');
        }
      }

      // Retrieve encrypted key data from IndexedDB in main thread
      console.debug('WebAuthnManager: Retrieving encrypted key from IndexedDB for account:', nearAccountId);
      const encryptedKeyData = await this.nearKeysDB.getEncryptedKey(nearAccountId);
      if (!encryptedKeyData) {
        throw new Error(`No encrypted key found for account: ${nearAccountId}`);
      }

      // Extract dual PRF outputs from credential
      const dualPrfOutputs = extractDualPrfOutputs(credential);

      if (!dualPrfOutputs.aesPrfOutput || !dualPrfOutputs.ed25519PrfOutput) {
        throw new Error('Failed to extract PRF outputs from credential');
      }

      console.debug('WebAuthnManager: Sending batch transaction signing request to worker');

      // Create transaction signing requests
      const txSigningRequests = transactions.map(tx => ({
        nearAccountId: tx.nearAccountId,
        receiverId: tx.receiverId,
        actions: JSON.stringify(tx.actions),
        nonce: tx.nonce,
        blockHashBytes: blockHashBytes
      }));

      // Send batch signing request to WASM worker
      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SignTransactionsWithActions,
          payload: {
            verification: {
              contractId: contractId,
              nearRpcUrl: nearRpcUrl,
              vrfChallenge: vrfChallenge,
              credential: serializeCredentialWithPRF(credential)
            },
            decryption: {
              aesPrfOutput: dualPrfOutputs.aesPrfOutput,
              encryptedPrivateKeyData: encryptedKeyData.encryptedData,
              encryptedPrivateKeyIv: encryptedKeyData.iv
            },
            txSigningRequests: txSigningRequests
          }
        },
        onEvent
      });

      if (response.type !== WorkerResponseType.SignatureSuccess) {
        console.error('WebAuthnManager: Batch transaction signing failed:', response);
        throw new Error('Batch transaction signing failed');
      }

      const wasmResult = response.payload as WasmTransactionSignResult;

      // Check if the batch operation succeeded
      if (!wasmResult.success) {
        const errorMsg = wasmResult.error || 'Batch transaction signing failed';
        console.error('WebAuthnManager: Batch transaction operation failed:', {
          success: wasmResult.success,
          error: wasmResult.error,
          logs: wasmResult.logs
        });
        throw new Error(errorMsg);
      }

      // Extract arrays from the single result - wasmResult contains arrays of all transactions
      const signedTransactions = wasmResult.signedTransactions || [];

      if (signedTransactions.length !== transactions.length) {
        throw new Error(`Expected ${transactions.length} signed transactions but received ${signedTransactions.length}`);
      }

      // Process results for each transaction
      const results = signedTransactions.map((signedTx, index) => {
        if (!signedTx || !signedTx.transactionJson || !signedTx.signatureJson) {
          throw new Error(`Incomplete signed transaction data received for transaction ${index + 1}`);
        }

        return {
          signedTransaction: new SignedTransaction({
            transaction: jsonTryParse(signedTx.transactionJson),
            signature: jsonTryParse(signedTx.signatureJson),
            borsh_bytes: Array.from(signedTx.borshBytes || [])
          }),
          nearAccountId: transactions[index].nearAccountId,
          logs: wasmResult.logs
        };
      });

      console.debug(`WebAuthnManager: Batch transaction signing successful for ${results.length} transactions`);
      return results;

    } catch (error: any) {
      console.error('WebAuthnManager: Batch transaction signing error:', error);
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
      console.info('SignerWorkerManager: Starting dual PRF-based keypair recovery from authentication credential');
      // Serialize the authentication credential for the worker (includes dual PRF outputs)
      const serializedCredential = serializeCredentialWithPRF<WebAuthnAuthenticationCredential>(
        credential
      );

      // Verify dual PRF outputs are available
      if (!serializedCredential.clientExtensionResults?.prf?.results?.first ||
          !serializedCredential.clientExtensionResults?.prf?.results?.second) {
        throw new Error('Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available');
      }

      // Use generic executeWorkerOperation with specific request type for better type safety
      const response = await this.executeWorkerOperation<typeof WorkerRequestType.RecoverKeypairFromPasskey>({
        message: {
          type: WorkerRequestType.RecoverKeypairFromPasskey,
          payload: {
            credential: serializedCredential,
            accountIdHint
          }
        }
      });

      // response is RecoverKeypairSuccessResponse | RecoverKeypairFailureResponse
      if (isRecoverKeypairSuccess(response)) {
        console.debug('SignerWorkerManager: Dual PRF keypair recovery successful');
        // extractRecoveryResult extracts response.payload as a WasmRecoverKeypairResult
        const wasmResult = extractRecoveryResult(response);

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
      console.info('SignerWorkerManager: Starting COSE public key extraction');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.ExtractCosePublicKey,
          payload: {
            attestationObjectBase64url
          }
        }
      });

      if (isCoseExtractionSuccess(response)) {
        console.info('SignerWorkerManager: COSE public key extraction successful');
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

  /**
   * Sign transaction with raw private key (for key replacement in Option D device linking)
   * No TouchID/PRF required - uses provided private key directly
   */
  async signTransactionWithKeyPair({
    nearPrivateKey,
    signerAccountId,
    receiverId,
    nonce,
    blockHashBytes,
    actions
  }: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHashBytes: number[];
    actions: ActionParams[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    try {
      console.info('SignerWorkerManager: Starting transaction signing with provided private key');

      // Validate actions
      actions.forEach((action, index) => {
        try {
          validateActionParams(action);
        } catch (error) {
          throw new Error(`Action ${index} validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SignTransactionWithKeyPair,
          payload: {
            nearPrivateKey,
            signerAccountId,
            receiverId,
            nonce,
            blockHashBytes,
            actions: JSON.stringify(actions)
          }
        }
      });

      if (response.type !== WorkerResponseType.SignatureSuccess) {
        console.error('SignerWorkerManager: Transaction signing with private key failed:', response);
        throw new Error('Transaction signing with private key failed');
      }

      const wasmResult = response.payload as WasmTransactionSignResult;

      // Check if the operation succeeded
      if (!wasmResult.success) {
        const errorMsg = wasmResult.error || 'Transaction signing failed';
        console.error('SignerWorkerManager: Transaction signing operation failed:', {
          success: wasmResult.success,
          error: wasmResult.error,
          logs: wasmResult.logs
        });
        throw new Error(errorMsg);
      }

      // Extract the signed transaction
      const signedTransactions = wasmResult.signedTransactions || [];

      if (signedTransactions.length !== 1) {
        throw new Error(`Expected 1 signed transaction but received ${signedTransactions.length}`);
      }

      const signedTx = signedTransactions[0];
      if (!signedTx || !signedTx.transactionJson || !signedTx.signatureJson) {
        throw new Error('Incomplete signed transaction data received');
      }

      const result = {
        signedTransaction: new SignedTransaction({
          transaction: jsonTryParse(signedTx.transactionJson),
          signature: jsonTryParse(signedTx.signatureJson),
          borsh_bytes: Array.from(signedTx.borshBytes || [])
        }),
        logs: wasmResult.logs
      };

      console.debug('SignerWorkerManager: Transaction signing with private key successful');
      return result;

    } catch (error: any) {
      console.error('SignerWorkerManager: Transaction signing with private key error:', error);
      throw error;
    }
  }

}