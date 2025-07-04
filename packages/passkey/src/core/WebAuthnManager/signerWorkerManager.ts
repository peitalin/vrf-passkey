import type { NearClient } from '../NearClient';
import { SignedTransaction } from "../NearClient";
import { base64UrlEncode, base58Decode } from '../../utils/encoders';
import type {
  WorkerResponse,
  ActionParams,
  WebAuthnRegistrationCredential
} from '../types/signer-worker';
import {
  WorkerRequestType,
  WorkerResponseType,
  isEncryptionSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isCoseKeySuccess,
  isCoseValidationSuccess,
  isCheckRegistrationSuccess,
  isRegistrationSuccess,
  validateActionParams,
  serializeCredentialAndCreatePRF,
  serializeRegistrationCredentialAndCreatePRF,
} from '../types/signer-worker';
import { ActionType } from '../types/actions';
import { ClientAuthenticatorData } from '../IndexedDBManager';
import { TouchIdPrompt } from "./touchIdPrompt";
import { VRFChallenge } from '../types/webauthn';
import type { onProgressEvents } from '../types/webauthn';

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: Challenge store removed as VRF provides cryptographic freshness
 * without needing centralized challenge management
 */
export class SignerWorkerManager {

  constructor() {}

  createSecureWorker(): Worker {
    // Simple path resolution - build:all copies worker files to /workers/
    const workerUrl = new URL('/workers/web3authn-signer.worker.js', window.location.origin);
    console.log('Creating secure worker from:', workerUrl.href);

    try {
      const worker = new Worker(workerUrl, {
        type: 'module',
        name: 'Web3AuthnSignerWorker'
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
   * - Fallback behavior for backward compatibility
   */
  private async executeWorkerOperation({
    message,
    onEvent,
    timeoutMs = 30_000 // 30s
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
      let finalResponse: WorkerResponse | null = null;

      worker.onmessage = (event) => {
        const response = event.data as WorkerResponse;
        responses.push(response);

        // Handle progress updates
        if (response.type === WorkerResponseType.VERIFICATION_PROGRESS ||
            response.type === WorkerResponseType.SIGNING_PROGRESS ||
            response.type === WorkerResponseType.REGISTRATION_PROGRESS) {
          const payload = (response as any).payload;
          onEvent?.(payload);
          return; // Continue listening for more messages
        }

        // Handle completion messages
        if (response.type === WorkerResponseType.VERIFICATION_COMPLETE) {
          const verificationResult = (response as any).payload;
          onEvent?.(verificationResult);

          if (!verificationResult.success) {
            clearTimeout(timeoutId);
            worker.terminate();
            reject(new Error(`Verification failed: ${verificationResult.error}`));
            return;
          }
          return; // Continue listening for signing messages
        }

        // Handle final completion
        if (response.type === WorkerResponseType.SIGNING_COMPLETE ||
            response.type === WorkerResponseType.REGISTRATION_COMPLETE) {
          clearTimeout(timeoutId);
          worker.terminate();
          finalResponse = response;
          resolve(finalResponse);
          return;
        }

        // Handle errors
        if (response.type === WorkerResponseType.ERROR) {
          clearTimeout(timeoutId);
          worker.terminate();
          reject(new Error((response as any).payload.error));
          return;
        }

        // Handle other completion types (fallback to existing behavior)
        if (response.type.includes('SUCCESS') || response.type.includes('FAILURE')) {
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

      worker.postMessage(message);
    });
  }

  // === PRF OPERATIONS ===

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async deriveNearKeypairAndEncrypt(
    credential: PublicKeyCredential,
    nearAccountId: string,
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {

    const attestationObject = credential.response as AuthenticatorAttestationResponse
    const prfOutput = credential.getClientExtensionResults()?.prf?.results?.first as ArrayBuffer;
    if (!prfOutput) {
      throw new Error('PRF output not found in WebAuthn credentials');
    }

    try {
      console.log('WebAuthnManager: Starting secure registration with PRF using deterministic derivation');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.DERIVE_NEAR_KEYPAIR_AND_ENCRYPT,
          payload: {
            prfOutput: base64UrlEncode(prfOutput),
            nearAccountId: nearAccountId,
            attestationObjectBase64url: base64UrlEncode(attestationObject.attestationObject)
          }
        }
      });

      if (isEncryptionSuccess(response)) {
        console.log('WebAuthnManager: PRF registration successful with deterministic derivation');
        return {
          success: true,
          nearAccountId: nearAccountId,
          publicKey: response.payload.publicKey
        };
      } else {
        console.error('WebAuthnManager: PRF registration failed:', response);
        return {
          success: false,
          nearAccountId: nearAccountId,
          publicKey: ''
        };
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF registration error:', error);
      return {
        success: false,
        nearAccountId: nearAccountId,
        publicKey: ''
      };
    }
  }

  /**
   * Secure private key decryption with PRF
   *
   * For local private key export, we're just decrypting locally stored encrypted private keys
   *    - No network communication with servers
   *    - No transaction signing or blockchain interaction
   *    - No replay attack surface since nothing is transmitted
   *    - Security comes from device possession + biometrics
   *    - This is equivalent to: "If you can unlock your phone, you can access your local keychain"
   *
   * PRF DETERMINISTIC KEY DERIVATION: WebAuthn PRF provides cryptographic guarantees
   *    - Same SALT + same authenticator = same PRF output (deterministic)
   *    - Different SALT + same authenticator = different PRF output
   *    - Use a fixed user-scoped salt (sha256(`prf-salt:${accountId}`)) for deterministic PRF output
   *    - Impossible to derive PRF output without the physical authenticator
   */
  async decryptPrivateKeyWithPrf(
    touchIdPrompt: TouchIdPrompt,
    nearAccountId: string,
    authenticators: ClientAuthenticatorData[],
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    try {
      console.log('WebAuthnManager: Starting private key decryption with PRF (local operation)');
      console.log('WebAuthnManager: Security enforced by device possession + biometrics + PRF cryptography');

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
      const prfOutput = credential.getClientExtensionResults()?.prf?.results?.first as ArrayBuffer;
      if (!prfOutput) {
        throw new Error('PRF output not found in WebAuthn credentials');
      }

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF,
          payload: {
            nearAccountId: nearAccountId,
            prfOutput: base64UrlEncode(prfOutput)
          }
        }
      });

      if (isDecryptionSuccess(response)) {
        console.log('WebAuthnManager: PRF private key decryption successful');
        return {
          decryptedPrivateKey: response.payload.decryptedPrivateKey,
          nearAccountId: nearAccountId
        };
      } else {
        console.error('WebAuthnManager: PRF private key decryption failed:', response);
        throw new Error('Private key decryption failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF private key decryption error:', error);
      throw error;
    }
  }

  // === COSE OPERATIONS ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    console.log('WebAuthnManager: Extracting COSE public key from attestation object');

    const response = await this.executeWorkerOperation({
      message: {
        type: WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY,
        payload: {
          attestationObjectBase64url
        }
      }
    });

    if (isCoseKeySuccess(response)) {
      console.log('WebAuthnManager: COSE public key extraction successful');
      return new Uint8Array(response.payload.cosePublicKeyBytes);
    } else {
      console.error('WebAuthnManager: COSE public key extraction failed:', response);
      throw new Error('Failed to extract COSE public key from attestation object');
    }
  }

  /**
   * Validate COSE key format using WASM worker
   */
  async validateCoseKey(coseKeyBytes: Uint8Array): Promise<{ valid: boolean; info: any }> {
    console.log('WebAuthnManager: Validating COSE key format');
    const response = await this.executeWorkerOperation({
      message: {
        type: WorkerRequestType.VALIDATE_COSE_KEY,
        payload: {
          coseKeyBytes: Array.from(coseKeyBytes)
        }
      }
    });

    if (isCoseValidationSuccess(response)) {
      console.log('WebAuthnManager: COSE key validation successful');
      return {
        valid: response.payload.valid,
        info: response.payload.info
      };
    } else {
      console.error('WebAuthnManager: COSE key validation failed:', response);
      throw new Error('Failed to validate COSE key format');
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
          type: WorkerRequestType.CHECK_CAN_REGISTER_USER,
          payload: {
            vrfChallenge,
            credential: serializeRegistrationCredentialAndCreatePRF(credential),
            contractId,
            nearRpcUrl
          }
        },
        onEvent,
        timeoutMs: 60000 // Longer timeout for contract verification
      });

      if (isCheckRegistrationSuccess(response)) {
        console.log('WebAuthnManager: User can be registered on-chain');
        return {
          success: true,
          verified: response.payload.verified,
          registrationInfo: response.payload.registrationInfo,
          logs: response.payload.logs,
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
          type: WorkerRequestType.SIGN_VERIFY_AND_REGISTER_USER,
          payload: {
            vrfChallenge,
            credential: serializeRegistrationCredentialAndCreatePRF(credential),
            contractId,
            signerAccountId,
            nearAccountId,
            nonce: nonce.toString(),
            blockHashBytes: transactionBlockHashBytes
          }
        },
        onEvent,
        timeoutMs: 90000 // Extended timeout for transaction processing
      });

      if (isRegistrationSuccess(response)) {
        console.log('WebAuthnManager: On-chain user registration transaction successful');
        return {
          verified: response.payload.verified,
          registrationInfo: response.payload.registrationInfo,
          logs: response.payload.logs,
          signedTransaction: new SignedTransaction({
            transaction: response.payload.signedTransaction.transaction,
            signature: response.payload.signedTransaction.signature,
            borsh_bytes: response.payload.signedTransaction.borsh_bytes
          }),
          preSignedDeleteTransaction: new SignedTransaction({
            transaction: response.payload.preSignedDeleteTransaction.transaction,
            signature: response.payload.preSignedDeleteTransaction.signature,
            borsh_bytes: response.payload.preSignedDeleteTransaction.borsh_bytes
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

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS,
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
            credential: serializeCredentialAndCreatePRF(payload.credential),
            nearRpcUrl: payload.nearRpcUrl
          }
        },
        onEvent, // onEvent callback for wasm-worker events
        timeoutMs: 60000 // Longer timeout for contract verification + signing
      });

      if (response.type === WorkerResponseType.SIGNING_COMPLETE && (response as any).payload.success) {
        console.log('WebAuthnManager: Enhanced transaction signing successful with verification logs');
        return {
          signedTransaction: new SignedTransaction({
            transaction: response.payload.data.signed_transaction.transaction,
            signature: response.payload.data.signed_transaction.signature,
            borsh_bytes: response.payload.data.signed_transaction.borsh_bytes
          }),
          nearAccountId: response.payload.data.near_account_id,
          logs: response.payload.data.verification_logs
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

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.SIGN_TRANSFER_TRANSACTION,
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
            credential: serializeCredentialAndCreatePRF(payload.credential),
            nearRpcUrl: payload.nearRpcUrl
          }
        },
        onEvent, // onEvent callback for wasm-worker events
        timeoutMs: 60000 // Longer timeout for contract verification + signing
      });

      if (response.type === WorkerResponseType.SIGNING_COMPLETE && (response as any).payload.success) {
        console.log('WebAuthnManager: Enhanced transfer transaction signing successful with verification logs');
        return {
          signedTransaction: new SignedTransaction({
            transaction: response.payload.data.signed_transaction.transaction,
            signature: response.payload.data.signed_transaction.signature,
            borsh_bytes: response.payload.data.signed_transaction.borsh_bytes
          }),
          nearAccountId: (response as any).payload.data.near_account_id,
          logs: (response as any).payload.data.verification_logs
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
   * Recover keypair from registration credential for account recovery
   * Uses COSE public key extraction and deterministic derivation
   */
  async recoverKeypairFromPasskey(
    registrationCredential: WebAuthnRegistrationCredential,
    challenge: string,
    accountIdHint?: string
  ): Promise<{
    publicKey: string;
    accountIdHint?: string;
  }> {
    try {
      console.log('SignerWorkerManager: Starting keypair recovery from registration credential');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.RECOVER_KEYPAIR_FROM_PASSKEY,
          payload: {
            credential: registrationCredential,
            challenge,
            accountIdHint
          }
        }
      });

      if (response.type === WorkerResponseType.RECOVER_KEYPAIR_SUCCESS) {
        console.log('SignerWorkerManager: Recover keypair derivation successful');
        return {
          publicKey: (response as any).payload.publicKey,
          accountIdHint: (response as any).payload.accountIdHint
        };
      } else {
        console.error('SignerWorkerManager: Deterministic keypair derivation failed:', response);
        throw new Error('Deterministic keypair derivation failed in WASM worker');
      }
    } catch (error: any) {
      console.error('SignerWorkerManager: Deterministic keypair derivation error:', error);
      throw error;
    }
  }

}