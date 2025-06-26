import { bufferEncode } from '../../utils/encoders';
import type {
  WorkerResponse,
  RegistrationPayload,
  SigningPayload,
  ActionParams
} from '../types/worker';
import {
  WorkerRequestType,
  WorkerResponseType,
  isEncryptionSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isCoseKeySuccess,
  isCoseValidationSuccess,
  isRegistrationSuccess,
  validateActionParams,
  ActionType,
  serializeCredentialAndCreatePRF,
  serializeRegistrationCredentialAndCreatePRF,
} from '../types/worker';
import { ClientAuthenticatorData } from '../IndexedDBManager';
import { TouchIdPrompt } from "./touchIdPrompt";
import { VRFChallenge } from '../types/webauthn';
import { RPC_NODE_URL } from "../../config";

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
   * === UNIFIED WORKER OPERATION METHOD ===
   * Execute worker operation with optional progress updates (handles both single and multiple response patterns)
   *
   * FEATURES:
   * ✅ Single-response operations (traditional request-response)
   * ✅ Multi-response operations with progress updates (streaming SSE-like pattern)
   * ✅ Consistent error handling and timeouts
   * ✅ Fallback behavior for backward compatibility
   */
  private async executeWorkerOperation({
    message,
    onProgress,
    timeoutMs = 30_000 // 30s
  }: {
    message: Record<string, any>,
    onProgress?: (update: { step: string; message: string; data?: any; logs?: string[] }) => void,
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
          onProgress?.({
            step: (response as any).payload.step,
            message: (response as any).payload.message,
            data: (response as any).payload.data,
            logs: (response as any).payload.logs
          });
          return; // Continue listening for more messages
        }

        // Handle completion messages
        if (response.type === WorkerResponseType.VERIFICATION_COMPLETE) {
          const verificationResult = (response as any).payload;
          onProgress?.({
            step: 'verification_complete',
            message: verificationResult.success ? 'Contract verification successful' : 'Contract verification failed',
            data: verificationResult.data,
            logs: verificationResult.logs
          });

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
    prfOutput: ArrayBuffer,
    payload: RegistrationPayload,
    attestationObject: AuthenticatorAttestationResponse,
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    try {
      console.log('WebAuthnManager: Starting secure registration with PRF using deterministic derivation');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.DERIVE_NEAR_KEYPAIR_AND_ENCRYPT,
          payload: {
            prfOutput: bufferEncode(prfOutput),
            nearAccountId: payload.nearAccountId,
            attestationObjectBase64url: bufferEncode(attestationObject.attestationObject)
          }
        }
      });

      if (isEncryptionSuccess(response)) {
        console.log('WebAuthnManager: PRF registration successful with deterministic derivation');
        return {
          success: true,
          nearAccountId: payload.nearAccountId,
          publicKey: response.payload.publicKey
        };
      } else {
        console.error('WebAuthnManager: PRF registration failed:', response);
        return {
          success: false,
          nearAccountId: payload.nearAccountId,
          publicKey: ''
        };
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF registration error:', error);
      return {
        success: false,
        nearAccountId: payload.nearAccountId,
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
      const { prfOutput } = await touchIdPrompt.getCredentialsAndPrf({
        nearAccountId,
        challenge,
        authenticators,
      });

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF,
          payload: {
            nearAccountId: nearAccountId,
            prfOutput: bufferEncode(prfOutput)
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

  /**
   * Register WebAuthn credential with VRF verification
   * Calls verify_registration_response on the contract to register a new credential
   */
  async registerWithPrf({
    vrfChallenge,
    webauthnCredential,
    contractId,
    onProgress,
  }: {
    vrfChallenge: VRFChallenge,
    webauthnCredential: PublicKeyCredential,
    contractId: string;
    onProgress?: (update: { step: string; message: string; data?: any; logs?: string[] }) => void
  }): Promise<{ verified: boolean; registrationInfo?: any; logs?: string[] }> {
    try {
      console.log('WebAuthnManager: Starting WebAuthn registration with VRF verification');

      const response = await this.executeWorkerOperation({
        message: {
          type: WorkerRequestType.REGISTER_WITH_PRF,
          payload: {
            vrfChallenge,
            webauthnCredential: serializeRegistrationCredentialAndCreatePRF(webauthnCredential),
            contractId,
            nearRpcUrl: RPC_NODE_URL
          }
        },
        onProgress,
        timeoutMs: 60000 // Longer timeout for contract verification
      });

      if (isRegistrationSuccess(response)) {
        console.log('WebAuthnManager: WebAuthn registration with VRF verification successful');
        return {
          verified: response.payload.verified,
          registrationInfo: response.payload.registrationInfo,
          logs: response.payload.logs
        };
      } else {
        console.error('WebAuthnManager: WebAuthn registration with VRF verification failed:', response);
        throw new Error('WebAuthn registration with VRF verification failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: WebAuthn registration with VRF verification error:', error);
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
      webauthnCredential: PublicKeyCredential;
    },
    onProgress?: (update: { step: string; message: string; data?: any; logs?: string[] }) => void
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string; logs?: string[] }> {
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
            webauthnCredential: serializeCredentialAndCreatePRF(payload.webauthnCredential),
            nearRpcUrl: RPC_NODE_URL
          }
        },
        onProgress, // onProgress callback for wasm-worker events
        timeoutMs: 60000 // Longer timeout for contract verification + signing
      });

      if (response.type === WorkerResponseType.SIGNING_COMPLETE && (response as any).payload.success) {
        console.log('WebAuthnManager: Enhanced transaction signing successful with verification logs');
        return {
          signedTransactionBorsh: (response as any).payload.data.signedTransactionBorsh,
          nearAccountId: payload.nearAccountId,
          logs: (response as any).payload.data.verificationLogs
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
      webauthnCredential: PublicKeyCredential;
    },
    onProgress?: (update: { step: string; message: string; data?: any; logs?: string[] }) => void
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string; logs?: string[] }> {
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
            webauthnCredential: serializeCredentialAndCreatePRF(payload.webauthnCredential),
            nearRpcUrl: RPC_NODE_URL
          }
        },
        onProgress, // onProgress callback for wasm-worker events
        timeoutMs: 60000 // Longer timeout for contract verification + signing
      });

      if (response.type === WorkerResponseType.SIGNING_COMPLETE && (response as any).payload.success) {
        console.log('WebAuthnManager: Enhanced transfer transaction signing successful with verification logs');
        return {
          signedTransactionBorsh: (response as any).payload.data.signedTransactionBorsh,
          nearAccountId: payload.nearAccountId,
          logs: (response as any).payload.data.verificationLogs
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

}