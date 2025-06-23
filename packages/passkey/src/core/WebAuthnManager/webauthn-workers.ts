import { bufferEncode } from '../../utils/encoders';
import type {
  WorkerResponse,
  RegistrationPayload,
  SigningPayload
} from '../types/worker';
import {
  WorkerRequestType,
  isEncryptionSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isCoseKeySuccess,
  isCoseValidationSuccess,
  isVRFKeyPairSuccess,
  isVRFChallengeSuccess
} from '../types/worker';
import type {
  PrfSaltConfig
} from '../types/webauthn';

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: Challenge store removed as VRF provides cryptographic freshness
 * without needing centralized challenge management
 */
export class WebAuthnWorkers {
  private readonly PRF_SALTS: PrfSaltConfig = {
    nearKeyEncryption: new Uint8Array(new Array(32).fill(42))
  };

  constructor() {
    // No challenge cleanup needed - VRF provides cryptographic freshness
  }

  // === WORKER MANAGEMENT ===

  createSecureWorker(): Worker {
    // Simple path resolution - build:all copies worker files to /workers/
    const workerUrl = new URL('/workers/onetimePasskeySigner.worker.js', window.location.origin);

    console.log('Creating secure worker from:', workerUrl.href);

    try {
      const worker = new Worker(workerUrl, {
        type: 'module',
        name: 'PasskeyWorker'
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

  async executeWorkerOperation(
    worker: Worker,
    message: Record<string, any>,
    timeoutMs: number = 30000
  ): Promise<WorkerResponse> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        worker.terminate();
        reject(new Error(`Worker operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      worker.onmessage = (event) => {
        clearTimeout(timeoutId);
        worker.terminate();
        resolve(event.data as WorkerResponse);
      };

      worker.onerror = (error) => {
        clearTimeout(timeoutId);
        worker.terminate();
        reject(new Error(`Worker error: ${error}`));
      };

      console.log('Sending message to worker:', { type: message.type });
      worker.postMessage(message);
    });
  }

  // === PRF OPERATIONS ===

  getPrfSalts(): PrfSaltConfig {
    return this.PRF_SALTS;
  }

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async secureRegistrationWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: RegistrationPayload,
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    try {
      console.log('WebAuthnManager: Starting secure registration with PRF');

      const worker = this.createSecureWorker();
      const response = await this.executeWorkerOperation(worker, {
        type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF,
        payload: {
          prfOutput: bufferEncode(prfOutput),
          nearAccountId: payload.nearAccountId
        }
      });

      if (isEncryptionSuccess(response)) {
        console.log('WebAuthnManager: PRF registration successful');
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
   * Secure transaction signing with PRF: WebAuthn + WASM worker signing using PRF
   * Note: No challenge validation needed - VRF provides cryptographic freshness
   */
  async secureTransactionSigningWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: SigningPayload
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    try {
      console.log('WebAuthnManager: Starting secure transaction signing with PRF');

      const worker = this.createSecureWorker();

      const workerPayload = {
        nearAccountId: payload.nearAccountId,
        prfOutput: bufferEncode(prfOutput),
        receiverId: payload.receiverId,
        contractMethodName: payload.contractMethodName,
        contractArgs: payload.contractArgs,
        gasAmount: payload.gasAmount,
        depositAmount: payload.depositAmount,
        nonce: payload.nonce,
        blockHashBytes: payload.blockHashBytes
      };

      // Validate all required parameters are defined
      const requiredFields = ['nearAccountId', 'receiverId', 'contractMethodName', 'gasAmount', 'depositAmount', 'nonce'];
      const missingFields = requiredFields.filter(field => !workerPayload[field as keyof typeof workerPayload]);

      if (missingFields.length > 0) {
        throw new Error(`Missing required fields for transaction signing: ${missingFields.join(', ')}`);
      }

      if (!payload.blockHashBytes || payload.blockHashBytes.length === 0) {
        throw new Error('blockHashBytes is required and cannot be empty');
      }

      if (!prfOutput || prfOutput.byteLength === 0) {
        throw new Error('PRF output is required and cannot be empty');
      }

      console.log('WebAuthnManager: Worker payload for signing:', {
        ...workerPayload,
        prfOutput: `[${bufferEncode(prfOutput).length} chars]`, // Don't log the actual PRF
        blockHashBytes: `[${payload.blockHashBytes?.length || 0} bytes]`
      });

      const response = await this.executeWorkerOperation(worker, {
        type: WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF,
        payload: workerPayload
      });

      console.log('WebAuthnManager: Worker response debug:', {
        type: response.type,
        hasPayload: !!response.payload,
        isSignatureSuccessCheck: isSignatureSuccess(response)
      });

      if (response.type === 'SIGNATURE_SUCCESS' && response.payload?.signedTransactionBorsh) {
        console.log('WebAuthnManager: PRF transaction signing successful');
        return {
          signedTransactionBorsh: response.payload.signedTransactionBorsh,
          nearAccountId: payload.nearAccountId
        };
      } else {
        console.error('WebAuthnManager: PRF transaction signing failed:', response);
        throw new Error('Transaction signing failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF transaction signing error:', error);
      throw error;
    }
  }

  /**
   * Secure private key decryption with PRF
   *
   * For local private key export, we're just decrypting locally stored encrypted private keys
   *    - No network communication with servers
   *    - No transaction signing or blockchain interaction
   *    - No replay attack surface since nothing is transmitted
   *    - Security comes from device possession + biometrics, not challenge validation
   *
   * This is equivalent to: "If you can unlock your phone, you can access your local keychain"
   *
   * RANDOM CHALLENGE PURPOSE: Prevents pre-computation attacks
   *    - Fresh random challenge ensures PRF output cannot be pre-computed
   *    - Challenge doesn't need server validation - randomness is sufficient
   *    - Challenge is NOT a shared secret - it's public in WebAuthn clientDataJSON
   *
   * PRF DETERMINISTIC KEY DERIVATION: WebAuthn PRF provides cryptographic guarantees
   *    - Same SALT + same authenticator = same PRF output (deterministic)
   *    - Different SALT + same authenticator = different PRF output
   *    - We use FIXED salt (new Array(32).fill(42)) so we always get same PRF output
   *    - Challenge can be random because PRF depends on SALT, not challenge
   *    - Impossible to derive PRF output without the physical authenticator
   */
  async securePrivateKeyDecryptionWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    try {
      console.log('WebAuthnManager: Starting secure private key decryption with PRF (local operation)');
      console.log('WebAuthnManager: Security enforced by device possession + biometrics + PRF cryptography');

      const worker = this.createSecureWorker();
      const response = await this.executeWorkerOperation(worker, {
        type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        payload: {
          nearAccountId: nearAccountId,
          prfOutput: bufferEncode(prfOutput)
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
  async extractCosePublicKeyFromAttestation(attestationObjectBase64url: string): Promise<Uint8Array> {
    console.log('WebAuthnManager: Extracting COSE public key from attestation object');

    const worker = this.createSecureWorker();
    const response = await this.executeWorkerOperation(worker, {
      type: WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY,
      payload: {
        attestationObjectBase64url
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
  async validateCoseKeyFormat(coseKeyBytes: Uint8Array): Promise<{ valid: boolean; info: any }> {
    console.log('WebAuthnManager: Validating COSE key format');

    const worker = this.createSecureWorker();
    const response = await this.executeWorkerOperation(worker, {
      type: WorkerRequestType.VALIDATE_COSE_KEY,
      payload: {
        coseKeyBytes: Array.from(coseKeyBytes)
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
}