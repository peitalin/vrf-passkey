import { bufferEncode } from '../../utils/encoders';
import type { WorkerResponse } from '../types/worker';

// === INTERFACES ===

export interface WebAuthnChallenge {
  id: string;
  challenge: string; // Base64url encoded challenge from server
  timestamp: number;
  used: boolean;
  operation: 'registration' | 'authentication';
  timeout: number;
}

export interface PrfSaltConfig {
  nearKeyEncryption: Uint8Array;
}

export interface RegistrationPayload {
  nearAccountId: string;
}

export interface SigningPayload {
  nearAccountId: string;
  receiverId: string;
  contractMethodName: string;
  contractArgs: Record<string, any>;
  gasAmount: string;
  depositAmount: string;
  nonce: string;
  blockHashBytes: number[];
}

// === WORKER TYPES ===

export enum WorkerRequestType {
  ENCRYPT_PRIVATE_KEY_WITH_PRF = 'ENCRYPT_PRIVATE_KEY_WITH_PRF',
  DECRYPT_PRIVATE_KEY_WITH_PRF = 'DECRYPT_PRIVATE_KEY_WITH_PRF',
  DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF = 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF',
  EXTRACT_COSE_PUBLIC_KEY = 'EXTRACT_COSE_PUBLIC_KEY',
  VALIDATE_COSE_KEY = 'VALIDATE_COSE_KEY'
}

// Type guards for worker responses
export function isEncryptionSuccess(response: WorkerResponse): response is WorkerResponse & { payload: { publicKey: string } } {
  return response.type === 'ENCRYPTION_SUCCESS';
}

export function isSignatureSuccess(response: WorkerResponse): response is WorkerResponse & { payload: { signedTransactionBorsh: number[] } } {
  return response.type === 'SIGNATURE_SUCCESS';
}

export function isDecryptionSuccess(response: WorkerResponse): response is WorkerResponse & { payload: { decryptedPrivateKey: string } } {
  return response.type === 'DECRYPTION_SUCCESS';
}

export function isCoseKeySuccess(response: WorkerResponse): response is WorkerResponse & { payload: { cosePublicKeyBytes: number[] } } {
  return response.type === 'COSE_KEY_SUCCESS';
}

export function isCoseValidationSuccess(response: WorkerResponse): response is WorkerResponse & { payload: { valid: boolean; info: any } } {
  return response.type === 'COSE_VALIDATION_SUCCESS';
}

/**
 * WebAuthnWorkers handles PRF, challenges, workers, and COSE operations
 */
export class WebAuthnWorkers {
  private readonly activeChallenges = new Map<string, WebAuthnChallenge>();
  private readonly CHALLENGE_TIMEOUT = 30000; // 30 seconds
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute
  private readonly PRF_SALTS: PrfSaltConfig = {
    nearKeyEncryption: new Uint8Array(new Array(32).fill(42))
  };

  constructor() {
    // Start cleanup interval for expired challenges
    setInterval(() => this.cleanupExpiredChallenges(), this.CLEANUP_INTERVAL);
  }

  // === CHALLENGE MANAGEMENT ===

  registerServerChallenge(
    serverChallenge: string,
    operation: 'registration' | 'authentication'
  ): string {
    const challengeId = `${operation}_${Date.now()}_${Math.random().toString(36).substring(2)}`;

    const challenge: WebAuthnChallenge = {
      id: challengeId,
      challenge: serverChallenge,
      timestamp: Date.now(),
      used: false,
      operation,
      timeout: this.CHALLENGE_TIMEOUT
    };

    this.activeChallenges.set(challengeId, challenge);
    console.log(`Registered ${operation} challenge: ${challengeId}`);
    return challengeId;
  }

  validateAndConsumeChallenge(
    challengeId: string,
    operation: 'registration' | 'authentication'
  ): WebAuthnChallenge {
    const challenge = this.activeChallenges.get(challengeId);

    if (!challenge) {
      throw new Error(`Challenge ${challengeId} not found`);
    }

    if (challenge.used) {
      throw new Error(`Challenge ${challengeId} has already been used`);
    }

    if (challenge.operation !== operation) {
      throw new Error(`Challenge ${challengeId} is for ${challenge.operation}, not ${operation}`);
    }

    const now = Date.now();
    if (now - challenge.timestamp > challenge.timeout) {
      this.activeChallenges.delete(challengeId);
      throw new Error(`Challenge ${challengeId} has expired`);
    }

    // Mark as used and remove from active challenges
    challenge.used = true;
    this.activeChallenges.delete(challengeId);

    console.log(`Validated and consumed ${operation} challenge: ${challengeId}`);
    return challenge;
  }

  private cleanupExpiredChallenges(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [challengeId, challenge] of this.activeChallenges.entries()) {
      if (now - challenge.timestamp > challenge.timeout) {
        this.activeChallenges.delete(challengeId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Cleaned up ${cleaned} expired challenges`);
    }
  }

  clearAllChallenges(): void {
    this.activeChallenges.clear();
    console.log('Cleared all WebAuthn challenges');
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
    challengeId?: string,
    skipChallengeValidation: boolean = false
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    try {
      if (!skipChallengeValidation && challengeId) {
        this.validateAndConsumeChallenge(challengeId, 'registration');
        console.log('WebAuthnManager: Challenge validated for PRF registration');
      }

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
   */
  async secureTransactionSigningWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: SigningPayload,
    challengeId: string
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    try {
      // Skip challenge validation for serverless mode (challengeId starts with 'serverless-')
      // SECURITY NOTE: the contract will replace it with a proper challenge after
      if (!challengeId.startsWith('serverless-')) {
        this.validateAndConsumeChallenge(challengeId, 'authentication');
        console.log('WebAuthnManager: Challenge validated for PRF signing');
      } else {
        console.log('WebAuthnManager: Skipping challenge validation for serverless mode');
      }

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
    prfOutput: ArrayBuffer,
    challengeId: string // Parameter kept for API compatibility, but not used for validation
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    try {
      // For local private key decryption, we don't need challenge validation
      // The security comes from device possession + biometric verification + PRF cryptography
      // See additional security notes in the comments above
      console.log('WebAuthnManager: Starting secure private key decryption with PRF (local operation)');
      console.log('WebAuthnManager: Skipping challenge validation - security enforced by device possession + biometrics');

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