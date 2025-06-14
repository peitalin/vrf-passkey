import { WASM_WORKER_FILENAME } from '../../config';
import { bufferEncode, bufferDecode } from '../../utils/encoders';
import {
  WorkerRequestType,
  WorkerResponseType,
  type WorkerRequest,
  type WorkerResponse,
  isEncryptionSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isCoseKeySuccess,
  isCoseValidationSuccess,
  isWorkerError
} from '../types/worker';
import { indexDBManager } from '../IndexDBManager';
import type {
  GenerateRegistrationOptionsRequest,
  GenerateRegistrationOptionsResponse,
  GenerateAuthenticationOptionsRequest,
  GenerateAuthenticationOptionsResponse,
  VerifyRegistrationRequest,
  VerifyAuthenticationRequest,
  VerifyAuthenticationResponse
} from '../../types/endpoints';

// === CONSTANTS ===
const USER_DATA_DB_NAME = 'PasskeyUserData';
const USER_DATA_DB_VERSION = 1;
const USER_DATA_STORE_NAME = 'userData';

// === TYPE DEFINITIONS ===

interface UserData {
  username: string;
  nearAccountId?: string;
  clientNearPublicKey?: string;
  lastUpdated: number;
  prfSupported?: boolean;
  deterministicKey?: boolean;
  passkeyCredential?: {
    id: string;
    rawId: string;
  };
}

interface WebAuthnChallenge {
  id: string;
  challenge: string; // Base64url encoded challenge from server
  timestamp: number;
  used: boolean;
  operation: 'registration' | 'authentication';
  timeout: number;
}

interface RegistrationPayload {
  nearAccountId: string;
}

interface SigningPayload {
  nearAccountId: string;
  receiverId: string;
  contractMethodName: string;
  contractArgs: Record<string, any>;
  gasAmount: string;
  depositAmount: string;
  nonce: string;
  blockHashBytes: number[];
}

interface PrfSaltConfig {
  nearKeyEncryption: Uint8Array;
}

interface WebAuthnRegistrationWithPrf {
  credential: PublicKeyCredential;
  prfEnabled: boolean;
  commitmentId?: string;
}

interface WebAuthnAuthenticationWithPrf {
  credential: PublicKeyCredential;
  prfOutput?: ArrayBuffer;
}

interface RegistrationOptions {
  options: PublicKeyCredentialCreationOptions;
  challengeId: string;
  commitmentId?: string;
}

interface AuthenticationOptions {
  options: PublicKeyCredentialRequestOptions;
  challengeId: string;
}

/**
 * WebAuthnManager - Secure encapsulation of WebAuthn operations and WASM workers
 *
 * Key Security Features:
 * - Workers only created after successful WebAuthn challenges
 * - Single-use, time-limited challenges
 * - Atomic operations (one challenge = one worker = one operation)
 * - No direct worker access outside this class
 * - Automatic cleanup and termination
 * - PRF extension support for enhanced security
 */
export class WebAuthnManager {
  private readonly activeChallenges = new Map<string, WebAuthnChallenge>();
  private readonly CHALLENGE_TIMEOUT = 30000; // 30 seconds
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute
  private readonly PRF_SALTS: PrfSaltConfig = {
    nearKeyEncryption: new Uint8Array(new Array(32).fill(42))
  };

  constructor() {
    setInterval(() => this.cleanupExpiredChallenges(), this.CLEANUP_INTERVAL);
  }

  // === INDEXDB OPERATIONS (Now using unified IndexDBManager) ===

  /**
   * Store user data using unified IndexDBManager
   */
  async storeUserData(userData: UserData): Promise<void> {
    await indexDBManager.storeWebAuthnUserData(userData);
  }

  /**
   * Retrieve user data using unified IndexDBManager
   */
  async getUserData(username: string): Promise<UserData | null> {
    return await indexDBManager.getWebAuthnUserData(username);
  }

  /**
   * Get all user data using unified IndexDBManager
   */
  async getAllUserData(): Promise<UserData[]> {
    const allUsers = await indexDBManager.getAllUsers();
    return allUsers.map(user => ({
      username: user.username,
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: user.clientNearPublicKey,
      lastUpdated: user.lastUpdated,
      prfSupported: user.prfSupported,
      passkeyCredential: user.passkeyCredential
    }));
  }

  // === CONVENIENCE METHODS ===

  /**
   * Check if a passkey credential exists for a username
   */
  async hasPasskeyCredential(username: string): Promise<boolean> {
    return await indexDBManager.hasPasskeyCredential(username);
  }

  /**
   * Get the last used username from stored user data
   */
  async getLastUsedUsername(): Promise<string | null> {
    return await indexDBManager.getLastUsedUsername();
  }

  // === CHALLENGE MANAGEMENT ===

  /**
   * Register a server-generated challenge for tracking
   */
  private registerServerChallenge(
    serverChallenge: string,
    operation: 'registration' | 'authentication'
  ): string {
    const challengeId = crypto.randomUUID();
    const challenge: WebAuthnChallenge = {
      id: challengeId,
      challenge: serverChallenge,
      timestamp: Date.now(),
      used: false,
      operation,
      timeout: this.CHALLENGE_TIMEOUT
    };

    this.activeChallenges.set(challengeId, challenge);
    console.log(`WebAuthnManager: Registered ${operation} challenge ${challengeId}`);
    return challengeId;
  }

  /**
   * Validate and consume a challenge (single-use)
   */
  private validateAndConsumeChallenge(
    challengeId: string,
    operation: 'registration' | 'authentication'
  ): WebAuthnChallenge {
    const challenge = this.activeChallenges.get(challengeId);

    if (!challenge) {
      throw new Error('Invalid or expired challenge');
    }

    if (challenge.used) {
      throw new Error('Challenge already used');
    }

    if (challenge.operation !== operation) {
      throw new Error('Challenge operation mismatch');
    }

    if (Date.now() - challenge.timestamp > challenge.timeout) {
      this.activeChallenges.delete(challengeId);
      throw new Error('Challenge expired');
    }

    challenge.used = true;
    this.activeChallenges.delete(challengeId);
    return challenge;
  }

  /**
   * Clean up expired challenges
   */
  private cleanupExpiredChallenges(): void {
    const now = Date.now();
    for (const [id, challenge] of this.activeChallenges.entries()) {
      if (now - challenge.timestamp > challenge.timeout) {
        this.activeChallenges.delete(id);
      }
    }
  }

  /**
   * Clear all active challenges
   */
  clearAllChallenges(): void {
    this.activeChallenges.clear();
    console.log('WebAuthnManager: Cleared all active challenges');
  }

  // === WORKER OPERATIONS ===

  /**
   * Create a one-time WASM worker
   */
  private createSecureWorker(): Worker {
    // Environment-aware worker path resolution
    // For development: try frontend public directory first
    // For production: fall back to package paths

    const isDevelopment = window.location.hostname === 'localhost' || window.location.hostname.includes('example.localhost');

    let workerUrl: URL;

    if (isDevelopment) {
      // Development: try public workers directory first (temporary dev solution)
      workerUrl = new URL('/workers/onetimePasskeySigner.worker.js', window.location.origin);
      console.log('🛠️ Development mode: Using frontend public workers directory');
    } else {
      // Production: use package paths with environment detection
      const currentUrl = new URL(import.meta.url);

      // Navigate up to find the package root (where onetimePasskeySigner.worker.js is located)
      // This works whether we're in dist/esm/core/ or dist/esm/react/src/core/

      // First try: assume we're in the main esm build (dist/esm/core/)
      workerUrl = new URL('../../onetimePasskeySigner.worker.js', currentUrl);

      // Check if we're in the react build by looking at the path
      if (currentUrl.pathname.includes('/react/src/core/')) {
        // We're in dist/esm/react/src/core/, need to go up 4 levels
        workerUrl = new URL('../../../../onetimePasskeySigner.worker.js', currentUrl);
      }

      console.log('🚀 Production mode: Using package worker paths');
    }

    console.log('WebAuthnManager: Worker config:', {
      WASM_WORKER_FILENAME,
      'import.meta.url': import.meta.url,
      'isDevelopment': isDevelopment,
      'detected location': import.meta.url.includes('/react/src/core/') ? 'react build' : 'main build',
      'resolved workerUrl': workerUrl.href
    });

    const worker = new Worker(workerUrl, { type: 'module' });

    console.log('WebAuthnManager: Created secure one-time worker');
    return worker;
  }

  /**
   * Execute worker operation with timeout and cleanup
   */
  private async executeWorkerOperation(
    worker: Worker,
    message: Record<string, any>,
    timeoutMs: number = 30000
  ): Promise<WorkerResponse> {
    return new Promise((resolve, reject) => {
      let completed = false;

      const timeoutId = setTimeout(() => {
        if (!completed) {
          completed = true;
          worker.terminate();
          reject(new Error('Worker operation timed out'));
        }
      }, timeoutMs);

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        if (!completed) {
          completed = true;
          clearTimeout(timeoutId);
          console.log('Worker response received:', event.data);
          resolve(event.data);
          setTimeout(() => worker.terminate(), 100);
        }
      };

      worker.onerror = (error: ErrorEvent) => {
        if (!completed) {
          completed = true;
          clearTimeout(timeoutId);
          worker.terminate();
          reject(new Error(`Worker error: ${error.message || 'Unknown worker error'}`));
        }
      };

      // Add message error handler for unhandled promise rejections in worker
      worker.addEventListener('messageerror', (event) => {
        if (!completed) {
          completed = true;
          clearTimeout(timeoutId);
          worker.terminate();
          console.error('Worker message error:', event);
          reject(new Error('Worker message serialization error'));
        }
      });

      console.log('Sending message to worker:', message);
      worker.postMessage(message);
    });
  }

  // === SERVER COMMUNICATION ===

  /**
   * Get registration options from server with custom URL and register challenge
   */
  async getRegistrationOptionsFromServer(
    serverUrl: string,
    username: string
  ): Promise<RegistrationOptions> {
    try {
      const requestData: GenerateRegistrationOptionsRequest = {
        username
      };

      const response = await fetch(`${serverUrl}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to fetch registration options'
        }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const serverResponseObject: GenerateRegistrationOptionsResponse = await response.json();

      if (!serverResponseObject?.options?.challenge ||
          typeof serverResponseObject.options.challenge !== 'string') {
        console.error("[FRONTEND ERROR] Invalid or missing options.challenge in server response:",
                     serverResponseObject);
        throw new Error('Invalid or missing options.challenge in server response.');
      }

      if (serverResponseObject.options.excludeCredentials &&
          !Array.isArray(serverResponseObject.options.excludeCredentials)) {
        console.error("[FRONTEND ERROR] options.excludeCredentials is not an array:",
                     serverResponseObject.options.excludeCredentials);
      }

      // Convert JSON format to WebAuthn API format
      const convertedOptions: PublicKeyCredentialCreationOptions = {
        challenge: bufferDecode(serverResponseObject.options.challenge),
        rp: serverResponseObject.options.rp,
        user: {
          id: typeof serverResponseObject.options.user.id === 'string'
            ? new TextEncoder().encode(serverResponseObject.options.user.id)
            : serverResponseObject.options.user.id as BufferSource,
          name: serverResponseObject.options.user.name,
          displayName: serverResponseObject.options.user.displayName
        },
        pubKeyCredParams: serverResponseObject.options.pubKeyCredParams,
        excludeCredentials: serverResponseObject.options.excludeCredentials?.map(c => ({
          id: typeof c.id === 'string' ? bufferDecode(c.id) : c.id as BufferSource,
          type: 'public-key' as const,
          transports: c.transports as AuthenticatorTransport[]
        })),
        authenticatorSelection: serverResponseObject.options.authenticatorSelection,
        timeout: serverResponseObject.options.timeout,
        attestation: serverResponseObject.options.attestation,
        extensions: serverResponseObject.options.extensions
      };

      const challengeId = this.registerServerChallenge(serverResponseObject.options.challenge, 'registration');
      const commitmentId = serverResponseObject.commitmentId;

      return { options: convertedOptions, challengeId, commitmentId };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get registration options:', error);
      throw error;
    }
  }

  /**
   * Get registration options from contract directly (for serverless mode)
   */
  async getRegistrationOptionsFromContract(
    nearRpcProvider: any,
    username: string
  ): Promise<RegistrationOptions> {
    const { WEBAUTHN_CONTRACT_ID, RELAYER_ACCOUNT_ID } = await import('../../config');
    const { ContractService } = await import('../ContractService');
    const { indexDBManager } = await import('../IndexDBManager');

    // Generate NEAR account ID
    const nearAccountId = indexDBManager.generateNearAccountId(username, RELAYER_ACCOUNT_ID);

    // Create contract service instance
    const contractService = new ContractService(
      nearRpcProvider,
      WEBAUTHN_CONTRACT_ID,
      'WebAuthn Passkey',
      window.location.hostname,
      RELAYER_ACCOUNT_ID
    );

    // Get existing authenticators for exclusion
    const existingAuthenticators = await indexDBManager.getAuthenticatorsByUser(nearAccountId);

    const userId = contractService.generateUserId();
    const { contractArgs } = contractService.buildRegistrationOptionsArgs(
      username,
      userId,
      existingAuthenticators
    );

    // Call contract to get registration options
    const optionsResult = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'generate_registration_options',
      args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
      finality: 'optimistic'
    });

    const parsedOptions = contractService.parseContractResponse(optionsResult, 'generate_registration_options');

    return {
      options: parsedOptions.options,
      challengeId: parsedOptions.options.challenge,
      commitmentId: parsedOptions.commitmentId
    };
  }

  /**
   * Get authentication options from server with custom URL and register challenge
   */
  async getAuthenticationOptionsFromServer(
    serverUrl: string,
    username?: string
  ): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> {
    try {
      const requestData: GenerateAuthenticationOptionsRequest = {
        username
      };

      const response = await fetch(`${serverUrl}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to fetch authentication options'
        }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const options: GenerateAuthenticationOptionsResponse = await response.json();
      const challengeId = this.registerServerChallenge(options.challenge, 'authentication');

      return { options, challengeId };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get authentication options:', error);
      throw error;
    }
  }

  /**
   * Get authentication options from contract directly (for serverless mode)
   */
  async getAuthenticationOptionsFromContract(
    nearRpcProvider: any,
    username: string
  ): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> {
    const { WEBAUTHN_CONTRACT_ID, RELAYER_ACCOUNT_ID } = await import('../../config');
    const { ContractService } = await import('../ContractService');
    const { indexDBManager } = await import('../IndexDBManager');

    // Generate NEAR account ID
    const nearAccountId = indexDBManager.generateNearAccountId(username, RELAYER_ACCOUNT_ID);

    // Get user's authenticators to find one for authentication
    const authenticators = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error('No authenticators found for user. Please register first.');
    }

    // Use the first (latest) authenticator
    const authenticator = authenticators[0];

    // Create contract service instance
    const contractService = new ContractService(
      nearRpcProvider,
      WEBAUTHN_CONTRACT_ID,
      'WebAuthn Passkey',
      window.location.hostname,
      RELAYER_ACCOUNT_ID
    );

    const contractArgs = contractService.buildAuthenticationOptionsArgs(
      authenticator,
      undefined, // allowCredentials
      'preferred' // userVerification
    );

    // Call contract to get authentication options
    const optionsResult = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'generate_authentication_options',
      args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
      finality: 'optimistic'
    });

    const parsedOptions = contractService.parseContractResponse(optionsResult, 'generate_authentication_options');

    return {
      options: parsedOptions.options,
      challengeId: parsedOptions.commitmentId || crypto.randomUUID()
    };
  }

  // === HELPER METHODS ===

  /**
   * Convert PublicKeyCredentialRequestOptionsJSON to PublicKeyCredentialRequestOptions
   * Handles type conversions and buffer decoding
   */
  private convertAuthenticationOptions(
    options: PublicKeyCredentialRequestOptionsJSON
  ): PublicKeyCredentialRequestOptions {
    return {
      challenge: typeof options.challenge === 'string'
        ? bufferDecode(options.challenge)
        : options.challenge,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map(c => ({
        id: typeof c.id === 'string' ? bufferDecode(c.id) : c.id,
        type: 'public-key' as const,
        transports: c.transports as AuthenticatorTransport[]
      })),
      userVerification: (options.userVerification || "preferred") as UserVerificationRequirement,
      timeout: options.timeout || 60000,
      extensions: options.extensions
    };
  }

  // === WEBAUTHN OPERATIONS ===

  /**
   * Register with PRF extension support
   */
  async registerWithPrf(
    username: string,
    useOptimistic?: boolean
  ): Promise<WebAuthnRegistrationWithPrf> {
    return this.registerWithPrfAndUrl(undefined, username, useOptimistic);
  }

  /**
   * Register with PRF extension support with custom server URL
   */
  async registerWithPrfAndUrl(
    serverUrl: string | undefined,
    username: string,
    useOptimistic?: boolean
  ): Promise<WebAuthnRegistrationWithPrf> {
    console.log('🔒 WebAuthnManager.registerWithPrf called for:', username, 'useOptimistic:', useOptimistic);
    console.log('🔒 Active challenges before registration:', this.activeChallenges.size);

    if (!serverUrl) {
      throw new Error('serverUrl is required for registration. Use getRegistrationOptionsFromServer() with explicit serverUrl.');
    }

    const { options, challengeId, commitmentId } = await this.getRegistrationOptionsFromServer(serverUrl, username);

    // Options are already converted to the proper format by getRegistrationOptionsFromServer
    const extendedOptions: PublicKeyCredentialCreationOptions = {
      ...options,
      extensions: {
        ...options.extensions,
        prf: {
          eval: {
            first: this.PRF_SALTS.nearKeyEncryption
          }
        }
      }
    };

    const credential = await navigator.credentials.create({
      publicKey: extendedOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('Passkey creation cancelled or failed');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfResults = (extensionResults as any).prf;
    const prfEnabled = prfResults?.enabled === true;

    console.log('WebAuthnManager: Registration completed, PRF enabled:', prfEnabled, 'PRF eval results:', prfResults);

    return { credential, prfEnabled, commitmentId };
  }

  /**
   * Authenticate with PRF extension support (serverless mode)
   */
  async authenticateWithPrf(
    username?: string,
    purpose: 'encryption' | 'signing' = 'signing',
    useOptimistic: boolean = true
  ): Promise<WebAuthnAuthenticationWithPrf> {
    // For serverless mode, we need to get authentication options from stored user data
    // since we can't call the contract for authentication options (it's not a view function)

    if (!username) {
      const lastUsedUsername = await this.getLastUsedUsername();
      if (!lastUsedUsername) {
        throw new Error('No username provided and no last used username found');
      }
      username = lastUsedUsername;
    }

    const userData = await this.getUserData(username);
    if (!userData?.passkeyCredential) {
      throw new Error(`No passkey credential found for user ${username}`);
    }

    // Create a simple challenge for serverless authentication
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const challengeB64url = bufferEncode(challenge);

    // Build authentication options using stored credential
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge,
      rpId: window.location.hostname,
      allowCredentials: [{
        id: bufferDecode(userData.passkeyCredential.rawId),
        type: 'public-key' as const,
        transports: ['internal', 'usb', 'nfc', 'ble', 'hybrid'] as AuthenticatorTransport[]
      }],
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: this.PRF_SALTS.nearKeyEncryption
          }
        }
      }
    };

    const credential = await navigator.credentials.get({
      publicKey: authOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('Passkey authentication cancelled');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    console.log('WebAuthnManager: Serverless authentication completed, PRF output available:', !!prfOutput);

    return { credential, prfOutput };
  }

  /**
   * Authenticate with PRF extension support with custom server URL
   */
  async authenticateWithPrfAndUrl(
    serverUrl: string | undefined,
    username?: string,
    purpose: 'encryption' | 'signing' = 'signing',
    useOptimistic: boolean = true
  ): Promise<WebAuthnAuthenticationWithPrf> {
    if (!serverUrl) {
      throw new Error('serverUrl is required for authentication. Use getAuthenticationOptionsFromServer() with explicit serverUrl.');
    }

    const { options, challengeId } = await this.getAuthenticationOptionsFromServer(serverUrl, username);

    const extendedOptions: PublicKeyCredentialRequestOptions = {
      ...this.convertAuthenticationOptions(options),
      extensions: {
        ...options.extensions,
        prf: {
          eval: {
            first: this.PRF_SALTS.nearKeyEncryption
          }
        }
      }
    };

    const credential = await navigator.credentials.get({
      publicKey: extendedOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('Passkey authentication cancelled');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    console.log('WebAuthnManager: Authentication completed, PRF output available:', !!prfOutput);

    return { credential, prfOutput };
  }

  // === SECURE WORKFLOWS ===

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async secureRegistrationWithPrf(
    username: string,
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
    username: string,
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
      const response = await this.executeWorkerOperation(worker, {
        type: WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF,
        payload: {
          nearAccountId: payload.nearAccountId,
          prfOutput: bufferEncode(prfOutput),
          receiverId: payload.receiverId,
          contractMethodName: payload.contractMethodName,
          contractArgs: payload.contractArgs,
          gasAmount: payload.gasAmount,
          depositAmount: payload.depositAmount,
          nonce: payload.nonce,
          blockHashBytes: payload.blockHashBytes
        }
      });

      if (isSignatureSuccess(response)) {
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
   */
  async securePrivateKeyDecryptionWithPrf(
    username: string,
    prfOutput: ArrayBuffer,
    challengeId: string
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    try {
      this.validateAndConsumeChallenge(challengeId, 'authentication');
      console.log('WebAuthnManager: Challenge validated for PRF decryption');

      const userData = await this.getUserData(username);
      if (!userData?.nearAccountId) {
        throw new Error('User data not found or missing NEAR account ID');
      }

      console.log('WebAuthnManager: Starting secure private key decryption with PRF');

      const worker = this.createSecureWorker();
      const response = await this.executeWorkerOperation(worker, {
        type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        payload: {
          nearAccountId: userData.nearAccountId,
          prfOutput: bufferEncode(prfOutput)
        }
      });

      if (isDecryptionSuccess(response)) {
        console.log('WebAuthnManager: PRF private key decryption successful');
        return {
          decryptedPrivateKey: response.payload.decryptedPrivateKey,
          nearAccountId: userData.nearAccountId
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