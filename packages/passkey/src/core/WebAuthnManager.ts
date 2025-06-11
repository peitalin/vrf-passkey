import { SERVER_URL, WASM_WORKER_FILENAME } from '../config';
import { bufferEncode, bufferDecode } from '../utils/encoders';

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

interface WorkerResponse {
  type: string;
  payload: {
    error?: string;
    publicKey?: string;
    nearAccountId?: string;
    signedTransactionBorsh?: number[];
    stored?: boolean;
    decryptedPrivateKey?: string;
  };
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

  // === INDEXEDDB OPERATIONS ===

  /**
   * Open IndexedDB connection for user data
   */
  async openUserDataDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(USER_DATA_DB_NAME, USER_DATA_DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(USER_DATA_STORE_NAME)) {
          db.createObjectStore(USER_DATA_STORE_NAME, { keyPath: 'username' });
        }
      };
    });
  }

  /**
   * Store user data in IndexedDB
   */
  async storeUserData(userData: UserData): Promise<void> {
    const db = await this.openUserDataDB();
    const transaction = db.transaction([USER_DATA_STORE_NAME], 'readwrite');
    const store = transaction.objectStore(USER_DATA_STORE_NAME);

    return new Promise((resolve, reject) => {
      const request = store.put({ ...userData, lastUpdated: Date.now() });
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

  /**
   * Retrieve user data from IndexedDB
   */
  async getUserData(username: string): Promise<UserData | null> {
    const db = await this.openUserDataDB();
    const transaction = db.transaction([USER_DATA_STORE_NAME], 'readonly');
    const store = transaction.objectStore(USER_DATA_STORE_NAME);

    return new Promise((resolve, reject) => {
      const request = store.get(username);
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

  /**
   * Get all user data from IndexedDB
   */
  async getAllUserData(): Promise<UserData[]> {
    const db = await this.openUserDataDB();
    const transaction = db.transaction([USER_DATA_STORE_NAME], 'readonly');
    const store = transaction.objectStore(USER_DATA_STORE_NAME);

    return new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => {
        db.close();
        resolve(request.result || []);
      };
      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    });
  }

  // === CONVENIENCE METHODS ===

  /**
   * Check if a passkey credential exists for a username
   */
  async hasPasskeyCredential(username: string): Promise<boolean> {
    try {
      const userData = await this.getUserData(username);
      return !!userData && !!userData.clientNearPublicKey;
    } catch (error) {
      console.warn('Error checking passkey credential:', error);
      return false;
    }
  }

  /**
   * Get the last used username from stored user data
   */
  async getLastUsedUsername(): Promise<string | null> {
    try {
      const allUsers = await this.getAllUserData();
      if (allUsers.length === 0) return null;

      // Sort by lastUpdated timestamp and return the most recent
      const sortedUsers = allUsers.sort((a, b) => b.lastUpdated - a.lastUpdated);
      return sortedUsers[0].username;
    } catch (error) {
      console.warn('Error getting last used username:', error);
      return null;
    }
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
   * Get registration options from server and register challenge
   */
  async getRegistrationOptions(
    username: string,
    useOptimistic?: boolean
  ): Promise<RegistrationOptions> {
    try {
      const response = await fetch(`${SERVER_URL}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, useOptimistic }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to fetch registration options'
        }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const serverResponseObject = await response.json();

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

      const options = serverResponseObject.options;
      const challengeId = this.registerServerChallenge(options.challenge, 'registration');
      const commitmentId = serverResponseObject.commitmentId;

      return { options, challengeId, commitmentId };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get registration options:', error);
      throw error;
    }
  }

  /**
   * Get authentication options from server and register challenge
   */
  async getAuthenticationOptions(
    username?: string,
    useOptimistic?: boolean
  ): Promise<AuthenticationOptions> {
    try {
      const payload: Record<string, any> = {};
      if (username) payload.username = username;
      if (useOptimistic !== undefined) payload.useOptimistic = useOptimistic;

      const response = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to fetch authentication options'
        }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const options = await response.json();
      const challengeId = this.registerServerChallenge(options.challenge, 'authentication');

      return { options, challengeId };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get authentication options:', error);
      throw error;
    }
  }

  // === WEBAUTHN OPERATIONS ===

  /**
   * Register with PRF extension support
   */
  async registerWithPrf(
    username: string,
    useOptimistic?: boolean
  ): Promise<WebAuthnRegistrationWithPrf> {
    console.log('🔒 WebAuthnManager.registerWithPrf called for:', username, 'useOptimistic:', useOptimistic);
    console.log('🔒 Active challenges before registration:', this.activeChallenges.size);

    const { options, challengeId, commitmentId } = await this.getRegistrationOptions(username, useOptimistic);

    if (typeof options?.challenge !== 'string') {
      const errorMsg = "[ERROR] In registerWithPrf, options.challenge is NOT in the right format.";
      console.error(errorMsg, "Value:", options?.challenge, "Full options:", options);
      throw new TypeError(errorMsg);
    }

    let processedExcludeCredentials: PublicKeyCredentialDescriptor[] | undefined;
    if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
      processedExcludeCredentials = options.excludeCredentials.map((c, index) => {
        // Handle server response where id is a base64url string that needs decoding
        const credentialId = c.id;
        if (typeof credentialId === 'string') {
          return { ...c, id: bufferDecode(credentialId) };
        } else {
          // If it's already a BufferSource, use as-is
          console.warn(`[WARNING] excludeCredentials[${index}].id is not a string:`, credentialId);
          return { ...c, id: credentialId || new ArrayBuffer(0) };
        }
      });
    }

    const extendedOptions: PublicKeyCredentialCreationOptions = {
      ...options,
      challenge: typeof options.challenge === 'string'
        ? bufferDecode(options.challenge)
        : options.challenge,
      user: {
        ...options.user,
        id: typeof options.user.id === 'string'
          ? new TextEncoder().encode(options.user.id)
          : options.user.id
      },
      excludeCredentials: processedExcludeCredentials,
      authenticatorSelection: options.authenticatorSelection || {
        residentKey: "required",
        userVerification: "preferred"
      },
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
   * Authenticate with PRF extension support
   */
  async authenticateWithPrf(
    username?: string,
    purpose: 'encryption' | 'signing' = 'signing',
    useOptimistic: boolean = true
  ): Promise<WebAuthnAuthenticationWithPrf> {
    const { options, challengeId } = await this.getAuthenticationOptions(username, useOptimistic);

    const extendedOptions: PublicKeyCredentialRequestOptions = {
      ...options,
      challenge: typeof options.challenge === 'string'
        ? bufferDecode(options.challenge)
        : options.challenge,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map(c => ({
        ...c,
        id: typeof c.id === 'string' ? bufferDecode(c.id) : c.id
      })),
      userVerification: options.userVerification || "preferred",
      timeout: options.timeout || 60000,
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
        type: 'ENCRYPT_PRIVATE_KEY_WITH_PRF',
        payload: {
          prfOutput: bufferEncode(prfOutput),
          nearAccountId: payload.nearAccountId
        }
      });

      if (response.type === 'ENCRYPTION_SUCCESS') {
        console.log('WebAuthnManager: PRF registration successful');

        await this.storeUserData({
          username,
          nearAccountId: payload.nearAccountId,
          clientNearPublicKey: response.payload.publicKey!,
          prfSupported: true,
          lastUpdated: Date.now()
        });

        return {
          success: true,
          nearAccountId: response.payload.nearAccountId!,
          publicKey: response.payload.publicKey!
        };
      } else {
        throw new Error(response.payload?.error || 'PRF encryption failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF registration failed:', error);
      throw error;
    }
  }

  /**
   * Secure signing flow with PRF: WebAuthn + WASM worker decryption/signing using PRF
   */
  async secureTransactionSigningWithPrf(
    username: string,
    prfOutput: ArrayBuffer,
    payload: SigningPayload,
    challengeId: string
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    try {
      this.validateAndConsumeChallenge(challengeId, 'authentication');
      console.log('WebAuthnManager: Starting secure transaction signing with PRF');

      const worker = this.createSecureWorker();
      const response = await this.executeWorkerOperation(worker, {
        type: 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF',
        payload: {
          nearAccountId: payload.nearAccountId,
          prfOutput: bufferEncode(prfOutput),
          receiverId: payload.receiverId,
          contractMethodName: payload.contractMethodName,
          contractArgs: payload.contractArgs,
          gasAmount: payload.gasAmount,
          depositAmount: payload.depositAmount,
          nonce: payload.nonce,
          blockHashBytes: payload.blockHashBytes,
        }
      });

      if (response.type === 'SIGNATURE_SUCCESS') {
        console.log('WebAuthnManager: PRF transaction signing successful');
        return {
          signedTransactionBorsh: response.payload.signedTransactionBorsh!,
          nearAccountId: response.payload.nearAccountId!
        };
      } else {
        throw new Error(response.payload?.error || 'PRF signing failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF transaction signing failed:', error);
      throw error;
    }
  }

  /**
   * Secure private key decryption with PRF: WebAuthn + WASM worker decryption using PRF
   * WARNING: This exposes the private key - use only for secure key export workflows
   */
  async securePrivateKeyDecryptionWithPrf(
    username: string,
    prfOutput: ArrayBuffer,
    challengeId: string
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    try {
      this.validateAndConsumeChallenge(challengeId, 'authentication');
      console.log('WebAuthnManager: Starting secure private key decryption with PRF');

      // Get user data first
      const userData = await this.getUserData(username);
      if (!userData?.nearAccountId) {
        throw new Error(`No account data found for user: ${username}`);
      }

      const worker = this.createSecureWorker();
      const response = await this.executeWorkerOperation(worker, {
        type: 'DECRYPT_PRIVATE_KEY_WITH_PRF',
        payload: {
          nearAccountId: userData.nearAccountId,
          prfOutput: bufferEncode(prfOutput),
        }
      });

      if (response.type === 'DECRYPTION_SUCCESS') {
        console.log('WebAuthnManager: PRF private key decryption successful');
        return {
          decryptedPrivateKey: response.payload.decryptedPrivateKey!,
          nearAccountId: response.payload.nearAccountId!
        };
      } else {
        throw new Error(response.payload?.error || 'PRF decryption failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: PRF private key decryption failed:', error);
      throw error;
    }
  }
}

// === EXPORTS ===
export const webAuthnManager = new WebAuthnManager();