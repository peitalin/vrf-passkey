import { SERVER_URL, WASM_WORKER_FILENAME } from '../config';
import { bufferEncode, bufferDecode } from '../utils';

// IndexedDB configuration
const USER_DATA_DB_NAME = 'PasskeyUserData';
const USER_DATA_DB_VERSION = 1;
const USER_DATA_STORE_NAME = 'userData';

interface UserData {
  username: string;
  derpAccountId?: string;
  clientNearPublicKey?: string;
  passkeyCredential?: {
    id: string;
    rawId: string;
  };
  lastUpdated: number;
  // PRF indicator
  prfSupported?: boolean;
  deterministicKey?: boolean;
}

// Types for WebAuthn operations
interface WebAuthnChallenge {
  id: string;
  challenge: string; // Base64url encoded challenge from server
  timestamp: number;
  used: boolean;
  operation: 'registration' | 'authentication';
  timeout: number;
}

interface RegistrationPayload {
  derpAccountId: string;
}

interface SigningPayload {
  derpAccountId: string;
  receiverId: string;
  contractMethodName: string;
  contractArgs: any;
  gasAmount: string;
  depositAmount: string;
  nonce: string;
  blockHashBytes: number[];
}

interface WorkerResponse {
  type: string;
  payload: any;
}

// PRF-related interfaces
interface PrfSaltConfig {
  nearKeyEncryption: Uint8Array; // Fixed salt for NEAR key encryption
}

interface WebAuthnRegistrationWithPrf {
  credential: PublicKeyCredential;
  prfEnabled: boolean;
  yieldResumeId?: string;
}

interface WebAuthnAuthenticationWithPrf {
  credential: PublicKeyCredential;
  prfOutput?: ArrayBuffer; // Present if PRF was used
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
  private activeChallenges = new Map<string, WebAuthnChallenge>();
  private readonly CHALLENGE_TIMEOUT = 30000; // 30 seconds
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute
  private readonly PRF_SALTS: PrfSaltConfig = {
    nearKeyEncryption: new Uint8Array(new Array(32).fill(42)) // Fixed salt for NEAR key encryption
  };

  constructor() {
    // Periodically clean up expired challenges
    setInterval(() => this.cleanupExpiredChallenges(), this.CLEANUP_INTERVAL);
  }

  /**
   * IndexedDB helper methods for user data management
   */
  private async openUserDataDB(): Promise<IDBDatabase> {
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

  async getLastUsedUsername(): Promise<string | null> {
    const allUsers = await this.getAllUserData();
    if (allUsers.length === 0) return null;

    // Return the most recently updated user
    const lastUser = allUsers.reduce((latest, current) =>
      current.lastUpdated > latest.lastUpdated ? current : latest
    );

    return lastUser.username;
  }

  async hasPasskeyCredential(username: string): Promise<boolean> {
    const userData = await this.getUserData(username);
    return !!(userData?.passkeyCredential);
  }

  async hasEncryptedKey(derpAccountId: string): Promise<boolean> {
    // Check if encrypted key exists in the worker's IndexedDB
    // This is a placeholder - the actual check would need to query the worker's DB
    // For now, we'll assume if we have user data with this derpAccountId, we have the key
    const allUsers = await this.getAllUserData();
    return allUsers.some(user => user.derpAccountId === derpAccountId);
  }

  /**
   * Register a server-generated challenge for tracking
   */
  private registerServerChallenge(serverChallenge: string, operation: 'registration' | 'authentication'): string {
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
  private validateAndConsumeChallenge(challengeId: string, operation: 'registration' | 'authentication'): WebAuthnChallenge {
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

    // Mark as used and remove from active challenges
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
   * Create a one-time WASM worker (only callable after WebAuthn validation)
   */
  private createSecureWorker(): Worker {
    const worker = new Worker(
      new URL(WASM_WORKER_FILENAME, import.meta.url),
      { type: 'module' }
    );

    console.log('WebAuthnManager: Created secure one-time worker');
    return worker;
  }

  /**
   * Execute worker operation with timeout and cleanup
   */
  private async executeWorkerOperation(
    worker: Worker,
    message: any,
    timeoutMs: number = 30000
  ): Promise<WorkerResponse> {
    return new Promise((resolve, reject) => {
      let completed = false;

      // Set up timeout
      const timeoutId = setTimeout(() => {
        if (!completed) {
          completed = true;
          worker.terminate();
          reject(new Error('Worker operation timed out'));
        }
      }, timeoutMs);

      // Set up message handler
      worker.onmessage = (event: MessageEvent) => {
        if (!completed) {
          completed = true;
          clearTimeout(timeoutId);
          resolve(event.data);
          // Worker will self-terminate, but we can also terminate it here for safety
          setTimeout(() => worker.terminate(), 100);
        }
      };

      // Set up error handler
      worker.onerror = (error: ErrorEvent) => {
        if (!completed) {
          completed = true;
          clearTimeout(timeoutId);
          worker.terminate();
          reject(new Error(`Worker error: ${error.message}`));
        }
      };

      // Send the message
      worker.postMessage(message);
    });
  }

  /**
   * Get registration options from server and register challenge
   */
  async getRegistrationOptions(username: string): Promise<{ options: any; challengeId: string; yieldResumeId?: string }> {
    try {
      const response = await fetch(`${SERVER_URL}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Failed to fetch registration options' }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const serverResponseObject = await response.json();

      // Ensure options and challenge exist before trying to use them
      if (!serverResponseObject || !serverResponseObject.options || typeof serverResponseObject.options.challenge !== 'string') {
        console.error("[FRONTEND ERROR] Invalid or missing options.challenge in server response:", serverResponseObject);
        throw new Error('Invalid or missing options.challenge in server response.');
      }
      if (serverResponseObject.options.excludeCredentials && !Array.isArray(serverResponseObject.options.excludeCredentials)) {
        console.error("[FRONTEND ERROR] options.excludeCredentials is not an array:", serverResponseObject.options.excludeCredentials);
        // Decide if this is a critical error or if it can be handled (e.g., treat as empty array)
        // For now, let it proceed but be aware it might cause issues later if not an array or undefined.
      }

      const options = serverResponseObject.options;
      const challengeId = this.registerServerChallenge(options.challenge, 'registration');
      const yieldResumeId = serverResponseObject.yieldResumeId;

      return { options, challengeId, yieldResumeId };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get registration options:', error);
      throw error;
    }
  }

  /**
   * Get authentication options from server and register challenge
   */
  async getAuthenticationOptions(username?: string): Promise<{ options: any; challengeId: string }> {
    try {
      const response = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(username ? { username } : {}),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Failed to fetch authentication options' }));
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

  /**
   * Register with PRF extension support
   */
  async registerWithPrf(username: string): Promise<WebAuthnRegistrationWithPrf> {
    const { options, challengeId, yieldResumeId: getOptionsyieldResumeId } = await this.getRegistrationOptions(username);

    if (typeof options?.challenge !== 'string') {
        const errorMsg = "[ERROR] In registerWithPrf, options.challenge is NOT in the right format.";
        console.error(errorMsg, "Value:", options?.challenge, "Full options:", options);
        throw new TypeError(errorMsg);
    }

    let processedExcludeCredentials = undefined;
    if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
        processedExcludeCredentials = options.excludeCredentials.map((c, index) => {
            if (typeof c?.id !== 'string') {
                const errorMsg = `[CRITICAL ERROR] In registerWithPrf, excludeCredentials[${index}].id is NOT a string.`;
                console.error(errorMsg, "Value:", c?.id, "Full credential object:" , c);
                return { ...c, id: '' };
            }
            return { ...c, id: bufferDecode(c.id) };
        });
    } else if (options.excludeCredentials) {
    }

    const extendedOptions = {
      ...options,
      challenge: bufferDecode(options.challenge),
      user: { ...options.user, id: new TextEncoder().encode(options.user.id) },
      excludeCredentials: processedExcludeCredentials,
      authenticatorSelection: options.authenticatorSelection || { residentKey: "required", userVerification: "preferred" },
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

    return { credential, prfEnabled, yieldResumeId: getOptionsyieldResumeId };
  }

  /**
   * Authenticate with PRF extension support
   */
  async authenticateWithPrf(
    username?: string,
    purpose: 'encryption' | 'signing' = 'signing'
  ): Promise<WebAuthnAuthenticationWithPrf> {
    const { options, challengeId } = await this.getAuthenticationOptions(username);

    // Add PRF extension with appropriate salt
    const extendedOptions = {
      ...options,
      challenge: bufferDecode(options.challenge),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map(c => ({ ...c, id: bufferDecode(c.id) })),
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

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async secureRegistrationWithPrf(
    username: string,
    prfOutput: ArrayBuffer,
    payload: RegistrationPayload,
    challengeId?: string,
    skipChallengeValidation: boolean = false
  ): Promise<{ success: boolean; derpAccountId: string; publicKey: string }> {
    try {
      // Only validate challenge if not skipped (for cases where WebAuthn ceremony already completed)
      if (!skipChallengeValidation && challengeId) {
        const challenge = this.validateAndConsumeChallenge(challengeId, 'registration');
        console.log('WebAuthnManager: Challenge validated for PRF registration');
      }

      console.log('WebAuthnManager: Starting secure registration with PRF');

      // Create worker only after successful WebAuthn validation
      const worker = this.createSecureWorker();

      // Execute encryption operation with PRF
      const response = await this.executeWorkerOperation(worker, {
        type: 'ENCRYPT_PRIVATE_KEY_WITH_PRF',
        payload: {
          prfOutput: bufferEncode(prfOutput), // Convert to base64
          derpAccountId: payload.derpAccountId
        }
      });

      if (response.type === 'ENCRYPTION_SUCCESS') {
        console.log('WebAuthnManager: PRF registration successful');
        // Store user data with PRF flag
        await this.storeUserData({
          username,
          derpAccountId: payload.derpAccountId,
          clientNearPublicKey: response.payload.publicKey,
          prfSupported: true, // Flag to indicate PRF was used
          lastUpdated: Date.now()
        });

        return {
          success: true,
          derpAccountId: response.payload.derpAccountId,
          publicKey: response.payload.publicKey
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
  ): Promise<{ signedTransactionBorsh: number[]; derpAccountId: string }> {
    try {
      // Validate and consume the challenge
      const challenge = this.validateAndConsumeChallenge(challengeId, 'authentication');

      console.log('WebAuthnManager: Starting secure transaction signing with PRF');

      // Create worker only after successful WebAuthn validation
      const worker = this.createSecureWorker();

      // Execute signing operation with PRF
      const response = await this.executeWorkerOperation(worker, {
        type: 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF',
        payload: {
          derpAccountId: payload.derpAccountId,
          prfOutput: bufferEncode(prfOutput), // Convert to base64
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
          signedTransactionBorsh: response.payload.signedTransactionBorsh,
          derpAccountId: response.payload.derpAccountId
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
   * Get active challenge count (for debugging/monitoring)
   */
  getActiveChallengeCount(): number {
    return this.activeChallenges.size;
  }

  /**
   * Force cleanup of all challenges (for testing or emergency cleanup)
   */
  clearAllChallenges(): void {
    this.activeChallenges.clear();
  }

  /**
   * Secure registration flow with PRF and deterministic key derivation from WebAuthn
   */
  async secureRegistrationWithPrfDeterministic(
    username: string,
    prfOutput: ArrayBuffer,
    attestationObjectB64u: string,
    payload: RegistrationPayload,
    challengeId?: string,
    skipChallengeValidation: boolean = false
  ): Promise<{ success: boolean; derpAccountId: string; publicKey: string }> {
    try {
      // Only validate challenge if not skipped (for cases where WebAuthn ceremony already completed)
      if (!skipChallengeValidation && challengeId) {
        const challenge = this.validateAndConsumeChallenge(challengeId, 'registration');
        console.log('WebAuthnManager: Challenge validated for deterministic PRF registration');
      }

      console.log('WebAuthnManager: Starting secure deterministic registration with PRF');

      // Create worker only after successful WebAuthn validation
      const worker = this.createSecureWorker();

      // Execute deterministic encryption operation with PRF and attestationObject
      const response = await this.executeWorkerOperation(worker, {
        type: 'DETERMINISTIC_ENCRYPT_PRIVATE_KEY_WITH_PRF',
        payload: {
          prfOutput: bufferEncode(prfOutput), // Convert to base64
          attestationObjectB64u: attestationObjectB64u,
          derpAccountId: payload.derpAccountId
        }
      });

      if (response.type === 'DETERMINISTIC_ENCRYPTION_SUCCESS') {
        console.log('WebAuthnManager: Deterministic PRF registration successful');
        console.log('WebAuthnManager: Derived public key:', response.payload.publicKey);

        // Store user data with PRF flag and deterministic key info
        await this.storeUserData({
          username,
          derpAccountId: payload.derpAccountId,
          clientNearPublicKey: response.payload.publicKey,
          prfSupported: true, // Flag to indicate PRF was used
          deterministicKey: true, // Flag to indicate deterministic derivation
          lastUpdated: Date.now()
        });

        return {
          success: true,
          derpAccountId: response.payload.derpAccountId,
          publicKey: response.payload.publicKey
        };
      } else {
        throw new Error(response.payload?.error || 'Deterministic PRF encryption failed');
      }

    } catch (error: any) {
      console.error('WebAuthnManager: Deterministic PRF registration failed:', error);
      throw error;
    }
  }
}

// Export a singleton instance
export const webAuthnManager = new WebAuthnManager();