import { publicKeyCredentialToJSON } from '../utils';
import { SERVER_URL, WASM_WORKER_FILENAME } from '../config';

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
  blockHash: string;
}

interface WorkerResponse {
  type: string;
  payload: any;
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
 */
export class WebAuthnManager {
  private activeChallenges = new Map<string, WebAuthnChallenge>();
  private readonly CHALLENGE_TIMEOUT = 30000; // 30 seconds
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute

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
  async getRegistrationOptions(username: string): Promise<{ options: any; challengeId: string }> {
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

      const options = await response.json();
      const challengeId = this.registerServerChallenge(options.challenge, 'registration');

      return { options, challengeId };
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
   * Secure registration flow: WebAuthn + WASM worker encryption
   */
  async secureRegistration(
    passkeyAttestationResponse: any,
    payload: RegistrationPayload,
    challengeId: string
  ): Promise<{ success: boolean; derpAccountId: string; publicKey: string }> {
    try {
      // Validate and consume the challenge
      const challenge = this.validateAndConsumeChallenge(challengeId, 'registration');

      console.log('WebAuthnManager: Starting secure registration');

      // Create worker only after successful WebAuthn validation
      const worker = this.createSecureWorker();

      // Execute encryption operation
      const response = await this.executeWorkerOperation(worker, {
        type: 'ENCRYPT_PRIVATE_KEY',
        payload: {
          passkeyAttestationResponse,
          derpAccountId: payload.derpAccountId,
        }
      });

      if (response.type === 'ENCRYPTION_SUCCESS') {
        console.log('WebAuthnManager: Registration successful');
        return {
          success: true,
          derpAccountId: response.payload.derpAccountId,
          publicKey: response.payload.publicKey
        };
      } else {
        throw new Error(response.payload?.error || 'Encryption failed');
      }

    } catch (error: any) {
      console.error('WebAuthnManager: Registration failed:', error);
      throw error;
    }
  }

  /**
   * Secure signing flow: WebAuthn + WASM worker decryption/signing
   */
  async secureTransactionSigning(
    passkeyAssertionResponse: any,
    payload: SigningPayload,
    challengeId: string
  ): Promise<{ signedTransactionBorsh: number[]; derpAccountId: string }> {
    try {
      // Validate and consume the challenge
      const challenge = this.validateAndConsumeChallenge(challengeId, 'authentication');

      console.log('WebAuthnManager: Starting secure transaction signing');

      // Create worker only after successful WebAuthn validation
      const worker = this.createSecureWorker();

      // Execute signing operation
      const response = await this.executeWorkerOperation(worker, {
        type: 'DECRYPT_AND_SIGN_TRANSACTION',
        payload: {
          derpAccountId: payload.derpAccountId,
          passkeyAssertionResponse,
          receiverId: payload.receiverId,
          contractMethodName: payload.contractMethodName,
          contractArgs: payload.contractArgs,
          gasAmount: payload.gasAmount,
          depositAmount: payload.depositAmount,
          nonce: payload.nonce,
          blockHash: payload.blockHash,
        }
      });

      if (response.type === 'SIGNATURE_SUCCESS') {
        console.log('WebAuthnManager: Transaction signing successful');
        return {
          signedTransactionBorsh: response.payload.signedTransactionBorsh,
          derpAccountId: response.payload.derpAccountId
        };
      } else {
        throw new Error(response.payload?.error || 'Signing failed');
      }

    } catch (error: any) {
      console.error('WebAuthnManager: Transaction signing failed:', error);
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
}

// Export a singleton instance
export const webAuthnManager = new WebAuthnManager();