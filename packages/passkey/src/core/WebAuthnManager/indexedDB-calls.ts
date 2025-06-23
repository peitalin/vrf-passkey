import { IndexedDBManager } from '../IndexedDBManager';
import type { ClientUserData, ClientAuthenticatorData } from '../IndexedDBManager';
import type { IDBPDatabase } from 'idb';

/**
 * WebAuthnIndexedDBCalls provides a facade for all IndexedDB operations
 * This centralizes data access and provides a clean abstraction layer
 */
export class WebAuthnIndexedDBCalls {

  // =================================================================
  // USER OPERATIONS
  // =================================================================

  /**
   * Get user data by NEAR account ID
   */
  async getUser(nearAccountId: string): Promise<ClientUserData | null> {
    return await IndexedDBManager.getUser(nearAccountId);
  }

  /**
   * Register a new user
   */
  async registerUser(nearAccountId: string, additionalData?: Partial<ClientUserData>): Promise<ClientUserData> {
    return await IndexedDBManager.registerUser(nearAccountId, additionalData);
  }

  /**
   * Update user's last login timestamp
   */
  async updateLastLogin(nearAccountId: string): Promise<void> {
    return await IndexedDBManager.updateLastLogin(nearAccountId);
  }

  /**
   * Get all registered users
   */
  async getAllUsers(): Promise<ClientUserData[]> {
    return await IndexedDBManager.getAllUsers();
  }

  /**
   * Get the most recently used user
   */
  async getLastUser(): Promise<ClientUserData | null> {
    return await IndexedDBManager.getLastUser();
  }

  /**
   * Check if user has passkey credentials
   */
  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return await IndexedDBManager.hasPasskeyCredential(nearAccountId);
  }

  /**
   * Update user data
   */
  async updateUser(nearAccountId: string, updates: Partial<ClientUserData>): Promise<void> {
    return await IndexedDBManager.updateUser(nearAccountId, updates);
  }

  // =================================================================
  // AUTHENTICATOR OPERATIONS
  // =================================================================

  /**
   * Get all authenticators for a user
   */
  async getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]> {
    return await IndexedDBManager.getAuthenticatorsByUser(nearAccountId);
  }

  /**
   * Store a new authenticator
   */
  async storeAuthenticator(authenticatorData: {
    nearAccountId: string;
    credentialID: string;
    credentialPublicKey: Uint8Array;
    transports?: string[];
    clientNearPublicKey?: string;
    name?: string;
    registered: string;
    lastUsed?: string;
    backedUp: boolean;
    syncedAt: string;
  }): Promise<void> {
    return await IndexedDBManager.storeAuthenticator(authenticatorData);
  }

  /**
   * Update authenticator usage timestamp
   */
  async updateAuthenticatorLastUsed(nearAccountId: string, credentialId: string, timestamp: string): Promise<void> {
    return await IndexedDBManager.updateAuthenticatorLastUsed(nearAccountId, credentialId, timestamp);
  }

  // =================================================================
  // WEBAUTHN DATA OPERATIONS
  // =================================================================

  /**
   * Store WebAuthn user data (encrypted VRF credentials, PRF info, etc.)
   */
  async storeWebAuthnUserData(userData: {
    nearAccountId: string;
    clientNearPublicKey?: string;
    lastUpdated?: number;
    prfSupported?: boolean;
    passkeyCredential?: {
      id: string;
      rawId: string;
    };
    vrfCredentials?: {
      encrypted_vrf_data_b64u: string;
      aes_gcm_nonce_b64u: string;
    };
  }): Promise<void> {
    return await IndexedDBManager.storeWebAuthnUserData(userData);
  }

  /**
   * Get WebAuthn user data
   */
  async getWebAuthnUserData(nearAccountId: string): Promise<{
    nearAccountId: string;
    clientNearPublicKey?: string;
    lastUpdated: number;
    prfSupported?: boolean;
    passkeyCredential?: {
      id: string;
      rawId: string;
    };
    vrfCredentials?: {
      encrypted_vrf_data_b64u: string;
      aes_gcm_nonce_b64u: string;
    };
  } | null> {
    return await IndexedDBManager.getWebAuthnUserData(nearAccountId);
  }

  // =================================================================
  // ATOMIC OPERATIONS
  // =================================================================

  /**
   * Perform an atomic operation (transaction)
   */
  async atomicOperation<T>(callback: (db: IDBPDatabase) => Promise<T>): Promise<T> {
    return await IndexedDBManager.atomicOperation(callback);
  }

  /**
   * Rollback user registration (cleanup on failure)
   */
  async rollbackUserRegistration(nearAccountId: string): Promise<void> {
    return await IndexedDBManager.rollbackUserRegistration(nearAccountId);
  }

  // =================================================================
  // UTILITY OPERATIONS
  // =================================================================

  /**
   * Extract username from NEAR account ID (e.g., "user.testnet" -> "user")
   */
  extractUsername(nearAccountId: string): string {
    return IndexedDBManager.extractUsername(nearAccountId);
  }

  /**
   * Clear all user data (for testing/debugging)
   */
  async clearAllUsers(): Promise<void> {
    return await IndexedDBManager.clearAllUsers();
  }

  /**
   * Clear all app state (for testing/debugging)
   */
  async clearAllAppState(): Promise<void> {
    return await IndexedDBManager.clearAllAppState();
  }
}
