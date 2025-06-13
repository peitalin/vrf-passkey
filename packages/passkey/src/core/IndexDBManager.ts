import { openDB, type IDBPDatabase } from 'idb';

// === UNIFIED TYPE DEFINITIONS ===
export interface ClientUserData {
  // Primary keys
  nearAccountId: string;
  username: string;

  // User metadata
  registeredAt: number;
  lastLogin?: number;
  lastUpdated: number;

  // WebAuthn/Passkey data (merged from WebAuthnManager)
  clientNearPublicKey?: string;
  prfSupported?: boolean;
  passkeyCredential?: {
    id: string;
    rawId: string;
  };

  // User preferences
  preferences?: UserPreferences;
}

export interface UserPreferences {
  optimisticAuth: boolean;
}

// Authenticator cache
export interface ClientAuthenticatorData {
  nearAccountId: string;
  credentialID: string;
  credentialPublicKey: Uint8Array;
  counter: number;
  transports?: string[]; // AuthenticatorTransport[]
  clientNearPublicKey?: string; // Renamed from clientManagedNearPublicKey
  name?: string;
  registered: string; // ISO date string
  lastUsed?: string; // ISO date string
  backedUp: boolean;
  syncedAt: string; // When this cache entry was last synced with contract
}

interface AppStateEntry<T = any> {
  key: string;
  value: T;
}

interface IndexDBManagerConfig {
  dbName: string;
  dbVersion: number;
  userStore: string;
  appStateStore: string;
  authenticatorStore: string;
}

// === CONSTANTS ===
const DB_CONFIG: IndexDBManagerConfig = {
  dbName: 'PasskeyClientDB',
  dbVersion: 4, // Increment version for schema changes
  userStore: 'users',
  appStateStore: 'appState',
  authenticatorStore: 'authenticators'
} as const;

class IndexDBManager {
  private config: IndexDBManagerConfig;
  private db: IDBPDatabase | null = null;

  constructor(config: IndexDBManagerConfig) {
    this.config = config;
  }

  private async getDB(): Promise<IDBPDatabase> {
    if (this.db) {
      return this.db;
    }

    this.db = await openDB(this.config.dbName, this.config.dbVersion, {
      upgrade(db, oldVersion): void {
        // Create stores if they don't exist
        if (!db.objectStoreNames.contains(DB_CONFIG.userStore)) {
          db.createObjectStore(DB_CONFIG.userStore, { keyPath: 'nearAccountId' });
        }
        if (!db.objectStoreNames.contains(DB_CONFIG.appStateStore)) {
          db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
        }
        if (!db.objectStoreNames.contains(DB_CONFIG.authenticatorStore)) {
          // Use composite key for authenticators
          const authStore = db.createObjectStore(DB_CONFIG.authenticatorStore, { keyPath: ['nearAccountId', 'credentialID'] });
          authStore.createIndex('nearAccountId', 'nearAccountId', { unique: false });
        }
      },
      blocked() {
        console.warn('IndexDB connection is blocked.');
      },
      blocking() {
        console.warn('IndexDB connection is blocking another connection.');
      },
      terminated: () => {
        console.warn('IndexDB connection has been terminated.');
        this.db = null;
      },
    });

    return this.db;
  }

  // === APP STATE METHODS ===

  async getAppState<T = any>(key: string): Promise<T | undefined> {
    const db = await this.getDB();
    const result = await db.get(DB_CONFIG.appStateStore, key);
    return result?.value as T | undefined;
  }

  async setAppState<T = any>(key: string, value: T): Promise<void> {
    const db = await this.getDB();
    const entry: AppStateEntry<T> = { key, value };
    await db.put(DB_CONFIG.appStateStore, entry);
  }

  // === USER MANAGEMENT METHODS ===

  deriveUsername(nearAccountId: string): string {
    return nearAccountId.split('.')[0];
  }

  generateNearAccountId(username: string, relayerAccountId: string): string {
    const sanitized = username
      .toLowerCase()
      .replace(/[^a-z0-9_\\-]/g, '')
      .substring(0, 32);
    return `${sanitized}.${relayerAccountId}`;
  }

  async storeUser(userData: ClientUserData): Promise<void> {
    const db = await this.getDB();
    await db.put(DB_CONFIG.userStore, userData);
    await this.setAppState('lastUserAccountId', userData.nearAccountId);
  }

  async getUser(nearAccountId: string): Promise<ClientUserData | null> {
    if (!nearAccountId) return null;

    const db = await this.getDB();
    const result = await db.get(DB_CONFIG.userStore, nearAccountId);
    return result || null;
  }

  async getUserByUsername(username: string): Promise<ClientUserData | null> {
    const db = await this.getDB();
    const allUsers = await db.getAll(DB_CONFIG.userStore);
    return allUsers.find(user => user.username === username) || null;
  }

  async getLastUser(): Promise<ClientUserData | null> {
    const lastUserAccount = await this.getAppState<string>('lastUserAccountId');
    if (!lastUserAccount) return null;

    return this.getUser(lastUserAccount);
  }

  async getLastUsedUsername(): Promise<string | null> {
    try {
      const allUsers = await this.getAllUsers();
      if (allUsers.length === 0) return null;

      // Sort by lastUpdated timestamp and return the most recent
      const sortedUsers = allUsers.sort((a, b) => b.lastUpdated - a.lastUpdated);
      return sortedUsers[0].username;
    } catch (error) {
      console.warn('Error getting last used username:', error);
      return null;
    }
  }

  async hasPasskeyCredential(username: string): Promise<boolean> {
    try {
      const userData = await this.getUserByUsername(username);
      return !!userData && !!userData.clientNearPublicKey;
    } catch (error) {
      console.warn('Error checking passkey credential:', error);
      return false;
    }
  }

  async registerUser(
    username: string,
    relayerAccountId: string,
    additionalData?: Partial<ClientUserData>
  ): Promise<ClientUserData> {
    const nearAccountId = this.generateNearAccountId(username, relayerAccountId);
    const now = Date.now();

    const userData: ClientUserData = {
      nearAccountId,
      username: this.deriveUsername(nearAccountId),
      registeredAt: now,
      lastLogin: now,
      lastUpdated: now,
      preferences: {
        optimisticAuth: true,
      },
      ...additionalData,
    };

    await this.storeUser(userData);
    return userData;
  }

  async updateUser(nearAccountId: string, updates: Partial<ClientUserData>): Promise<void> {
    const user = await this.getUser(nearAccountId);
    if (user) {
      const updatedUser = {
        ...user,
        ...updates,
        lastUpdated: Date.now()
      };
      await this.storeUser(updatedUser);
    }
  }

  async updateLastLogin(nearAccountId: string): Promise<void> {
    await this.updateUser(nearAccountId, { lastLogin: Date.now() });
  }

  async updatePreferences(
    nearAccountId: string,
    preferences: Partial<UserPreferences>
  ): Promise<void> {
    const user = await this.getUser(nearAccountId);
    if (user) {
      const updatedPreferences = {
        ...user.preferences,
        ...preferences
      } as UserPreferences;
      await this.updateUser(nearAccountId, { preferences: updatedPreferences });
    }
  }

  // === WEBAUTHN COMPATIBILITY METHODS ===

  /**
   * Store WebAuthn user data (compatibility with WebAuthnManager)
   */
  async storeWebAuthnUserData(userData: {
    username: string;
    nearAccountId?: string;
    clientNearPublicKey?: string;
    lastUpdated?: number;
    prfSupported?: boolean;
    passkeyCredential?: {
      id: string;
      rawId: string;
    };
  }): Promise<void> {
    const nearAccountId = userData.nearAccountId || this.generateNearAccountId(userData.username, 'webauthn-contract.testnet');

    // Get existing user data or create new
    let existingUser = await this.getUser(nearAccountId);
    if (!existingUser) {
      existingUser = await this.registerUser(userData.username, 'webauthn-contract.testnet');
    }

    // Update with WebAuthn-specific data
    await this.updateUser(nearAccountId, {
      clientNearPublicKey: userData.clientNearPublicKey,
      prfSupported: userData.prfSupported,
      passkeyCredential: userData.passkeyCredential,
      lastUpdated: userData.lastUpdated || Date.now()
    });
  }

  /**
   * Get WebAuthn user data (compatibility with WebAuthnManager)
   */
  async getWebAuthnUserData(username: string): Promise<{
    username: string;
    nearAccountId?: string;
    clientNearPublicKey?: string;
    lastUpdated: number;
    prfSupported?: boolean;
    passkeyCredential?: {
      id: string;
      rawId: string;
    };
  } | null> {
    const user = await this.getUserByUsername(username);
    if (!user) return null;

    return {
      username: user.username,
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: user.clientNearPublicKey,
      lastUpdated: user.lastUpdated,
      prfSupported: user.prfSupported,
      passkeyCredential: user.passkeyCredential
    };
  }

  // === UTILITY METHODS ===

  async getAllUsers(): Promise<ClientUserData[]> {
    const db = await this.getDB();
    return db.getAll(DB_CONFIG.userStore);
  }

  async deleteUser(nearAccountId: string): Promise<void> {
    const db = await this.getDB();
    await db.delete(DB_CONFIG.userStore, nearAccountId);
    // Also clean up related authenticators
    await this.clearAuthenticatorsForUser(nearAccountId);
  }

  async clearAllUsers(): Promise<void> {
    const db = await this.getDB();
    await db.clear(DB_CONFIG.userStore);
  }

  async clearAllAppState(): Promise<void> {
    const db = await this.getDB();
    await db.clear(DB_CONFIG.appStateStore);
  }

  // === AUTHENTICATOR CACHE METHODS ===

  /**
   * Store authenticator data for a user
   */
  async storeAuthenticator(authenticatorData: ClientAuthenticatorData): Promise<void> {
    const db = await this.getDB();
    await db.put(DB_CONFIG.authenticatorStore, authenticatorData);
  }

  /**
   * Get all authenticators for a user
   */
  async getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]> {
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.authenticatorStore, 'readonly');
    const store = tx.objectStore(DB_CONFIG.authenticatorStore);
    const index = store.index('nearAccountId');

    return await index.getAll(nearAccountId);
  }

  /**
   * Get a specific authenticator by credential ID
   */
  async getAuthenticatorByCredentialId(
    nearAccountId: string,
    credentialId: string
  ): Promise<ClientAuthenticatorData | null> {
    const db = await this.getDB();
    const result = await db.get(DB_CONFIG.authenticatorStore, [nearAccountId, credentialId]);
    return result || null;
  }

  /**
   * Update authenticator counter (critical for replay protection)
   */
  async updateAuthenticatorCounter(
    nearAccountId: string,
    credentialId: string,
    counter: number,
    lastUsed?: string
  ): Promise<void> {
    const authenticator = await this.getAuthenticatorByCredentialId(nearAccountId, credentialId);
    if (authenticator) {
      authenticator.counter = counter;
      authenticator.lastUsed = lastUsed || new Date().toISOString();
      authenticator.syncedAt = new Date().toISOString();
      await this.storeAuthenticator(authenticator);
    }
  }

  /**
   * Clear all authenticators for a user
   */
  async clearAuthenticatorsForUser(nearAccountId: string): Promise<void> {
    const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.authenticatorStore, 'readwrite');
    const store = tx.objectStore(DB_CONFIG.authenticatorStore);

    for (const auth of authenticators) {
      await store.delete([nearAccountId, auth.credentialID]);
    }
  }

  /**
   * Sync authenticators from contract data
   */
  async syncAuthenticatorsFromContract(
    nearAccountId: string,
    contractAuthenticators: Array<{
      credentialID: string;
      credentialPublicKey: Uint8Array;
      counter: number;
      transports?: string[];
      clientNearPublicKey?: string;
      name?: string;
      registered: string;
      lastUsed?: string;
      backedUp: boolean;
    }>
  ): Promise<void> {
    // Clear existing cache for this user
    await this.clearAuthenticatorsForUser(nearAccountId);

    // Add all contract authenticators to cache
    const syncedAt = new Date().toISOString();
    for (const auth of contractAuthenticators) {
      const clientAuth: ClientAuthenticatorData = {
        nearAccountId,
        credentialID: auth.credentialID,
        credentialPublicKey: auth.credentialPublicKey,
        counter: auth.counter,
        transports: auth.transports,
        clientNearPublicKey: auth.clientNearPublicKey,
        name: auth.name,
        registered: auth.registered,
        lastUsed: auth.lastUsed,
        backedUp: auth.backedUp,
        syncedAt,
      };
      await this.storeAuthenticator(clientAuth);
    }
  }

  /**
   * Get the latest (first registered) authenticator for a user
   */
  async getLatestAuthenticatorByUser(nearAccountId: string): Promise<{ credentialID: string } | null> {
    const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) return null;

    // Sort by registered date (earliest first)
    authenticators.sort((a, b) => new Date(a.registered).getTime() - new Date(b.registered).getTime());
    return { credentialID: authenticators[0].credentialID };
  }
}

// Export a singleton instance
export const indexDBManager = new IndexDBManager(DB_CONFIG);