import { openDB, type IDBPDatabase } from 'idb';

// === TYPE DEFINITIONS ===
export interface ClientUserData {
  nearAccountId: string;
  username: string;
  displayName?: string;
  registeredAt: number;
  lastLogin?: number;
  preferences?: UserPreferences;
}

export interface UserPreferences {
  optimisticAuth: boolean;
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
}

// === CONSTANTS ===
const DB_CONFIG: IndexDBManagerConfig = {
  dbName: 'PasskeyClientDB',
  dbVersion: 1,
  userStore: 'users',
  appStateStore: 'appState'
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
      upgrade(db): void {
        if (!db.objectStoreNames.contains(DB_CONFIG.userStore)) {
          db.createObjectStore(DB_CONFIG.userStore, { keyPath: 'nearAccountId' });
        }
        if (!db.objectStoreNames.contains(DB_CONFIG.appStateStore)) {
          db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
        }
      },
      // Optional: Add event handlers for better debugging
      blocked() {
        console.warn('IndexDB connection is blocked.');
      },
      blocking() {
        console.warn('IndexDB connection is blocking another connection.');
      },
      terminated: () => {
        console.warn('IndexDB connection has been terminated.');
        // Reset the db property to allow re-opening
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

  async getLastUser(): Promise<ClientUserData | null> {
    const lastUserAccount = await this.getAppState<string>('lastUserAccountId');
    if (!lastUserAccount) return null;

    return this.getUser(lastUserAccount);
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
      displayName: username,
      registeredAt: now,
      lastLogin: now,
      preferences: {
        optimisticAuth: true,
      },
      ...additionalData,
    };

    await this.storeUser(userData);
    return userData;
  }

  async updateLastLogin(nearAccountId: string): Promise<void> {
    const user = await this.getUser(nearAccountId);
    if (user) {
      user.lastLogin = Date.now();
      await this.storeUser(user);
    }
  }

  async updatePreferences(
    nearAccountId: string,
    preferences: Partial<UserPreferences>
  ): Promise<void> {
    const user = await this.getUser(nearAccountId);
    if (user) {
      user.preferences = {
        ...user.preferences,
        ...preferences
      } as UserPreferences;
      await this.storeUser(user);
    }
  }

  // === UTILITY METHODS ===

  async getAllUsers(): Promise<ClientUserData[]> {
    const db = await this.getDB();
    return db.getAll(DB_CONFIG.userStore);
  }

  async deleteUser(nearAccountId: string): Promise<void> {
    const db = await this.getDB();
    await db.delete(DB_CONFIG.userStore, nearAccountId);
  }

  async clearAllUsers(): Promise<void> {
    const db = await this.getDB();
    await db.clear(DB_CONFIG.userStore);
  }

  async clearAllAppState(): Promise<void> {
    const db = await this.getDB();
    await db.clear(DB_CONFIG.appStateStore);
  }
}

// Export a singleton instance
export const indexDBManager = new IndexDBManager(DB_CONFIG);