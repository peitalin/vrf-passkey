// === EXPORTS ===
export { PasskeyClientDBManager } from './passkeyClientDB';
export { PasskeyNearKeysDBManager } from './passkeyNearKeysDB';

// Re-export types for convenience
export type {
  ClientUserData,
  UserPreferences,
  ClientAuthenticatorData
} from './passkeyClientDB';

export type {
  EncryptedKeyData
} from './passkeyNearKeysDB';

// === SINGLETON INSTANCES ===
import { PasskeyClientDBManager, type ClientUserData } from './passkeyClientDB';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from './passkeyNearKeysDB';

// Export singleton instances for backward compatibility with existing code
export const passkeyClientDB = new PasskeyClientDBManager();
export const passkeyNearKeysDB = new PasskeyNearKeysDBManager();

// === UNIFIED INTERFACE ===
/**
 * Unified IndexedDB interface providing access to both databases
 * This allows centralized access while maintaining separation of concerns
 */
export class UnifiedIndexedDBManager {
  public readonly clientDB: PasskeyClientDBManager;
  public readonly nearKeysDB: PasskeyNearKeysDBManager;

  constructor() {
    this.clientDB = passkeyClientDB;
    this.nearKeysDB = passkeyNearKeysDB;
  }

  // === CONVENIENCE METHODS ===

  /**
   * Get user data and check if they have encrypted NEAR keys
   */
  async getUserWithKeys(nearAccountId: string): Promise<{
    userData: ClientUserData | null;
    hasKeys: boolean;
    keyData?: EncryptedKeyData | null;
  }> {
    const [userData, hasKeys, keyData] = await Promise.all([
      this.clientDB.getUser(nearAccountId),
      this.nearKeysDB.hasEncryptedKey(nearAccountId),
      this.nearKeysDB.getEncryptedKey(nearAccountId)
    ]);

    return {
      userData,
      hasKeys,
      keyData: hasKeys ? keyData : undefined
    };
  }
}

// Export singleton instance of unified manager
export const IndexedDBManager = new UnifiedIndexedDBManager();