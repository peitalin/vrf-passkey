import { PasskeyClientDBManager } from './passkeyClientDB.js';
import { PasskeyNearKeysDBManager } from './passkeyNearKeysDB.js';

// === EXPORTS ===
// Export singleton instances for backward compatibility with existing code
const passkeyClientDB = new PasskeyClientDBManager();
const passkeyNearKeysDB = new PasskeyNearKeysDBManager();
// === UNIFIED INTERFACE ===
/**
 * Unified IndexedDB interface providing access to both databases
 * This allows centralized access while maintaining separation of concerns
 */
class UnifiedIndexedDBManager {
    constructor() {
        this.clientDB = passkeyClientDB;
        this.nearKeysDB = passkeyNearKeysDB;
    }
    // === CONVENIENCE METHODS ===
    /**
     * Get user data and check if they have encrypted NEAR keys
     */
    async getUserWithKeys(nearAccountId) {
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
const IndexedDBManager = new UnifiedIndexedDBManager();

export { IndexedDBManager, PasskeyClientDBManager, PasskeyNearKeysDBManager, UnifiedIndexedDBManager, passkeyClientDB, passkeyNearKeysDB };
//# sourceMappingURL=index.js.map
