'use strict';

var passkeyClientDB$1 = require('./passkeyClientDB.js');
var passkeyNearKeysDB$1 = require('./passkeyNearKeysDB.js');

// === EXPORTS ===
// Export singleton instances for backward compatibility with existing code
const passkeyClientDB = new passkeyClientDB$1.PasskeyClientDBManager();
const passkeyNearKeysDB = new passkeyNearKeysDB$1.PasskeyNearKeysDBManager();
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

exports.PasskeyClientDBManager = passkeyClientDB$1.PasskeyClientDBManager;
exports.PasskeyNearKeysDBManager = passkeyNearKeysDB$1.PasskeyNearKeysDBManager;
exports.IndexedDBManager = IndexedDBManager;
exports.UnifiedIndexedDBManager = UnifiedIndexedDBManager;
exports.passkeyClientDB = passkeyClientDB;
exports.passkeyNearKeysDB = passkeyNearKeysDB;
//# sourceMappingURL=index.js.map
