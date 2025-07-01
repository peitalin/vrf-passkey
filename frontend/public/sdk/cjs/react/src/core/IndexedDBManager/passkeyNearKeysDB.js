'use strict';

// === CONSTANTS ===
const DB_CONFIG = {
    dbName: 'PasskeyNearKeys',
    dbVersion: 1,
    storeName: 'encryptedKeys',
    keyPath: 'nearAccountId'
};
class PasskeyNearKeysDBManager {
    constructor(config = DB_CONFIG) {
        this.config = config;
    }
    /**
     * Open IndexedDB connection
     */
    async openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.config.dbName, this.config.dbVersion);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains(this.config.storeName)) {
                    db.createObjectStore(this.config.storeName, { keyPath: this.config.keyPath });
                }
            };
        });
    }
    /**
     * Store encrypted key data
     */
    async storeEncryptedKey(data) {
        const db = await this.openDB();
        const transaction = db.transaction([this.config.storeName], 'readwrite');
        const store = transaction.objectStore(this.config.storeName);
        return new Promise((resolve, reject) => {
            const request = store.put(data);
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
     * Retrieve encrypted key data
     */
    async getEncryptedKey(nearAccountId) {
        console.log('PasskeyNearKeysDB: getEncryptedKey - Retrieving for account:', nearAccountId);
        const db = await this.openDB();
        const transaction = db.transaction([this.config.storeName], 'readonly');
        const store = transaction.objectStore(this.config.storeName);
        return new Promise((resolve, reject) => {
            const request = store.get(nearAccountId);
            request.onsuccess = () => {
                const result = request.result;
                if (!result?.encryptedData) {
                    console.warn('PasskeyNearKeysDB: getEncryptedKey - No result found');
                }
                db.close();
                resolve(result);
            };
            request.onerror = () => {
                console.error('PasskeyNearKeysDB: getEncryptedKey - Error:', request.error);
                db.close();
                reject(request.error);
            };
        });
    }
    /**
     * Verify key storage by attempting retrieval
     */
    async verifyKeyStorage(nearAccountId) {
        try {
            const retrievedKey = await this.getEncryptedKey(nearAccountId);
            return !!retrievedKey;
        }
        catch (error) {
            console.error('PasskeyNearKeysDB: verifyKeyStorage - Error:', error);
            return false;
        }
    }
    /**
     * Delete encrypted key data for a specific account
     */
    async deleteEncryptedKey(nearAccountId) {
        console.log('PasskeyNearKeysDB: deleteEncryptedKey - Deleting for account:', nearAccountId);
        const db = await this.openDB();
        const transaction = db.transaction([this.config.storeName], 'readwrite');
        const store = transaction.objectStore(this.config.storeName);
        return new Promise((resolve, reject) => {
            const request = store.delete(nearAccountId);
            request.onsuccess = () => {
                console.log('PasskeyNearKeysDB: deleteEncryptedKey - Successfully deleted');
                db.close();
                resolve();
            };
            request.onerror = () => {
                console.error('PasskeyNearKeysDB: deleteEncryptedKey - Error:', request.error);
                db.close();
                reject(request.error);
            };
        });
    }
    /**
     * Get all encrypted keys (for migration or debugging purposes)
     */
    async getAllEncryptedKeys() {
        const db = await this.openDB();
        const transaction = db.transaction([this.config.storeName], 'readonly');
        const store = transaction.objectStore(this.config.storeName);
        return new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => {
                db.close();
                resolve(request.result || []);
            };
            request.onerror = () => {
                console.error('PasskeyNearKeysDB: getAllEncryptedKeys - Error:', request.error);
                db.close();
                reject(request.error);
            };
        });
    }
    /**
     * Clear all encrypted keys (for testing or reset purposes)
     */
    async clearAllEncryptedKeys() {
        console.log('PasskeyNearKeysDB: clearAllEncryptedKeys - Clearing all keys');
        const db = await this.openDB();
        const transaction = db.transaction([this.config.storeName], 'readwrite');
        const store = transaction.objectStore(this.config.storeName);
        return new Promise((resolve, reject) => {
            const request = store.clear();
            request.onsuccess = () => {
                console.log('PasskeyNearKeysDB: clearAllEncryptedKeys - Successfully cleared');
                db.close();
                resolve();
            };
            request.onerror = () => {
                console.error('PasskeyNearKeysDB: clearAllEncryptedKeys - Error:', request.error);
                db.close();
                reject(request.error);
            };
        });
    }
    /**
     * Check if a key exists for the given account
     */
    async hasEncryptedKey(nearAccountId) {
        try {
            const keyData = await this.getEncryptedKey(nearAccountId);
            return !!keyData;
        }
        catch (error) {
            console.error('PasskeyNearKeysDB: hasEncryptedKey - Error:', error);
            return false;
        }
    }
    /**
     * Update timestamp for an existing encrypted key (for tracking last access)
     */
    async updateKeyTimestamp(nearAccountId) {
        const existingKey = await this.getEncryptedKey(nearAccountId);
        if (existingKey) {
            const updatedKey = {
                ...existingKey,
                timestamp: Date.now()
            };
            await this.storeEncryptedKey(updatedKey);
        }
    }
}

exports.PasskeyNearKeysDBManager = PasskeyNearKeysDBManager;
//# sourceMappingURL=passkeyNearKeysDB.js.map
