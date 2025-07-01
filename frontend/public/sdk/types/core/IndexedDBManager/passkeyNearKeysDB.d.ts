export interface EncryptedKeyData {
    nearAccountId: string;
    encryptedData: string;
    iv: string;
    timestamp: number;
}
interface PasskeyNearKeysDBConfig {
    dbName: string;
    dbVersion: number;
    storeName: string;
    keyPath: string;
}
export declare class PasskeyNearKeysDBManager {
    private config;
    constructor(config?: PasskeyNearKeysDBConfig);
    /**
     * Open IndexedDB connection
     */
    private openDB;
    /**
     * Store encrypted key data
     */
    storeEncryptedKey(data: EncryptedKeyData): Promise<void>;
    /**
     * Retrieve encrypted key data
     */
    getEncryptedKey(nearAccountId: string): Promise<EncryptedKeyData | null>;
    /**
     * Verify key storage by attempting retrieval
     */
    verifyKeyStorage(nearAccountId: string): Promise<boolean>;
    /**
     * Delete encrypted key data for a specific account
     */
    deleteEncryptedKey(nearAccountId: string): Promise<void>;
    /**
     * Get all encrypted keys (for migration or debugging purposes)
     */
    getAllEncryptedKeys(): Promise<EncryptedKeyData[]>;
    /**
     * Clear all encrypted keys (for testing or reset purposes)
     */
    clearAllEncryptedKeys(): Promise<void>;
    /**
     * Check if a key exists for the given account
     */
    hasEncryptedKey(nearAccountId: string): Promise<boolean>;
    /**
     * Update timestamp for an existing encrypted key (for tracking last access)
     */
    updateKeyTimestamp(nearAccountId: string): Promise<void>;
}
export {};
//# sourceMappingURL=passkeyNearKeysDB.d.ts.map