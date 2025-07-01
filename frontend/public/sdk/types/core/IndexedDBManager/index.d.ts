export { PasskeyClientDBManager } from './passkeyClientDB';
export { PasskeyNearKeysDBManager } from './passkeyNearKeysDB';
export type { ClientUserData, UserPreferences, ClientAuthenticatorData } from './passkeyClientDB';
export type { EncryptedKeyData } from './passkeyNearKeysDB';
import { PasskeyClientDBManager, type ClientUserData } from './passkeyClientDB';
import { PasskeyNearKeysDBManager, type EncryptedKeyData } from './passkeyNearKeysDB';
export declare const passkeyClientDB: PasskeyClientDBManager;
export declare const passkeyNearKeysDB: PasskeyNearKeysDBManager;
/**
 * Unified IndexedDB interface providing access to both databases
 * This allows centralized access while maintaining separation of concerns
 */
export declare class UnifiedIndexedDBManager {
    readonly clientDB: PasskeyClientDBManager;
    readonly nearKeysDB: PasskeyNearKeysDBManager;
    constructor();
    /**
     * Get user data and check if they have encrypted NEAR keys
     */
    getUserWithKeys(nearAccountId: string): Promise<{
        userData: ClientUserData | null;
        hasKeys: boolean;
        keyData?: EncryptedKeyData | null;
    }>;
}
export declare const IndexedDBManager: UnifiedIndexedDBManager;
//# sourceMappingURL=index.d.ts.map