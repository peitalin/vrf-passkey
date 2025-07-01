import { type IDBPDatabase } from 'idb';
import { type ValidationResult } from '../utils/validation';
export interface ClientUserData {
    nearAccountId: string;
    registeredAt: number;
    lastLogin?: number;
    lastUpdated: number;
    clientNearPublicKey?: string;
    prfSupported?: boolean;
    passkeyCredential?: {
        id: string;
        rawId: string;
    };
    encryptedVrfKeypair?: {
        encrypted_vrf_data_b64u: string;
        aes_gcm_nonce_b64u: string;
    };
    preferences?: UserPreferences;
}
export interface UserPreferences {
    useRelayer: boolean;
    useNetwork: 'testnet' | 'mainnet';
}
export interface ClientAuthenticatorData {
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
}
interface PasskeyClientDBConfig {
    dbName: string;
    dbVersion: number;
    userStore: string;
    appStateStore: string;
    authenticatorStore: string;
}
export declare class PasskeyClientDBManager {
    private config;
    private db;
    constructor(config?: PasskeyClientDBConfig);
    private getDB;
    getAppState<T = any>(key: string): Promise<T | undefined>;
    setAppState<T = any>(key: string, value: T): Promise<void>;
    /**
     * Validate that a NEAR account ID is in the expected format
     * Supports both <username>.<relayerAccountId> and <username>.testnet formats
     */
    validateNearAccountId(nearAccountId: string): ValidationResult;
    /**
     * Extract username from NEAR account ID
     */
    extractUsername(nearAccountId: string): string;
    /**
     * Generate a NEAR account ID from a username and domain
     * @param username - The username to use for the account ID
     * @param domain - The domain to use for the account ID
     * @returns The generated NEAR account ID
     */
    generateNearAccountId(username: string, domain: string): string;
    getUser(nearAccountId: string): Promise<ClientUserData | null>;
    /**
     * Get the current/last user
     * This is maintained via app state and updated whenever a user is stored or updated
     */
    getLastUser(): Promise<ClientUserData | null>;
    hasPasskeyCredential(nearAccountId: string): Promise<boolean>;
    /**
     * Register a new user with the given NEAR account ID
     * @param nearAccountId - Full NEAR account ID (e.g., "username.testnet" or "username.relayer.testnet")
     * @param additionalData - Additional user data to store
     */
    registerUser(nearAccountId: string, additionalData?: Partial<ClientUserData>): Promise<ClientUserData>;
    updateUser(nearAccountId: string, updates: Partial<ClientUserData>): Promise<void>;
    updateLastLogin(nearAccountId: string): Promise<void>;
    updatePreferences(nearAccountId: string, preferences: Partial<UserPreferences>): Promise<void>;
    private storeUser;
    /**
     * Store WebAuthn user data (compatibility with WebAuthnManager)
     * @param userData - User data with nearAccountId as primary identifier
     */
    storeWebAuthnUserData(userData: {
        nearAccountId: string;
        clientNearPublicKey?: string;
        lastUpdated?: number;
        prfSupported?: boolean;
        passkeyCredential?: {
            id: string;
            rawId: string;
        };
        encryptedVrfKeypair?: {
            encrypted_vrf_data_b64u: string;
            aes_gcm_nonce_b64u: string;
        };
    }): Promise<void>;
    getAllUsers(): Promise<ClientUserData[]>;
    deleteUser(nearAccountId: string): Promise<void>;
    clearAllUsers(): Promise<void>;
    clearAllAppState(): Promise<void>;
    /**
     * Store authenticator data for a user
     */
    storeAuthenticator(authenticatorData: ClientAuthenticatorData): Promise<void>;
    /**
     * Get all authenticators for a user
     */
    getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]>;
    /**
     * Get a specific authenticator by credential ID
     */
    getAuthenticatorByCredentialId(nearAccountId: string, credentialId: string): Promise<ClientAuthenticatorData | null>;
    /**
     * Update authenticator last used timestamp
     */
    updateAuthenticatorLastUsed(nearAccountId: string, credentialId: string, lastUsed?: string): Promise<void>;
    /**
     * Clear all authenticators for a user
     */
    clearAuthenticatorsForUser(nearAccountId: string): Promise<void>;
    /**
     * Sync authenticators from contract data
     */
    syncAuthenticatorsFromContract(nearAccountId: string, contractAuthenticators: Array<{
        credentialID: string;
        credentialPublicKey: Uint8Array;
        transports?: string[];
        clientNearPublicKey?: string;
        name?: string;
        registered: string;
        lastUsed?: string;
        backedUp: boolean;
    }>): Promise<void>;
    /**
     * Delete all authenticators for a user
     */
    deleteAllAuthenticatorsForUser(nearAccountId: string): Promise<void>;
    /**
     * Atomic operation wrapper for multiple IndexedDB operations
     * Either all operations succeed or all are rolled back
     */
    atomicOperation<T>(operation: (db: IDBPDatabase) => Promise<T>): Promise<T>;
    /**
     * Complete rollback of user registration data
     * Deletes user, authenticators, and WebAuthn data atomically
     */
    rollbackUserRegistration(nearAccountId: string): Promise<void>;
}
export {};
//# sourceMappingURL=passkeyClientDB.d.ts.map