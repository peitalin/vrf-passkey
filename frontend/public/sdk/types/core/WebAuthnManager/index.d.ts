import type { Provider } from '@near-js/providers';
import { VRFWorkerStatus } from './vrfWorkerManager';
import { TouchIdPrompt } from './touchIdPrompt';
import type { UserData, ActionParams } from '../types/signer-worker';
import type { ClientUserData, ClientAuthenticatorData } from '../IndexedDBManager';
import type { onProgressEvents, VerifyAndSignTransactionResult, VRFChallenge } from '../types/webauthn';
import type { EncryptedVRFKeypair, VRFInputData } from './vrfWorkerManager';
import type { PasskeyManagerConfigs } from '../types/passkeyManager';
/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - signerWorkerManager: NEAR transaction signing, and VRF Web3Authn verification RPC calls
 * - vrfWorkerManager: VRF keypair generation, challenge generation
 * - touchIdPrompt: TouchID prompt for biometric authentication
 */
export declare class WebAuthnManager {
    private readonly vrfWorkerManager;
    private readonly signerWorkerManager;
    readonly configs: PasskeyManagerConfigs;
    readonly touchIdPrompt: TouchIdPrompt;
    constructor(configs: PasskeyManagerConfigs);
    initializeVrfWorkerManager(): Promise<void>;
    getVrfWorkerStatus(): Promise<VRFWorkerStatus>;
    clearVrfSession(): Promise<void>;
    generateVRFChallenge(vrfInputData: VRFInputData): Promise<VRFChallenge>;
    /**
     * Generate VRF keypair for bootstrapping - stores in memory unencrypted temporarily
     * This is used during registration to generate a VRF keypair that will be used for
     * WebAuthn ceremony and later encrypted with the real PRF output
     *
     * @param saveInMemory - Whether to persist the generated VRF keypair in WASM worker memory
     * @param vrfInputParams - Optional parameters to generate VRF challenge/proof in same call
     * @returns VRF public key and optionally VRF challenge data
     */
    generateVrfKeypair(saveInMemory: boolean, vrfInputParams: {
        userId: string;
        rpId: string;
        blockHeight: number;
        blockHashBytes: number[];
        timestamp: number;
    }): Promise<{
        vrfPublicKey: string;
        vrfChallenge: VRFChallenge;
    }>;
    /**
     * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
     * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
     *
     * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
     * @param prfOutput - PRF output from WebAuthn ceremony for encryption
     * @returns Encrypted VRF keypair data ready for storage
     */
    encryptVrfKeypairWithCredentials({ credential, vrfPublicKey, }: {
        credential: PublicKeyCredential;
        vrfPublicKey: string;
    }): Promise<{
        vrfPublicKey: string;
        encryptedVrfKeypair: any;
    }>;
    /**
     * Unlock VRF keypair in VRF Worker memory using PRF output from WebAuthn ceremony
     * This decrypts the stored VRF keypair and keeps it in memory for challenge generation
     * requires touchId (conditional - only if webauthnCredential not provided)
     *
     * @param nearAccountId - NEAR account ID associated with the VRF keypair
     * @param encryptedVrfKeypair - Encrypted VRF keypair data from storage
     * @param webauthnCredential - WebAuthn credential from TouchID prompt (optional)
     * If not provided, will do a TouchID prompt (e.g. login flow)
     * @returns Success status and optional error message
     */
    unlockVRFKeypair({ nearAccountId, encryptedVrfKeypair, webauthnCredential, authenticators, onEvent }: {
        nearAccountId: string;
        encryptedVrfKeypair: EncryptedVRFKeypair;
        webauthnCredential?: PublicKeyCredential;
        authenticators?: ClientAuthenticatorData[];
        onEvent?: (event: {
            type: string;
            data: {
                step: string;
                message: string;
            };
        }) => void;
    }): Promise<{
        success: boolean;
        error?: string;
    }>;
    storeUserData(userData: UserData): Promise<void>;
    getUser(nearAccountId: string): Promise<ClientUserData | null>;
    getAllUserData(): Promise<UserData[]>;
    getAllUsers(): Promise<ClientUserData[]>;
    getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]>;
    updateLastLogin(nearAccountId: string): Promise<void>;
    registerUser(nearAccountId: string, additionalData?: Partial<ClientUserData>): Promise<ClientUserData>;
    storeAuthenticator(authenticatorData: {
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
    }): Promise<void>;
    extractUsername(nearAccountId: string): string;
    atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T>;
    rollbackUserRegistration(nearAccountId: string): Promise<void>;
    hasPasskeyCredential(nearAccountId: string): Promise<boolean>;
    getLastUsedNearAccountId(): Promise<string | null>;
    /**
     * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
     */
    deriveNearKeypairAndEncrypt({ credential, nearAccountId, }: {
        credential: PublicKeyCredential;
        nearAccountId: string;
    }): Promise<{
        success: boolean;
        nearAccountId: string;
        publicKey: string;
    }>;
    /**
     * Export private key using PRF-based decryption
     * Requires TouchId
     *
     * SECURITY MODEL: Local random challenge is sufficient for private key export because:
     * - User must possess physical authenticator device
     * - Device enforces biometric/PIN verification before PRF access
     * - No network communication or replay attack surface
     * - Challenge only needs to be random to prevent pre-computation
     * - Security comes from device possession + biometrics, not challenge validation
     */
    exportNearKeypairWithTouchId(nearAccountId: string): Promise<{
        accountId: string;
        publicKey: string;
        privateKey: string;
    }>;
    /**
     * Sign a NEAR Transfer transaction using PRF
     * Requires TouchId
     *
     * Enhanced Transfer transaction signing with contract verification and progress updates
     * Uses the new verify+sign WASM function for secure, efficient transaction processing
     */
    signTransferTransaction(payload: {
        nearAccountId: string;
        receiverId: string;
        depositAmount: string;
        nonce: string;
        blockHashBytes: number[];
        contractId: string;
        vrfChallenge: VRFChallenge;
    }, onEvent?: (update: onProgressEvents) => void): Promise<VerifyAndSignTransactionResult>;
    /**
     * Transaction signing with contract verification and progress updates.
     * Demonstrates the "streaming" worker pattern similar to SSE.
     *
     * Requires a successful TouchID/biometric prompt before transaction signing in wasm worker
     * Automatically verifies the authentication with the web3authn contract.
     *
     * @param payload - Transaction payload containing:
     *   - nearAccountId: NEAR account ID performing the transaction
     *   - receiverId: NEAR account ID receiving the transaction
     *   - actions: Array of NEAR actions to execute
     *   - nonce: Transaction nonce
     *   - blockHashBytes: Recent block hash for transaction freshness
     *   - contractId: Web3Authn contract ID for verification
     *   - vrfChallenge: VRF challenge used in authentication
     *   - webauthnCredential: WebAuthn credential from TouchID prompt
     * @param onEvent - Optional callback for progress updates during signing
     */
    signTransactionWithActions(payload: {
        nearAccountId: string;
        receiverId: string;
        actions: ActionParams[];
        nonce: string;
        blockHashBytes: number[];
        contractId: string;
        vrfChallenge: VRFChallenge;
    }, onEvent?: (update: onProgressEvents) => void): Promise<VerifyAndSignTransactionResult>;
    /**
     * Extract COSE public key from WebAuthn attestation object using WASM worker
     */
    extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array>;
    checkCanRegisterUser({ contractId, webauthnCredential, vrfChallenge, onEvent, }: {
        contractId: string;
        webauthnCredential: PublicKeyCredential;
        vrfChallenge: VRFChallenge;
        onEvent?: (update: onProgressEvents) => void;
    }): Promise<{
        success: boolean;
        verified?: boolean;
        registrationInfo?: any;
        logs?: string[];
        signedTransactionBorsh?: number[];
        error?: string;
    }>;
    /**
     * Register user on-chain with transaction (STATE-CHANGING)
     * This performs the actual on-chain registration transaction
     */
    signVerifyAndRegisterUser({ contractId, webauthnCredential, vrfChallenge, signerAccountId, nearAccountId, publicKeyStr, nearRpcProvider, onEvent, }: {
        contractId: string;
        webauthnCredential: PublicKeyCredential;
        vrfChallenge: VRFChallenge;
        signerAccountId: string;
        nearAccountId: string;
        publicKeyStr: string;
        nearRpcProvider: Provider;
        onEvent?: (update: onProgressEvents) => void;
    }): Promise<{
        success: boolean;
        verified?: boolean;
        registrationInfo?: any;
        logs?: string[];
        signedTransactionBorsh?: number[];
        error?: string;
    }>;
}
//# sourceMappingURL=index.d.ts.map