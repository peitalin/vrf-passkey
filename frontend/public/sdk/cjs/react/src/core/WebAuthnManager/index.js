'use strict';

var signerWorkerManager = require('./signerWorkerManager.js');
var index = require('../IndexedDBManager/index.js');
var vrfWorkerManager = require('./vrfWorkerManager.js');
var touchIdPrompt = require('./touchIdPrompt.js');

/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - signerWorkerManager: NEAR transaction signing, and VRF Web3Authn verification RPC calls
 * - vrfWorkerManager: VRF keypair generation, challenge generation
 * - touchIdPrompt: TouchID prompt for biometric authentication
 */
class WebAuthnManager {
    constructor(configs) {
        this.vrfWorkerManager = new vrfWorkerManager.VrfWorkerManager();
        this.signerWorkerManager = new signerWorkerManager.SignerWorkerManager();
        this.touchIdPrompt = new touchIdPrompt.TouchIdPrompt();
        this.configs = configs;
    }
    ///////////////////////////////////////
    // VRF MANAGER FUNCTIONS
    ///////////////////////////////////////
    async initializeVrfWorkerManager() {
        return this.vrfWorkerManager.initialize();
    }
    async getVrfWorkerStatus() {
        return this.vrfWorkerManager.getVrfWorkerStatus();
    }
    async clearVrfSession() {
        return this.vrfWorkerManager.clearVrfSession();
    }
    async generateVRFChallenge(vrfInputData) {
        return this.vrfWorkerManager.generateVRFChallenge(vrfInputData);
    }
    /**
     * Generate VRF keypair for bootstrapping - stores in memory unencrypted temporarily
     * This is used during registration to generate a VRF keypair that will be used for
     * WebAuthn ceremony and later encrypted with the real PRF output
     *
     * @param saveInMemory - Whether to persist the generated VRF keypair in WASM worker memory
     * @param vrfInputParams - Optional parameters to generate VRF challenge/proof in same call
     * @returns VRF public key and optionally VRF challenge data
     */
    async generateVrfKeypair(saveInMemory, vrfInputParams) {
        return await this.vrfWorkerManager.generateVrfKeypair(saveInMemory, vrfInputParams);
    }
    /**
     * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
     * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
     *
     * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
     * @param prfOutput - PRF output from WebAuthn ceremony for encryption
     * @returns Encrypted VRF keypair data ready for storage
     */
    async encryptVrfKeypairWithCredentials({ credential, vrfPublicKey, }) {
        return await this.vrfWorkerManager.encryptVrfKeypairWithCredentials(vrfPublicKey, credential);
    }
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
    async unlockVRFKeypair({ nearAccountId, encryptedVrfKeypair, webauthnCredential, authenticators, onEvent }) {
        if (!authenticators) {
            authenticators = await this.getAuthenticatorsByUser(nearAccountId);
            if (!authenticators || authenticators.length === 0) {
                throw new Error('No authenticators found for account ' + nearAccountId + '. Please register.');
            }
        }
        if (!webauthnCredential) {
            // login flow: unlock VRF generator with a normal TouchId prompt with JS RNG
            const { credential } = await this.touchIdPrompt.getCredentialsAndPrf({
                nearAccountId,
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                authenticators,
            });
            webauthnCredential = credential;
        }
        const prfOutput = webauthnCredential?.getClientExtensionResults().prf?.results?.first;
        if (!prfOutput) {
            throw new Error('PRF output not found in WebAuthn credentials');
        }
        return await this.vrfWorkerManager.unlockVRFKeypair({
            touchIdPrompt: this.touchIdPrompt,
            nearAccountId: nearAccountId,
            encryptedVrfKeypair: encryptedVrfKeypair,
            authenticators,
            prfOutput,
            onEvent,
        });
    }
    ///////////////////////////////////////
    // INDEXEDDB OPERATIONS
    ///////////////////////////////////////
    async storeUserData(userData) {
        await index.IndexedDBManager.clientDB.storeWebAuthnUserData(userData);
    }
    async getUser(nearAccountId) {
        return await index.IndexedDBManager.clientDB.getUser(nearAccountId);
    }
    async getAllUserData() {
        const allUsers = await index.IndexedDBManager.clientDB.getAllUsers();
        return allUsers.map(user => ({
            nearAccountId: user.nearAccountId,
            clientNearPublicKey: user.clientNearPublicKey,
            lastUpdated: user.lastUpdated,
            prfSupported: user.prfSupported,
            deterministicKey: true,
            passkeyCredential: user.passkeyCredential,
            encryptedVrfKeypair: user.encryptedVrfKeypair
        }));
    }
    async getAllUsers() {
        return await index.IndexedDBManager.clientDB.getAllUsers();
    }
    async getAuthenticatorsByUser(nearAccountId) {
        return await index.IndexedDBManager.clientDB.getAuthenticatorsByUser(nearAccountId);
    }
    async updateLastLogin(nearAccountId) {
        return await index.IndexedDBManager.clientDB.updateLastLogin(nearAccountId);
    }
    async registerUser(nearAccountId, additionalData) {
        return await index.IndexedDBManager.clientDB.registerUser(nearAccountId, additionalData);
    }
    async storeAuthenticator(authenticatorData) {
        return await index.IndexedDBManager.clientDB.storeAuthenticator(authenticatorData);
    }
    extractUsername(nearAccountId) {
        return index.IndexedDBManager.clientDB.extractUsername(nearAccountId);
    }
    async atomicOperation(callback) {
        return await index.IndexedDBManager.clientDB.atomicOperation(callback);
    }
    async rollbackUserRegistration(nearAccountId) {
        return await index.IndexedDBManager.clientDB.rollbackUserRegistration(nearAccountId);
    }
    async hasPasskeyCredential(nearAccountId) {
        return await index.IndexedDBManager.clientDB.hasPasskeyCredential(nearAccountId);
    }
    async getLastUsedNearAccountId() {
        const lastUser = await index.IndexedDBManager.clientDB.getLastUser();
        return lastUser?.nearAccountId || null;
    }
    ///////////////////////////////////////
    // SIGNER WASM WORKER OPERATIONS
    ///////////////////////////////////////
    /**
     * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
     */
    async deriveNearKeypairAndEncrypt({ credential, nearAccountId, }) {
        return await this.signerWorkerManager.deriveNearKeypairAndEncrypt(credential, nearAccountId);
    }
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
    async exportNearKeypairWithTouchId(nearAccountId) {
        console.log(`🔐 Exporting private key for account: ${nearAccountId}`);
        // Get user data to verify user exists
        const userData = await this.getUser(nearAccountId);
        if (!userData) {
            throw new Error(`No user data found for ${nearAccountId}`);
        }
        if (!userData.clientNearPublicKey) {
            throw new Error(`No public key found for ${nearAccountId}`);
        }
        // Get stored authenticator data for this user
        const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
        if (authenticators.length === 0) {
            throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
        }
        // Use WASM worker to decrypt private key
        const decryptionResult = await this.signerWorkerManager.decryptPrivateKeyWithPrf(this.touchIdPrompt, nearAccountId, authenticators);
        return {
            accountId: userData.nearAccountId,
            publicKey: userData.clientNearPublicKey,
            privateKey: decryptionResult.decryptedPrivateKey,
        };
    }
    /**
     * Sign a NEAR Transfer transaction using PRF
     * Requires TouchId
     *
     * Enhanced Transfer transaction signing with contract verification and progress updates
     * Uses the new verify+sign WASM function for secure, efficient transaction processing
     */
    async signTransferTransaction(payload, onEvent) {
        const { nearAccountId, vrfChallenge } = payload;
        onEvent?.({
            step: 2,
            phase: 'authentication',
            status: 'progress',
            message: 'Authenticating with VRF challenge...'
        });
        // Get stored authenticator data
        const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
        if (authenticators.length === 0) {
            throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
        }
        const { credential } = await this.touchIdPrompt.getCredentialsAndPrf({
            nearAccountId,
            challenge: vrfChallenge.outputAs32Bytes(),
            authenticators,
        });
        console.log('✅ VRF WebAuthn authentication completed');
        onEvent?.({
            step: 3,
            phase: 'contract-verification',
            status: 'progress',
            message: 'Authentication verified - preparing transaction...'
        });
        onEvent?.({
            step: 4,
            phase: 'transaction-signing',
            status: 'progress',
            message: 'Signing transaction in secure worker...'
        });
        return await this.signerWorkerManager.signTransferTransaction({
            ...payload,
            webauthnCredential: credential,
        }, onEvent);
    }
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
    async signTransactionWithActions(payload, onEvent) {
        const { nearAccountId, vrfChallenge } = payload;
        onEvent?.({
            step: 2,
            phase: 'authentication',
            status: 'progress',
            message: 'Authenticating with VRF challenge...'
        });
        // Get stored authenticator data
        const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
        if (authenticators.length === 0) {
            throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
        }
        const { credential } = await this.touchIdPrompt.getCredentialsAndPrf({
            nearAccountId,
            challenge: vrfChallenge.outputAs32Bytes(),
            authenticators,
        });
        console.log('✅ VRF WebAuthn authentication completed');
        onEvent?.({
            step: 3,
            phase: 'contract-verification',
            status: 'progress',
            message: 'Authentication verified - preparing transaction...'
        });
        onEvent?.({
            step: 4,
            phase: 'transaction-signing',
            status: 'progress',
            message: 'Signing transaction in secure worker...'
        });
        return await this.signerWorkerManager.signTransactionWithActions({
            ...payload,
            webauthnCredential: credential,
        }, onEvent);
    }
    // === COSE OPERATIONS (Delegated to WebAuthnWorkers) ===
    /**
     * Extract COSE public key from WebAuthn attestation object using WASM worker
     */
    async extractCosePublicKey(attestationObjectBase64url) {
        return await this.signerWorkerManager.extractCosePublicKey(attestationObjectBase64url);
    }
    ///////////////////////////////////////
    // REGISTRATION
    ///////////////////////////////////////
    async checkCanRegisterUser({ contractId, webauthnCredential, vrfChallenge, onEvent, }) {
        return await this.signerWorkerManager.checkCanRegisterUser({
            contractId,
            webauthnCredential,
            vrfChallenge,
            onEvent,
        });
    }
    /**
     * Register user on-chain with transaction (STATE-CHANGING)
     * This performs the actual on-chain registration transaction
     */
    async signVerifyAndRegisterUser({ contractId, webauthnCredential, vrfChallenge, signerAccountId, nearAccountId, publicKeyStr, nearRpcProvider, onEvent, }) {
        try {
            const registrationResult = await this.signerWorkerManager.signVerifyAndRegisterUser({
                vrfChallenge,
                webauthnCredential,
                contractId,
                signerAccountId,
                nearAccountId,
                publicKeyStr,
                nearRpcProvider,
                onEvent,
            });
            console.debug("On-chain registration completed:", registrationResult);
            if (registrationResult.verified) {
                console.debug('✅ On-chain user registration successful');
                return {
                    success: true,
                    verified: true,
                    registrationInfo: registrationResult.registrationInfo,
                    logs: registrationResult.logs,
                    signedTransactionBorsh: registrationResult.signedTransactionBorsh,
                };
            }
            else {
                console.warn('❌ On-chain user registration failed');
                return {
                    success: false,
                    verified: false,
                    error: 'On-chain registration transaction failed',
                };
            }
        }
        catch (error) {
            console.error('WebAuthnManager: On-chain registration error:', error);
            return {
                success: false,
                verified: false,
                error: error.message || 'On-chain registration failed',
            };
        }
    }
}

exports.WebAuthnManager = WebAuthnManager;
//# sourceMappingURL=index.js.map
