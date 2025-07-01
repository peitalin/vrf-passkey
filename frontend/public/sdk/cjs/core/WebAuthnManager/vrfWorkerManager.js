'use strict';

var webauthn = require('../types/webauthn.js');

/**
 * VRF Manager
 * Uses Web Workers for VRF keypair management with client-hosted worker files.
 */
/**
 * VRF Worker Manager
 *
 * This class manages VRF operations using Web Workers for:
 * - VRF keypair unlocking (login)
 * - VRF challenge generation (authentication)
 * - Session management (browser session only)
 * - Client-hosted worker files
 */
class VrfWorkerManager {
    constructor(config = {}) {
        this.vrfWorker = null;
        this.initializationPromise = null;
        this.messageId = 0;
        this.currentVrfAccountId = null;
        this.config = {
            // Default to client-hosted worker file
            vrfWorkerUrl: '/workers/web3authn-vrf.worker.js',
            workerTimeout: 10000,
            debug: false,
            ...config
        };
        console.log('VRF Manager: Initializing with client-hosted Web Worker...');
    }
    /**
   * Initialize VRF functionality using Web Workers
   */
    async initialize() {
        if (this.initializationPromise) {
            return this.initializationPromise;
        }
        this.initializationPromise = this.createVrfWorker();
        return this.initializationPromise;
    }
    /**
     * Initialize Web Worker with client-hosted VRF worker
     */
    async createVrfWorker() {
        try {
            console.log('VRF Manager: Worker URL:', this.config.vrfWorkerUrl);
            // Create Web Worker from client-hosted file
            this.vrfWorker = new Worker(this.config.vrfWorkerUrl, {
                type: 'module',
                name: 'Web3AuthnVRFWorker'
            });
            // Set up error handling
            this.vrfWorker.onerror = (error) => {
                console.error('VRF Manager: Web Worker error:', error);
            };
            // Test communication with the Web Worker
            await this.testWebWorkerCommunication();
        }
        catch (error) {
            throw new Error(`VRF Web Worker initialization failed: ${error.message}`);
        }
    }
    /**
     * Send message to Web Worker and wait for response
     */
    async sendMessage(message, customTimeout) {
        return new Promise((resolve, reject) => {
            if (!this.vrfWorker) {
                reject(new Error('VRF Web Worker not available'));
                return;
            }
            const timeoutMs = customTimeout || 30000;
            const timeout = setTimeout(() => {
                reject(new Error(`VRF Web Worker communication timeout (${timeoutMs}ms) for message type: ${message.type}`));
            }, timeoutMs);
            const handleMessage = (event) => {
                const response = event.data;
                if (response.id === message.id) {
                    clearTimeout(timeout);
                    this.vrfWorker.removeEventListener('message', handleMessage);
                    resolve(response);
                }
            };
            this.vrfWorker.addEventListener('message', handleMessage);
            this.vrfWorker.postMessage(message);
        });
    }
    /**
     * Generate unique message ID
     */
    generateMessageId() {
        return `vrf_${Date.now()}_${++this.messageId}`;
    }
    /**
     * Unlock VRF keypair in Web Worker memory using PRF output
     * This is called during login to decrypt and load the VRF keypair in-memory
     */
    async unlockVRFKeypair({ touchIdPrompt, nearAccountId, encryptedVrfKeypair, authenticators, prfOutput, onEvent, }) {
        if (!this.vrfWorker) {
            throw new Error('VRF Web Worker not initialized');
        }
        if (!prfOutput) {
            let challenge = crypto.getRandomValues(new Uint8Array(32));
            let credentialsAndPrf = await touchIdPrompt.getCredentialsAndPrf({
                nearAccountId,
                challenge,
                authenticators,
            });
            prfOutput = credentialsAndPrf.prfOutput;
            onEvent?.({
                type: 'loginProgress',
                data: {
                    step: 'verifying-server',
                    message: 'TouchId success! Unlocking VRF keypair in secure memory...'
                }
            });
        }
        const message = {
            type: 'UNLOCK_VRF_KEYPAIR',
            id: this.generateMessageId(),
            data: {
                nearAccountId,
                encryptedVrfKeypair,
                prfKey: Array.from(new Uint8Array(prfOutput))
            }
        };
        const response = await this.sendMessage(message);
        if (response.success) {
            // Track the current VRF session account at TypeScript level
            this.currentVrfAccountId = nearAccountId;
            console.log(`VRF Manager: VRF keypair unlocked for ${nearAccountId}`);
        }
        else {
            console.error('VRF Manager: Failed to unlock VRF keypair:', response.error);
        }
        return response;
    }
    /**
     * Generate VRF challenge using in-memory VRF keypair
     * This is called during authentication to create WebAuthn challenges
     */
    async generateVRFChallenge(inputData) {
        console.log('VRF Manager: Generating VRF challenge...');
        if (!this.vrfWorker) {
            throw new Error('VRF Web Worker not initialized');
        }
        const message = {
            type: 'GENERATE_VRF_CHALLENGE',
            id: this.generateMessageId(),
            data: {
                user_id: inputData.userId,
                rp_id: inputData.rpId,
                block_height: inputData.blockHeight,
                block_hash: Array.from(inputData.blockHash),
                timestamp: inputData.timestamp
            }
        };
        const response = await this.sendMessage(message);
        console.log("RESPONSE:", response);
        if (!response.success || !response.data) {
            throw new Error(`VRF challenge generation failed: ${response.error}`);
        }
        console.log('VRF Manager: VRF challenge generated successfully');
        return new webauthn.VRFChallenge(response.data);
    }
    /**
     * Get current VRF session status
     */
    async getVrfWorkerStatus() {
        if (!this.vrfWorker) {
            return { active: false, nearAccountId: null };
        }
        try {
            const message = {
                type: 'CHECK_VRF_STATUS',
                id: this.generateMessageId(),
                data: {}
            };
            const response = await this.sendMessage(message);
            if (response.success && response.data) {
                return {
                    active: response.data.active,
                    nearAccountId: this.currentVrfAccountId || null,
                    sessionDuration: response.data.sessionDuration
                };
            }
            return { active: false, nearAccountId: null };
        }
        catch (error) {
            console.warn('VRF Manager: Failed to get VRF status:', error);
            return { active: false, nearAccountId: null };
        }
    }
    /**
     * Logout and clear VRF session
     */
    async clearVrfSession() {
        console.log('VRF Manager: Logging out...');
        if (!this.vrfWorker) {
            return;
        }
        try {
            const message = {
                type: 'LOGOUT',
                id: this.generateMessageId(),
                data: {}
            };
            const response = await this.sendMessage(message);
            if (response.success) {
                // Clear the TypeScript-tracked account ID
                this.currentVrfAccountId = null;
                console.log('VRF Manager: Logged out: VRF keypair securely zeroized');
            }
            else {
                console.warn('️VRF Manager: Logout failed:', response.error);
            }
        }
        catch (error) {
            console.warn('VRF Manager: Logout error:', error);
        }
    }
    /**
     * Generate VRF keypair for bootstrapping - stores in memory unencrypted temporarily
     * This is used during registration to generate a VRF keypair that will be used for
     * WebAuthn ceremony and later encrypted with the real PRF output
     *
     * @param saveInMemory - Always true for bootstrap (VRF keypair stored in memory)
     * @param vrfInputParams - Optional parameters to generate VRF challenge/proof in same call
     * @returns VRF public key and optionally VRF challenge data
     */
    async generateVrfKeypair(saveInMemory, vrfInputParams) {
        console.log('VRF Manager: Generating bootstrap VRF keypair', {
            saveInMemory,
            withChallenge: !!vrfInputParams
        });
        // Wait for any existing initialization to complete before proceeding
        if (this.initializationPromise) {
            await this.initializationPromise;
        }
        else if (!this.vrfWorker) {
            await this.initialize();
        }
        if (!this.vrfWorker) {
            throw new Error('VRF Web Worker not initialized after initialization attempt');
        }
        try {
            const message = {
                type: 'GENERATE_VRF_KEYPAIR_BOOTSTRAP',
                id: this.generateMessageId(),
                data: {
                    // Include VRF input parameters if provided for challenge generation
                    vrfInputParams: vrfInputParams ? {
                        user_id: vrfInputParams.userId,
                        rp_id: vrfInputParams.rpId,
                        block_height: vrfInputParams.blockHeight,
                        block_hash: vrfInputParams.blockHashBytes,
                        timestamp: vrfInputParams.timestamp
                    } : undefined
                }
            };
            const response = await this.sendMessage(message);
            if (!response.success || !response.data) {
                throw new Error(`VRF bootstrap keypair generation failed: ${response.error}`);
            }
            // If VRF challenge data was also generated, include it in the result
            if (!response?.data?.vrf_challenge_data) {
                throw new Error('VRF challenge data failed to be generated');
            }
            if (vrfInputParams && saveInMemory) {
                // Track the account ID for this VRF session if saving in memory
                this.currentVrfAccountId = vrfInputParams.userId;
            }
            return {
                vrfPublicKey: response.data.vrf_public_key,
                vrfChallenge: new webauthn.VRFChallenge({
                    vrfInput: response.data.vrf_challenge_data.vrfInput,
                    vrfOutput: response.data.vrf_challenge_data.vrfOutput,
                    vrfProof: response.data.vrf_challenge_data.vrfProof,
                    vrfPublicKey: response.data.vrf_challenge_data.vrfPublicKey,
                    userId: response.data.vrf_challenge_data.userId,
                    rpId: response.data.vrf_challenge_data.rpId,
                    blockHeight: response.data.vrf_challenge_data.blockHeight,
                    blockHash: response.data.vrf_challenge_data.blockHash,
                })
            };
        }
        catch (error) {
            console.error('VRF Manager: Bootstrap VRF keypair generation failed:', error);
            throw new Error(`Failed to generate bootstrap VRF keypair: ${error.message}`);
        }
    }
    /**
     * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
     * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
     *
     * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
     * @param credential - WebAuthn credentials for encryption
     * @returns Encrypted VRF keypair data ready for storage
     */
    async encryptVrfKeypairWithCredentials(expectedPublicKey, credential) {
        console.log('VRF Manager: Encrypting in-memory VRF keypair with PRF output');
        if (!this.vrfWorker) {
            throw new Error('VRF Web Worker not initialized');
        }
        const prfOutput = credential.getClientExtensionResults()?.prf?.results?.first;
        if (!prfOutput) {
            throw new Error('PRF output not found in WebAuthn credentials');
        }
        try {
            const message = {
                type: 'ENCRYPT_VRF_KEYPAIR_WITH_PRF',
                id: this.generateMessageId(),
                data: {
                    expectedPublicKey: expectedPublicKey,
                    prfKey: Array.from(new Uint8Array(prfOutput))
                }
            };
            const response = await this.sendMessage(message);
            if (!response.success || !response.data) {
                throw new Error(`VRF keypair encryption failed: ${response.error}`);
            }
            const result = {
                vrfPublicKey: response.data.vrf_public_key,
                encryptedVrfKeypair: response.data.encrypted_vrf_keypair
            };
            console.log('VRF Manager: VRF keypair encryption successful');
            return result;
        }
        catch (error) {
            console.error('VRF Manager: VRF keypair encryption failed:', error);
            throw new Error(`Failed to encrypt VRF keypair: ${error.message}`);
        }
    }
    /**
     * Test Web Worker communication with progressive retry
     */
    async testWebWorkerCommunication() {
        const maxAttempts = 3;
        const baseDelay = 1000;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                console.log(`VRF Manager: Communication test attempt ${attempt}/${maxAttempts}`);
                const timeoutMs = attempt === 1 ? 8000 : 5000;
                const pingResponse = await this.sendMessage({
                    type: 'PING',
                    id: this.generateMessageId(),
                    data: {}
                }, timeoutMs);
                if (!pingResponse.success) {
                    throw new Error(`VRF Web Worker PING failed: ${pingResponse.error}`);
                }
                console.log('VRF Manager: Web Worker communication verified');
                return;
            }
            catch (error) {
                console.warn(`️ VRF Manager: Communication test attempt ${attempt} failed:`, error.message);
                if (attempt === maxAttempts) {
                    throw new Error(`Communication test failed after ${maxAttempts} attempts: ${error.message}`);
                }
                const delay = baseDelay * attempt;
                console.log(`   Waiting ${delay}ms before retry...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }
}

exports.VrfWorkerManager = VrfWorkerManager;
//# sourceMappingURL=vrfWorkerManager.js.map
