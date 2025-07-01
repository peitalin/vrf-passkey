'use strict';

var index = require('../WebAuthnManager/index.js');
var index$1 = require('./registration/index.js');
var login = require('./login.js');
var actions = require('./actions.js');

/**
 * Main PasskeyManager class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
class PasskeyManager {
    constructor(configs, nearRpcProvider) {
        if (!nearRpcProvider) {
            throw new Error('NEAR RPC provider is required');
        }
        this.configs = configs;
        this.nearRpcProvider = nearRpcProvider;
        this.webAuthnManager = new index.WebAuthnManager(configs);
        // Initialize VRF Worker in the background
        this.initializeVrfWorkerManager();
    }
    /**
     * Register a new passkey for the given NEAR account ID
     */
    async registerPasskey(nearAccountId, options) {
        return index$1.registerPasskey(this.getContext(), nearAccountId, options);
    }
    /**
     * Login with an existing passkey
     */
    async loginPasskey(nearAccountId, options) {
        return login.loginPasskey(this.getContext(), nearAccountId, options);
    }
    /**
     * Logout: Clear VRF session (clear VRF keypair in worker)
     */
    async logoutAndClearVrfSession() {
        return this.webAuthnManager.clearVrfSession();
    }
    /**
     * Execute a blockchain action/transaction using the new user-friendly API
     *
     * @example
     * ```typescript
     * // Function call
     * await passkeyManager.executeAction('alice.near', {
     *   type: 'FunctionCall',
     *   receiverId: 'contract.near',
     *   methodName: 'set_greeting',
     *   args: { message: 'Hello World!' },
     *   gas: '30000000000000',
     *   deposit: '0'
     * });
     *
     * // Transfer
     * await passkeyManager.executeAction('alice.near', {
     *   type: 'Transfer',
     *   receiverId: 'bob.near',
     *   amount: '1000000000000000000000000' // 1 NEAR
     * });
     * ```
     */
    async executeAction(nearAccountId, actionArgs, options) {
        return actions.executeAction(this.getContext(), nearAccountId, actionArgs, options);
    }
    /**
     * Get comprehensive login state information
     * This is the preferred method for frontend components to check login status
     */
    async getLoginState(nearAccountId) {
        try {
            // Determine target account ID
            let targetAccountId = nearAccountId;
            if (!targetAccountId) {
                // Try to get the last used account
                targetAccountId = await this.webAuthnManager.getLastUsedNearAccountId() || undefined;
            }
            if (!targetAccountId) {
                return {
                    isLoggedIn: false,
                    nearAccountId: null,
                    publicKey: null,
                    vrfActive: false,
                    userData: null
                };
            }
            // Get comprehensive user data from IndexedDB (single call instead of two)
            const userData = await this.webAuthnManager.getUser(targetAccountId);
            const publicKey = userData?.clientNearPublicKey || null;
            // Check VRF Web Worker status
            const vrfStatus = await this.webAuthnManager.getVrfWorkerStatus();
            const vrfActive = vrfStatus.active && vrfStatus.nearAccountId === targetAccountId;
            // Determine if user is considered "logged in"
            // User is logged in if they have user data and either VRF is active OR they have valid credentials
            const isLoggedIn = !!(userData && (vrfActive || userData.clientNearPublicKey));
            return {
                isLoggedIn,
                nearAccountId: targetAccountId,
                publicKey,
                vrfActive,
                userData,
                vrfSessionDuration: vrfStatus.sessionDuration
            };
        }
        catch (error) {
            console.warn('Error getting login state:', error);
            return {
                isLoggedIn: false,
                nearAccountId: nearAccountId || null,
                publicKey: null,
                vrfActive: false,
                userData: null
            };
        }
    }
    async getRecentLogins() {
        // Get all user accounts from IndexDB
        const allUsersData = await this.webAuthnManager.getAllUserData();
        const accountIds = allUsersData.map(user => user.nearAccountId);
        // Get last used account for initial state
        const lastUsedAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
        return {
            accountIds,
            lastUsedAccountId,
        };
    }
    async hasPasskeyCredential(nearAccountId) {
        return await this.webAuthnManager.hasPasskeyCredential(nearAccountId);
    }
    /**
     * Export key pair (both private and public keys)
     */
    async exportNearKeypairWithTouchId(nearAccountId) {
        // Export private key using the method above
        return await this.webAuthnManager.exportNearKeypairWithTouchId(nearAccountId);
    }
    ///////////////////////////////////////
    // PRIVATE FUNCTIONS
    ///////////////////////////////////////
    /**
     * Internal VRF Worker initialization that runs automatically
     * This abstracts VRF implementation details away from users
     */
    async initializeVrfWorkerManager() {
        try {
            console.log('PasskeyManager: Initializing VRF Web Worker...');
            await this.webAuthnManager.initializeVrfWorkerManager();
        }
        catch (error) {
            console.warn('️PasskeyManager: VRF Web Worker auto-initialization failed:', error.message);
        }
    }
    getContext() {
        return {
            webAuthnManager: this.webAuthnManager,
            nearRpcProvider: this.nearRpcProvider,
            configs: this.configs
        };
    }
}

exports.PasskeyManager = PasskeyManager;
//# sourceMappingURL=index.js.map
