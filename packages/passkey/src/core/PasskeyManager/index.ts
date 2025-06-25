import { WebAuthnManager } from '../WebAuthnManager';
import { IndexedDBManager } from '../IndexedDBManager';
import { VRFManager } from '../WebAuthnManager/vrfManager';
import { generateUserScopedPrfSalt } from '../../utils';

import { registerPasskey } from './registration';
import { loginPasskey } from './login';
import { executeAction } from './actions';
import type {
  PasskeyManagerConfig,
  RegistrationOptions,
  RegistrationResult,
  LoginOptions,
  LoginResult,
  ActionOptions,
  ActionResult
} from '../types/passkeyManager';
import type { SerializableActionArgs } from '../types';
import type { Provider } from '@near-js/providers';
import { TxExecutionStatus } from '@near-js/types';

// See default finality settings
// https://github.com/near/near-api-js/blob/99f34864317725467a097dc3c7a3cc5f7a5b43d4/packages/accounts/src/account.ts#L68
export const DEFAULT_WAIT_STATUS: TxExecutionStatus = "INCLUDED_FINAL";

/**
 * Main PasskeyManager class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class PasskeyManager {
  private webAuthnManager: WebAuthnManager;
  private nearRpcProvider: Provider;
  private config: PasskeyManagerConfig;
  private vrfManager: VRFManager;
  private vrfInitializationPromise: Promise<void> | null = null;

  constructor(
    config: PasskeyManagerConfig,
    nearRpcProvider: Provider
  ) {
    this.config = config;
    this.webAuthnManager = new WebAuthnManager();
    this.nearRpcProvider = nearRpcProvider;
    this.vrfManager = new VRFManager();

    // Initialize VRF Web Worker automatically in the background
    this.vrfInitializationPromise = this.initializeVRFWorkerInternal();
  }

  /**
   * Internal VRF Web Worker initialization that runs automatically
   * This abstracts VRF implementation details away from users
   */
  private async initializeVRFWorkerInternal(): Promise<void> {
    try {
      await this.vrfManager.initialize();
    } catch (error: any) {
      console.warn('️PasskeyManager: VRF Web Worker auto-initialization failed:', error.message);
    }
  }

  /**
   * Ensure VRF Web Worker is ready (used internally by VRF operations)
   */
  private async ensureVRFReady(): Promise<void> {
    if (this.vrfInitializationPromise) {
      await this.vrfInitializationPromise;
    }
  }

  /**
   * Register a new passkey for the given NEAR account ID
   */
  async registerPasskey(
    nearAccountId: string,
    options: RegistrationOptions
  ): Promise<RegistrationResult> {
    return registerPasskey(this, nearAccountId, options);
  }

  /**
   * Login with an existing passkey
   */
  async loginPasskey(
    nearAccountId: string,
    options?: LoginOptions
  ): Promise<LoginResult> {
    // Ensure VRF Web Worker is ready for VRF operations
    await this.ensureVRFReady();

    return loginPasskey(this, nearAccountId, options);
  }

  /**
   * Execute a blockchain action/transaction
   */
  async executeAction(
    nearAccountId: string,
    actionArgs: SerializableActionArgs,
    options?: ActionOptions
  ): Promise<ActionResult> {
    if (!this.nearRpcProvider) {
      throw new Error('NEAR RPC provider is required for action execution');
    }

    // Ensure VRF Web Worker is ready for VRF operations
    await this.ensureVRFReady();

    return executeAction(this, nearAccountId, actionArgs, options);
  }

  /**
   * Set the NEAR RPC provider
   */
  setNearRpcProvider(provider: any): void {
    this.nearRpcProvider = provider;
  }

  /**
   * Get the current configuration
   */
  getConfig(): PasskeyManagerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<PasskeyManagerConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get access to the underlying WebAuthnManager for advanced operations
   */
  getWebAuthnManager(): WebAuthnManager {
    return this.webAuthnManager;
  }

  /**
   * Get access to the underlying NearRpcProvider for advanced operations
   */
  getNearRpcProvider(): Provider {
    return this.nearRpcProvider;
  }

  /**
   * Get access to the VRF manager
   */
  getVRFManager(): VRFManager {
    return this.vrfManager;
  }

  /**
   * Get comprehensive login state information
   * This is the preferred method for frontend components to check login status
   */
  async getLoginState(nearAccountId?: string): Promise<{
    isLoggedIn: boolean;
    nearAccountId: string | null;
    publicKey: string | null;
    vrfActive: boolean;
    userData: any | null;
    vrfSessionDuration?: number;
  }> {
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

      // Check VRF Web Worker status
      await this.ensureVRFReady();
      const vrfStatus = await this.vrfManager.getVRFStatus();
      const vrfActive = vrfStatus.active && vrfStatus.nearAccountId === targetAccountId;

      // Get public key
      const publicKey = userData?.clientNearPublicKey || null;

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

    } catch (error: any) {
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

  /**
   * Export private key using PRF-based decryption
   *
   * SECURITY MODEL: Local random challenge is sufficient for private key export because:
   * - User must possess physical authenticator device
   * - Device enforces biometric/PIN verification before PRF access
   * - No network communication or replay attack surface
   * - Challenge only needs to be random to prevent pre-computation
   * - Security comes from device possession + biometrics, not challenge validation
   */
  async exportPrivateKey(nearAccountId?: string): Promise<string> {
    // If no nearAccountId provided, try to get the last used account
    if (!nearAccountId) {
      const lastUsedNearAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
      if (!lastUsedNearAccountId) {
        throw new Error('No NEAR account ID provided and no last used account found');
      }
      nearAccountId = lastUsedNearAccountId;
    }

    // Get user data to verify user exists
    const userData = await this.webAuthnManager.getUser(nearAccountId);
    if (!userData) {
      throw new Error(`No user data found for ${nearAccountId}`);
    }
    if (!userData.prfSupported) {
      throw new Error('PRF is required for private key export but not supported by this user\'s authenticator');
    }

    console.log(`🔐 Exporting private key for account: ${nearAccountId}`);
    // For private key export, we can use direct WebAuthn authentication with local random challenge
    // This is secure because the security comes from device possession + biometrics, not challenge validation
    console.log('Using local authentication for private key export');

    // Get stored authenticator data for this user
    const authenticators = await this.webAuthnManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    // Generate local random challenge - this is sufficient for local key export security
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const { prfOutput } = await this.webAuthnManager.touchIdPrompt.getCredentialsAndPrf({
      nearAccountId,
      challenge,
      authenticators,
    });

    // Use WASM worker to decrypt private key
    const decryptionResult = await this.webAuthnManager.securePrivateKeyDecryptionWithPrf(
      nearAccountId,
      prfOutput
    );

    console.log(`✅ Private key exported successfully for account: ${nearAccountId}`);
    return decryptionResult.decryptedPrivateKey;
  }

  /**
   * Export key pair (both private and public keys)
   */
  async exportKeyPair(nearAccountId?: string): Promise<{
    userAccountId: string;
    privateKey: string;
    publicKey: string
  }> {
    // If no nearAccountId provided, try to get the last used account
    if (!nearAccountId) {
      const lastUsedNearAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
      if (!lastUsedNearAccountId) {
        throw new Error('No NEAR account ID provided and no last used account found');
      }
      nearAccountId = lastUsedNearAccountId;
    }

    // Get user data to retrieve public key
    const userData = await this.webAuthnManager.getUser(nearAccountId);
    if (!userData) {
      throw new Error(`No user data found for ${nearAccountId}`);
    }
    if (!userData.clientNearPublicKey) {
      throw new Error(`No NEAR public key found for account ${nearAccountId}`);
    }

    // Export private key using the method above
    const privateKey = await this.exportPrivateKey(nearAccountId);

    return {
      userAccountId: nearAccountId,
      privateKey,
      publicKey: userData.clientNearPublicKey
    };
  }

}


// Re-export types for convenience
export type {
  PasskeyManagerConfig,
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  LoginOptions,
  LoginResult,
  LoginEvent,
  ActionOptions,
  ActionResult,
  ActionEvent,
  EventCallback,
  OperationHooks
} from '../types/passkeyManager';