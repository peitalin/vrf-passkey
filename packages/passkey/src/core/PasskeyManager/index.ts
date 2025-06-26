import type { Provider } from '@near-js/providers';
import { TxExecutionStatus } from '@near-js/types';

import { WebAuthnManager } from '../WebAuthnManager';
import { VrfWorkerManager, VRFWorkerStatus } from '../WebAuthnManager/vrfWorkerManager';
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
  private vrfInitializationPromise: Promise<void> | null = null;

  constructor(
    config: PasskeyManagerConfig,
    nearRpcProvider: Provider
  ) {
    this.config = config;
    this.nearRpcProvider = nearRpcProvider;
    this.webAuthnManager = new WebAuthnManager();
    // Initialize VRF Web Worker automatically in the background
    this.vrfInitializationPromise = this.initializeVrfWorkerManager();
  }

  /**
   * Internal VRF Web Worker initialization that runs automatically
   * This abstracts VRF implementation details away from users
   */
  private async initializeVrfWorkerManager(): Promise<void> {
    try {
      console.log('PasskeyManager: Initializing VRF Web Worker...');
      await this.webAuthnManager.initializeVrfWorkerManager();
    } catch (error: any) {
      console.warn('️PasskeyManager: VRF Web Worker auto-initialization failed:', error.message);
    }
  }

  /**
   * Logout: Clear VRF session (clear VRF keypair in worker)
   */
  async clearVrfSession(): Promise<void> {
    return this.webAuthnManager.clearVrfSession();
  }

  async getVrfWorkerStatus(): Promise<VRFWorkerStatus> {
    return this.webAuthnManager.getVrfWorkerStatus();
  }

  getConfig(): PasskeyManagerConfig {
    return { ...this.config };
  }

  updateConfig(newConfig: Partial<PasskeyManagerConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  getWebAuthnManager(): WebAuthnManager {
    return this.webAuthnManager;
  }

  getNearRpcProvider(): Provider {
    return this.nearRpcProvider;
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

    return executeAction(this, nearAccountId, actionArgs, options);
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
      const vrfStatus = await this.webAuthnManager.getVrfWorkerStatus();
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
   * Export key pair (both private and public keys)
   */
  async exportKeyPair(nearAccountId: string): Promise<{
    userAccountId: string;
    privateKey: string;
    publicKey: string
  }> {
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
  private async exportPrivateKey(nearAccountId: string): Promise<string> {
    // Get user data to verify user exists
    const userData = await this.webAuthnManager.getUser(nearAccountId);
    if (!userData) {
      throw new Error(`No user data found for ${nearAccountId}`);
    }

    console.log(`🔐 Exporting private key for account: ${nearAccountId}`);
    // Get stored authenticator data for this user
    const authenticators = await this.webAuthnManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    // Use WASM worker to decrypt private key
    const decryptionResult = await this.webAuthnManager.decryptPrivateKeyWithPrf(
      nearAccountId,
      authenticators
    );

    console.log(`✅ Private key exported successfully for account: ${nearAccountId}`);
    return decryptionResult.decryptedPrivateKey;
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