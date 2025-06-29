import type { Provider } from '@near-js/providers';

import { WebAuthnManager } from '../WebAuthnManager';
import { registerPasskey } from './registration';
import { loginPasskey } from './login';
import { executeAction } from './actions';
import type {
  PasskeyManagerConfigs,
  RegistrationOptions,
  RegistrationResult,
  LoginOptions,
  LoginResult,
  ActionOptions,
  ActionResult
} from '../types/passkeyManager';
import type { ActionArgs } from '../types/actions';

export interface PasskeyManagerContext {
  webAuthnManager: WebAuthnManager;
  nearRpcProvider: Provider;
  configs: PasskeyManagerConfigs;
}

/**
 * Main PasskeyManager class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class PasskeyManager {
  private readonly webAuthnManager: WebAuthnManager;
  private readonly nearRpcProvider: Provider;
  readonly configs: PasskeyManagerConfigs;

  constructor(
    configs: PasskeyManagerConfigs,
    nearRpcProvider: Provider
  ) {
    if (!nearRpcProvider) {
      throw new Error('NEAR RPC provider is required');
    }
    this.configs = configs;
    this.nearRpcProvider = nearRpcProvider;
    this.webAuthnManager = new WebAuthnManager(configs);
    // Initialize VRF Worker in the background
    this.initializeVrfWorkerManager();
  }

  /**
   * Register a new passkey for the given NEAR account ID
   */
  async registerPasskey(
    nearAccountId: string,
    options: RegistrationOptions
  ): Promise<RegistrationResult> {
    return registerPasskey(this.getContext(), nearAccountId, options);
  }

  /**
   * Login with an existing passkey
   */
  async loginPasskey(
    nearAccountId: string,
    options?: LoginOptions
  ): Promise<LoginResult> {
    return loginPasskey(this.getContext(), nearAccountId, options);
  }

  /**
   * Logout: Clear VRF session (clear VRF keypair in worker)
   */
  async logoutAndClearVrfSession(): Promise<void> {
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
  async executeAction(
    nearAccountId: string,
    actionArgs: ActionArgs,
    options?: ActionOptions
  ): Promise<ActionResult> {
    return executeAction(this.getContext(), nearAccountId, actionArgs, options);
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

  async getRecentLogins(): Promise<{ accountIds: string[], lastUsedAccountId: string | null }> {
      // Get all user accounts from IndexDB
      const allUsersData = await this.webAuthnManager.getAllUserData();
      const accountIds = allUsersData.map(user => user.nearAccountId);
      // Get last used account for initial state
      const lastUsedAccountId = await this.webAuthnManager.getLastUsedNearAccountId();

      return {
        accountIds,
        lastUsedAccountId,
      }
  }

  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return await this.webAuthnManager.hasPasskeyCredential(nearAccountId);
  }

  /**
   * Export key pair (both private and public keys)
   */
  async exportNearKeypairWithTouchId(nearAccountId: string): Promise<{
    accountId: string;
    privateKey: string;
    publicKey: string
  }> {
    // Export private key using the method above
    return await this.webAuthnManager.exportNearKeypairWithTouchId(nearAccountId)
  }

  ///////////////////////////////////////
  // PRIVATE FUNCTIONS
  ///////////////////////////////////////

  /**
   * Internal VRF Worker initialization that runs automatically
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

  private getContext(): PasskeyManagerContext {
    return {
      webAuthnManager: this.webAuthnManager,
      nearRpcProvider: this.nearRpcProvider,
      configs: this.configs
    }
  }

}


// Re-export types for convenience
export type {
  PasskeyManagerConfigs,
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