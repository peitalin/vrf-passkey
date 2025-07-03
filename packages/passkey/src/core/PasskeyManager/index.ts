import { WebAuthnManager } from '../WebAuthnManager';
import { registerPasskey } from './registration';
import { loginPasskey } from './login';
import { executeAction } from './actions';
import { addDeviceToAccount, getDeviceKeys, type AddKeysOptions, type AddKeysResult, type DeviceKeysView } from './addDevice';
import { recoverAccount, AccountRecoveryFlow, type RecoveryResult } from './recoverAccount';
import { MinimalNearClient, type NearClient } from '../NearClient';
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
import { ActionType } from '../types/actions';

export interface PasskeyManagerContext {
  webAuthnManager: WebAuthnManager;
  nearClient: NearClient;
  configs: PasskeyManagerConfigs;
}

/**
 * Main PasskeyManager class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class PasskeyManager {
  private readonly webAuthnManager: WebAuthnManager;
  private readonly nearClient: NearClient;
  readonly configs: PasskeyManagerConfigs;

  constructor(
    configs: PasskeyManagerConfigs,
    nearClient?: NearClient
  ) {
    this.configs = configs;
    // Use provided client or create default one
    this.nearClient = nearClient || new MinimalNearClient(configs.nearRpcUrl);
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

  // === KEY MANAGEMENT METHODS (Phase 2) ===

  /**
   * Add current device's passkey-derived keypair to an existing NEAR account for multi-device access
   *
   * @param accountId - Account ID to add the device to
   * @param privateKey - Private key from the existing account (for signing AddKey transaction)
   * @param options - Optional configuration for the operation
   *
   * @example
   * ```typescript
   * // First export the keypair from another device
   * const { accountId, privateKey } = await passkeyManager.exportNearKeypairWithTouchId('alice.near');
   *
   * // Then on the new device, add it as an additional access key
   * const result = await passkeyManager.addDeviceToAccount(
   *   privateKey,
   *   accountId,
   *   {
   *     onEvent: (event) => console.log('Progress:', event.message),
   *     gas: '30000000000000'
   *   }
   * );
   * ```
   */
  async addDeviceToAccount({ accountId, privateKey, options }: {
    accountId: string,
    privateKey: string,
    options?: AddKeysOptions
  }): Promise<AddKeysResult> {
    return addDeviceToAccount({
      context: this.getContext(),
      accountId,
      privateKey,
      options
    });
  }

  /**
   * Get comprehensive device keys view for an account
   * Shows all access keys with metadata about device types and management options
   *
   * @example
   * ```typescript
   * const keysView = await passkeyManager.getDeviceKeys('alice.near');
   * console.log(`Account has ${keysView.keys.length} access keys`);
   * keysView.keys.forEach(key => {
   *   console.log(`${key.publicKey} - ${key.deviceType} - Current: ${key.isCurrentDevice}`);
   * });
   * ```
   */
  async getDeviceKeys(accountId: string): Promise<DeviceKeysView> {
    return getDeviceKeys(this.getContext(), accountId);
  }

  /**
   * Delete a device key from an account
   *
   * @example
   * ```typescript
   * const result = await passkeyManager.deleteDeviceKey(
   *   'alice.near',
   *   'ed25519:5K8...old-device-key',
   *   {
   *     onEvent: (event) => console.log('Progress:', event.message)
   *   }
   * );
   * ```
   */
  async deleteDeviceKey(
    accountId: string,
    publicKeyToDelete: string,
    options?: ActionOptions
  ): Promise<ActionResult> {
    // Validate that we're not deleting the last key
    const keysView = await this.getDeviceKeys(accountId);
    if (keysView.keys.length <= 1) {
      throw new Error('Cannot delete the last access key from an account');
    }

    // Find the key to delete
    const keyToDelete = keysView.keys.find(k => k.publicKey === publicKeyToDelete);
    if (!keyToDelete) {
      throw new Error(`Access key ${publicKeyToDelete} not found on account ${accountId}`);
    }

    if (!keyToDelete.canDelete) {
      throw new Error(`Cannot delete this access key`);
    }

    // Use the executeAction method with DeleteKey action
    return this.executeAction(accountId, {
      type: ActionType.DeleteKey,
      receiverId: accountId,
      publicKey: publicKeyToDelete
    }, options);
  }

  ///////////////////////////////////////
  // ACCOUNT RECOVERY METHODS
  ///////////////////////////////////////

  /**
   * Recover account access using a passkey on this device
   * @param accountId The NEAR account ID to recover. Must be an account derived from a passkey you own on this device
   * @param options Optional action configuration and event handlers
   * @param reuseCredential Optional WebAuthn credential to reuse from discovery phase
   * @returns Recovery result with account details
   *
   * @example
   * ```typescript
   * const result = await passkeyManager.recoverAccountWithAccountId(
   *   'alice.near',
   *   {
   *     onEvent: (event) => console.log('Recovery progress:', event.message),
   *     onError: (error) => console.error('Recovery error:', error)
   *   }
   * );
   * ```
   */
  async recoverAccountWithAccountId(
    accountId: string,
    options?: ActionOptions,
    reuseCredential?: PublicKeyCredential
  ): Promise<RecoveryResult> {
    return recoverAccount(this.getContext(), accountId, options, reuseCredential);
  }

  /**
   * Creates an AccountRecoveryFlow instance, for step-by-step account recovery UX
   *
   * @example
   * ```typescript
   * const flow = passkeyManager.startAccountRecoveryFlow();
   *
   * // Phase 1: Discover available accounts
   * const options = await flow.discover(); // Returns PasskeyOptionWithoutCredential[]
   *
   * // Phase 2: User selects account in UI
   * const selectedOption = await waitForUserSelection(options);
   *
   * // Phase 3: Execute recovery with secure credential lookup
   * const result = await flow.recover({
   *   credentialId: selectedOption.credentialId,
   *   accountId: selectedOption.accountId
   * });
   * console.log('Recovery state:', flow.getState());
   * ```
   */
  startAccountRecoveryFlow(options?: ActionOptions): AccountRecoveryFlow {
    return new AccountRecoveryFlow(this.getContext(), options);
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
      nearClient: this.nearClient,
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

// Re-export key management types
export type {
  AddKeysOptions,
  AddKeysResult,
  DeviceKeysView
} from './addDevice';

// Re-export account recovery types and classes
export type {
  RecoveryResult,
  AccountLookupResult,
  PasskeyOption,
  PasskeyOptionWithoutCredential,
  PasskeySelection
} from './recoverAccount';

export {
  AccountRecoveryFlow
} from './recoverAccount';