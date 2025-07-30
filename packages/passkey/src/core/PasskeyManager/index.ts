import { WebAuthnManager } from '../WebAuthnManager';
import { registerPasskey } from './registration';
import { loginPasskey, getLoginState, getRecentLogins, logoutAndClearVrfSession } from './login';
import { executeAction } from './actions';
import { recoverAccount, AccountRecoveryFlow, type RecoveryResult } from './recoverAccount';
import { MinimalNearClient, type NearClient } from '../NearClient';
import type {
  PasskeyManagerConfigs,
  RegistrationOptions,
  RegistrationResult,
  LoginOptions,
  LoginResult,
  HooksOptions,
  ActionResult,
  LoginState,
} from '../types/passkeyManager';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import { ActionType, type ActionArgs } from '../types/actions';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  StartDeviceLinkingOptionsDevice2,
  ScanAndLinkDeviceOptionsDevice1
} from '../types/linkDevice';
import { LinkDeviceFlow } from './linkDevice';
import { scanAndLinkDevice, linkDeviceWithQRData } from './scanDevice';
import {
  signNEP413Message,
  type SignNEP413MessageParams,
  type SignNEP413MessageResult
} from './signNEP413';

///////////////////////////////////////
// PASSKEY MANAGER
///////////////////////////////////////

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
    // VRF worker initializes automatically in the constructor
  }

  private getContext(): PasskeyManagerContext {
    return {
      webAuthnManager: this.webAuthnManager,
      nearClient: this.nearClient,
      configs: this.configs
    }
  }

  ///////////////////////////////////////
  // === Registration and Login ===
  ///////////////////////////////////////

  /**
   * Register a new passkey for the given NEAR account ID
   * Uses AccountId for on-chain operations and PRF salt derivation
   */
  async registerPasskey(
    nearAccountId: string,
    options: RegistrationOptions
  ): Promise<RegistrationResult> {
    return registerPasskey(this.getContext(), toAccountId(nearAccountId), options);
  }

  /**
   * Login with an existing passkey
   * Uses AccountId for on-chain operations and VRF operations
   */
  async loginPasskey(
    nearAccountId: string,
    options?: LoginOptions
  ): Promise<LoginResult> {
    return loginPasskey(this.getContext(), toAccountId(nearAccountId), options);
  }

  /**
   * Logout: Clear VRF session (clear VRF keypair in worker)
   */
  async logoutAndClearVrfSession(): Promise<void> {
    return logoutAndClearVrfSession(this.getContext());
  }

  /**
   * Get comprehensive login state information
   * Uses AccountId for core account login state
   */
  async getLoginState(nearAccountId?: string): Promise<LoginState> {
    return getLoginState(
      this.getContext(),
      nearAccountId ? toAccountId(nearAccountId) : undefined
    );
  }

  /**
   * Get check if accountId has a passkey from IndexedDB
   */
  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    // Convert device-specific ID to base account ID for IndexedDB lookup
    const baseAccountId = toAccountId(nearAccountId);
    return await this.webAuthnManager.hasPasskeyCredential(baseAccountId);
  }

  async getRecentLogins(): Promise<{
    accountIds: string[],
    lastUsedAccountId: {
      nearAccountId: AccountId,
      deviceNumber: number,
    } | null
  }> {
    return getRecentLogins(this.getContext());
  }

  ///////////////////////////////////////
  // === Transactions ===
  ///////////////////////////////////////

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
    options?: HooksOptions
  ): Promise<ActionResult> {
    return executeAction(this.getContext(), toAccountId(nearAccountId), actionArgs, options);
  }

  ///////////////////////////////////////
  // === NEP-413 MESSAGE SIGNING ===
  ///////////////////////////////////////

  /**
   * Sign a NEP-413 message using the user's passkey-derived private key
   *
   * This function implements the NEP-413 standard for off-chain message signing:
   * - Creates a payload with message, recipient, nonce, and state
   * - Serializes using Borsh
   * - Adds NEP-413 prefix (2^31 + 413)
   * - Hashes with SHA-256
   * - Signs with Ed25519
   * - Returns base64-encoded signature
   *
   * @param nearAccountId - NEAR account ID to sign with
   * @param params - NEP-413 signing parameters
   * - message: string - The message to sign
   * - recipient: string - The recipient of the message
   * - state: string - Optional state parameter
   * @param options - Action options for event handling
   * - onEvent: EventCallback<ActionSSEEvent> - Optional event callback
   * - onError: (error: Error) => void - Optional error callback
   * - hooks: OperationHooks - Optional operation hooks
   * - waitUntil: TxExecutionStatus - Optional waitUntil status
   * @returns Promise resolving to signing result
   *
   * @example
   * ```typescript
   * const result = await passkeyManager.signNEP413Message('alice.near', {
   *   message: 'Hello World',
   *   recipient: 'app.example.com',
   *   state: 'optional-state'
   * });
   *
   * if (result.success) {
   *   console.log('Signature:', result.signature);
   *   console.log('Public key:', result.publicKey);
   * }
   * ```
   */
  async signNEP413Message(
    nearAccountId: string,
    params: SignNEP413MessageParams,
    options?: HooksOptions
  ): Promise<SignNEP413MessageResult> {
    return signNEP413Message(this.getContext(), toAccountId(nearAccountId), params, options);
  }

  ///////////////////////////////////////
  // === KEY MANAGEMENT ===
  ///////////////////////////////////////

  /**
   * Export key pair (both private and public keys)
   * Uses AccountId for consistent PRF salt derivation
   */
  async exportNearKeypairWithTouchId(nearAccountId: string): Promise<{
    accountId: string;
    privateKey: string;
    publicKey: string
  }> {
    // Export private key using the method above
    return await this.webAuthnManager.exportNearKeypairWithTouchId(toAccountId(nearAccountId))
  }

  ///////////////////////////////////////
  // === Link Device ===
  ///////////////////////////////////////

  /**
   * Creates a LinkDeviceFlow instance for step-by-step device linking UX
   * for Device2 (the companion device is the one that generates the QR code)
   * Device1 (the original device) scans the QR code and executes the AddKey
   * and `store_device_linking_mapping` contract calls.
   *
   * @example
   * ```typescript
   *
   * // Device2: Generate QR and start polling
   * const flow = passkeyManager.startDeviceLinkingFlow({ onEvent: ... });
   * const { qrData, qrCodeDataURL } = await flow.generateQR('alice.near');
   *
   * // Device1: Scan and authorize
   * const result = await passkeyManager.scanAndLinkDevice({ onEvent: ... });
   *
   * // Device2: Flow automatically completes when AddKey is detected
   * // it polls the chain for `store_device_linking_mapping` contract events
   * const state = flow.getState();
   * ```
   */
  startDeviceLinkingFlow(options: StartDeviceLinkingOptionsDevice2): LinkDeviceFlow {
    return new LinkDeviceFlow(this.getContext(), options);
  }

  /**
   * Device1: Scan QR code and execute AddKey transaction (convenience method)
   */
  async scanAndLinkDevice(options: ScanAndLinkDeviceOptionsDevice1): Promise<LinkDeviceResult> {
    return scanAndLinkDevice(this.getContext(), options);
  }

  /**
   * Device1: Link device using pre-scanned QR data (skips QR scanning step)
   */
  async linkDeviceWithQRData(
    qrData: DeviceLinkingQRData,
    options: Omit<ScanAndLinkDeviceOptionsDevice1, 'cameraId' | 'cameraConfigs'>
  ): Promise<LinkDeviceResult> {
    return linkDeviceWithQRData(this.getContext(), qrData, options);
  }

  /**
   * Delete a device key from an account
   */
  async deleteDeviceKey(publicKeyToDelete: string): Promise<void> {
    // // Validate that we're not deleting the last key
    // const keysView = await getDeviceKeys(this.getContext(), accountId);
    // if (keysView.keys.length <= 1) {
    //   throw new Error('Cannot delete the last access key from an account');
    // }

    // // Find the key to delete
    // const keyToDelete = keysView.keys.find(k => k.publicKey === publicKeyToDelete);
    // if (!keyToDelete) {
    //   throw new Error(`Access key ${publicKeyToDelete} not found on account ${accountId}`);
    // }

    // if (!keyToDelete.canDelete) {
    //   throw new Error(`Cannot delete this access key`);
    // }

    // // Use the executeAction method with DeleteKey action
    // return this.executeAction(accountId, {
    //   type: ActionType.DeleteKey,
    //   receiverId: accountId,
    //   publicKey: publicKeyToDelete
    // }, options);
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
    options?: HooksOptions,
    reuseCredential?: PublicKeyCredential
  ): Promise<RecoveryResult> {
    return recoverAccount(this.getContext(), toAccountId(accountId), options, reuseCredential);
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
  startAccountRecoveryFlow(options?: HooksOptions): AccountRecoveryFlow {
    return new AccountRecoveryFlow(this.getContext(), options);
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
  HooksOptions,
  ActionResult,
  ActionEvent,
  EventCallback,
  OperationHooks,
} from '../types/passkeyManager';

export type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  LinkDeviceResult
} from '../types/linkDevice';

// Re-export device linking error types and classes
export {
  DeviceLinkingPhase,
  DeviceLinkingError,
  DeviceLinkingErrorCode
} from '../types/linkDevice';

// Re-export device linking flow class
export {
  LinkDeviceFlow
} from './linkDevice';

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

// Re-export NEP-413 types
export type {
  SignNEP413MessageParams,
  SignNEP413MessageResult
} from './signNEP413';