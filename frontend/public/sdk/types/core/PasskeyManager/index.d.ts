import type { Provider } from '@near-js/providers';
import { WebAuthnManager } from '../WebAuthnManager';
import type { PasskeyManagerConfigs, RegistrationOptions, RegistrationResult, LoginOptions, LoginResult, ActionOptions, ActionResult } from '../types/passkeyManager';
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
export declare class PasskeyManager {
    private readonly webAuthnManager;
    private readonly nearRpcProvider;
    readonly configs: PasskeyManagerConfigs;
    constructor(configs: PasskeyManagerConfigs, nearRpcProvider: Provider);
    /**
     * Register a new passkey for the given NEAR account ID
     */
    registerPasskey(nearAccountId: string, options: RegistrationOptions): Promise<RegistrationResult>;
    /**
     * Login with an existing passkey
     */
    loginPasskey(nearAccountId: string, options?: LoginOptions): Promise<LoginResult>;
    /**
     * Logout: Clear VRF session (clear VRF keypair in worker)
     */
    logoutAndClearVrfSession(): Promise<void>;
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
    executeAction(nearAccountId: string, actionArgs: ActionArgs, options?: ActionOptions): Promise<ActionResult>;
    /**
     * Get comprehensive login state information
     * This is the preferred method for frontend components to check login status
     */
    getLoginState(nearAccountId?: string): Promise<{
        isLoggedIn: boolean;
        nearAccountId: string | null;
        publicKey: string | null;
        vrfActive: boolean;
        userData: any | null;
        vrfSessionDuration?: number;
    }>;
    getRecentLogins(): Promise<{
        accountIds: string[];
        lastUsedAccountId: string | null;
    }>;
    hasPasskeyCredential(nearAccountId: string): Promise<boolean>;
    /**
     * Export key pair (both private and public keys)
     */
    exportNearKeypairWithTouchId(nearAccountId: string): Promise<{
        accountId: string;
        privateKey: string;
        publicKey: string;
    }>;
    /**
     * Internal VRF Worker initialization that runs automatically
     * This abstracts VRF implementation details away from users
     */
    private initializeVrfWorkerManager;
    private getContext;
}
export type { PasskeyManagerConfigs, RegistrationOptions, RegistrationResult, RegistrationSSEEvent, LoginOptions, LoginResult, LoginEvent, ActionOptions, ActionResult, ActionEvent, EventCallback, OperationHooks } from '../types/passkeyManager';
//# sourceMappingURL=index.d.ts.map