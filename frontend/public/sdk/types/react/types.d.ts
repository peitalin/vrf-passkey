import type { ReactNode } from 'react';
import type { LoginOptions, RegistrationOptions, PasskeyManager } from '../core/PasskeyManager';
/** Actual authentication state - represents what's currently authenticated/registered */
export interface LoginState {
    /** Whether a user is currently authenticated */
    isLoggedIn: boolean;
    /** The public key of the currently authenticated user (if available) */
    nearPublicKey: string | null;
    /** The NEAR account ID of the currently authenticated user (e.g., "alice.testnet") */
    nearAccountId: string | null;
}
/** UI input state - tracks user input and form state */
export interface AccountInputState {
    /** The username portion being typed by the user (e.g., "alice") */
    inputUsername: string;
    /** The username from the last logged-in account */
    lastLoggedInUsername: string;
    /** The domain from the last logged-in account (e.g., ".testnet") */
    lastLoggedInDomain: string;
    /** The complete account ID for input operations (e.g., "alice.testnet") */
    targetAccountId: string;
    /** The domain postfix to display in the UI (e.g., ".testnet") */
    displayPostfix: string;
    /** Whether the current input matches an existing account in IndexDB */
    isUsingExistingAccount: boolean;
    /** Whether the target account has passkey credentials */
    accountExists: boolean;
    /** All account IDs stored in IndexDB */
    indexDBAccounts: string[];
}
export interface BaseResult {
    success: boolean;
    error?: string;
}
export interface RegistrationResult extends BaseResult {
    clientNearPublicKey?: string | null;
    nearAccountId?: string | null;
    transactionId?: string | null;
}
export interface LoginResult extends BaseResult {
    loggedInUsername?: string;
    clientNearPublicKey?: string | null;
    nearAccountId?: string;
}
export interface ExecuteActionCallbacks {
    beforeDispatch?: () => void;
    afterDispatch?: (success: boolean, data?: any) => void;
}
export interface ActionExecutionResult {
    transaction_outcome?: {
        id: string;
    };
    error?: string;
}
export interface ToastStyleOptions {
    background?: string;
    color?: string;
}
export interface ToastOptions {
    id?: string;
    duration?: number;
    style?: ToastStyleOptions;
}
export interface ManagedToast {
    loading: (message: string, options?: ToastOptions) => string;
    success: (message: string, options?: ToastOptions) => string;
    error: (message: string, options?: ToastOptions) => string;
    dismiss: (id: string) => void;
}
export interface NearRpcProviderHook {
    getNearRpcProvider: () => import('@near-js/providers').Provider;
}
export interface UseAccountInputReturn extends AccountInputState {
    setInputUsername: (username: string) => void;
    refreshAccountData: () => Promise<void>;
}
export interface UseRelayerOptions {
    initialValue?: boolean;
}
export interface UseRelayerReturn {
    useRelayer: boolean;
    setUseRelayer: (value: boolean) => void;
    toggleRelayer: () => void;
}
export interface PasskeyContextType {
    loginState: LoginState;
    accountInputState: AccountInputState;
    logout: () => void;
    loginPasskey: (nearAccountId: string, options: LoginOptions) => Promise<LoginResult>;
    registerPasskey: (nearAccountId: string, options: RegistrationOptions) => Promise<RegistrationResult>;
    getLoginState: (nearAccountId?: string) => Promise<{
        isLoggedIn: boolean;
        nearAccountId: string | null;
        publicKey: string | null;
        vrfActive: boolean;
        userData: any | null;
        vrfSessionDuration?: number;
    }>;
    setInputUsername: (username: string) => void;
    refreshAccountData: () => Promise<void>;
    useRelayer: boolean;
    setUseRelayer: (value: boolean) => void;
    toggleRelayer: () => void;
    passkeyManager: PasskeyManager;
}
export interface PasskeyContextProviderProps {
    children: ReactNode;
    config?: {
        nearNetwork?: 'testnet' | 'mainnet';
        relayerOptions?: {
            relayerAccount?: string;
            relayServerUrl?: string;
            initialUseRelayer?: boolean;
        };
        debugMode?: boolean;
    };
}
export type { RegistrationOptions, LoginOptions, ActionOptions, RegistrationSSEEvent, LoginEvent, ActionEvent } from '../core/types/passkeyManager';
//# sourceMappingURL=types.d.ts.map