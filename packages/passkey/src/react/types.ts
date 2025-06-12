import type { ReactNode } from 'react';
import type { WebAuthnManager } from '../core/WebAuthnManager';
import type { LoginOptions, RegistrationOptions, PasskeyManager} from '../core/PasskeyManager';

// === CORE STATE TYPES ===
export interface LoginState {
  isLoggedIn: boolean;
  username: string | null;
  nearPublicKey: string | null;
  nearAccountId: string | null;
}

// === RESULT TYPES ===
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

// === ACTION EXECUTION TYPES ===
export interface ExecuteActionCallbacks {
  optimisticAuth?: boolean;
  beforeDispatch?: () => void;
  afterDispatch?: (success: boolean, data?: any) => void;
}

export interface ActionExecutionResult {
  transaction_outcome?: {
    id: string;
  };
  error?: string;
}

// === TOAST TYPES ===
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

// === HOOK TYPES ===
export interface NearRpcProviderHook {
  getNearRpcProvider: () => import('@near-js/providers').Provider;
}

export interface OptimisticAuthOptions {
  currentUser?: string | null;
}

export interface OptimisticAuthHook {
  optimisticAuth: boolean;
  setOptimisticAuth: (value: boolean) => void;
}

// === SIMPLIFIED CONTEXT TYPES ===
export interface PasskeyContextType {
  // User login state
  loginState: LoginState;
  // Core PasskeyManager instance - provides all functionality
  passkeyManager: PasskeyManager;
  // Simple utility functions
  logout: () => void;
  loginPasskey: (username: string, options: LoginOptions) => Promise<LoginResult>;
  registerPasskey: (username: string, options: RegistrationOptions) => Promise<RegistrationResult>;
  // Settings
  optimisticAuth: boolean;
  setOptimisticAuth: (value: boolean) => void;
  // Legacy compatibility - direct access to WebAuthnManager
  webAuthnManager: WebAuthnManager;
}

export interface PasskeyContextProviderProps {
  children: ReactNode;

  // Optional configuration
  config?: {
    serverUrl?: string;
    nearNetwork?: 'testnet' | 'mainnet';
    relayerAccount?: string;
    optimisticAuth?: boolean;
  };
}

// === CONVENIENCE RE-EXPORTS ===
export type {
  // Core manager types
  RegistrationOptions,
  LoginOptions,
  ActionOptions,
  RegistrationSSEEvent,
  LoginEvent,
  ActionEvent
} from '../core/PasskeyManager/types';