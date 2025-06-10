import type { ReactNode } from 'react';
import type { SerializableActionArgs } from '../../types';

// === CORE STATE TYPES ===
export interface PasskeyState {
  isLoggedIn: boolean;
  username: string | null;
  nearPublicKey: string | null;
  nearAccountId: string | null;
  isProcessing: boolean;
  currentGreeting: string | null;
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

export interface GreetingResult extends BaseResult {
  greeting?: string;
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
export interface RpcProviderHook {
  getRpcProvider: () => import('@near-js/providers').Provider;
}

export interface OptimisticAuthOptions {
  currentUser?: string | null;
}

export interface OptimisticAuthHook {
  optimisticAuth: boolean;
  setOptimisticAuth: (value: boolean) => void;
}

// === CONTEXT TYPES ===
export interface PasskeyContextType extends PasskeyState {
  setUsernameState: (username: string) => void;
  registerPasskey: (username: string) => Promise<RegistrationResult>;
  loginPasskey: (username?: string) => Promise<LoginResult>;
  logoutPasskey: () => void;
  executeDirectActionViaWorker: (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ) => Promise<void>;
  fetchCurrentGreeting: () => Promise<GreetingResult>;
  optimisticAuth: boolean;
  setOptimisticAuth: (value: boolean) => void;
}

export interface PasskeyContextProviderProps {
  children: ReactNode;
}