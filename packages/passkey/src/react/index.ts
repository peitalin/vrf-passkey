// === REACT CONTEXT ===
export { PasskeyContextProvider as PasskeyProvider, usePasskeyContext } from './context/index';

// === REACT HOOKS ===
export { useOptimisticAuth } from './hooks/useOptimisticAuth';
export { useGreetingService } from './hooks/useNearGreetingService';
export { useRpcProvider } from './hooks/useNearRpcProvider';
export { usePasskeyRegistration } from './hooks/usePasskeyRegistration';
export { usePasskeyLogin } from './hooks/usePasskeyLogin';
export { usePasskeyActions } from './hooks/usePasskeyActions';

// === REACT COMPONENTS ===
export { PasskeyLogin } from './components/PasskeyLogin';
export { Toggle } from './components/Toggle';

// === TYPES ===
export type {
  PasskeyState,
  PasskeyContextType,
  PasskeyContextProviderProps,
  RegistrationResult,
  LoginResult,
  GreetingResult,
  ExecuteActionCallbacks,
  ActionExecutionResult,
  ToastOptions,
  ToastStyleOptions,
  ManagedToast,
  RpcProviderHook,
  OptimisticAuthOptions,
  OptimisticAuthHook
} from './types';

// === RE-EXPORT CORE ===
export type { PasskeyConfig, UserData } from '../core/types';
export { PasskeyManager } from '../core/PasskeyManager';