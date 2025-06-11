// === REACT CONTEXT ===
export { PasskeyProvider, usePasskeyContext } from './context/index';

// === REACT HOOKS ===
export { useOptimisticAuth } from './hooks/useOptimisticAuth';
export { useGreetingService } from './hooks/useNearGreetingService';
export { useNearRpcProvider } from './hooks/useNearRpcProvider';
export { usePasskeyRegistration } from './hooks/usePasskeyRegistration';
export { usePasskeyLogin } from './hooks/usePasskeyLogin';
export { usePasskeyActions } from './hooks/usePasskeyActions';

// === REACT COMPONENTS ===
export { ProfileButton } from './components/ProfileButton';

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
  NearRpcProviderHook,
  OptimisticAuthOptions,
  OptimisticAuthHook
} from './types';

// === PROFILE BUTTON TYPES ===
export type {
  ProfileDimensions,
  ProfileAnimationConfig,
  ProfileMenuItem,
  ProfileButtonProps,
  ProfileTriggerProps,
  ProfileDropdownProps,
  ProfileMenuItemProps,
  ProfileToggleSectionProps,
  ProfileLogoutSectionProps,
  ProfileStateRefs,
  ProfileCalculationParams,
} from './components/ProfileButton/types';

// === RE-EXPORT CORE ===
export type { PasskeyConfig, UserData } from '../core/types';
export { PasskeyManager } from '../core/PasskeyManager';