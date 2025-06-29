// === REACT CONTEXT ===
export { PasskeyProvider, usePasskeyContext } from './context/index';

// === REACT HOOKS ===

export { useNearRpcProvider } from './hooks/useNearRpcProvider';
export { useAccountInput } from './hooks/useAccountInput';
export { useRelayer } from './hooks/useRelayer';

// === REACT COMPONENTS ===
export { ProfileButton } from './components/ProfileSettingsButton';

// === TYPES ===
export type {
  LoginState,
  PasskeyContextType,
  PasskeyContextProviderProps,
  RegistrationResult,
  LoginResult,
  ExecuteActionCallbacks,
  ActionExecutionResult,
  ToastOptions,
  ToastStyleOptions,
  ManagedToast,
  NearRpcProviderHook,

  AccountInputState,
  UseAccountInputReturn,
  UseRelayerOptions,
  UseRelayerReturn,
  // Re-exported from PasskeyManager types
  RegistrationOptions,
  LoginOptions,
  ActionOptions,
  RegistrationSSEEvent,
  LoginEvent,
  ActionEvent
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
  ProfileLogoutSectionProps,
  ProfileRelayerToggleSectionProps,
  ProfileStateRefs,
  ProfileCalculationParams,
  ToggleColorProps,
} from './components/ProfileSettingsButton/types';

// === RE-EXPORT CORE ===
export type { PasskeyManagerConfigs as PasskeyConfigs } from '../core/types/passkeyManager';
export type { UserData } from '../core/types/signer-worker';
export { PasskeyManager } from '../core/PasskeyManager';

// === RE-EXPORT ACTION TYPES ===
export type {
  ActionArgs,
  FunctionCallAction,
  TransferAction,
  CreateAccountAction,
  DeployContractAction,
  StakeAction,
  AddKeyAction,
  DeleteKeyAction,
  DeleteAccountAction
} from '../core/types/actions';

// === RE-EXPORT ACTION HELPER FUNCTIONS ===
export {
  functionCall,
  transfer,
  createAccount,
  deployContract,
  stake,
  addFullAccessKey,
  addFunctionCallKey,
  deleteKey,
  deleteAccount,
  ActionType
} from '../core/types/actions';