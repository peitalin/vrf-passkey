// === REACT CONTEXT ===
export { PasskeyProvider, usePasskeyContext } from './context/index';

// === REACT HOOKS ===

export { useNearClient } from './hooks/useNearClient';
export type { NearClient } from '../core/NearClient';
export { useAccountInput } from './hooks/useAccountInput';
export { useRelayer } from './hooks/useRelayer';
export { TxExecutionStatus } from '../core/types/actions';

// === REACT COMPONENTS ===
export { ProfileButton } from './components/ProfileSettingsButton';
// Lazy-loaded QR Scanner (jsQR library ~234kB)
export { QRCodeScanner } from './components/QRCodeScanner.lazy';

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