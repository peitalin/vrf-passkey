export { PasskeyManager } from './core/PasskeyManager';
export { DEFAULT_WAIT_STATUS } from './core/types/rpc';
export { WebAuthnManager } from './core/WebAuthnManager';
export { IndexedDBManager } from './core/IndexedDBManager';

// === Flow Classes ===
export { LinkDeviceFlow, AccountRecoveryFlow } from './core/PasskeyManager';

// === Re-exported from various type definition files ===
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
} from './core/types/passkeyManager';

export type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  DeviceLinkingStatus,
  LinkDeviceResult,
  DeviceLinkingError,
  DeviceLinkingErrorCode
} from './core/types/linkDevice';

export type {
  WebAuthnRegistrationWithPrf,
  WebAuthnAuthenticationWithPrf,
} from './core/types/webauthn';

export type { UserData } from './core/types/signer-worker';

// === WORKER TYPES ===
export {
  WorkerRequestType,
  WorkerResponseType
} from './core/types/signer-worker';

export type {
  WorkerResponseForRequest,
  EncryptionResponse,
  RecoveryResponse,
  CheckRegistrationResponse,
  RegistrationResponse,
  TransactionResponse,
  TransferResponse,
  DecryptionResponse,
  CoseExtractionResponse,
} from './core/types/signer-worker';

export {
  isEncryptionSuccess,
  isRegistrationSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isWorkerError,
  serializeCredentialWithPRF,
  takeAesPrfOutput,
} from './core/types/signer-worker';

// === UTILITIES ===
export { base64UrlEncode, base64UrlDecode } from './utils/encoders';
export * from './config';

// === MAIN PASSKEY SDK EXPORTS ===

// === TYPES ===
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
} from './core/types/actions';

export {
  ActionType
} from './core/types/actions';

// Action helper functions for easy action creation
export {
  functionCall,
  transfer,
  createAccount,
  deployContract,
  stake,
  addFullAccessKey,
  addFunctionCallKey,
  deleteKey,
  deleteAccount
} from './core/types/actions';

// === ERROR TYPES ===
export type { PasskeyErrorDetails } from './core/types/errors';