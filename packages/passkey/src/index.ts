
export { PasskeyManager } from './core/PasskeyManager';
export { WebAuthnManager } from './core/WebAuthnManager';
export { LinkDeviceFlow, AccountRecoveryFlow } from './core/PasskeyManager';
export { type NearClient, MinimalNearClient } from './core/NearClient';

export * from './config';
export { base64UrlEncode, base64UrlDecode } from './utils/encoders';

///////////////////////////////////////////////////////////////
// === Types re-exported from various type definition files ===
///////////////////////////////////////////////////////////////

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
  OperationHooks
} from './core/types/passkeyManager';

export { DEFAULT_WAIT_STATUS } from './core/types/rpc';

// === Device Linking Types ===
export {
  DeviceLinkingPhase,
  type DeviceLinkingEvent
} from './core/types/passkeyManager';
export type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  LinkDeviceResult,
  DeviceLinkingError,
  DeviceLinkingErrorCode
} from './core/types/linkDevice';

// === AccountID Types ===
export type { AccountId } from './core/types/accountIds';
export { toAccountId } from './core/types/accountIds';

export type {
  SignNEP413MessageParams,
  SignNEP413MessageResult
} from './core/PasskeyManager/signNEP413';

// === Action Types ===
export { ActionType } from './core/types/actions';
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

// === SERVER PACKAGE ===
// Core NEAR Account Service for server-side operations
export {
  NearAccountService,
  getServerConfig,
  validateServerConfig,
  getTestServerConfig
} from './server';

export type {
  ServerConfig,
  AccountCreationRequest,
  AccountCreationResult,
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
  ContractVrfData,
  WebAuthnRegistrationCredential
} from './server';