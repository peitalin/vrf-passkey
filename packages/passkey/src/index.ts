// === MAIN EXPORTS ===
export { PasskeyManager } from './core/PasskeyManager';
export { WebAuthnManager } from './core/WebAuthnManager';
export { indexDBManager } from './core/IndexDBManager';
export { authEventEmitter, AuthEventEmitter } from './core/AuthEventEmitter';
export type { AuthEvent } from './core/AuthEventEmitter';

// === TYPES ===
export type {
  PasskeyConfig,
  RegisterResult,
  LoginResult,
  SignTransactionResult,
  TransactionParams,
  SignedTransaction,
  UserData,
  ClientUserData,
  UserPreferences,
  WebAuthnChallenge,
  WebAuthnRegistrationWithPrf,
  WebAuthnAuthenticationWithPrf,
  RegistrationOptions,
  AuthenticationOptions,
  WorkerResponse,
  RegistrationPayload,
  SigningPayload,
  PrfSaltConfig,
  ServerAuthenticationOptions
} from './core/types';

// === ERROR CLASSES ===
export {
  PasskeyError,
  AuthenticationError,
  RegistrationError,
  TransactionError
} from './core/types';

// === UTILITIES ===
export * from './utils/encoders';
export * from './config';