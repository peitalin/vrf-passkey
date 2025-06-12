// === MAIN EXPORTS ===
export { PasskeyManager } from './core/PasskeyManager';
export { WebAuthnManager } from './core/WebAuthnManager';
export { indexDBManager } from './core/IndexDBManager';

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

// === WORKER TYPES ===
export {
  WorkerRequestType,
  WorkerResponseType
} from './core/types/worker';

export type {
  WorkerRequest,
  WorkerResponse as TypedWorkerResponse,
  EncryptPrivateKeyWithPrfRequest,
  DecryptAndSignTransactionWithPrfRequest,
  DecryptPrivateKeyWithPrfRequest,
  EncryptionSuccessResponse,
  EncryptionFailureResponse,
  SignatureSuccessResponse,
  SignatureFailureResponse,
  DecryptionSuccessResponse,
  DecryptionFailureResponse,
  ErrorResponse
} from './core/types/worker';

export {
  isEncryptionSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isWorkerError
} from './core/types/worker';

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