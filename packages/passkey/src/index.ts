export { PasskeyManager } from './core/PasskeyManager';
export { WebAuthnManager } from './core/WebAuthnManager';
export { IndexedDBManager } from './core/IndexedDBManager';

// === Re-exported from various type definition files ===
export type {
  PasskeyManagerConfig as PasskeyConfig,
  RegistrationResult,
  LoginResult,
  ActionResult as SignTransactionResult,
  TransactionParams
} from './core/types/passkeyManager';

export type {
  WebAuthnRegistrationWithPrf,
  WebAuthnAuthenticationWithPrf,
} from './core/types/webauthn';

export type { UserData } from './core/types/worker';

// === WORKER TYPES ===
export {
  WorkerRequestType,
  WorkerResponseType
} from './core/types/worker';

export type {
  WorkerRequest,
  WorkerResponse as TypedWorkerResponse,
  DeriveNearKeypairAndEncryptRequest,
  DecryptPrivateKeyWithPrfRequest,
  SignTransactionWithActionsRequest,
  SignTransferTransactionRequest,
  EncryptionSuccessResponse,
  EncryptionFailureResponse,
  RegistrationSuccessResponse,
  RegistrationFailureResponse,
  SignatureSuccessResponse,
  SignatureFailureResponse,
  DecryptionSuccessResponse,
  DecryptionFailureResponse,
  ErrorResponse
} from './core/types/worker';

export {
  isEncryptionSuccess,
  isRegistrationSuccess,
  isSignatureSuccess,
  isDecryptionSuccess,
  isWorkerError,
  serializeCredentialAndCreatePRF,
  serializeRegistrationCredentialAndCreatePRF,
  takePrfOutputFromCredential,
  takePrfOutputFromRegistrationCredential,
} from './core/types/worker';

// === UTILITIES ===
export * from './utils/encoders';
export * from './config';