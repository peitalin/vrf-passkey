import { base64UrlEncode } from "../../utils/encoders";
import type { VRFChallenge, onProgressEvents } from "./webauthn";
import { ActionType } from "./actions";
import type { SignedTransaction } from '../NearClient';
import type { TransactionStruct, SignatureStruct } from './rpc';

// === IMPORT AUTO-GENERATED WASM TYPES ===
// These are the source of truth generated from Rust structs via wasm-bindgen
// Import as instance types from the WASM module classes
import * as wasmModule from '../../wasm_signer_worker/wasm_signer_worker.js';
export type WasmRecoverKeypairResult = InstanceType<typeof wasmModule.RecoverKeypairResult>;
export type WasmRegistrationResult = InstanceType<typeof wasmModule.RegistrationResult>;
export type WasmRegistrationCheckResult = InstanceType<typeof wasmModule.RegistrationCheckResult>;
export type WasmRegistrationInfo = InstanceType<typeof wasmModule.RegistrationInfoStruct>;
export type WasmSignedTransaction = InstanceType<typeof wasmModule.WasmSignedTransaction>;
export type WasmTransactionSignResult = InstanceType<typeof wasmModule.TransactionSignResult>;
export type WasmDecryptPrivateKeyResult = InstanceType<typeof wasmModule.DecryptPrivateKeyResult>;
export type WasmEncryptionResult = InstanceType<typeof wasmModule.EncryptionResult>;

// === IMPORT CLEAN WASM ENUMS ===
// Import the numeric enums generated from Rust - these are the source of truth
import {
  WorkerRequestType,
  WorkerResponseType,
} from '../../wasm_signer_worker/wasm_signer_worker.js';
import { AccountId } from "./accountIds";
// Export the WASM enums directly
export { WorkerRequestType, WorkerResponseType };

/**
 * Dual PRF outputs for separate encryption and signing key derivation
 */
export interface DualPrfOutputs {
  /** Base64-encoded PRF output from prf.results.first for AES-GCM encryption */
  aesPrfOutput: string;
  /** Base64-encoded PRF output from prf.results.second for Ed25519 signing */
  ed25519PrfOutput: string;
}

// === GROUPED PARAMETER INTERFACES ===

/**
 * Decryption-specific parameters for secure key operations
 * Matches Rust Decryption struct
 */
export interface Decryption {
  /** Base64-encoded PRF output for AES-GCM decryption */
  aesPrfOutput: string;
  /** Base64url-encoded encrypted private key data */
  encryptedPrivateKeyData: string;
  /** Base64url-encoded AES-GCM nonce */
  encryptedPrivateKeyIv: string;
}

/**
 * Transaction-specific parameters for NEAR actions
 * Matches Rust TxData struct
 */
export interface TxData {
  /** NEAR account ID that will sign the transaction */
  signerAccountId: string;
  /** NEAR account ID that will receive the transaction */
  receiverAccountId: string;
  /** Transaction nonce as number */
  nonce: number;
  /** Block hash bytes for the transaction */
  blockHashBytes: number[];
  /** JSON string containing array of actions */
  actionsJson: string;
}

/**
 * Contract verification parameters
 * Matches Rust Verification struct
 */
export interface Verification {
  /** Contract ID for verification */
  contractId: string;
  /** NEAR RPC provider URL for verification */
  nearRpcUrl: string;
}

// === USER DATA TYPES ===

export interface UserData {
  nearAccountId: AccountId;
  deviceNumber?: number; // Device number for multi-device support (1-indexed)
  clientNearPublicKey?: string;
  lastUpdated: number;
  prfSupported?: boolean;
  deterministicKey?: boolean;
  passkeyCredential?: {
    id: string;
    rawId: string;
  };
  encryptedVrfKeypair?: {
    encrypted_vrf_data_b64u: string;
    aes_gcm_nonce_b64u: string;
  };
}

// === WORKER MESSAGE TYPE ENUMS ===

/**
 * Worker error details for better debugging
 */
export interface WorkerErrorDetails {
  code: WorkerErrorCode;
  message: string;
  operation: WorkerRequestType;
  timestamp: number;
  context?: Record<string, any>;
  stack?: string;
}

export enum WorkerErrorCode {
  WASM_INIT_FAILED = 'WASM_INIT_FAILED',
  INVALID_REQUEST = 'INVALID_REQUEST',
  TIMEOUT = 'TIMEOUT',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  SIGNING_FAILED = 'SIGNING_FAILED',
  STORAGE_FAILED = 'STORAGE_FAILED',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

// === REQUEST MESSAGE INTERFACES ===

// Base interface for all worker requests
export interface BaseWorkerRequest {
  type: WorkerRequestType;
  operationId?: string;
  timestamp?: number;
}

// === GENERIC REQUEST TYPE ===
// Generic message interface that uses WASM types
export interface WorkerMessage<T extends WorkerRequestType> {
  type: T;
  payload: any; // properly typed based on the specific request interface above
}

// === PROGRESS MESSAGE TYPES ===

// Progress message types that can be sent from WASM to the main thread
export enum ProgressMessageType {
  VERIFICATION_PROGRESS = 'VERIFICATION_PROGRESS',
  VERIFICATION_COMPLETE = 'VERIFICATION_COMPLETE',
  SIGNING_PROGRESS = 'SIGNING_PROGRESS',
  SIGNING_COMPLETE = 'SIGNING_COMPLETE',
  REGISTRATION_PROGRESS = 'REGISTRATION_PROGRESS',
  REGISTRATION_COMPLETE = 'REGISTRATION_COMPLETE',
}

// Step identifiers for progress tracking
export enum ProgressStep {
  PREPARATION = 'preparation',
  AUTHENTICATION = 'authentication',
  CONTRACT_VERIFICATION = 'contract_verification',
  TRANSACTION_SIGNING = 'transaction_signing',
  BROADCASTING = 'broadcasting',
  VERIFICATION_COMPLETE = 'verification_complete',
  SIGNING_COMPLETE = 'signing_complete',
}

// === RESPONSE MESSAGE INTERFACES ===

// Base interface for all worker responses
export interface BaseWorkerResponse {
  type: WorkerResponseType;
  payload: Record<string, any>;
}

// === GENERIC WORKER RESPONSE TYPES ===

// Map request types to their expected success response payloads (WASM types)
export interface RequestResponseMap {
  [WorkerRequestType.DeriveNearKeypairAndEncrypt]: WasmEncryptionResult;
  [WorkerRequestType.RecoverKeypairFromPasskey]: WasmRecoverKeypairResult;
  [WorkerRequestType.CheckCanRegisterUser]: WasmRegistrationCheckResult;
  [WorkerRequestType.SignVerifyAndRegisterUser]: WasmRegistrationResult;
  [WorkerRequestType.DecryptPrivateKeyWithPrf]: WasmDecryptPrivateKeyResult;
  [WorkerRequestType.SignTransactionsWithActions]: WasmTransactionSignResult;
  [WorkerRequestType.ExtractCosePublicKey]: wasmModule.CoseExtractionResult;
  [WorkerRequestType.SignTransactionWithKeyPair]: WasmTransactionSignResult;
}

// Generic success response type that uses WASM types
export interface WorkerSuccessResponse<T extends WorkerRequestType> extends BaseWorkerResponse {
  type: WorkerResponseType;
  payload: RequestResponseMap[T];
}

// Generic error response type
export interface WorkerErrorResponse extends BaseWorkerResponse {
  type: WorkerResponseType;
  payload: {
    error: string;
    errorCode?: WorkerErrorCode;
    context?: Record<string, any>;
  };
}

// Progress response type
export interface WorkerProgressResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.VerificationProgress
      | typeof WorkerResponseType.SigningProgress
      | typeof WorkerResponseType.RegistrationProgress
      | typeof WorkerResponseType.VerificationComplete    // Moved from completion to progress
      | typeof WorkerResponseType.SigningComplete         // Moved from completion to progress
      | typeof WorkerResponseType.RegistrationComplete;   // Moved from completion to progress
  payload: onProgressEvents;
}

// === MAIN RESPONSE TYPE ===
// This is the only response type you need - it's generic and uses WASM types
export type WorkerResponseForRequest<T extends WorkerRequestType> =
  | WorkerSuccessResponse<T>
  | WorkerErrorResponse
  | WorkerProgressResponse;

// === CONVENIENCE TYPE ALIASES ===

export type EncryptionResponse = WorkerResponseForRequest<typeof WorkerRequestType.DeriveNearKeypairAndEncrypt>;
export type RecoveryResponse = WorkerResponseForRequest<typeof WorkerRequestType.RecoverKeypairFromPasskey>;
export type CheckRegistrationResponse = WorkerResponseForRequest<typeof WorkerRequestType.CheckCanRegisterUser>;
export type RegistrationResponse = WorkerResponseForRequest<typeof WorkerRequestType.SignVerifyAndRegisterUser>;
export type TransactionResponse = WorkerResponseForRequest<typeof WorkerRequestType.SignTransactionsWithActions>;
export type DecryptionResponse = WorkerResponseForRequest<typeof WorkerRequestType.DecryptPrivateKeyWithPrf>;
export type CoseExtractionResponse = WorkerResponseForRequest<typeof WorkerRequestType.ExtractCosePublicKey>;

// === TYPE GUARDS FOR GENERIC RESPONSES ===

export function isWorkerSuccess<T extends WorkerRequestType>(
  response: WorkerResponseForRequest<T>
): response is WorkerSuccessResponse<T> {
  return (
    response.type === WorkerResponseType.EncryptionSuccess ||
    response.type === WorkerResponseType.RecoverKeypairSuccess ||
    response.type === WorkerResponseType.RegistrationSuccess ||
    response.type === WorkerResponseType.SignatureSuccess ||
    response.type === WorkerResponseType.DecryptionSuccess ||
    response.type === WorkerResponseType.CoseExtractionSuccess
  );
}

export function isWorkerError<T extends WorkerRequestType>(
  response: WorkerResponseForRequest<T>
): response is WorkerErrorResponse {
  return (
    response.type === WorkerResponseType.Error ||
    response.type === WorkerResponseType.DeriveNearKeyFailure ||
    response.type === WorkerResponseType.RecoverKeypairFailure ||
    response.type === WorkerResponseType.RegistrationFailure ||
    response.type === WorkerResponseType.SignatureFailure ||
    response.type === WorkerResponseType.DecryptionFailure ||
    response.type === WorkerResponseType.CoseExtractionFailure
  );
}

export function isWorkerProgress<T extends WorkerRequestType>(
  response: WorkerResponseForRequest<T>
): response is WorkerProgressResponse {
  return (
    response.type === WorkerResponseType.VerificationProgress ||
    response.type === WorkerResponseType.SigningProgress ||
    response.type === WorkerResponseType.RegistrationProgress ||
    response.type === WorkerResponseType.VerificationComplete ||  // Moved from completion to progress
    response.type === WorkerResponseType.SigningComplete ||       // Moved from completion to progress
    response.type === WorkerResponseType.RegistrationComplete     // Moved from completion to progress
  );
}

// === SPECIFIC TYPE GUARDS FOR COMMON OPERATIONS ===

export function isEncryptionSuccess(response: EncryptionResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.DeriveNearKeypairAndEncrypt> {
  return response.type === WorkerResponseType.EncryptionSuccess;
}

export function isRecoverKeypairSuccess(response: RecoveryResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.RecoverKeypairFromPasskey> {
  return response.type === WorkerResponseType.RecoverKeypairSuccess;
}

export function isCheckRegistrationSuccess(response: CheckRegistrationResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.CheckCanRegisterUser> {
  return response.type === WorkerResponseType.RegistrationSuccess;
}

export function isRegistrationSuccess(response: RegistrationResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.SignVerifyAndRegisterUser> {
  return response.type === WorkerResponseType.RegistrationSuccess;
}

export function isSignatureSuccess(response: TransactionResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions> {
  return response.type === WorkerResponseType.SignatureSuccess;
}

export function isDecryptionSuccess(response: DecryptionResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.DecryptPrivateKeyWithPrf> {
  return response.type === WorkerResponseType.DecryptionSuccess;
}

export function isCoseExtractionSuccess(response: CoseExtractionResponse): response is WorkerSuccessResponse<typeof WorkerRequestType.ExtractCosePublicKey> {
  return response.type === WorkerResponseType.CoseExtractionSuccess;
}

// === ACTION TYPE VALIDATION ===

/**
 * Validate action parameters before sending to worker
 */
export function validateActionParams(actionParams: ActionParams): void {
  switch (actionParams.actionType) {
    case ActionType.FunctionCall:
      if (!actionParams.method_name) {
        throw new Error('method_name required for FunctionCall');
      }
      if (!actionParams.args) {
        throw new Error('args required for FunctionCall');
      }
      if (!actionParams.gas) {
        throw new Error('gas required for FunctionCall');
      }
      if (!actionParams.deposit) {
        throw new Error('deposit required for FunctionCall');
      }
      // Validate args is valid JSON string
      try {
        JSON.parse(actionParams.args);
      } catch {
        throw new Error('FunctionCall action args must be valid JSON string');
      }
      break;
    case ActionType.Transfer:
      if (!actionParams.deposit) {
        throw new Error('deposit required for Transfer');
      }
      break;
    case ActionType.CreateAccount:
      // No additional validation needed
      break;
    case ActionType.DeployContract:
      if (!actionParams.code || actionParams.code.length === 0) {
        throw new Error('code required for DeployContract');
      }
      break;
    case ActionType.Stake:
      if (!actionParams.stake) {
        throw new Error('stake amount required for Stake');
      }
      if (!actionParams.public_key) {
        throw new Error('public_key required for Stake');
      }
      break;
    case ActionType.AddKey:
      if (!actionParams.public_key) {
        throw new Error('public_key required for AddKey');
      }
      if (!actionParams.access_key) {
        throw new Error('access_key required for AddKey');
      }
      break;
    case ActionType.DeleteKey:
      if (!actionParams.public_key) {
        throw new Error('public_key required for DeleteKey');
      }
      break;
    case ActionType.DeleteAccount:
      if (!actionParams.beneficiary_id) {
        throw new Error('beneficiary_id required for DeleteAccount');
      }
      break;
    default:
      throw new Error(`Unsupported action type: ${(actionParams as any).actionType}`);
  }
}

// === WEBAUTHN CREDENTIAL TYPES ===

// Serializable WebAuthn credential to send to the wasm worker
export interface WebAuthnAuthenticationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string; // base64url-encoded
    authenticatorData: string; // base64url-encoded
    signature: string; // base64url-encoded
    userHandle: string | null; // base64url-encoded or null
  };
  // Dual PRF outputs extracted in main thread just before transferring to worker
  clientExtensionResults: {
    prf: {
      results: {
        // base64url-encoded PRF output for AES-GCM (via utils/encoders.base64UrlEncode)
        first: string | undefined;
        // base64url-encoded PRF output for Ed25519 (via utils/encoders.base64UrlEncode)
        second: string | undefined;
      }
    }
  }
}

export interface WebAuthnRegistrationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string,
    attestationObject: string,
    transports: string[],
  };
  // Dual PRF outputs extracted in main thread just before transferring to worker
  clientExtensionResults: {
    prf: {
      results: {
        // base64url-encoded PRF output for AES-GCM (via utils/encoders.base64UrlEncode)
        first: string | undefined;
        // base64url-encoded PRF output for Ed25519 (via utils/encoders.base64UrlEncode)
        second: string | undefined;
      }
    }
  }
}

/**
 * Extract the first PRF output from WebAuthn credential
 * For AES-GCM derivation.
 *
 * @param credential - WebAuthn credential with dual PRF extension results
 * @returns Base64url-encoded AES PRF output
 * @throws Error if AES PRF output is not available
 */
export function extractAesPrfOutput(credential: PublicKeyCredential): { aesPrfOutput: string } {
  const extensions = credential.getClientExtensionResults();
  const aesPrfOutput = extensions.prf?.results?.first as ArrayBuffer;
  if (!aesPrfOutput) {
    throw new Error('AES PRF output required but not available - ensure first PRF output is present');
  }
  return {
    aesPrfOutput: base64UrlEncode(aesPrfOutput),
  };
}

/**
 * Extract dual PRF outputs from WebAuthn credential
 *
 * @param credential - WebAuthn credential with dual PRF extension results
 * @returns DualPrfOutputs with both AES and Ed25519 PRF outputs
 * @throws Error if dual PRF outputs are not available
 */
export function extractDualPrfOutputs(credential: PublicKeyCredential): DualPrfOutputs {
  const extensions = credential.getClientExtensionResults();
  const aesPrfOutput = extensions.prf?.results?.first;
  const ed25519PrfOutput = extensions.prf?.results?.second;

  if (!aesPrfOutput || !ed25519PrfOutput) {
    throw new Error('Dual PRF outputs required but not available - ensure both first and second PRF outputs are present');
  }

  return {
    aesPrfOutput: base64UrlEncode(aesPrfOutput as ArrayBuffer),
    ed25519PrfOutput: base64UrlEncode(ed25519PrfOutput as ArrayBuffer)
  };
}
/**
 * Extract dual PRF outputs from WebAuthn credential extension results
 * ENCODING: Uses base64url for WASM compatibility
 */
function extractDualPrfFromCredential(credential: PublicKeyCredential): {
  first?: string;
  second?: string;
} {
  const extensionResults = credential.getClientExtensionResults();
  const prfResults = extensionResults?.prf?.results;
  if (!prfResults) {
    throw new Error('Missing PRF results from credential, use a PRF-enabled Authenticator');
  }
  return {
    first: prfResults?.first ? base64UrlEncode(prfResults.first as ArrayBuffer) : undefined,
    second: prfResults?.second ? base64UrlEncode(prfResults.second as ArrayBuffer) : undefined
  };
}

type SerializableCredential = WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;

/**
 * Serialize PublicKeyCredential with PRF handling for both authentication and registration
 * - Handles dual PRF extraction consistently
 * - Uses base64url encoding for WASM compatibility
 */
export function serializeCredentialWithPRF<C extends SerializableCredential>(
  credential: PublicKeyCredential
): C {
  // Check if this is a registration credential by looking for attestationObject
  const response = credential.response;
  const isRegistration = 'attestationObject' in response;

  const credentialBase = {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {},
    clientExtensionResults: {
      prf: {
        results: extractDualPrfFromCredential(credential)
      }
    }
  }

  if (isRegistration) {
    const attestationResponse = response as AuthenticatorAttestationResponse;
    return {
      ...credentialBase,
    response: {
      clientDataJSON: base64UrlEncode(attestationResponse.clientDataJSON),
      attestationObject: base64UrlEncode(attestationResponse.attestationObject),
      transports: attestationResponse.getTransports() || [],
    },
    } as C;
  } else {
    const assertionResponse = response as AuthenticatorAssertionResponse;
    return {
      ...credentialBase,
      response: {
        clientDataJSON: base64UrlEncode(assertionResponse.clientDataJSON),
        authenticatorData: base64UrlEncode(assertionResponse.authenticatorData),
        signature: base64UrlEncode(assertionResponse.signature),
        userHandle: assertionResponse.userHandle ? base64UrlEncode(assertionResponse.userHandle as ArrayBuffer) : null,
      },
    } as C;
    }
  }

/**
 * Removes PRF outputs from the credential and returns the credential without PRF along with just the AES PRF output
 * @param credential - The WebAuthn credential containing PRF outputs
 * @returns Object containing credential with PRF removed and the extracted AES PRF output
 * Does not return the second PRF output (Ed25519 PRF)
 */
export function takeAesPrfOutput(credential: SerializableCredential): ({
  credentialWithoutPrf: SerializableCredential,
  aesPrfOutput: string
}) {
  const aesPrfOutput = credential.clientExtensionResults?.prf?.results?.first;
  if (!aesPrfOutput) {
    throw new Error('PRF output missing from credential.clientExtensionResults: required for secure key decryption');
  }

  const credentialWithoutPrf: SerializableCredential = {
    ...credential,
    clientExtensionResults: {
      ...credential.clientExtensionResults,
      prf: {
        ...credential.clientExtensionResults?.prf,
        results: {
          first: undefined, // AES PRF output
          second: undefined // Ed25519 PRF output
        }
      }
    }
  };

  return { credentialWithoutPrf, aesPrfOutput };
}

// === ACTION TYPES ===

// ActionParams now matches the Rust enum structure exactly
export type ActionParams =
  | { actionType: ActionType.CreateAccount }
  | { actionType: ActionType.DeployContract; code: number[] }
  | {
      actionType: ActionType.FunctionCall;
      method_name: string;
      args: string; // JSON string, not object
      gas: string;
      deposit: string;
    }
  | { actionType: ActionType.Transfer; deposit: string }
  | { actionType: ActionType.Stake; stake: string; public_key: string }
  | { actionType: ActionType.AddKey; public_key: string; access_key: string }
  | { actionType: ActionType.DeleteKey; public_key: string }
  | { actionType: ActionType.DeleteAccount; beneficiary_id: string }

// === TYPE-SAFE HELPER FUNCTIONS ===

/**
 * Helper type to get just the success response payload type for a request
 */
export type SuccessPayloadForRequest<T extends WorkerRequestType> = RequestResponseMap[T];

// === SPECIFIC TYPE-SAFE EXTRACTORS ===

/**
 * Type-safe extractor for encryption results
 * Only works with successful responses, throws on error
 */
export function extractEncryptionResult(response: EncryptionResponse): WasmEncryptionResult {
  if (isEncryptionSuccess(response)) {
    return response.payload;
  }
  throw new Error('Cannot extract result from non-success response');
}

/**
 * Type-safe extractor for transaction signing results
 * Only works with successful responses, throws on error
 */
export function extractTransactionResult(response: TransactionResponse): WasmTransactionSignResult {
  if (isSignatureSuccess(response)) {
    return response.payload;
  }
  throw new Error('Cannot extract result from non-success response');
}

/**
 * Type-safe extractor for registration results
 * Only works with successful responses, throws on error
 */
export function extractRegistrationResult(response: RegistrationResponse): WasmRegistrationResult {
  if (isRegistrationSuccess(response)) {
    return response.payload;
  }
  throw new Error('Cannot extract result from non-success response');
}

/**
 * Type-safe extractor for keypair recovery results
 * Only works with successful responses, throws on error
 */
export function extractRecoveryResult(response: RecoveryResponse): WasmRecoverKeypairResult {
  if (isRecoverKeypairSuccess(response)) {
    return response.payload;
  }
  throw new Error('Cannot extract result from non-success response');
}