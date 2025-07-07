import { base64UrlEncode } from "../../utils/encoders";
import type { VRFChallenge, onProgressEvents } from "./webauthn";
import { ActionType } from "./actions";
import type { Transaction, Signature } from '@near-js/transactions';
import type { SignedTransaction } from '../NearClient';

// === IMPORT AUTO-GENERATED WASM TYPES ===
// These are the source of truth generated from Rust structs via wasm-bindgen
// Import as instance types from the WASM module classes
import * as wasmModule from '../../wasm_signer_worker/wasm_signer_worker.js';
export type WasmRecoverKeypairResult = InstanceType<typeof wasmModule.RecoverKeypairResult>;
export type WasmRegistrationResult = InstanceType<typeof wasmModule.RegistrationResult>;
export type WasmRegistrationCheckResult = InstanceType<typeof wasmModule.RegistrationCheckResult>;
export type WasmRegistrationInfo = InstanceType<typeof wasmModule.RegistrationInfoStruct>;
export type WasmJsonSignedTransaction = InstanceType<typeof wasmModule.JsonSignedTransactionStruct>;
export type WasmTransactionSignResult = InstanceType<typeof wasmModule.TransactionSignResult>;
export type WasmDecryptPrivateKeyResult = InstanceType<typeof wasmModule.DecryptPrivateKeyResult>;
export type WasmEncryptionResult = InstanceType<typeof wasmModule.EncryptionResult>;

// === IMPORT CLEAN WASM ENUMS ===
// Import the numeric enums generated from Rust - these are the source of truth
import {
  WorkerRequestType,
  WorkerResponseType,
} from '../../wasm_signer_worker/wasm_signer_worker.js';

// Export the WASM enums directly - no string mapping needed!
export { WorkerRequestType, WorkerResponseType };

// === TYPE DEFINITIONS ===
// Create type unions from the numeric enum values
export type WorkerRequestTypeValues = WorkerRequestType;
export type WorkerResponseTypeValues = WorkerResponseType;

// === DUAL PRF TYPES ===

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

/**
 * Registration transaction-specific parameters
 * Matches Rust RegistrationTxData struct
 */
export interface RegistrationTxData {
  /** Account ID that will sign the registration transaction */
  signerAccountId: string;
  /** Transaction nonce as number */
  nonce: number;
  /** Block hash bytes for the transaction */
  blockHashBytes: number[];
}

/**
 * Transfer transaction-specific parameters
 * Matches Rust TransferTxData struct
 */
export interface TransferTxData {
  /** Account ID that will sign the transfer */
  signerAccountId: string;
  /** Account ID that will receive the transfer */
  receiverAccountId: string;
  /** Transaction nonce as number */
  nonce: number;
  /** Block hash bytes for the transaction */
  blockHashBytes: number[];
  /** Transfer amount as string */
  depositAmount: string;
}

// === GROUPED REQUEST INTERFACES ===

/**
 * Transaction signing request with grouped parameters
 * Matches Rust TransactionSigningRequest struct
 */
export interface TransactionSigningRequestGrouped {
  /** Verification parameters */
  verification: Verification;
  /** Decryption parameters */
  decryption: Decryption;
  /** Transaction parameters */
  transaction: TxData;
}

/**
 * Transfer transaction request with grouped parameters
 * Matches Rust TransferTransactionRequest struct
 */
export interface TransferTransactionRequestGrouped {
  /** Verification parameters */
  verification: Verification;
  /** Decryption parameters */
  decryption: Decryption;
  /** Transfer transaction parameters */
  transaction: TransferTxData;
}

/**
 * Registration request with grouped parameters
 * Matches Rust RegistrationRequest struct
 */
export interface RegistrationRequestGrouped {
  /** Verification parameters */
  verification: Verification;
  /** Decryption parameters */
  decryption: Decryption;
  /** Registration transaction parameters */
  transaction: RegistrationTxData;
}

// === TRANSACTION TYPES ===

/**
 * Structured SignedTransaction format that mirrors near-js
 * Provides both the decoded transaction/signature and helper methods
 */
export interface StructuredSignedTransaction {
  /** Decoded transaction object */
  transaction: Transaction;
  /** Decoded signature object */
  signature: Signature;
  /** Helper method to encode back to bytes */
  encode: () => Uint8Array;
  /** Raw access to the full SignedTransaction instance for advanced usage */
  _raw: SignedTransaction;
}

/**
 * Serializable transaction data for worker communication
 * Contains the same data as SignedTransaction but without methods
 */
export interface SerializableSignedTransaction {
  /** Decoded transaction object */
  transaction: any;
  /** Decoded signature object */
  signature: any;
  /** Borsh-encoded bytes as number array */
  borsh_bytes: number[];
}

// === USER DATA TYPES ===

export interface UserData {
  nearAccountId: string;
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
  operation: WorkerRequestTypeValues;
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
  type: WorkerRequestTypeValues;
  operationId?: string;
  timestamp?: number;
}

// Dual PRF key derivation for secure private key generation
export interface DeriveNearKeypairAndEncryptRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.DeriveNearKeypairAndEncrypt;
  payload: {
    /** Dual PRF outputs from WebAuthn */
    dualPrfOutputs: DualPrfOutputs;
    /** NEAR account ID for key derivation */
    nearAccountId: string;
  };
}

// WebAuthn + WASM private key recovery (view function)
export interface RecoverKeypairFromPasskeyRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.RecoverKeypairFromPasskey;
  payload: {
    /** WebAuthn authentication credential with PRF outputs */
    credential: WebAuthnAuthenticationCredential;
    /** Optional account ID hint for recovery */
    accountIdHint?: string;
  };
}

export interface DecryptPrivateKeyWithPrfRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.DecryptPrivateKeyWithPrf;
  payload: {
    /** NEAR account ID */
    nearAccountId: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Base64url-encoded encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Base64url-encoded AES-GCM nonce for decryption */
    encryptedPrivateKeyIv: string;
  };
}

// Check if user can register (view function)
export interface CheckCanRegisterUserRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.CheckCanRegisterUser;
  payload: {
    /** VRF challenge data */
    vrfChallenge: VRFChallenge;
    /** WebAuthn registration credential */
    credential: WebAuthnRegistrationCredential;
    /** Contract ID for verification */
    contractId: string;
    /** NEAR RPC URL */
    nearRpcUrl: string;
  };
}

// Multi-action request with WebAuthn verification (PRF extracted in worker for security)
export interface SignTransactionWithActionsRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.SignTransactionWithActions;
  payload: {
    /** NEAR account ID for the signer */
    nearAccountId: string;
    /** Receiver account ID */
    receiverId: string;
    /** Serialized actions JSON string */
    actions: string;
    /** Transaction nonce */
    nonce: string;
    /** Block hash bytes */
    blockHashBytes: number[];
    /** Contract ID for verification */
    contractId: string;
    /** VRF challenge data */
    vrfChallenge: VRFChallenge;
    /** WebAuthn authentication credential with PRF outputs */
    credential: WebAuthnAuthenticationCredential;
    /** NEAR RPC URL */
    nearRpcUrl: string;
    /** Base64url-encoded encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Base64url-encoded AES-GCM nonce for decryption */
    encryptedPrivateKeyIv: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
  };
}

// Convenience request for Transfer transactions (PRF extracted in worker for security)
export interface SignTransferTransactionRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.SignTransferTransaction;
  payload: {
    /** NEAR account ID for the signer */
    nearAccountId: string;
    /** Receiver account ID */
    receiverId: string;
    /** Transfer amount in yoctoNEAR */
    depositAmount: string;
    /** Transaction nonce */
    nonce: string;
    /** Block hash bytes */
    blockHashBytes: number[];
    /** Contract ID for verification */
    contractId: string;
    /** VRF challenge data */
    vrfChallenge: VRFChallenge;
    /** WebAuthn authentication credential with PRF outputs */
    credential: WebAuthnAuthenticationCredential;
    /** NEAR RPC URL */
    nearRpcUrl: string;
    /** Base64url-encoded encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Base64url-encoded AES-GCM nonce for decryption */
    encryptedPrivateKeyIv: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
  };
}

// Actually register user (state-changing function - send_tx RPC)
export interface SignVerifyAndRegisterUserRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.SignVerifyAndRegisterUser;
  payload: {
    /** VRF challenge data */
    vrfChallenge: VRFChallenge;
    /** WebAuthn registration credential */
    credential: WebAuthnRegistrationCredential;
    /** Contract ID for verification */
    contractId: string;
    /** NEAR RPC URL */
    nearRpcUrl: string;
    /** NEAR account ID for the user */
    nearAccountId: string;
    /** Transaction nonce */
    nonce: string;
    /** Block hash bytes */
    blockHashBytes: number[];
  };
}

// COSE public key extraction from attestation object
export interface ExtractCosePublicKeyRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.ExtractCosePublicKey;
  payload: {
    /** Base64url-encoded attestation object */
    attestationObjectBase64url: string;
  };
}

// Add key with PRF authentication
export interface AddKeyWithPrfRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.AddKeyWithPrf;
  payload: {
    /** VRF challenge data */
    vrfChallenge: VRFChallenge;
    /** WebAuthn authentication credential with PRF outputs */
    credential: WebAuthnAuthenticationCredential;
    /** Contract ID for verification */
    contractId: string;
    /** NEAR RPC URL */
    nearRpcUrl: string;
    /** NEAR account ID */
    nearAccountId: string;
    /** New public key to add */
    newPublicKey: string;
    /** Access key permissions JSON */
    accessKeyJson: string;
    /** Transaction nonce */
    nonce: string;
    /** Block hash bytes */
    blockHashBytes: number[];
    /** Base64url-encoded encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Base64url-encoded AES-GCM nonce for decryption */
    encryptedPrivateKeyIv: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
  };
}

// Delete key with PRF authentication
export interface DeleteKeyWithPrfRequest extends BaseWorkerRequest {
  type: typeof WorkerRequestType.DeleteKeyWithPrf;
  payload: {
    /** VRF challenge data */
    vrfChallenge: VRFChallenge;
    /** WebAuthn authentication credential with PRF outputs */
    credential: WebAuthnAuthenticationCredential;
    /** Contract ID for verification */
    contractId: string;
    /** NEAR RPC URL */
    nearRpcUrl: string;
    /** NEAR account ID */
    nearAccountId: string;
    /** Public key to delete */
    publicKeyToDelete: string;
    /** Transaction nonce */
    nonce: string;
    /** Block hash bytes */
    blockHashBytes: number[];
    /** Base64url-encoded encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Base64url-encoded AES-GCM nonce for decryption */
    encryptedPrivateKeyIv: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
  };
}

export type WorkerRequest =
  | DeriveNearKeypairAndEncryptRequest
  | RecoverKeypairFromPasskeyRequest
  | CheckCanRegisterUserRequest
  | SignVerifyAndRegisterUserRequest
  | DecryptPrivateKeyWithPrfRequest
  | SignTransactionWithActionsRequest
  | SignTransferTransactionRequest
  | AddKeyWithPrfRequest
  | DeleteKeyWithPrfRequest
  | ExtractCosePublicKeyRequest;

// === PROGRESS MESSAGE TYPES ===

/**
 * Progress message types that can be sent from WASM to the main thread
 */
export enum ProgressMessageType {
  VERIFICATION_PROGRESS = 'VERIFICATION_PROGRESS',
  VERIFICATION_COMPLETE = 'VERIFICATION_COMPLETE',
  SIGNING_PROGRESS = 'SIGNING_PROGRESS',
  SIGNING_COMPLETE = 'SIGNING_COMPLETE',
  REGISTRATION_PROGRESS = 'REGISTRATION_PROGRESS',
  REGISTRATION_COMPLETE = 'REGISTRATION_COMPLETE',
}

/**
 * Step identifiers for progress tracking
 */
export enum ProgressStep {
  PREPARATION = 'preparation',
  AUTHENTICATION = 'authentication',
  CONTRACT_VERIFICATION = 'contract_verification',
  TRANSACTION_SIGNING = 'transaction_signing',
  BROADCASTING = 'broadcasting',
  VERIFICATION_COMPLETE = 'verification_complete',
  SIGNING_COMPLETE = 'signing_complete',
}

/**
 * Parameters for the sendProgressMessage function called by WASM
 */
export interface ProgressMessageParams {
  /** Type of progress message */
  messageType: ProgressMessageType | string;
  /** Step identifier */
  step: ProgressStep | string;
  /** Human-readable progress message */
  message: string;
  /** JSON string containing structured data */
  data: string;
  /** Optional JSON string containing array of log messages */
  logs?: string;
}

/**
 * Worker progress message that gets posted to the main thread
 */
export interface WorkerProgressMessage {
  /** Message type corresponding to WorkerResponseType */
  type: string;
  /** Payload containing onProgressEvents-compatible data plus legacy fields */
  payload: any; // Will be properly typed when imported with onProgressEvents
}

// === RESPONSE MESSAGE INTERFACES ===

export interface BaseWorkerResponse {
  type: WorkerResponseTypeValues;
  payload: Record<string, any>;
}

export interface EncryptionSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.EncryptionSuccess;
  payload: WasmEncryptionResult;
}

export interface EncryptionFailureResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.DeriveNearKeyFailure;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface RecoverKeypairSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.RecoverKeypairSuccess;
  payload: WasmRecoverKeypairResult;
}

export interface RecoverKeypairFailureResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.RecoverKeypairFailure;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface CheckRegistrationSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.RegistrationSuccess;
  payload: WasmRegistrationCheckResult;
}

export interface RegistrationSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.RegistrationSuccess;
  payload: WasmRegistrationResult;
}

export interface RegistrationFailureResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.RegistrationFailure;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface SignatureSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.SignatureSuccess;
  payload: WasmTransactionSignResult;
}

export interface SignatureFailureResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.SignatureFailure;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface DecryptionSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.DecryptionSuccess;
  payload: WasmDecryptPrivateKeyResult;
}

export interface DecryptionFailureResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.DecryptionFailure;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface ErrorResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.Error;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface CoseExtractionSuccessResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.CoseExtractionSuccess;
  payload: wasmModule.CoseExtractionResult;
}

export interface CoseExtractionFailureResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.CoseExtractionFailure;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export type WorkerResponse =
  | EncryptionSuccessResponse
  | EncryptionFailureResponse
  | RecoverKeypairSuccessResponse
  | RecoverKeypairFailureResponse
  | CheckRegistrationSuccessResponse
  | RegistrationSuccessResponse
  | RegistrationFailureResponse
  | SignatureSuccessResponse
  | SignatureFailureResponse
  | DecryptionSuccessResponse
  | DecryptionFailureResponse
  | ProgressResponse
  | CompletionResponse
  | ErrorResponse
  | CoseExtractionSuccessResponse
  | CoseExtractionFailureResponse;

// === TYPE GUARDS ===

export function isEncryptionSuccess(response: WorkerResponse): response is EncryptionSuccessResponse {
  return response.type === WorkerResponseType.EncryptionSuccess;
}

export function isRecoverKeypairSuccess(response: WorkerResponse): response is RecoverKeypairSuccessResponse {
  return response.type === WorkerResponseType.RecoverKeypairSuccess;
}

export function isCheckRegistrationSuccess(response: WorkerResponse): response is CheckRegistrationSuccessResponse {
  return response.type === WorkerResponseType.RegistrationSuccess;
}

export function isRegistrationSuccess(response: WorkerResponse): response is RegistrationSuccessResponse {
  return response.type === WorkerResponseType.RegistrationSuccess;
}

export function isSignatureSuccess(response: WorkerResponse): response is SignatureSuccessResponse {
  return response.type === WorkerResponseType.SignatureSuccess;
}

export function isDecryptionSuccess(response: WorkerResponse): response is DecryptionSuccessResponse {
  return response.type === WorkerResponseType.DecryptionSuccess;
}

export function isCoseExtractionSuccess(response: WorkerResponse): response is CoseExtractionSuccessResponse {
  return response.type === WorkerResponseType.CoseExtractionSuccess;
}

export function isWorkerError(response: WorkerResponse): response is
  ErrorResponse |
  EncryptionFailureResponse |
  RecoverKeypairFailureResponse |
  RegistrationFailureResponse |
  SignatureFailureResponse |
  DecryptionFailureResponse |
  CoseExtractionFailureResponse
{
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

export function isWorkerSuccess(response: WorkerResponse): response is
  EncryptionSuccessResponse |
  RecoverKeypairSuccessResponse |
  RegistrationSuccessResponse |
  SignatureSuccessResponse |
  DecryptionSuccessResponse |
  CoseExtractionSuccessResponse
{
  return (
    response.type === WorkerResponseType.EncryptionSuccess ||
    response.type === WorkerResponseType.RecoverKeypairSuccess ||
    response.type === WorkerResponseType.RegistrationSuccess ||
    response.type === WorkerResponseType.SignatureSuccess ||
    response.type === WorkerResponseType.DecryptionSuccess ||
    response.type === WorkerResponseType.CoseExtractionSuccess
  );
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

// Progressive response interfaces
export interface ProgressResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.VerificationProgress
      | typeof WorkerResponseType.SigningProgress
      | typeof WorkerResponseType.RegistrationProgress;
  payload: onProgressEvents;
}

export interface CompletionResponse extends BaseWorkerResponse {
  type: typeof WorkerResponseType.VerificationComplete
      | typeof WorkerResponseType.SigningComplete
      | typeof WorkerResponseType.RegistrationComplete;
  payload: onProgressEvents;
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
 * Extract dual PRF outputs from WebAuthn credential
 * Based on docs/dual_prf_key_derivation.md implementation plan
 *
 * @param credential - WebAuthn credential with dual PRF extension results
 * @returns DualPrfOutputs with both AES and Ed25519 PRF outputs
 * @throws Error if dual PRF outputs are not available
 */
export function extractDualPrfOutputs(credential: PublicKeyCredential): DualPrfOutputs {
  const extensions = credential.getClientExtensionResults();
  const prfResults = extensions.prf?.results;

  if (!prfResults?.first || !prfResults?.second) {
    throw new Error('Dual PRF outputs required but not available - ensure both first and second PRF outputs are present');
  }

  // Convert BufferSource to ArrayBuffer if needed
  const firstArrayBuffer = prfResults.first instanceof ArrayBuffer
    ? prfResults.first
    : prfResults.first.buffer.slice(prfResults.first.byteOffset, prfResults.first.byteOffset + prfResults.first.byteLength);

  const secondArrayBuffer = prfResults.second instanceof ArrayBuffer
    ? prfResults.second
    : prfResults.second.buffer.slice(prfResults.second.byteOffset, prfResults.second.byteOffset + prfResults.second.byteLength);

  return {
    aesPrfOutput: base64UrlEncode(firstArrayBuffer),
    ed25519PrfOutput: base64UrlEncode(secondArrayBuffer)
  };
}

/**
 * Serialize PublicKeyCredential with PRF handling for both authentication and registration
 *
 * UNIFIED APPROACH:
 * - Automatically detects credential type (registration vs authentication)
 * - Handles dual PRF extraction consistently
 * - Uses base64url encoding for WASM compatibility
 *
 * SECURITY FEATURES:
 * - Just-in-time serialization - minimal exposure time
 * - Consistent base64url encoding for proper WASM decoding
 * - Secure against encoding/decoding failures
 */
export function serializeCredentialWithPRF<C extends WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential>(
  credential: PublicKeyCredential
): C {
  // Extract dual PRF outputs immediately for secure transfer to worker
  const prfOutputs = extractDualPrfFromCredential(credential);

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
        results: prfOutputs
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
 * Extract dual PRF outputs from WebAuthn credential extension results
 *
 * SECURITY: Immediate extraction minimizes exposure time of PRF outputs
 * ENCODING: Uses base64url for WASM compatibility
 */
function extractDualPrfFromCredential(credential: PublicKeyCredential): {
  first?: string;
  second?: string;
} {
  try {
    const extensionResults = credential.getClientExtensionResults();
    const prfResults = extensionResults?.prf?.results;

  return {
      first: prfResults?.first ? base64UrlEncode(prfResults.first as ArrayBuffer) : undefined,
      second: prfResults?.second ? base64UrlEncode(prfResults.second as ArrayBuffer) : undefined
    };
  } catch (error) {
    console.warn('[serialize]: Dual PRF extraction failed:', error);
    throw new Error('[serialize]: Dual PRF extraction failed. Please try again.');
  }
}

type SerializableCredential = WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;

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