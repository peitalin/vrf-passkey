import { base64UrlEncode } from "../../utils/encoders";
import type { VRFChallenge } from "./webauthn";
import { ActionType } from "./actions";
import type { Transaction, Signature } from '@near-js/transactions';
import type { SignedTransaction } from '../NearClient';

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

export enum WorkerRequestType {
  DERIVE_NEAR_KEYPAIR_AND_ENCRYPT = 'DERIVE_NEAR_KEYPAIR_AND_ENCRYPT',
  RECOVER_KEYPAIR_FROM_PASSKEY = 'RECOVER_KEYPAIR_FROM_PASSKEY',
  CHECK_CAN_REGISTER_USER = 'CHECK_CAN_REGISTER_USER',
  SIGN_VERIFY_AND_REGISTER_USER = 'SIGN_VERIFY_AND_REGISTER_USER',
  DECRYPT_PRIVATE_KEY_WITH_PRF = 'DECRYPT_PRIVATE_KEY_WITH_PRF',
  GENERATE_VRF_KEYPAIR_WITH_PRF = 'GENERATE_VRF_KEYPAIR_WITH_PRF',
  GENERATE_VRF_CHALLENGE_WITH_PRF = 'GENERATE_VRF_CHALLENGE_WITH_PRF',
  SIGN_TRANSACTION_WITH_ACTIONS = 'SIGN_TRANSACTION_WITH_ACTIONS',
  SIGN_TRANSFER_TRANSACTION = 'SIGN_TRANSFER_TRANSACTION',
  // New action-specific functions
  ADD_KEY_WITH_PRF = 'ADD_KEY_WITH_PRF',
  DELETE_KEY_WITH_PRF = 'DELETE_KEY_WITH_PRF',
  // COSE operations
  EXTRACT_COSE_PUBLIC_KEY = 'EXTRACT_COSE_PUBLIC_KEY',
}

export enum WorkerResponseType {
  ENCRYPTION_SUCCESS = 'ENCRYPTION_SUCCESS',
  DERIVE_NEAR_KEY_FAILURE = 'DERIVE_NEAR_KEY_FAILURE',
  RECOVER_KEYPAIR_SUCCESS = 'RECOVER_KEYPAIR_SUCCESS',
  RECOVER_KEYPAIR_FAILURE = 'RECOVER_KEYPAIR_FAILURE',
  REGISTRATION_SUCCESS = 'REGISTRATION_SUCCESS',
  REGISTRATION_FAILURE = 'REGISTRATION_FAILURE',
  SIGNATURE_SUCCESS = 'SIGNATURE_SUCCESS',
  SIGNATURE_FAILURE = 'SIGNATURE_FAILURE',
  DECRYPTION_SUCCESS = 'DECRYPTION_SUCCESS',
  DECRYPTION_FAILURE = 'DECRYPTION_FAILURE',
  VRF_KEYPAIR_SUCCESS = 'VRF_KEYPAIR_SUCCESS',
  VRF_KEYPAIR_FAILURE = 'VRF_KEYPAIR_FAILURE',
  VRF_CHALLENGE_SUCCESS = 'VRF_CHALLENGE_SUCCESS',
  VRF_CHALLENGE_FAILURE = 'VRF_CHALLENGE_FAILURE',
  // COSE operations
  COSE_EXTRACTION_SUCCESS = 'COSE_EXTRACTION_SUCCESS',
  COSE_EXTRACTION_FAILURE = 'COSE_EXTRACTION_FAILURE',
  ERROR = 'ERROR',
  VERIFICATION_PROGRESS = 'VERIFICATION_PROGRESS',
  VERIFICATION_COMPLETE = 'VERIFICATION_COMPLETE',
  REGISTRATION_PROGRESS = 'REGISTRATION_PROGRESS',
  REGISTRATION_COMPLETE = 'REGISTRATION_COMPLETE',
  SIGNING_PROGRESS = 'SIGNING_PROGRESS',
  SIGNING_COMPLETE = 'SIGNING_COMPLETE',
}

// === WORKER-RELATED TYPES ===

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
  VRF_KEYPAIR_GENERATION_FAILED = 'VRF_KEYPAIR_GENERATION_FAILED',
  VRF_CHALLENGE_GENERATION_FAILED = 'VRF_CHALLENGE_GENERATION_FAILED',
  VRF_ENCRYPTION_FAILED = 'VRF_ENCRYPTION_FAILED',
  VRF_DECRYPTION_FAILED = 'VRF_DECRYPTION_FAILED',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

// === REQUEST MESSAGE INTERFACES ===

export interface BaseWorkerRequest {
  type: WorkerRequestType;
  operationId?: string;
  timestamp?: number;
}

export interface DeriveNearKeypairAndEncryptRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DERIVE_NEAR_KEYPAIR_AND_ENCRYPT;
  payload: {
    /** Dual PRF outputs for separate AES and Ed25519 key derivation */
    dualPrfOutputs: DualPrfOutputs;
    /** NEAR account ID to associate with the encrypted key */
    nearAccountId: string;
  };
}

export interface RecoverKeypairFromPasskeyRequest extends BaseWorkerRequest {
  type: WorkerRequestType.RECOVER_KEYPAIR_FROM_PASSKEY;
  payload: {
    /** Serialized WebAuthn registration credential with attestation object for COSE key extraction */
    credential: WebAuthnRegistrationCredential;
    /** Optional account ID hint for validation */
    accountIdHint?: string;
  };
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

// Check if user can register (view function - query RPC)
export interface CheckCanRegisterUserRequest extends BaseWorkerRequest {
  type: WorkerRequestType.CHECK_CAN_REGISTER_USER;
  payload: {
    /** VRF challenge data for verification */
    vrfChallenge: VRFChallenge;
    /** Serialized WebAuthn registration credential */
    credential: WebAuthnRegistrationCredential;
    /** Contract ID for verification */
    contractId: string;
    /** NEAR RPC provider URL for verification */
    nearRpcUrl: string;
  };
}

// Actually register user (state-changing function - send_tx RPC)
export interface SignVerifyAndRegisterUserRequest extends BaseWorkerRequest {
  type: WorkerRequestType.SIGN_VERIFY_AND_REGISTER_USER;
  payload: {
    /** VRF challenge data for verification */
    vrfChallenge: VRFChallenge;
    /** Serialized WebAuthn registration credential */
    credential: WebAuthnRegistrationCredential;
    /** Contract ID for verification */
    contractId: string;
    /** Signer account ID for the transaction */
    signerAccountId: string;
    /** NEAR account ID that owns the keys to be used for registration */
    nearAccountId: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];
  };
}

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

// Multi-action request with WebAuthn verification (PRF extracted in worker for security)
export interface SignTransactionWithActionsRequest extends BaseWorkerRequest {
  type: WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS;
  payload: {
    /** NEAR account ID whose key should be used for signing */
    nearAccountId: string;
    /** Receiver account ID */
    receiverId: string;
    /** JSON string containing array of actions to include in the transaction */
    actions: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];

    ////////////////////////////////////////////////////////
    // WebAuthn verification parameters (required for enhanced verify+sign flow)
    ////////////////////////////////////////////////////////

    /** Contract ID for verification */
    contractId: string;
    /** VRF challenge data for verification */
    vrfChallenge: VRFChallenge;
    /** Serialized WebAuthn credential (PRF extracted in worker for security) */
    credential: WebAuthnAuthenticationCredential;
    /** NEAR RPC provider URL for verification */
    nearRpcUrl: string;
  };
}

// Convenience request for Transfer transactions (PRF extracted in worker for security)
export interface SignTransferTransactionRequest extends BaseWorkerRequest {
  type: WorkerRequestType.SIGN_TRANSFER_TRANSACTION;
  payload: {
    /** NEAR account ID whose key should be used for signing */
    nearAccountId: string;
    /** Receiver account ID */
    receiverId: string;
    /** Deposit amount in string format */
    depositAmount: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];

    ////////////////////////////////////////////////////////
    // WebAuthn verification parameters (required for enhanced verify+sign flow)
    ////////////////////////////////////////////////////////

    /** Contract ID for verification */
    contractId: string;
    /** VRF challenge data for verification */
    vrfChallenge: VRFChallenge;
    /** Serialized WebAuthn credential (PRF extracted in worker for security) */
    credential: WebAuthnAuthenticationCredential;
    /** NEAR RPC provider URL for verification */
    nearRpcUrl: string;
  };
}

export interface DecryptPrivateKeyWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF;
  payload: {
    /** NEAR account ID whose key should be decrypted */
    nearAccountId: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
  };
}

export interface GenerateVrfKeypairWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.GENERATE_VRF_KEYPAIR_WITH_PRF;
  payload: {
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
  };
}

export interface GenerateVrfChallengeWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.GENERATE_VRF_CHALLENGE_WITH_PRF;
  payload: {
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Base64url-encoded encrypted VRF data */
    encryptedVrfKeypair: string;
    /** Base64url-encoded AES-GCM nonce for VRF decryption */
    aesGcmNonce: string;
    /** User ID for VRF input construction */
    userId: string;
    /** Relying Party ID for VRF input construction */
    rpId: string;
    /** Block height from NEAR blockchain */
    blockHeight: number;
    /** Block hash bytes from NEAR blockchain */
    blockHashBytes: number[];
    /** Timestamp for VRF input construction */
    timestamp: number;
  };
}

// New request interfaces for the action-specific functions

export interface AddKeyWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.ADD_KEY_WITH_PRF;
  payload: {
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Encrypted private key IV */
    encryptedPrivateKeyIv: string;
    /** Signer account ID */
    signerAccountId: string;
    /** The public key to add (in "ed25519:..." format) */
    newPublicKey: string;
    /** JSON-serialized AccessKey */
    accessKeyJson: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];
    /** Contract ID for verification */
    contractId: string;
    /** VRF challenge data for verification */
    vrfChallenge: VRFChallenge;
    /** Serialized WebAuthn credential */
    credential: WebAuthnAuthenticationCredential;
    /** NEAR RPC provider URL for verification */
    nearRpcUrl: string;
  };
}

export interface DeleteKeyWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DELETE_KEY_WITH_PRF;
  payload: {
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Encrypted private key data */
    encryptedPrivateKeyData: string;
    /** Encrypted private key IV */
    encryptedPrivateKeyIv: string;
    /** Signer account ID */
    signerAccountId: string;
    /** The public key to delete (in "ed25519:..." format) */
    publicKeyToDelete: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];
    /** Contract ID for verification */
    contractId: string;
    /** VRF challenge data for verification */
    vrfChallenge: VRFChallenge;
    /** Serialized WebAuthn credential */
    credential: WebAuthnAuthenticationCredential;
    /** NEAR RPC provider URL for verification */
    nearRpcUrl: string;
  };
}

export interface ExtractCosePublicKeyRequest extends BaseWorkerRequest {
  type: WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY;
  payload: {
    /** Base64url-encoded WebAuthn attestation object */
    attestationObjectBase64url: string;
  };
}

export type WorkerRequest =
  | DeriveNearKeypairAndEncryptRequest
  | RecoverKeypairFromPasskeyRequest
  | CheckCanRegisterUserRequest
  | SignVerifyAndRegisterUserRequest
  | DecryptPrivateKeyWithPrfRequest
  | GenerateVrfKeypairWithPrfRequest
  | GenerateVrfChallengeWithPrfRequest
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
  type: WorkerResponseType;
  payload: Record<string, any>;
  operationId?: string;
  timestamp?: number;
  executionTime?: number;
}

export interface EncryptionSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.ENCRYPTION_SUCCESS;
  payload: {
    /** NEAR account ID for the encrypted key */
    nearAccountId: string;
    /** Generated public key in NEAR format */
    publicKey: string;
    /** Whether the key was successfully stored */
    stored: boolean;
  };
}

export interface EncryptionFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.DERIVE_NEAR_KEY_FAILURE;
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
  type: WorkerResponseType.RECOVER_KEYPAIR_SUCCESS;
  payload: {
    /** Derived public key in NEAR format (ed25519:...) */
    publicKey: string;
    /** Account ID hint if provided */
    accountIdHint?: string;
  };
}

export interface RecoverKeypairFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.RECOVER_KEYPAIR_FAILURE;
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
  type: WorkerResponseType.REGISTRATION_SUCCESS;
  payload: {
    /// Whether the registration was verified
    verified: boolean;
    /// Registration information from the contract
    registrationInfo?: {
      credential_id: number[];
      credential_public_key: number[];
      user_id: string;
      vrf_public_key?: number[];
    };
    /// Contract logs from the registration verification
    logs?: string[];
  };
}

export interface RegistrationSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.REGISTRATION_SUCCESS;
  payload: {
    /// Whether the registration was verified
    verified: boolean;
    /// Registration information from the contract
    registrationInfo: {
      credential_id: number[];
      credential_public_key: number[];
      user_id: string;
      vrf_public_key?: number[];
    };
    /// Contract logs from the registration verification
    logs: string[];
    /// Serializable SignedTransaction data (methods added on receiving end)
    signedTransaction: SerializableSignedTransaction;
    /// Pre-signed delete transaction for rollback (serializable)
    preSignedDeleteTransaction: SerializableSignedTransaction;
  };
}

export interface RegistrationFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.REGISTRATION_FAILURE;
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
  type: WorkerResponseType.SIGNATURE_SUCCESS;
  payload: {
    /** NEAR account ID that signed the transaction */
    nearAccountId: string;
    /** Structured SignedTransaction object (new format, if available) */
    signedTransaction: SignedTransaction;
  };
}

export interface SignatureFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.SIGNATURE_FAILURE;
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
  type: WorkerResponseType.DECRYPTION_SUCCESS;
  payload: {
    /** Decrypted private key in NEAR format */
    decryptedPrivateKey: string;
    /** NEAR account ID for the decrypted key */
    nearAccountId: string;
  };
}

export interface DecryptionFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.DECRYPTION_FAILURE;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}


export interface VRFKeyPairSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.VRF_KEYPAIR_SUCCESS;
  payload: {
    /** VRF public key (base64url encoded) */
    vrfPublicKey: string;
    /** Encrypted VRF keypair data */
    encryptedVrfKeypair: {
      encrypted_vrf_data_b64u: string;
      aes_gcm_nonce_b64u: string;
    };
  };
}

export interface VRFKeyPairFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.VRF_KEYPAIR_FAILURE;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface VRFChallengeSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.VRF_CHALLENGE_SUCCESS;
  payload: {
    /** VRF input data (base64url encoded) */
    vrfInput: string;
    /** VRF output (base64url encoded) - used as WebAuthn challenge */
    vrfOutput: string;
    /** VRF proof (base64url encoded) */
    vrfProof: string;
    /** VRF public key (base64url encoded) */
    vrfPublicKey: string;
    /** Relying Party ID */
    rpId: string;
  };
}

export interface VRFChallengeFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.VRF_CHALLENGE_FAILURE;
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
  type: WorkerResponseType.ERROR;
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
  type: WorkerResponseType.COSE_EXTRACTION_SUCCESS;
  payload: {
    /** Extracted COSE public key bytes */
    cosePublicKeyBytes: Uint8Array;
  };
}

export interface CoseExtractionFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.COSE_EXTRACTION_FAILURE;
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
  | VRFKeyPairSuccessResponse
  | VRFKeyPairFailureResponse
  | VRFChallengeSuccessResponse
  | VRFChallengeFailureResponse
  | ProgressResponse
  | CompletionResponse
  | ErrorResponse
  | CoseExtractionSuccessResponse
  | CoseExtractionFailureResponse;

// === TYPE GUARDS ===

export function isEncryptionSuccess(response: WorkerResponse): response is EncryptionSuccessResponse {
  return response.type === WorkerResponseType.ENCRYPTION_SUCCESS;
}

export function isRecoverKeypairSuccess(response: WorkerResponse): response is RecoverKeypairSuccessResponse {
  return response.type === WorkerResponseType.RECOVER_KEYPAIR_SUCCESS;
}

export function isCheckRegistrationSuccess(response: WorkerResponse): response is CheckRegistrationSuccessResponse {
  return response.type === WorkerResponseType.REGISTRATION_SUCCESS;
}

export function isRegistrationSuccess(response: WorkerResponse): response is RegistrationSuccessResponse {
  return response.type === WorkerResponseType.REGISTRATION_SUCCESS;
}

export function isSignatureSuccess(response: WorkerResponse): response is SignatureSuccessResponse {
  return response.type === WorkerResponseType.SIGNATURE_SUCCESS;
}

export function isDecryptionSuccess(response: WorkerResponse): response is DecryptionSuccessResponse {
  return response.type === WorkerResponseType.DECRYPTION_SUCCESS;
}

export function isCoseExtractionSuccess(response: WorkerResponse): response is CoseExtractionSuccessResponse {
  return response.type === WorkerResponseType.COSE_EXTRACTION_SUCCESS;
}

export function isWorkerError(response: WorkerResponse): response is
  ErrorResponse |
  EncryptionFailureResponse |
  RecoverKeypairFailureResponse |
  RegistrationFailureResponse |
  SignatureFailureResponse |
  DecryptionFailureResponse |
  VRFKeyPairFailureResponse |
  VRFChallengeFailureResponse |
  CoseExtractionFailureResponse
{
  return (
    response.type === WorkerResponseType.ERROR ||
    response.type === WorkerResponseType.DERIVE_NEAR_KEY_FAILURE ||
    response.type === WorkerResponseType.RECOVER_KEYPAIR_FAILURE ||
    response.type === WorkerResponseType.REGISTRATION_FAILURE ||
    response.type === WorkerResponseType.SIGNATURE_FAILURE ||
    response.type === WorkerResponseType.DECRYPTION_FAILURE ||
    response.type === WorkerResponseType.VRF_KEYPAIR_FAILURE ||
    response.type === WorkerResponseType.VRF_CHALLENGE_FAILURE ||
    response.type === WorkerResponseType.COSE_EXTRACTION_FAILURE
  );
}

export function isWorkerSuccess(response: WorkerResponse): response is
  EncryptionSuccessResponse |
  RecoverKeypairSuccessResponse |
  RegistrationSuccessResponse |
  SignatureSuccessResponse |
  DecryptionSuccessResponse |
  VRFKeyPairSuccessResponse |
  VRFChallengeSuccessResponse |
  CoseExtractionSuccessResponse
{
  return (
    response.type === WorkerResponseType.ENCRYPTION_SUCCESS ||
    response.type === WorkerResponseType.RECOVER_KEYPAIR_SUCCESS ||
    response.type === WorkerResponseType.REGISTRATION_SUCCESS ||
    response.type === WorkerResponseType.SIGNATURE_SUCCESS ||
    response.type === WorkerResponseType.DECRYPTION_SUCCESS ||
    response.type === WorkerResponseType.VRF_KEYPAIR_SUCCESS ||
    response.type === WorkerResponseType.VRF_CHALLENGE_SUCCESS ||
    response.type === WorkerResponseType.COSE_EXTRACTION_SUCCESS
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
export interface ProgressResponse {
  type: WorkerResponseType.VERIFICATION_PROGRESS
      | WorkerResponseType.SIGNING_PROGRESS
      | WorkerResponseType.REGISTRATION_PROGRESS;
  payload: {
    step: string;
    message: string;
    logs?: string[];
    data?: any;
  };
}

export interface CompletionResponse {
  type: WorkerResponseType.VERIFICATION_COMPLETE
      | WorkerResponseType.SIGNING_COMPLETE
      | WorkerResponseType.REGISTRATION_COMPLETE;
  payload: {
    success: boolean;
    data: {
      signed_transaction: SerializableSignedTransaction;
      near_account_id: string;
      verification_logs: string[];
    };
    error?: string;
    logs?: string[];
  };
}