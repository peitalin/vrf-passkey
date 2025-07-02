import { base64UrlEncode } from "../../utils/encoders";
import type { VRFChallenge } from "./webauthn";
import { ActionType } from "./actions";
import type { Transaction, Signature } from '@near-js/transactions';
import type { SignedTransaction } from '../NearClient';

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
  // COSE operations
  EXTRACT_COSE_PUBLIC_KEY = 'EXTRACT_COSE_PUBLIC_KEY',
  VALIDATE_COSE_KEY = 'VALIDATE_COSE_KEY',
  GENERATE_VRF_KEYPAIR_WITH_PRF = 'GENERATE_VRF_KEYPAIR_WITH_PRF',
  GENERATE_VRF_CHALLENGE_WITH_PRF = 'GENERATE_VRF_CHALLENGE_WITH_PRF',
  SIGN_TRANSACTION_WITH_ACTIONS = 'SIGN_TRANSACTION_WITH_ACTIONS',
  SIGN_TRANSFER_TRANSACTION = 'SIGN_TRANSFER_TRANSACTION',
  // New action-specific functions
  ADD_KEY_WITH_PRF = 'ADD_KEY_WITH_PRF',
  DELETE_KEY_WITH_PRF = 'DELETE_KEY_WITH_PRF',
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
  COSE_KEY_SUCCESS = 'COSE_KEY_SUCCESS',
  COSE_KEY_FAILURE = 'COSE_KEY_FAILURE',
  COSE_VALIDATION_SUCCESS = 'COSE_VALIDATION_SUCCESS',
  COSE_VALIDATION_FAILURE = 'COSE_VALIDATION_FAILURE',
  VRF_KEYPAIR_SUCCESS = 'VRF_KEYPAIR_SUCCESS',
  VRF_KEYPAIR_FAILURE = 'VRF_KEYPAIR_FAILURE',
  VRF_CHALLENGE_SUCCESS = 'VRF_CHALLENGE_SUCCESS',
  VRF_CHALLENGE_FAILURE = 'VRF_CHALLENGE_FAILURE',
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
  COSE_EXTRACTION_FAILED = 'COSE_EXTRACTION_FAILED',
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
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** NEAR account ID to associate with the encrypted key */
    nearAccountId: string;
    /** Base64url-encoded WebAuthn attestation object for deterministic key derivation */
    attestationObjectBase64url: string;
  };
}

export interface RecoverKeypairFromPasskeyRequest extends BaseWorkerRequest {
  type: WorkerRequestType.RECOVER_KEYPAIR_FROM_PASSKEY;
  payload: {
    /** Serialized WebAuthn registration credential with attestation object for COSE key extraction */
    credential: WebAuthnRegistrationCredential;
    /** Challenge that was used in the WebAuthn registration ceremony (base64url-encoded) */
    challenge: string;
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
  // PRF output extracted in main thread just before transferring to worker
  clientExtensionResults: {
    prf: {
      results: {
        first: string | undefined; // base64url-encoded PRF output (via utils/encoders.base64UrlEncode)
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
  // PRF output extracted in main thread just before transferring to worker
  clientExtensionResults: {
    prf: {
      results: {
        first: string | undefined; // base64url-encoded PRF output (via utils/encoders.base64UrlEncode)
      }
    }
  }
}

/**
 * Symbol for storing PRF output - completely hidden from console.log and object inspection
 * This ensures PRF data doesn't accidentally leak in logs while still being accessible programmatically
 */
const PRF_OUTPUT_SYMBOL = Symbol('prfOutput');

/**
 * Serialize PublicKeyCredential for worker communication with PRF handling
 *
 * ENCODING STRATEGY:
 * - All fields (including PRF output) → base64url (via utils/encoders.base64UrlEncode) for WASM compatibility
 *
 * SECURITY FEATURES:
 * - Just-in-time serialization - minimal exposure time
 * - Consistent base64url encoding for proper WASM decoding
 * - Secure against encoding/decoding failures
 */
export function serializeCredentialAndCreatePRF(credential: PublicKeyCredential): WebAuthnAuthenticationCredential {
  // Extract PRF output immediately for secure transfer to worker
  let prfOutput: string | undefined;
  try {
    const extensionResults = credential.getClientExtensionResults();
    const prfOutputBuffer = extensionResults?.prf?.results?.first as ArrayBuffer;
    if (prfOutputBuffer) {
      // PRF output should use base64url encoding for consistency with WASM expectations
      prfOutput = base64UrlEncode(prfOutputBuffer);
    }
  } catch (error) {
    console.warn('[serialize]: PRF extraction failed:', error);
    throw new Error('[serialize]: PRF extraction failed. Please try again.');
  }

  return {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
      authenticatorData: base64UrlEncode((credential.response as any).authenticatorData),
      signature: base64UrlEncode((credential.response as any).signature),
      userHandle: (credential.response as any).userHandle ?
        base64UrlEncode((credential.response as any).userHandle) : null,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: prfOutput
        }
      }
    }
  }
}

/**
 * Serialize PublicKeyCredential for registration with PRF handling
 *
 * FOR REGISTRATION CREDENTIALS ONLY - uses AuthenticatorAttestationResponse fields
 *
 * ENCODING STRATEGY:
 * - All fields (including PRF output) → base64url (via utils/encoders.base64UrlEncode) for WASM compatibility
 *
 * SECURITY FEATURES:
 * - Just-in-time serialization - minimal exposure time
 * - Consistent base64url encoding for proper WASM decoding
 * - Secure against encoding/decoding failures
 */
export function serializeRegistrationCredentialAndCreatePRF(
  credential: PublicKeyCredential
): WebAuthnRegistrationCredential {
  // Extract PRF output immediately for secure transfer to worker
  let prfOutput: string | undefined;
  try {
    const extensionResults = credential.getClientExtensionResults();
    const prfOutputBuffer = extensionResults?.prf?.results?.first as ArrayBuffer;
    if (prfOutputBuffer) {
      // PRF output should use base64url encoding for consistency with WASM expectations
      prfOutput = base64UrlEncode(prfOutputBuffer);
    }
  } catch (error) {
    console.warn('[serialize]: Registration PRF extraction failed:', error);
    throw new Error('[serialize]: Registration PRF extraction failed. Please try again.');
  }

  // Cast to AuthenticatorAttestationResponse to access registration-specific fields
  const attestationResponse = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: base64UrlEncode(attestationResponse.clientDataJSON),
      attestationObject: base64UrlEncode(attestationResponse.attestationObject),
      transports: attestationResponse.getTransports() || [],
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: prfOutput
        }
      }
    }
  }
}


type SerializableCredential = WebAuthnAuthenticationCredential | WebAuthnRegistrationCredential;

// Removes the PRF output from the credential and returns the PRF output separately
export function takePrfOutputFromCredential(credential: SerializableCredential): ({
  credentialWithoutPrf: SerializableCredential,
  prfOutput: string
}) {
  // Access PRF through the getter (which reads from Symbol property)
  const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
  if (!prfOutput) {
    throw new Error('PRF output missing from credential.clientExtensionResults: required for secure key decryption');
  }

  // Create credential without PRF by removing the Symbol property
  const credentialWithoutPrf = {
    ...credential,
    clientExtensionResults: {
      ...credential.clientExtensionResults,
      prf: {
        ...credential.clientExtensionResults?.prf,
        results: {
          // Return undefined for first since Symbol is removed
          first: undefined
        }
      }
    }
  };

  return { credentialWithoutPrf, prfOutput };
}

// Removes the PRF output from the registration credential and returns the PRF output separately
export function takePrfOutputFromRegistrationCredential(credential: WebAuthnRegistrationCredential): ({
  credentialWithoutPrf: WebAuthnRegistrationCredential,
  prfOutput: string
}) {
  // Access PRF through the extension results
  const prfOutput = credential.clientExtensionResults?.prf?.results?.first;
  if (!prfOutput) {
    throw new Error('PRF output missing from registration credential.clientExtensionResults: required for secure key operations');
  }

  // Create credential without PRF by removing the PRF output
  const credentialWithoutPrf = {
    ...credential,
    clientExtensionResults: {
      ...credential.clientExtensionResults,
      prf: {
        ...credential.clientExtensionResults?.prf,
        results: {
          // Return undefined for first since we're removing it
          first: undefined
        }
      }
    }
  };

  return { credentialWithoutPrf, prfOutput };
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

export interface ExtractCosePublicKeyRequest extends BaseWorkerRequest {
  type: WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY;
  payload: {
    /** Base64url-encoded WebAuthn attestation object */
    attestationObjectBase64url: string;
  };
}

export interface ValidateCoseKeyRequest extends BaseWorkerRequest {
  type: WorkerRequestType.VALIDATE_COSE_KEY;
  payload: {
    /** COSE key bytes to validate */
    coseKeyBytes: number[];
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

export type WorkerRequest =
  | DeriveNearKeypairAndEncryptRequest
  | RecoverKeypairFromPasskeyRequest
  | CheckCanRegisterUserRequest
  | SignVerifyAndRegisterUserRequest
  | DecryptPrivateKeyWithPrfRequest
  | ExtractCosePublicKeyRequest
  | ValidateCoseKeyRequest
  | GenerateVrfKeypairWithPrfRequest
  | GenerateVrfChallengeWithPrfRequest
  | SignTransactionWithActionsRequest
  | SignTransferTransactionRequest
  | AddKeyWithPrfRequest
  | DeleteKeyWithPrfRequest;

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
    /// Structured SignedTransaction object with embedded borsh bytes
    signedTransaction: SignedTransaction;
    /// Pre-signed delete transaction for rollback with embedded borsh bytes
    preSignedDeleteTransaction: SignedTransaction;
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

export interface CoseKeySuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.COSE_KEY_SUCCESS;
  payload: {
    /** Extracted COSE public key bytes */
    cosePublicKeyBytes: number[];
  };
}

export interface CoseKeyFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.COSE_KEY_FAILURE;
  payload: {
    /** Error message describing the failure */
    error: string;
    /** Error code for programmatic handling */
    errorCode?: WorkerErrorCode;
    /** Additional error context */
    context?: Record<string, any>;
  };
}

export interface CoseValidationSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.COSE_VALIDATION_SUCCESS;
  payload: {
    /** Whether the COSE key is valid */
    valid: boolean;
    /** Additional validation information */
    info: {
      keyType?: string;
      algorithm?: number;
      curve?: string;
      [key: string]: any;
    };
  };
}

export interface CoseValidationFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.COSE_VALIDATION_FAILURE;
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
  | CoseKeySuccessResponse
  | CoseKeyFailureResponse
  | CoseValidationSuccessResponse
  | CoseValidationFailureResponse
  | VRFKeyPairSuccessResponse
  | VRFKeyPairFailureResponse
  | VRFChallengeSuccessResponse
  | VRFChallengeFailureResponse
  | ProgressResponse
  | CompletionResponse
  | ErrorResponse;

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

export function isCoseKeySuccess(response: WorkerResponse): response is CoseKeySuccessResponse {
  return response.type === WorkerResponseType.COSE_KEY_SUCCESS;
}

export function isCoseValidationSuccess(response: WorkerResponse): response is CoseValidationSuccessResponse {
  return response.type === WorkerResponseType.COSE_VALIDATION_SUCCESS;
}

export function isWorkerError(response: WorkerResponse): response is
  ErrorResponse |
  EncryptionFailureResponse |
  RecoverKeypairFailureResponse |
  RegistrationFailureResponse |
  SignatureFailureResponse |
  DecryptionFailureResponse |
  CoseKeyFailureResponse |
  CoseValidationFailureResponse |
  VRFKeyPairFailureResponse |
  VRFChallengeFailureResponse
{
  return [
    WorkerResponseType.ERROR,
    WorkerResponseType.DERIVE_NEAR_KEY_FAILURE,
    WorkerResponseType.RECOVER_KEYPAIR_FAILURE,
    WorkerResponseType.REGISTRATION_FAILURE,
    WorkerResponseType.SIGNATURE_FAILURE,
    WorkerResponseType.DECRYPTION_FAILURE,
    WorkerResponseType.COSE_KEY_FAILURE,
    WorkerResponseType.COSE_VALIDATION_FAILURE,
    WorkerResponseType.VRF_KEYPAIR_FAILURE,
    WorkerResponseType.VRF_CHALLENGE_FAILURE
  ].includes(response.type);
}

export function isWorkerSuccess(response: WorkerResponse): response is
  EncryptionSuccessResponse |
  RecoverKeypairSuccessResponse |
  RegistrationSuccessResponse |
  SignatureSuccessResponse |
  DecryptionSuccessResponse |
  CoseKeySuccessResponse |
  CoseValidationSuccessResponse |
  VRFKeyPairSuccessResponse |
  VRFChallengeSuccessResponse
{
  return [
    WorkerResponseType.ENCRYPTION_SUCCESS,
    WorkerResponseType.RECOVER_KEYPAIR_SUCCESS,
    WorkerResponseType.REGISTRATION_SUCCESS,
    WorkerResponseType.SIGNATURE_SUCCESS,
    WorkerResponseType.DECRYPTION_SUCCESS,
    WorkerResponseType.COSE_KEY_SUCCESS,
    WorkerResponseType.COSE_VALIDATION_SUCCESS,
    WorkerResponseType.VRF_KEYPAIR_SUCCESS,
    WorkerResponseType.VRF_CHALLENGE_SUCCESS
  ].includes(response.type);
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
    data?: any;
    error?: string;
    logs?: string[];
    /** SignedTransaction object */
    signedTransaction: SignedTransaction;
    /** Account ID for transaction signing operations */
    nearAccountId?: string;
  };
}