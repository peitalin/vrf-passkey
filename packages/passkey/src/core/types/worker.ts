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
  vrfCredentials?: {
    encrypted_vrf_data_b64u: string;
    aes_gcm_nonce_b64u: string;
  };
}

// === CONTRACT & NETWORK CALL TYPES ===

export interface ContractCallOptions {
  contractId: string;
  methodName: string;
  args: any;
  gas?: string;
  attachedDeposit?: string;
  nearAccountId?: string;
  prfOutput?: ArrayBuffer;
  viewOnly?: boolean;
  requiresAuth?: boolean;
}

export interface NetworkAuthenticationOptions {
  nearAccountId: string;
  receiverId: string;
  contractMethodName: string;
  contractArgs: Record<string, any>;
  gasAmount: string;
  depositAmount: string;
}

export interface AccessKeyView {
  nonce: bigint;
  permission: 'FullAccess' | { FunctionCall: any };
}

// === PAYLOAD TYPES FOR DIFFERENT OPERATIONS ===

export interface RegistrationPayload {
  nearAccountId: string;
}

export interface SigningPayload {
  nearAccountId: string;
  receiverId: string;
  contractMethodName: string;
  contractArgs: Record<string, any>;
  gasAmount: string;
  depositAmount: string;
  nonce: string;
  blockHashBytes: number[];
}

// === WORKER MESSAGE TYPE ENUMS ===

export enum WorkerRequestType {
  ENCRYPT_PRIVATE_KEY_WITH_PRF = 'ENCRYPT_PRIVATE_KEY_WITH_PRF',
  DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF = 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF',
  DECRYPT_PRIVATE_KEY_WITH_PRF = 'DECRYPT_PRIVATE_KEY_WITH_PRF',
  EXTRACT_COSE_PUBLIC_KEY = 'EXTRACT_COSE_PUBLIC_KEY',
  VALIDATE_COSE_KEY = 'VALIDATE_COSE_KEY',
  GENERATE_VRF_KEYPAIR_WITH_PRF = 'GENERATE_VRF_KEYPAIR_WITH_PRF',
  GENERATE_VRF_CHALLENGE_WITH_PRF = 'GENERATE_VRF_CHALLENGE_WITH_PRF',
  SIGN_TRANSACTION_WITH_ACTIONS = 'SIGN_TRANSACTION_WITH_ACTIONS',
  SIGN_TRANSFER_TRANSACTION = 'SIGN_TRANSFER_TRANSACTION',
}

export enum WorkerResponseType {
  ENCRYPTION_SUCCESS = 'ENCRYPTION_SUCCESS',
  ENCRYPTION_FAILURE = 'ENCRYPTION_FAILURE',
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

export interface EncryptPrivateKeyWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF;
  payload: {
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** NEAR account ID to associate with the encrypted key */
    nearAccountId: string;
  };
}

// === ACTION TYPES ===

export enum ActionType {
  CreateAccount = "CreateAccount",
  DeployContract = "DeployContract",
  FunctionCall = "FunctionCall",
  Transfer = "Transfer",
  Stake = "Stake",
  AddKey = "AddKey",
  DeleteKey = "DeleteKey",
  DeleteAccount = "DeleteAccount",
}

export interface ActionParams {
  actionType: ActionType;
  // Union type for all action-specific parameters
  functionCall?: {
    methodName: string;
    args: Record<string, any>;
    gas: string;
    deposit: string;
  };
  transfer?: {
    deposit: string;
  };
  createAccount?: {};
  deployContract?: {
    code: number[]; // WASM bytecode
  };
  stake?: {
    stake: string;
    publicKey: string;
  };
  addKey?: {
    publicKey: string;
    accessKey: any; // AccessKey object
  };
  deleteKey?: {
    publicKey: string;
  };
  deleteAccount?: {
    beneficiaryId: string;
  };
}

// Legacy request (for backward compatibility during transition)
export interface DecryptAndSignTransactionWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF;
  payload: {
    /** NEAR account ID whose key should be used for signing */
    nearAccountId: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Contract to call */
    receiverId: string;
    /** Method name on the contract */
    contractMethodName: string;
    /** Arguments to pass to the contract method */
    contractArgs: Record<string, any>;
    /** Gas amount in string format */
    gasAmount: string;
    /** Deposit amount in string format */
    depositAmount: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];
  };
}

// New multi-action request
export interface SignTransactionWithActionsRequest extends BaseWorkerRequest {
  type: WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS;
  payload: {
    /** NEAR account ID whose key should be used for signing */
    nearAccountId: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Receiver account ID */
    receiverId: string;
    /** Array of actions to include in the transaction */
    actions: ActionParams[];
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];
  };
}

// Convenience request for Transfer transactions
export interface SignTransferTransactionRequest extends BaseWorkerRequest {
  type: WorkerRequestType.SIGN_TRANSFER_TRANSACTION;
  payload: {
    /** NEAR account ID whose key should be used for signing */
    nearAccountId: string;
    /** Base64-encoded PRF output from WebAuthn */
    prfOutput: string;
    /** Receiver account ID */
    receiverId: string;
    /** Deposit amount in string format */
    depositAmount: string;
    /** Transaction nonce as string */
    nonce: string;
    /** Block hash bytes for the transaction */
    blockHashBytes: number[];
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
    encryptedVrfData: string;
    /** Base64url-encoded AES-GCM nonce for VRF decryption */
    encryptedVrfNonce: string;
    /** User ID for VRF input construction */
    userId: string;
    /** Relying Party ID for VRF input construction */
    rpId: string;
    /** Session ID for VRF input construction */
    sessionId: string;
    /** Block height from NEAR blockchain */
    blockHeight: number;
    /** Block hash bytes from NEAR blockchain */
    blockHashBytes: number[];
    /** Timestamp for VRF input construction */
    timestamp: number;
  };
}

export type WorkerRequest =
  | EncryptPrivateKeyWithPrfRequest
  | DecryptAndSignTransactionWithPrfRequest
  | DecryptPrivateKeyWithPrfRequest
  | ExtractCosePublicKeyRequest
  | ValidateCoseKeyRequest
  | GenerateVrfKeypairWithPrfRequest
  | GenerateVrfChallengeWithPrfRequest
  | SignTransactionWithActionsRequest
  | SignTransferTransactionRequest;

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
  type: WorkerResponseType.ENCRYPTION_FAILURE;
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
    /** Signed transaction in Borsh format */
    signedTransactionBorsh: number[];
    /** NEAR account ID that signed the transaction */
    nearAccountId: string;
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
  | ErrorResponse;

// === TYPE GUARDS ===

export function isEncryptionSuccess(response: WorkerResponse): response is EncryptionSuccessResponse {
  return response.type === WorkerResponseType.ENCRYPTION_SUCCESS;
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

export function isVRFKeyPairSuccess(response: WorkerResponse): response is VRFKeyPairSuccessResponse {
  return response.type === WorkerResponseType.VRF_KEYPAIR_SUCCESS;
}

export function isVRFChallengeSuccess(response: WorkerResponse): response is VRFChallengeSuccessResponse {
  return response.type === WorkerResponseType.VRF_CHALLENGE_SUCCESS;
}

export function isWorkerError(response: WorkerResponse): response is ErrorResponse | EncryptionFailureResponse | SignatureFailureResponse | DecryptionFailureResponse | CoseKeyFailureResponse | CoseValidationFailureResponse | VRFKeyPairFailureResponse | VRFChallengeFailureResponse {
  return [
    WorkerResponseType.ERROR,
    WorkerResponseType.ENCRYPTION_FAILURE,
    WorkerResponseType.SIGNATURE_FAILURE,
    WorkerResponseType.DECRYPTION_FAILURE,
    WorkerResponseType.COSE_KEY_FAILURE,
    WorkerResponseType.COSE_VALIDATION_FAILURE,
    WorkerResponseType.VRF_KEYPAIR_FAILURE,
    WorkerResponseType.VRF_CHALLENGE_FAILURE
  ].includes(response.type);
}

export function isWorkerSuccess(response: WorkerResponse): response is EncryptionSuccessResponse | SignatureSuccessResponse | DecryptionSuccessResponse | CoseKeySuccessResponse | CoseValidationSuccessResponse | VRFKeyPairSuccessResponse | VRFChallengeSuccessResponse {
  return [
    WorkerResponseType.ENCRYPTION_SUCCESS,
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
      if (!actionParams.functionCall?.methodName) {
        throw new Error('methodName required for FunctionCall');
      }
      if (!actionParams.functionCall?.args) {
        throw new Error('args required for FunctionCall');
      }
      if (!actionParams.functionCall?.gas) {
        throw new Error('gas required for FunctionCall');
      }
      if (!actionParams.functionCall?.deposit) {
        throw new Error('deposit required for FunctionCall');
      }
      break;
    case ActionType.Transfer:
      if (!actionParams.transfer?.deposit) {
        throw new Error('deposit required for Transfer');
      }
      break;
    case ActionType.CreateAccount:
      // No additional validation needed
      break;
    case ActionType.DeployContract:
      if (!actionParams.deployContract?.code || actionParams.deployContract.code.length === 0) {
        throw new Error('code required for DeployContract');
      }
      break;
    case ActionType.Stake:
      if (!actionParams.stake?.stake) {
        throw new Error('stake amount required for Stake');
      }
      if (!actionParams.stake?.publicKey) {
        throw new Error('publicKey required for Stake');
      }
      break;
    case ActionType.AddKey:
      if (!actionParams.addKey?.publicKey) {
        throw new Error('publicKey required for AddKey');
      }
      if (!actionParams.addKey?.accessKey) {
        throw new Error('accessKey required for AddKey');
      }
      break;
    case ActionType.DeleteKey:
      if (!actionParams.deleteKey?.publicKey) {
        throw new Error('publicKey required for DeleteKey');
      }
      break;
    case ActionType.DeleteAccount:
      if (!actionParams.deleteAccount?.beneficiaryId) {
        throw new Error('beneficiaryId required for DeleteAccount');
      }
      break;
    default:
      throw new Error(`Unsupported action type: ${actionParams.actionType}`);
  }
}

/**
 * Check if a worker request is for action-based signing
 */
export function isActionBasedSigningRequest(request: WorkerRequest): request is SignTransactionWithActionsRequest | SignTransferTransactionRequest {
  return request.type === WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS ||
         request.type === WorkerRequestType.SIGN_TRANSFER_TRANSACTION;
}

/**
 * Check if a worker request is a multi-action signing request
 */
export function isMultiActionSigningRequest(request: WorkerRequest): request is SignTransactionWithActionsRequest {
  return request.type === WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS;
}

/**
 * Check if a worker request is a transfer transaction signing request
 */
export function isTransferSigningRequest(request: WorkerRequest): request is SignTransferTransactionRequest {
  return request.type === WorkerRequestType.SIGN_TRANSFER_TRANSACTION;
}

// === UTILITY FUNCTIONS ===

/**
 * Create a standardized worker error response
 */
export function createWorkerErrorResponse(
  error: string,
  errorCode: WorkerErrorCode = WorkerErrorCode.UNKNOWN_ERROR,
  context?: Record<string, any>
): ErrorResponse {
  return {
    type: WorkerResponseType.ERROR,
    payload: {
      error,
      errorCode,
      context
    },
    timestamp: Date.now()
  };
}

/**
 * Extract error details from a worker response
 */
export function extractWorkerError(response: WorkerResponse): WorkerErrorDetails | null {
  if (!isWorkerError(response)) {
    return null;
  }

  const errorCode = response.payload.errorCode || WorkerErrorCode.UNKNOWN_ERROR;
  const message = response.payload.error || 'Unknown worker error';

  // Determine operation type from response type
  let operation: WorkerRequestType;
  switch (response.type) {
    case WorkerResponseType.ENCRYPTION_FAILURE:
      operation = WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF;
      break;
    case WorkerResponseType.SIGNATURE_FAILURE:
      operation = WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF;
      break;
    case WorkerResponseType.DECRYPTION_FAILURE:
      operation = WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF;
      break;
    case WorkerResponseType.COSE_KEY_FAILURE:
      operation = WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY;
      break;
    case WorkerResponseType.COSE_VALIDATION_FAILURE:
      operation = WorkerRequestType.VALIDATE_COSE_KEY;
      break;
    case WorkerResponseType.VRF_KEYPAIR_FAILURE:
      operation = WorkerRequestType.GENERATE_VRF_KEYPAIR_WITH_PRF;
      break;
    case WorkerResponseType.VRF_CHALLENGE_FAILURE:
      operation = WorkerRequestType.GENERATE_VRF_CHALLENGE_WITH_PRF;
      break;
    default:
      operation = WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF; // fallback
  }

  return {
    code: errorCode,
    message,
    operation,
    timestamp: response.timestamp || Date.now(),
    context: response.payload.context
  };
}