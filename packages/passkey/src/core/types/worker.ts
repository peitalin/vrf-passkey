// === WORKER MESSAGE TYPE ENUMS ===

export enum WorkerRequestType {
  ENCRYPT_PRIVATE_KEY_WITH_PRF = 'ENCRYPT_PRIVATE_KEY_WITH_PRF',
  DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF = 'DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF',
  DECRYPT_PRIVATE_KEY_WITH_PRF = 'DECRYPT_PRIVATE_KEY_WITH_PRF',
}

export enum WorkerResponseType {
  ENCRYPTION_SUCCESS = 'ENCRYPTION_SUCCESS',
  ENCRYPTION_FAILURE = 'ENCRYPTION_FAILURE',
  SIGNATURE_SUCCESS = 'SIGNATURE_SUCCESS',
  SIGNATURE_FAILURE = 'SIGNATURE_FAILURE',
  DECRYPTION_SUCCESS = 'DECRYPTION_SUCCESS',
  DECRYPTION_FAILURE = 'DECRYPTION_FAILURE',
  ERROR = 'ERROR',
}

// === REQUEST MESSAGE INTERFACES ===

export interface BaseWorkerRequest {
  type: WorkerRequestType;
}

export interface EncryptPrivateKeyWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF;
  payload: {
    prfOutput: string; // Base64-encoded PRF output
    nearAccountId: string;
  };
}

export interface DecryptAndSignTransactionWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF;
  payload: {
    nearAccountId: string;
    prfOutput: string; // Base64-encoded PRF output
    receiverId: string;
    contractMethodName: string;
    contractArgs: Record<string, any>;
    gasAmount: string;
    depositAmount: string;
    nonce: string;
    blockHashBytes: number[];
  };
}

export interface DecryptPrivateKeyWithPrfRequest extends BaseWorkerRequest {
  type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF;
  payload: {
    nearAccountId: string;
    prfOutput: string; // Base64-encoded PRF output
  };
}

export type WorkerRequest =
  | EncryptPrivateKeyWithPrfRequest
  | DecryptAndSignTransactionWithPrfRequest
  | DecryptPrivateKeyWithPrfRequest;

// === RESPONSE MESSAGE INTERFACES ===

export interface BaseWorkerResponse {
  type: WorkerResponseType;
  payload: Record<string, any>;
}

export interface EncryptionSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.ENCRYPTION_SUCCESS;
  payload: {
    nearAccountId: string;
    publicKey: string;
    stored: boolean;
  };
}

export interface EncryptionFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.ENCRYPTION_FAILURE;
  payload: {
    error: string;
  };
}

export interface SignatureSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.SIGNATURE_SUCCESS;
  payload: {
    signedTransactionBorsh: number[];
    nearAccountId: string;
  };
}

export interface SignatureFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.SIGNATURE_FAILURE;
  payload: {
    error: string;
  };
}

export interface DecryptionSuccessResponse extends BaseWorkerResponse {
  type: WorkerResponseType.DECRYPTION_SUCCESS;
  payload: {
    decryptedPrivateKey: string;
    nearAccountId: string;
  };
}

export interface DecryptionFailureResponse extends BaseWorkerResponse {
  type: WorkerResponseType.DECRYPTION_FAILURE;
  payload: {
    error: string;
  };
}

export interface ErrorResponse extends BaseWorkerResponse {
  type: WorkerResponseType.ERROR;
  payload: {
    error: string;
  };
}

export type WorkerResponse =
  | EncryptionSuccessResponse
  | EncryptionFailureResponse
  | SignatureSuccessResponse
  | SignatureFailureResponse
  | DecryptionSuccessResponse
  | DecryptionFailureResponse
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

export function isWorkerError(response: WorkerResponse): response is ErrorResponse | EncryptionFailureResponse | SignatureFailureResponse | DecryptionFailureResponse {
  return [
    WorkerResponseType.ERROR,
    WorkerResponseType.ENCRYPTION_FAILURE,
    WorkerResponseType.SIGNATURE_FAILURE,
    WorkerResponseType.DECRYPTION_FAILURE
  ].includes(response.type);
}