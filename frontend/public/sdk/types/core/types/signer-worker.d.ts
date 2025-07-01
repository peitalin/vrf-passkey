import type { VRFChallenge } from "./webauthn";
import { ActionType } from "./actions";
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
export declare enum WorkerRequestType {
    DERIVE_NEAR_KEYPAIR_AND_ENCRYPT = "DERIVE_NEAR_KEYPAIR_AND_ENCRYPT",
    CHECK_CAN_REGISTER_USER = "CHECK_CAN_REGISTER_USER",
    SIGN_VERIFY_AND_REGISTER_USER = "SIGN_VERIFY_AND_REGISTER_USER",
    DECRYPT_PRIVATE_KEY_WITH_PRF = "DECRYPT_PRIVATE_KEY_WITH_PRF",
    EXTRACT_COSE_PUBLIC_KEY = "EXTRACT_COSE_PUBLIC_KEY",
    VALIDATE_COSE_KEY = "VALIDATE_COSE_KEY",
    GENERATE_VRF_KEYPAIR_WITH_PRF = "GENERATE_VRF_KEYPAIR_WITH_PRF",
    GENERATE_VRF_CHALLENGE_WITH_PRF = "GENERATE_VRF_CHALLENGE_WITH_PRF",
    SIGN_TRANSACTION_WITH_ACTIONS = "SIGN_TRANSACTION_WITH_ACTIONS",
    SIGN_TRANSFER_TRANSACTION = "SIGN_TRANSFER_TRANSACTION",
    ADD_KEY_WITH_PRF = "ADD_KEY_WITH_PRF",
    DELETE_KEY_WITH_PRF = "DELETE_KEY_WITH_PRF",
    ROLLBACK_FAILED_REGISTRATION_WITH_PRF = "ROLLBACK_FAILED_REGISTRATION_WITH_PRF"
}
export declare enum WorkerResponseType {
    ENCRYPTION_SUCCESS = "ENCRYPTION_SUCCESS",
    DERIVE_NEAR_KEY_FAILURE = "DERIVE_NEAR_KEY_FAILURE",
    REGISTRATION_SUCCESS = "REGISTRATION_SUCCESS",
    REGISTRATION_FAILURE = "REGISTRATION_FAILURE",
    SIGNATURE_SUCCESS = "SIGNATURE_SUCCESS",
    SIGNATURE_FAILURE = "SIGNATURE_FAILURE",
    DECRYPTION_SUCCESS = "DECRYPTION_SUCCESS",
    DECRYPTION_FAILURE = "DECRYPTION_FAILURE",
    COSE_KEY_SUCCESS = "COSE_KEY_SUCCESS",
    COSE_KEY_FAILURE = "COSE_KEY_FAILURE",
    COSE_VALIDATION_SUCCESS = "COSE_VALIDATION_SUCCESS",
    COSE_VALIDATION_FAILURE = "COSE_VALIDATION_FAILURE",
    VRF_KEYPAIR_SUCCESS = "VRF_KEYPAIR_SUCCESS",
    VRF_KEYPAIR_FAILURE = "VRF_KEYPAIR_FAILURE",
    VRF_CHALLENGE_SUCCESS = "VRF_CHALLENGE_SUCCESS",
    VRF_CHALLENGE_FAILURE = "VRF_CHALLENGE_FAILURE",
    ERROR = "ERROR",
    VERIFICATION_PROGRESS = "VERIFICATION_PROGRESS",
    VERIFICATION_COMPLETE = "VERIFICATION_COMPLETE",
    REGISTRATION_PROGRESS = "REGISTRATION_PROGRESS",
    REGISTRATION_COMPLETE = "REGISTRATION_COMPLETE",
    SIGNING_PROGRESS = "SIGNING_PROGRESS",
    SIGNING_COMPLETE = "SIGNING_COMPLETE"
}
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
export declare enum WorkerErrorCode {
    WASM_INIT_FAILED = "WASM_INIT_FAILED",
    INVALID_REQUEST = "INVALID_REQUEST",
    TIMEOUT = "TIMEOUT",
    ENCRYPTION_FAILED = "ENCRYPTION_FAILED",
    DECRYPTION_FAILED = "DECRYPTION_FAILED",
    SIGNING_FAILED = "SIGNING_FAILED",
    COSE_EXTRACTION_FAILED = "COSE_EXTRACTION_FAILED",
    STORAGE_FAILED = "STORAGE_FAILED",
    VRF_KEYPAIR_GENERATION_FAILED = "VRF_KEYPAIR_GENERATION_FAILED",
    VRF_CHALLENGE_GENERATION_FAILED = "VRF_CHALLENGE_GENERATION_FAILED",
    VRF_ENCRYPTION_FAILED = "VRF_ENCRYPTION_FAILED",
    VRF_DECRYPTION_FAILED = "VRF_DECRYPTION_FAILED",
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
}
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
export type ActionParams = {
    actionType: ActionType.CreateAccount;
} | {
    actionType: ActionType.DeployContract;
    code: number[];
} | {
    actionType: ActionType.FunctionCall;
    method_name: string;
    args: string;
    gas: string;
    deposit: string;
} | {
    actionType: ActionType.Transfer;
    deposit: string;
} | {
    actionType: ActionType.Stake;
    stake: string;
    public_key: string;
} | {
    actionType: ActionType.AddKey;
    public_key: string;
    access_key: string;
} | {
    actionType: ActionType.DeleteKey;
    public_key: string;
} | {
    actionType: ActionType.DeleteAccount;
    beneficiary_id: string;
};
export interface CheckCanRegisterUserRequest extends BaseWorkerRequest {
    type: WorkerRequestType.CHECK_CAN_REGISTER_USER;
    payload: {
        /** VRF challenge data for verification */
        vrfChallenge: VRFChallenge;
        /** Serialized WebAuthn registration credential */
        webauthnCredential: SerializableWebAuthnRegistrationCredential;
        /** Contract ID for verification */
        contractId: string;
        /** NEAR RPC provider URL for verification */
        nearRpcUrl: string;
    };
}
export interface SignVerifyAndRegisterUserRequest extends BaseWorkerRequest {
    type: WorkerRequestType.SIGN_VERIFY_AND_REGISTER_USER;
    payload: {
        /** VRF challenge data for verification */
        vrfChallenge: VRFChallenge;
        /** Serialized WebAuthn registration credential */
        webauthnCredential: SerializableWebAuthnRegistrationCredential;
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
export interface SerializableWebAuthnCredential {
    id: string;
    rawId: string;
    type: string;
    authenticatorAttachment: string | null;
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle: string | null;
    };
    clientExtensionResults: {
        prf: {
            results: {
                first: string | undefined;
            };
        };
    };
}
export interface SerializableWebAuthnRegistrationCredential {
    id: string;
    rawId: string;
    type: string;
    authenticatorAttachment: string | null;
    response: {
        clientDataJSON: string;
        attestationObject: string;
        transports: string[];
    };
    clientExtensionResults: {
        prf: {
            results: {
                first: string | undefined;
            };
        };
    };
}
/**
 * Serialize PublicKeyCredential for worker communication with PRF handling
 *
 * ENCODING STRATEGY:
 * - All fields (including PRF output) → base64url (via utils/encoders.bufferEncode) for WASM compatibility
 *
 * SECURITY FEATURES:
 * ✅ Just-in-time serialization - minimal exposure time
 * ✅ Consistent base64url encoding for proper WASM decoding
 * ✅ Secure against encoding/decoding failures
 */
export declare function serializeCredentialAndCreatePRF(credential: PublicKeyCredential): SerializableWebAuthnCredential;
/**
 * Serialize PublicKeyCredential for registration with PRF handling
 *
 * FOR REGISTRATION CREDENTIALS ONLY - uses AuthenticatorAttestationResponse fields
 *
 * ENCODING STRATEGY:
 * - All fields (including PRF output) → base64url (via utils/encoders.bufferEncode) for WASM compatibility
 *
 * SECURITY FEATURES:
 * ✅ Just-in-time serialization - minimal exposure time
 * ✅ Consistent base64url encoding for proper WASM decoding
 * ✅ Secure against encoding/decoding failures
 */
export declare function serializeRegistrationCredentialAndCreatePRF(credential: PublicKeyCredential): SerializableWebAuthnRegistrationCredential;
type SerializableCredential = SerializableWebAuthnCredential | SerializableWebAuthnRegistrationCredential;
export declare function takePrfOutputFromCredential(credential: SerializableCredential): ({
    credentialWithoutPrf: SerializableCredential;
    prfOutput: string;
});
export declare function takePrfOutputFromRegistrationCredential(credential: SerializableWebAuthnRegistrationCredential): ({
    credentialWithoutPrf: SerializableWebAuthnRegistrationCredential;
    prfOutput: string;
});
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
        /** Contract ID for verification */
        contractId: string;
        /** VRF challenge data for verification */
        vrfChallenge: VRFChallenge;
        /** Serialized WebAuthn credential (PRF extracted in worker for security) */
        webauthnCredential: SerializableWebAuthnCredential;
        /** NEAR RPC provider URL for verification */
        nearRpcUrl: string;
    };
}
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
        /** Contract ID for verification */
        contractId: string;
        /** VRF challenge data for verification */
        vrfChallenge: VRFChallenge;
        /** Serialized WebAuthn credential (PRF extracted in worker for security) */
        webauthnCredential: SerializableWebAuthnCredential;
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
        webauthnCredential: SerializableWebAuthnCredential;
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
        webauthnCredential: SerializableWebAuthnCredential;
        /** NEAR RPC provider URL for verification */
        nearRpcUrl: string;
    };
}
export interface RollbackFailedRegistrationWithPrfRequest extends BaseWorkerRequest {
    type: WorkerRequestType.ROLLBACK_FAILED_REGISTRATION_WITH_PRF;
    payload: {
        /** Base64-encoded PRF output from WebAuthn */
        prfOutput: string;
        /** Encrypted private key data */
        encryptedPrivateKeyData: string;
        /** Encrypted private key IV */
        encryptedPrivateKeyIv: string;
        /** Signer account ID (account to delete) */
        signerAccountId: string;
        /** Beneficiary account ID (where remaining balance goes) */
        beneficiaryAccountId: string;
        /** Transaction nonce as string */
        nonce: string;
        /** Block hash bytes for the transaction */
        blockHashBytes: number[];
        /** Contract ID for verification */
        contractId: string;
        /** VRF challenge data for verification */
        vrfChallenge: VRFChallenge;
        /** Serialized WebAuthn credential */
        webauthnCredential: SerializableWebAuthnCredential;
        /** NEAR RPC provider URL for verification */
        nearRpcUrl: string;
        /** SECURITY: Name of the calling function for validation */
        callerFunction: string;
    };
}
export type WorkerRequest = DeriveNearKeypairAndEncryptRequest | CheckCanRegisterUserRequest | SignVerifyAndRegisterUserRequest | DecryptPrivateKeyWithPrfRequest | ExtractCosePublicKeyRequest | ValidateCoseKeyRequest | GenerateVrfKeypairWithPrfRequest | GenerateVrfChallengeWithPrfRequest | SignTransactionWithActionsRequest | SignTransferTransactionRequest | AddKeyWithPrfRequest | DeleteKeyWithPrfRequest | RollbackFailedRegistrationWithPrfRequest;
/**
 * Progress message types that can be sent from WASM to the main thread
 */
export declare enum ProgressMessageType {
    VERIFICATION_PROGRESS = "VERIFICATION_PROGRESS",
    VERIFICATION_COMPLETE = "VERIFICATION_COMPLETE",
    SIGNING_PROGRESS = "SIGNING_PROGRESS",
    SIGNING_COMPLETE = "SIGNING_COMPLETE",
    REGISTRATION_PROGRESS = "REGISTRATION_PROGRESS",
    REGISTRATION_COMPLETE = "REGISTRATION_COMPLETE"
}
/**
 * Step identifiers for progress tracking
 */
export declare enum ProgressStep {
    PREPARATION = "preparation",
    AUTHENTICATION = "authentication",
    CONTRACT_VERIFICATION = "contract_verification",
    TRANSACTION_SIGNING = "transaction_signing",
    BROADCASTING = "broadcasting",
    VERIFICATION_COMPLETE = "verification_complete",
    SIGNING_COMPLETE = "signing_complete"
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
    payload: any;
}
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
export interface RegistrationSuccessResponse extends BaseWorkerResponse {
    type: WorkerResponseType.REGISTRATION_SUCCESS;
    payload: {
        /** Whether the registration was verified */
        verified: boolean;
        /** Registration information from the contract */
        registrationInfo?: {
            credential_id: number[];
            credential_public_key: number[];
            user_id: string;
            vrf_public_key?: number[];
        };
        /** Contract logs from the registration verification */
        logs?: string[];
        /** Signed transaction bytes for state-changing registrations */
        signedTransactionBorsh?: number[];
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
export type WorkerResponse = EncryptionSuccessResponse | EncryptionFailureResponse | RegistrationSuccessResponse | RegistrationFailureResponse | SignatureSuccessResponse | SignatureFailureResponse | DecryptionSuccessResponse | DecryptionFailureResponse | CoseKeySuccessResponse | CoseKeyFailureResponse | CoseValidationSuccessResponse | CoseValidationFailureResponse | VRFKeyPairSuccessResponse | VRFKeyPairFailureResponse | VRFChallengeSuccessResponse | VRFChallengeFailureResponse | ProgressResponse | CompletionResponse | ErrorResponse;
export declare function isEncryptionSuccess(response: WorkerResponse): response is EncryptionSuccessResponse;
export declare function isRegistrationSuccess(response: WorkerResponse): response is RegistrationSuccessResponse;
export declare function isSignatureSuccess(response: WorkerResponse): response is SignatureSuccessResponse;
export declare function isDecryptionSuccess(response: WorkerResponse): response is DecryptionSuccessResponse;
export declare function isCoseKeySuccess(response: WorkerResponse): response is CoseKeySuccessResponse;
export declare function isCoseValidationSuccess(response: WorkerResponse): response is CoseValidationSuccessResponse;
export declare function isWorkerError(response: WorkerResponse): response is ErrorResponse | EncryptionFailureResponse | RegistrationFailureResponse | SignatureFailureResponse | DecryptionFailureResponse | CoseKeyFailureResponse | CoseValidationFailureResponse | VRFKeyPairFailureResponse | VRFChallengeFailureResponse;
export declare function isWorkerSuccess(response: WorkerResponse): response is EncryptionSuccessResponse | RegistrationSuccessResponse | SignatureSuccessResponse | DecryptionSuccessResponse | CoseKeySuccessResponse | CoseValidationSuccessResponse | VRFKeyPairSuccessResponse | VRFChallengeSuccessResponse;
/**
 * Validate action parameters before sending to worker
 */
export declare function validateActionParams(actionParams: ActionParams): void;
export interface ProgressResponse {
    type: WorkerResponseType.VERIFICATION_PROGRESS | WorkerResponseType.SIGNING_PROGRESS | WorkerResponseType.REGISTRATION_PROGRESS;
    payload: {
        step: string;
        message: string;
        logs?: string[];
        data?: any;
    };
}
export interface CompletionResponse {
    type: WorkerResponseType.VERIFICATION_COMPLETE | WorkerResponseType.SIGNING_COMPLETE | WorkerResponseType.REGISTRATION_COMPLETE;
    payload: {
        success: boolean;
        data?: any;
        error?: string;
        logs?: string[];
    };
}
export {};
//# sourceMappingURL=signer-worker.d.ts.map