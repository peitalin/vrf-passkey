'use strict';

var encoders = require('../../utils/encoders.js');
var actions = require('./actions.js');

// === WORKER MESSAGE TYPE ENUMS ===
exports.WorkerRequestType = void 0;
(function (WorkerRequestType) {
    WorkerRequestType["DERIVE_NEAR_KEYPAIR_AND_ENCRYPT"] = "DERIVE_NEAR_KEYPAIR_AND_ENCRYPT";
    WorkerRequestType["CHECK_CAN_REGISTER_USER"] = "CHECK_CAN_REGISTER_USER";
    WorkerRequestType["SIGN_VERIFY_AND_REGISTER_USER"] = "SIGN_VERIFY_AND_REGISTER_USER";
    WorkerRequestType["DECRYPT_PRIVATE_KEY_WITH_PRF"] = "DECRYPT_PRIVATE_KEY_WITH_PRF";
    // COSE operations
    WorkerRequestType["EXTRACT_COSE_PUBLIC_KEY"] = "EXTRACT_COSE_PUBLIC_KEY";
    WorkerRequestType["VALIDATE_COSE_KEY"] = "VALIDATE_COSE_KEY";
    WorkerRequestType["GENERATE_VRF_KEYPAIR_WITH_PRF"] = "GENERATE_VRF_KEYPAIR_WITH_PRF";
    WorkerRequestType["GENERATE_VRF_CHALLENGE_WITH_PRF"] = "GENERATE_VRF_CHALLENGE_WITH_PRF";
    WorkerRequestType["SIGN_TRANSACTION_WITH_ACTIONS"] = "SIGN_TRANSACTION_WITH_ACTIONS";
    WorkerRequestType["SIGN_TRANSFER_TRANSACTION"] = "SIGN_TRANSFER_TRANSACTION";
    // New action-specific functions
    WorkerRequestType["ADD_KEY_WITH_PRF"] = "ADD_KEY_WITH_PRF";
    WorkerRequestType["DELETE_KEY_WITH_PRF"] = "DELETE_KEY_WITH_PRF";
    WorkerRequestType["ROLLBACK_FAILED_REGISTRATION_WITH_PRF"] = "ROLLBACK_FAILED_REGISTRATION_WITH_PRF";
})(exports.WorkerRequestType || (exports.WorkerRequestType = {}));
exports.WorkerResponseType = void 0;
(function (WorkerResponseType) {
    WorkerResponseType["ENCRYPTION_SUCCESS"] = "ENCRYPTION_SUCCESS";
    WorkerResponseType["DERIVE_NEAR_KEY_FAILURE"] = "DERIVE_NEAR_KEY_FAILURE";
    WorkerResponseType["REGISTRATION_SUCCESS"] = "REGISTRATION_SUCCESS";
    WorkerResponseType["REGISTRATION_FAILURE"] = "REGISTRATION_FAILURE";
    WorkerResponseType["SIGNATURE_SUCCESS"] = "SIGNATURE_SUCCESS";
    WorkerResponseType["SIGNATURE_FAILURE"] = "SIGNATURE_FAILURE";
    WorkerResponseType["DECRYPTION_SUCCESS"] = "DECRYPTION_SUCCESS";
    WorkerResponseType["DECRYPTION_FAILURE"] = "DECRYPTION_FAILURE";
    WorkerResponseType["COSE_KEY_SUCCESS"] = "COSE_KEY_SUCCESS";
    WorkerResponseType["COSE_KEY_FAILURE"] = "COSE_KEY_FAILURE";
    WorkerResponseType["COSE_VALIDATION_SUCCESS"] = "COSE_VALIDATION_SUCCESS";
    WorkerResponseType["COSE_VALIDATION_FAILURE"] = "COSE_VALIDATION_FAILURE";
    WorkerResponseType["VRF_KEYPAIR_SUCCESS"] = "VRF_KEYPAIR_SUCCESS";
    WorkerResponseType["VRF_KEYPAIR_FAILURE"] = "VRF_KEYPAIR_FAILURE";
    WorkerResponseType["VRF_CHALLENGE_SUCCESS"] = "VRF_CHALLENGE_SUCCESS";
    WorkerResponseType["VRF_CHALLENGE_FAILURE"] = "VRF_CHALLENGE_FAILURE";
    WorkerResponseType["ERROR"] = "ERROR";
    WorkerResponseType["VERIFICATION_PROGRESS"] = "VERIFICATION_PROGRESS";
    WorkerResponseType["VERIFICATION_COMPLETE"] = "VERIFICATION_COMPLETE";
    WorkerResponseType["REGISTRATION_PROGRESS"] = "REGISTRATION_PROGRESS";
    WorkerResponseType["REGISTRATION_COMPLETE"] = "REGISTRATION_COMPLETE";
    WorkerResponseType["SIGNING_PROGRESS"] = "SIGNING_PROGRESS";
    WorkerResponseType["SIGNING_COMPLETE"] = "SIGNING_COMPLETE";
})(exports.WorkerResponseType || (exports.WorkerResponseType = {}));
exports.WorkerErrorCode = void 0;
(function (WorkerErrorCode) {
    WorkerErrorCode["WASM_INIT_FAILED"] = "WASM_INIT_FAILED";
    WorkerErrorCode["INVALID_REQUEST"] = "INVALID_REQUEST";
    WorkerErrorCode["TIMEOUT"] = "TIMEOUT";
    WorkerErrorCode["ENCRYPTION_FAILED"] = "ENCRYPTION_FAILED";
    WorkerErrorCode["DECRYPTION_FAILED"] = "DECRYPTION_FAILED";
    WorkerErrorCode["SIGNING_FAILED"] = "SIGNING_FAILED";
    WorkerErrorCode["COSE_EXTRACTION_FAILED"] = "COSE_EXTRACTION_FAILED";
    WorkerErrorCode["STORAGE_FAILED"] = "STORAGE_FAILED";
    WorkerErrorCode["VRF_KEYPAIR_GENERATION_FAILED"] = "VRF_KEYPAIR_GENERATION_FAILED";
    WorkerErrorCode["VRF_CHALLENGE_GENERATION_FAILED"] = "VRF_CHALLENGE_GENERATION_FAILED";
    WorkerErrorCode["VRF_ENCRYPTION_FAILED"] = "VRF_ENCRYPTION_FAILED";
    WorkerErrorCode["VRF_DECRYPTION_FAILED"] = "VRF_DECRYPTION_FAILED";
    WorkerErrorCode["UNKNOWN_ERROR"] = "UNKNOWN_ERROR";
})(exports.WorkerErrorCode || (exports.WorkerErrorCode = {}));
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
function serializeCredentialAndCreatePRF(credential) {
    // Extract PRF output immediately for secure transfer to worker
    let prfOutput;
    try {
        const extensionResults = credential.getClientExtensionResults();
        const prfOutputBuffer = extensionResults?.prf?.results?.first;
        if (prfOutputBuffer) {
            // PRF output should use base64url encoding for consistency with WASM expectations
            prfOutput = encoders.bufferEncode(prfOutputBuffer);
        }
    }
    catch (error) {
        console.warn('[serialize]: PRF extraction failed:', error);
        throw new Error('[serialize]: PRF extraction failed. Please try again.');
    }
    return {
        id: credential.id,
        rawId: encoders.bufferEncode(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        response: {
            clientDataJSON: encoders.bufferEncode(credential.response.clientDataJSON),
            authenticatorData: encoders.bufferEncode(credential.response.authenticatorData),
            signature: encoders.bufferEncode(credential.response.signature),
            userHandle: credential.response.userHandle ?
                encoders.bufferEncode(credential.response.userHandle) : null,
        },
        clientExtensionResults: {
            prf: {
                results: {
                    first: prfOutput
                }
            }
        }
    };
}
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
function serializeRegistrationCredentialAndCreatePRF(credential) {
    // Extract PRF output immediately for secure transfer to worker
    let prfOutput;
    try {
        const extensionResults = credential.getClientExtensionResults();
        const prfOutputBuffer = extensionResults?.prf?.results?.first;
        if (prfOutputBuffer) {
            // PRF output should use base64url encoding for consistency with WASM expectations
            prfOutput = encoders.bufferEncode(prfOutputBuffer);
        }
    }
    catch (error) {
        console.warn('[serialize]: Registration PRF extraction failed:', error);
        throw new Error('[serialize]: Registration PRF extraction failed. Please try again.');
    }
    // Cast to AuthenticatorAttestationResponse to access registration-specific fields
    const attestationResponse = credential.response;
    return {
        id: credential.id,
        rawId: encoders.bufferEncode(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        response: {
            clientDataJSON: encoders.bufferEncode(attestationResponse.clientDataJSON),
            attestationObject: encoders.bufferEncode(attestationResponse.attestationObject),
            transports: attestationResponse.getTransports() || [],
        },
        clientExtensionResults: {
            prf: {
                results: {
                    first: prfOutput
                }
            }
        }
    };
}
// Removes the PRF output from the credential and returns the PRF output separately
function takePrfOutputFromCredential(credential) {
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
function takePrfOutputFromRegistrationCredential(credential) {
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
// === PROGRESS MESSAGE TYPES ===
/**
 * Progress message types that can be sent from WASM to the main thread
 */
exports.ProgressMessageType = void 0;
(function (ProgressMessageType) {
    ProgressMessageType["VERIFICATION_PROGRESS"] = "VERIFICATION_PROGRESS";
    ProgressMessageType["VERIFICATION_COMPLETE"] = "VERIFICATION_COMPLETE";
    ProgressMessageType["SIGNING_PROGRESS"] = "SIGNING_PROGRESS";
    ProgressMessageType["SIGNING_COMPLETE"] = "SIGNING_COMPLETE";
    ProgressMessageType["REGISTRATION_PROGRESS"] = "REGISTRATION_PROGRESS";
    ProgressMessageType["REGISTRATION_COMPLETE"] = "REGISTRATION_COMPLETE";
})(exports.ProgressMessageType || (exports.ProgressMessageType = {}));
/**
 * Step identifiers for progress tracking
 */
exports.ProgressStep = void 0;
(function (ProgressStep) {
    ProgressStep["PREPARATION"] = "preparation";
    ProgressStep["AUTHENTICATION"] = "authentication";
    ProgressStep["CONTRACT_VERIFICATION"] = "contract_verification";
    ProgressStep["TRANSACTION_SIGNING"] = "transaction_signing";
    ProgressStep["BROADCASTING"] = "broadcasting";
    ProgressStep["VERIFICATION_COMPLETE"] = "verification_complete";
    ProgressStep["SIGNING_COMPLETE"] = "signing_complete";
})(exports.ProgressStep || (exports.ProgressStep = {}));
// === TYPE GUARDS ===
function isEncryptionSuccess(response) {
    return response.type === exports.WorkerResponseType.ENCRYPTION_SUCCESS;
}
function isRegistrationSuccess(response) {
    return response.type === exports.WorkerResponseType.REGISTRATION_SUCCESS;
}
function isSignatureSuccess(response) {
    return response.type === exports.WorkerResponseType.SIGNATURE_SUCCESS;
}
function isDecryptionSuccess(response) {
    return response.type === exports.WorkerResponseType.DECRYPTION_SUCCESS;
}
function isCoseKeySuccess(response) {
    return response.type === exports.WorkerResponseType.COSE_KEY_SUCCESS;
}
function isCoseValidationSuccess(response) {
    return response.type === exports.WorkerResponseType.COSE_VALIDATION_SUCCESS;
}
function isWorkerError(response) {
    return [
        exports.WorkerResponseType.ERROR,
        exports.WorkerResponseType.DERIVE_NEAR_KEY_FAILURE,
        exports.WorkerResponseType.REGISTRATION_FAILURE,
        exports.WorkerResponseType.SIGNATURE_FAILURE,
        exports.WorkerResponseType.DECRYPTION_FAILURE,
        exports.WorkerResponseType.COSE_KEY_FAILURE,
        exports.WorkerResponseType.COSE_VALIDATION_FAILURE,
        exports.WorkerResponseType.VRF_KEYPAIR_FAILURE,
        exports.WorkerResponseType.VRF_CHALLENGE_FAILURE
    ].includes(response.type);
}
// === ACTION TYPE VALIDATION ===
/**
 * Validate action parameters before sending to worker
 */
function validateActionParams(actionParams) {
    switch (actionParams.actionType) {
        case actions.ActionType.FunctionCall:
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
            }
            catch {
                throw new Error('FunctionCall action args must be valid JSON string');
            }
            break;
        case actions.ActionType.Transfer:
            if (!actionParams.deposit) {
                throw new Error('deposit required for Transfer');
            }
            break;
        case actions.ActionType.CreateAccount:
            // No additional validation needed
            break;
        case actions.ActionType.DeployContract:
            if (!actionParams.code || actionParams.code.length === 0) {
                throw new Error('code required for DeployContract');
            }
            break;
        case actions.ActionType.Stake:
            if (!actionParams.stake) {
                throw new Error('stake amount required for Stake');
            }
            if (!actionParams.public_key) {
                throw new Error('public_key required for Stake');
            }
            break;
        case actions.ActionType.AddKey:
            if (!actionParams.public_key) {
                throw new Error('public_key required for AddKey');
            }
            if (!actionParams.access_key) {
                throw new Error('access_key required for AddKey');
            }
            break;
        case actions.ActionType.DeleteKey:
            if (!actionParams.public_key) {
                throw new Error('public_key required for DeleteKey');
            }
            break;
        case actions.ActionType.DeleteAccount:
            if (!actionParams.beneficiary_id) {
                throw new Error('beneficiary_id required for DeleteAccount');
            }
            break;
        default:
            throw new Error(`Unsupported action type: ${actionParams.actionType}`);
    }
}

exports.isCoseKeySuccess = isCoseKeySuccess;
exports.isCoseValidationSuccess = isCoseValidationSuccess;
exports.isDecryptionSuccess = isDecryptionSuccess;
exports.isEncryptionSuccess = isEncryptionSuccess;
exports.isRegistrationSuccess = isRegistrationSuccess;
exports.isSignatureSuccess = isSignatureSuccess;
exports.isWorkerError = isWorkerError;
exports.serializeCredentialAndCreatePRF = serializeCredentialAndCreatePRF;
exports.serializeRegistrationCredentialAndCreatePRF = serializeRegistrationCredentialAndCreatePRF;
exports.takePrfOutputFromCredential = takePrfOutputFromCredential;
exports.takePrfOutputFromRegistrationCredential = takePrfOutputFromRegistrationCredential;
exports.validateActionParams = validateActionParams;
//# sourceMappingURL=signer-worker.js.map
