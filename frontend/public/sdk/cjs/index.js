'use strict';

var index = require('./core/PasskeyManager/index.js');
var rpc = require('./core/types/rpc.js');
var index$1 = require('./core/WebAuthnManager/index.js');
var index$2 = require('./core/IndexedDBManager/index.js');
var signerWorker = require('./core/types/signer-worker.js');
var encoders = require('./utils/encoders.js');
var config = require('./config.js');
var actions = require('./core/types/actions.js');



exports.PasskeyManager = index.PasskeyManager;
exports.DEFAULT_WAIT_STATUS = rpc.DEFAULT_WAIT_STATUS;
exports.WebAuthnManager = index$1.WebAuthnManager;
exports.IndexedDBManager = index$2.IndexedDBManager;
Object.defineProperty(exports, "WorkerRequestType", {
	enumerable: true,
	get: function () { return signerWorker.WorkerRequestType; }
});
Object.defineProperty(exports, "WorkerResponseType", {
	enumerable: true,
	get: function () { return signerWorker.WorkerResponseType; }
});
exports.isDecryptionSuccess = signerWorker.isDecryptionSuccess;
exports.isEncryptionSuccess = signerWorker.isEncryptionSuccess;
exports.isRegistrationSuccess = signerWorker.isRegistrationSuccess;
exports.isSignatureSuccess = signerWorker.isSignatureSuccess;
exports.isWorkerError = signerWorker.isWorkerError;
exports.serializeCredentialAndCreatePRF = signerWorker.serializeCredentialAndCreatePRF;
exports.serializeRegistrationCredentialAndCreatePRF = signerWorker.serializeRegistrationCredentialAndCreatePRF;
exports.takePrfOutputFromCredential = signerWorker.takePrfOutputFromCredential;
exports.takePrfOutputFromRegistrationCredential = signerWorker.takePrfOutputFromRegistrationCredential;
exports.bufferDecode = encoders.bufferDecode;
exports.bufferEncode = encoders.bufferEncode;
exports.DEFAULT_GAS_STRING = config.DEFAULT_GAS_STRING;
exports.GENERATE_AUTHENTICATION_OPTIONS_GAS_STRING = config.GENERATE_AUTHENTICATION_OPTIONS_GAS_STRING;
exports.NEAR_EXPLORER_BASE_URL = config.NEAR_EXPLORER_BASE_URL;
exports.RELAYER_ACCOUNT_ID = config.RELAYER_ACCOUNT_ID;
exports.RPC_NODE_URL = config.RPC_NODE_URL;
exports.VERIFY_AUTHENTICATION_RESPONSE_GAS_STRING = config.VERIFY_AUTHENTICATION_RESPONSE_GAS_STRING;
exports.VIEW_GAS_STRING = config.VIEW_GAS_STRING;
exports.WEBAUTHN_CONTRACT_ID = config.WEBAUTHN_CONTRACT_ID;
Object.defineProperty(exports, "ActionType", {
	enumerable: true,
	get: function () { return actions.ActionType; }
});
exports.addFullAccessKey = actions.addFullAccessKey;
exports.addFunctionCallKey = actions.addFunctionCallKey;
exports.createAccount = actions.createAccount;
exports.deleteAccount = actions.deleteAccount;
exports.deleteKey = actions.deleteKey;
exports.deployContract = actions.deployContract;
exports.functionCall = actions.functionCall;
exports.stake = actions.stake;
exports.transfer = actions.transfer;
//# sourceMappingURL=index.js.map
