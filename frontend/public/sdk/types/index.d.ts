export { PasskeyManager } from './core/PasskeyManager';
export { DEFAULT_WAIT_STATUS } from './core/types/rpc';
export { WebAuthnManager } from './core/WebAuthnManager';
export { IndexedDBManager } from './core/IndexedDBManager';
export type { PasskeyManagerConfigs, RegistrationOptions, RegistrationResult, RegistrationSSEEvent, LoginOptions, LoginResult, LoginEvent, ActionOptions, ActionResult, ActionEvent, EventCallback, OperationHooks } from './core/types/passkeyManager';
export type { WebAuthnRegistrationWithPrf, WebAuthnAuthenticationWithPrf, } from './core/types/webauthn';
export type { UserData } from './core/types/signer-worker';
export { WorkerRequestType, WorkerResponseType } from './core/types/signer-worker';
export type { WorkerRequest, WorkerResponse as TypedWorkerResponse, DeriveNearKeypairAndEncryptRequest, DecryptPrivateKeyWithPrfRequest, SignTransactionWithActionsRequest, SignTransferTransactionRequest, EncryptionSuccessResponse, EncryptionFailureResponse, RegistrationSuccessResponse, RegistrationFailureResponse, SignatureSuccessResponse, SignatureFailureResponse, DecryptionSuccessResponse, DecryptionFailureResponse, ErrorResponse } from './core/types/signer-worker';
export { isEncryptionSuccess, isRegistrationSuccess, isSignatureSuccess, isDecryptionSuccess, isWorkerError, serializeCredentialAndCreatePRF, serializeRegistrationCredentialAndCreatePRF, takePrfOutputFromCredential, takePrfOutputFromRegistrationCredential, } from './core/types/signer-worker';
export { bufferEncode, bufferDecode } from './utils/encoders';
export * from './config';
export type { ActionArgs, FunctionCallAction, TransferAction, CreateAccountAction, DeployContractAction, StakeAction, AddKeyAction, DeleteKeyAction, DeleteAccountAction } from './core/types/actions';
export { ActionType } from './core/types/actions';
export { functionCall, transfer, createAccount, deployContract, stake, addFullAccessKey, addFunctionCallKey, deleteKey, deleteAccount } from './core/types/actions';
export type { PasskeyErrorDetails } from './core/types/errors';
//# sourceMappingURL=index.d.ts.map