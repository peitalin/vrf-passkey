'use strict';

/**
 * Enum for all supported NEAR action types
 * Provides type safety and better developer experience
 */
exports.ActionType = void 0;
(function (ActionType) {
    ActionType["CreateAccount"] = "CreateAccount";
    ActionType["DeployContract"] = "DeployContract";
    ActionType["FunctionCall"] = "FunctionCall";
    ActionType["Transfer"] = "Transfer";
    ActionType["Stake"] = "Stake";
    ActionType["AddKey"] = "AddKey";
    ActionType["DeleteKey"] = "DeleteKey";
    ActionType["DeleteAccount"] = "DeleteAccount";
})(exports.ActionType || (exports.ActionType = {}));
// === HELPER FUNCTIONS FOR CREATING ACTIONS ===
/**
 * Create a function call action with sensible defaults
 *
 * @example
 * ```typescript
 * const action = functionCall({
 *   receiverId: 'contract.near',
 *   methodName: 'set_greeting',
 *   args: { message: 'Hello World!' },
 *   gas: '30000000000000',
 *   deposit: '0'
 * });
 * ```
 */
function functionCall(params) {
    return {
        type: exports.ActionType.FunctionCall,
        receiverId: params.receiverId,
        methodName: params.methodName,
        args: params.args,
        gas: params.gas || '30000000000000',
        deposit: params.deposit || '0'
    };
}
/**
 * Create a transfer action
 *
 * @example
 * ```typescript
 * const action = transfer({
 *   receiverId: 'alice.near',
 *   amount: '1000000000000000000000000' // 1 NEAR
 * });
 * ```
 */
function transfer(params) {
    return {
        type: exports.ActionType.Transfer,
        receiverId: params.receiverId,
        amount: params.amount
    };
}
/**
 * Create an account creation action
 */
function createAccount(params) {
    return {
        type: exports.ActionType.CreateAccount,
        receiverId: params.receiverId
    };
}
/**
 * Create a contract deployment action
 */
function deployContract(params) {
    return {
        type: exports.ActionType.DeployContract,
        receiverId: params.receiverId,
        code: params.code
    };
}
/**
 * Create a staking action
 */
function stake(params) {
    return {
        type: exports.ActionType.Stake,
        receiverId: params.receiverId,
        stake: params.stake,
        publicKey: params.publicKey
    };
}
/**
 * Create an add key action with full access
 */
function addFullAccessKey(params) {
    return {
        type: exports.ActionType.AddKey,
        receiverId: params.receiverId,
        publicKey: params.publicKey,
        accessKey: {
            permission: 'FullAccess'
        }
    };
}
/**
 * Create an add key action with function call permissions
 */
function addFunctionCallKey(params) {
    return {
        type: exports.ActionType.AddKey,
        receiverId: params.receiverId,
        publicKey: params.publicKey,
        accessKey: {
            permission: {
                FunctionCall: {
                    allowance: params.allowance,
                    receiverId: params.contractId || params.receiverId,
                    methodNames: params.methodNames || []
                }
            }
        }
    };
}
/**
 * Create a delete key action
 */
function deleteKey(params) {
    return {
        type: exports.ActionType.DeleteKey,
        receiverId: params.receiverId,
        publicKey: params.publicKey
    };
}
/**
 * Create a delete account action
 */
function deleteAccount(params) {
    return {
        type: exports.ActionType.DeleteAccount,
        receiverId: params.receiverId,
        beneficiaryId: params.beneficiaryId
    };
}

exports.addFullAccessKey = addFullAccessKey;
exports.addFunctionCallKey = addFunctionCallKey;
exports.createAccount = createAccount;
exports.deleteAccount = deleteAccount;
exports.deleteKey = deleteKey;
exports.deployContract = deployContract;
exports.functionCall = functionCall;
exports.stake = stake;
exports.transfer = transfer;
//# sourceMappingURL=actions.js.map
