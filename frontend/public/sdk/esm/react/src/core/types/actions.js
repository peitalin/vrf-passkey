/**
 * Enum for all supported NEAR action types
 * Provides type safety and better developer experience
 */
var ActionType;
(function (ActionType) {
    ActionType["CreateAccount"] = "CreateAccount";
    ActionType["DeployContract"] = "DeployContract";
    ActionType["FunctionCall"] = "FunctionCall";
    ActionType["Transfer"] = "Transfer";
    ActionType["Stake"] = "Stake";
    ActionType["AddKey"] = "AddKey";
    ActionType["DeleteKey"] = "DeleteKey";
    ActionType["DeleteAccount"] = "DeleteAccount";
})(ActionType || (ActionType = {}));
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
        type: ActionType.FunctionCall,
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
        type: ActionType.Transfer,
        receiverId: params.receiverId,
        amount: params.amount
    };
}
/**
 * Create an account creation action
 */
function createAccount(params) {
    return {
        type: ActionType.CreateAccount,
        receiverId: params.receiverId
    };
}
/**
 * Create a contract deployment action
 */
function deployContract(params) {
    return {
        type: ActionType.DeployContract,
        receiverId: params.receiverId,
        code: params.code
    };
}
/**
 * Create a staking action
 */
function stake(params) {
    return {
        type: ActionType.Stake,
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
        type: ActionType.AddKey,
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
        type: ActionType.AddKey,
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
        type: ActionType.DeleteKey,
        receiverId: params.receiverId,
        publicKey: params.publicKey
    };
}
/**
 * Create a delete account action
 */
function deleteAccount(params) {
    return {
        type: ActionType.DeleteAccount,
        receiverId: params.receiverId,
        beneficiaryId: params.beneficiaryId
    };
}

export { ActionType, addFullAccessKey, addFunctionCallKey, createAccount, deleteAccount, deleteKey, deployContract, functionCall, stake, transfer };
//# sourceMappingURL=actions.js.map
