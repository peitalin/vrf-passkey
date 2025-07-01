import bs58 from 'bs58';
import { DEFAULT_GAS_STRING, RPC_NODE_URL } from '../../config.js';
import { ActionType } from '../types/actions.js';
import { DEFAULT_WAIT_STATUS } from '../types/rpc.js';

/**
 * Core action execution function without React dependencies
 * Handles blockchain transactions with PRF-based signing
 */
async function executeAction(context, nearAccountId, actionArgs, options) {
    const { onEvent, onError, hooks } = options || {};
    // Emit started event
    onEvent?.({
        step: 1,
        phase: 'preparation',
        status: 'progress',
        timestamp: Date.now(),
        message: `Starting ${actionArgs.type} action to ${actionArgs.receiverId}`
    });
    // Run beforeCall hook
    await hooks?.beforeCall?.();
    try {
        // 1. Validation
        const transactionContext = await validateActionInputs(context, nearAccountId, actionArgs, { onEvent, onError, hooks });
        // 2. VRF Authentication + Transaction Signing
        const signingResult = await verifyVrfAuthAndSignTransaction(context, nearAccountId, transactionContext, actionArgs, { onEvent, onError, hooks });
        // 3. Transaction Broadcasting
        const actionResult = await broadcastTransaction(signingResult, actionArgs, { onEvent, onError, hooks });
        hooks?.afterCall?.(true, actionResult);
        return actionResult;
    }
    catch (error) {
        console.error('[executeAction] Error during execution:', error);
        onError?.(error);
        onEvent?.({
            step: 0,
            phase: 'action-error',
            status: 'error',
            timestamp: Date.now(),
            message: `Action failed: ${error.message}`,
            error: error.message
        });
        hooks?.afterCall?.(false, error);
        return { success: false, error: error.message };
    }
}
// === HELPER FUNCTIONS ===
/**
 * 1. Validation - Validates inputs and prepares transaction context
 */
async function validateActionInputs(context, nearAccountId, actionArgs, options) {
    const { onEvent, onError, hooks } = options || {};
    const { webAuthnManager, nearRpcProvider } = context;
    try {
        // Basic validation
        if (!nearAccountId) {
            throw new Error('User not logged in or NEAR account ID not set for direct action.');
        }
        if (!actionArgs.receiverId) {
            throw new Error('Missing required parameter: receiverId');
        }
        if (actionArgs.type === ActionType.FunctionCall && (!actionArgs.methodName || actionArgs.args === undefined)) {
            throw new Error('Missing required parameters for function call: methodName or args');
        }
        if (actionArgs.type === ActionType.Transfer && !actionArgs.amount) {
            throw new Error('Missing required parameter for transfer: amount');
        }
        onEvent?.({
            step: 1,
            phase: 'preparation',
            status: 'progress',
            timestamp: Date.now(),
            message: 'Validating inputs...'
        });
        // Check if user has PRF support
        const userData = await webAuthnManager.getUser(nearAccountId);
        const usesPrf = userData?.prfSupported === true;
        const publicKeyStr = userData?.clientNearPublicKey;
        if (!usesPrf) {
            throw new Error('This application requires PRF support. Please use a PRF-capable authenticator.');
        }
        if (!publicKeyStr) {
            throw new Error('Client NEAR public key not found in user data');
        }
        // Get access key and transaction block info concurrently
        const [accessKeyInfo, transactionBlockInfo] = await Promise.all([
            nearRpcProvider.viewAccessKey(nearAccountId, publicKeyStr),
            nearRpcProvider.viewBlock({ finality: 'final' })
        ]);
        const nonce = accessKeyInfo.nonce + BigInt(1);
        const blockHashString = transactionBlockInfo.header.hash;
        const transactionBlockHashBytes = Array.from(bs58.decode(blockHashString));
        return {
            userData,
            publicKeyStr,
            accessKeyInfo,
            transactionBlockInfo,
            nonce,
            transactionBlockHashBytes
        };
    }
    catch (error) {
        const errorMsg = error.message || 'Validation failed';
        console.error('[Action Error]:', errorMsg, nearAccountId);
        onError?.(error);
        onEvent?.({
            step: 0,
            phase: 'action-error',
            status: 'error',
            timestamp: Date.now(),
            message: errorMsg,
            error: errorMsg
        });
        hooks?.afterCall?.(false, error);
        throw error;
    }
}
/**
 * 2. VRF Authentication - Handles VRF challenge generation and WebAuthn authentication
 *  with the webauthn contract
 */
async function verifyVrfAuthAndSignTransaction(context, nearAccountId, transactionContext, actionArgs, options) {
    const { onEvent, onError, hooks } = options || {};
    const { webAuthnManager, nearRpcProvider } = context;
    try {
        onEvent?.({
            step: 2,
            phase: 'authentication',
            status: 'progress',
            timestamp: Date.now(),
            message: 'Generating VRF challenge...'
        });
        console.log('[Direct Action] Using VRF authentication flow with contract verification');
        // Get managers and check if VRF session is active
        const vrfStatus = await webAuthnManager.getVrfWorkerStatus();
        if (!vrfStatus.active || vrfStatus.nearAccountId !== nearAccountId) {
            throw new Error('VRF keypair not unlocked - please login to unlock VRF session');
        }
        console.log(`VRF session active for ${nearAccountId} (${Math.round(vrfStatus.sessionDuration / 1000)}s)`);
        const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
        // Generate VRF challenge
        const vrfInputData = {
            userId: nearAccountId,
            rpId: window.location.hostname,
            blockHeight: blockInfo.header.height,
            blockHash: new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64')),
            timestamp: Date.now()
        };
        // Use VRF output as WebAuthn challenge
        const vrfChallenge = await webAuthnManager.generateVRFChallenge(vrfInputData);
        onEvent?.({
            step: 2,
            phase: 'authentication',
            status: 'progress',
            timestamp: Date.now(),
            message: 'Authenticating with VRF challenge...'
        });
        // Handle different action types
        let signingResult;
        if (actionArgs.type === ActionType.Transfer) {
            signingResult = await webAuthnManager.signTransferTransaction({
                nearAccountId: nearAccountId,
                receiverId: actionArgs.receiverId,
                depositAmount: actionArgs.amount,
                nonce: transactionContext.nonce.toString(),
                blockHashBytes: transactionContext.transactionBlockHashBytes,
                // Webauthn verification parameters
                contractId: webAuthnManager.configs.contractId,
                vrfChallenge: vrfChallenge,
            });
        }
        else if (actionArgs.type === ActionType.FunctionCall) {
            // Use the modern action-based WASM worker transaction signing for function calls
            signingResult = await webAuthnManager.signTransactionWithActions({
                nearAccountId: nearAccountId,
                receiverId: actionArgs.receiverId,
                actions: [
                    {
                        actionType: ActionType.FunctionCall,
                        method_name: actionArgs.methodName,
                        args: JSON.stringify(actionArgs.args), // Convert object to JSON string for worker
                        gas: actionArgs.gas || DEFAULT_GAS_STRING,
                        deposit: actionArgs.deposit || "0"
                    }
                ],
                nonce: transactionContext.nonce.toString(),
                blockHashBytes: transactionContext.transactionBlockHashBytes,
                // Webauthn verification parameters
                contractId: webAuthnManager.configs.contractId,
                vrfChallenge: vrfChallenge,
            });
        }
        else {
            throw new Error(`Action type ${actionArgs.type} is not yet supported`);
        }
        return signingResult;
    }
    catch (error) {
        const errorMsg = error.message || 'VRF authentication failed';
        console.error('[Action Error]:', errorMsg, nearAccountId);
        onError?.(error);
        onEvent?.({
            step: 0,
            phase: 'action-error',
            status: 'error',
            timestamp: Date.now(),
            message: errorMsg,
            error: errorMsg
        });
        hooks?.afterCall?.(false, error);
        throw error;
    }
}
/**
 * 3. Transaction Broadcasting - Broadcasts the signed transaction to NEAR network
 */
async function broadcastTransaction(signingResult, actionArgs, options) {
    const { onEvent, onError, hooks } = options || {};
    try {
        onEvent?.({
            step: 5,
            phase: 'broadcasting',
            status: 'progress',
            timestamp: Date.now(),
            message: 'Broadcasting transaction...'
        });
        // The signingResult contains Borsh-serialized SignedTransaction bytes
        const signedTransactionBorsh = new Uint8Array(signingResult.signedTransactionBorsh);
        // Send the transaction using NEAR RPC
        const rpcResponse = await fetch(RPC_NODE_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 'some_id',
                method: 'send_tx',
                params: {
                    signed_tx_base64: Buffer.from(signedTransactionBorsh).toString('base64'),
                    wait_until: DEFAULT_WAIT_STATUS.executeAction
                }
            })
        });
        const result = await rpcResponse.json();
        if (result.error) {
            const errorMessage = result.error.data?.message ||
                result.error.message ||
                'RPC error';
            throw new Error(errorMessage);
        }
        const actionResult = {
            success: true,
            transactionId: result.result?.transaction_outcome?.id,
            result: result.result
        };
        onEvent?.({
            step: 6,
            phase: 'action-complete',
            status: 'success',
            timestamp: Date.now(),
            message: 'Transaction completed successfully',
            data: {
                transactionId: actionResult.transactionId,
                result: actionResult.result
            }
        });
        return actionResult;
    }
    catch (error) {
        const errorMsg = error.message || 'Transaction broadcasting failed';
        console.error('[Action Error]:', errorMsg);
        onError?.(error);
        onEvent?.({
            step: 0,
            phase: 'action-error',
            status: 'error',
            timestamp: Date.now(),
            message: errorMsg,
            error: errorMsg
        });
        hooks?.afterCall?.(false, error);
        throw error;
    }
}

export { executeAction };
//# sourceMappingURL=actions.js.map
