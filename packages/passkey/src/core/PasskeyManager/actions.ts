import bs58 from 'bs58';
import type { AccessKeyView } from '@near-js/types';
import { TxExecutionStatus } from '@near-js/types';

import { RPC_NODE_URL, DEFAULT_GAS_STRING } from '../../config';
import { ActionParams } from '../types/signer-worker';
import { VerifyAndSignTransactionResult } from '../types/webauthn';
import { ActionType } from '../types';
import type { ActionArgs } from '../types';
import type { NearRpcCallParams } from '../types';
import type { PasskeyManager } from './index';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { ClientUserData } from '../IndexedDBManager';

// See default finality settings:
// https://github.com/near/near-api-js/blob/99f34864317725467a097dc3c7a3cc5f7a5b43d4/packages/accounts/src/account.ts#L68
// export const DEFAULT_WAIT_STATUS: TxExecutionStatus = "INCLUDED_FINAL";
export const DEFAULT_WAIT_STATUS: TxExecutionStatus = "EXECUTED_OPTIMISTIC";

interface BlockInfo {
  header: {
    hash: string;
    height: number;
  };
}

interface TransactionContext {
  userData: ClientUserData;
  publicKeyStr: string;
  accessKeyInfo: AccessKeyView;
  transactionBlockInfo: BlockInfo;
  nonce: bigint;
  transactionBlockHashBytes: number[];
}

interface RpcErrorData {
  message?: string;
}

interface RpcError {
  data?: RpcErrorData;
  message?: string;
}

interface RpcResponse {
  error?: RpcError;
  result?: any;
}

/**
 * Core action execution function without React dependencies
 * Handles blockchain transactions with PRF-based signing
 */
export async function executeAction(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<ActionResult> {

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
    const transactionContext = await validateActionInputs(
      passkeyManager,
      nearAccountId,
      actionArgs,
      { onEvent, onError, hooks }
    );

    // 2. VRF Authentication + Transaction Signing
    const signingResult = await verifyVrfAuthAndSignTransaction(
      passkeyManager,
      nearAccountId,
      transactionContext,
      actionArgs,
      { onEvent, onError, hooks }
    );

    // 3. Transaction Broadcasting
    const actionResult = await broadcastTransaction(
      signingResult,
      actionArgs,
      { onEvent, onError, hooks }
    );

    hooks?.afterCall?.(true, actionResult);
    return actionResult;

  } catch (error: any) {
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
async function validateActionInputs(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<TransactionContext> {

  const { onEvent, onError, hooks } = options || {};
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const nearRpcProvider = passkeyManager.getNearRpcProvider();

  // Basic validation
  if (!nearAccountId) {
    const errorMsg = 'User not logged in or NEAR account ID not set for direct action.';
    const error = new Error(errorMsg);
    console.error('[Direct Action] Error:', errorMsg, nearAccountId);
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

  onEvent?.({
    step: 1,
    phase: 'preparation',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Preparing transaction...'
  });

  // Check if user has PRF support
  const userData = await webAuthnManager.getUser(nearAccountId);
  const usesPrf = userData?.prfSupported === true;

  if (!usesPrf) {
    const errorMsg = 'This application requires PRF support. Please use a PRF-capable authenticator.';
    const error = new Error(errorMsg);
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

  // Get public key
  const publicKeyStr = userData?.clientNearPublicKey;
  if (!publicKeyStr) {
    const errorMsg = 'Client NEAR public key not found in user data';
    const error = new Error(errorMsg);
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

  // Get access key and transaction block info concurrently
  const [accessKeyInfo, transactionBlockInfo] = await Promise.all([
    nearRpcProvider.viewAccessKey(nearAccountId, publicKeyStr) as Promise<AccessKeyView>,
    nearRpcProvider.viewBlock({ finality: 'final' }) as Promise<BlockInfo>
  ]);

  const nonce = accessKeyInfo.nonce + BigInt(1);
  const blockHashString = transactionBlockInfo.header.hash;
  const transactionBlockHashBytes = Array.from(bs58.decode(blockHashString));

  // Validate action-specific parameters
  if (!actionArgs.receiverId) {
    const errorMsg = 'Missing required parameter: receiverId';
    const error = new Error(errorMsg);
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

  // Additional validation for function calls
  if (actionArgs.type === ActionType.FunctionCall && (!actionArgs.methodName || actionArgs.args === undefined)) {
    const errorMsg = 'Missing required parameters for function call: methodName or args';
    const error = new Error(errorMsg);
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

  // Additional validation for transfers
  if (actionArgs.type === ActionType.Transfer && !actionArgs.amount) {
    const errorMsg = 'Missing required parameter for transfer: amount';
    const error = new Error(errorMsg);
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

  return {
    userData,
    publicKeyStr,
    accessKeyInfo,
    transactionBlockInfo,
    nonce,
    transactionBlockHashBytes
  };
}

/**
 * 2. VRF Authentication - Handles VRF challenge generation and WebAuthn authentication
 *  with the webauthn contract
 */
async function verifyVrfAuthAndSignTransaction(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  transactionContext: TransactionContext,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<VerifyAndSignTransactionResult> {

  const { onEvent, onError, hooks } = options || {};
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const nearRpcProvider = passkeyManager.getNearRpcProvider();

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
    const errorMsg = 'VRF keypair not unlocked - please login to unlock VRF session';
    const error = new Error(errorMsg);
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
  console.log(`VRF session active for ${nearAccountId} (${Math.round(vrfStatus.sessionDuration! / 1000)}s)`);

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
  let signingResult: VerifyAndSignTransactionResult;

  if (actionArgs.type === ActionType.Transfer) {
    signingResult = await webAuthnManager.signTransferTransaction({
      nearAccountId: nearAccountId,
      receiverId: actionArgs.receiverId,
      depositAmount: actionArgs.amount,
      nonce: transactionContext.nonce.toString(),
      blockHashBytes: transactionContext.transactionBlockHashBytes,
      // Webauthn verification parameters
      contractId: passkeyManager.getConfig().contractId,
      vrfChallenge: vrfChallenge,
    });

  } else if (actionArgs.type === ActionType.FunctionCall) {
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
      ] as ActionParams[],
      nonce: transactionContext.nonce.toString(),
      blockHashBytes: transactionContext.transactionBlockHashBytes,
      // Webauthn verification parameters
      contractId: passkeyManager.getConfig().contractId,
      vrfChallenge: vrfChallenge,
    });

  } else {
    const errorMsg = `Action type ${actionArgs.type} is not yet supported`;
    const error = new Error(errorMsg);
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

  return signingResult;
}

/**
 * 3. Transaction Broadcasting - Broadcasts the signed transaction to NEAR network
 */
async function broadcastTransaction(
  signingResult: VerifyAndSignTransactionResult,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<ActionResult> {
  const { onEvent, onError, hooks } = options || {};

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
        wait_until: DEFAULT_WAIT_STATUS
      }
    } as NearRpcCallParams)
  });

  const result: RpcResponse = await rpcResponse.json();
  if (result.error) {
    const errorMessage = result.error.data?.message ||
                       result.error.message ||
                       'RPC error';
    const error = new Error(errorMessage);
    onError?.(error);
    onEvent?.({
      step: 0,
      phase: 'action-error',
      status: 'error',
      timestamp: Date.now(),
      message: errorMessage,
      error: errorMessage
    });
    hooks?.afterCall?.(false, error);
    throw error;
  }

  const actionResult: ActionResult = {
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



