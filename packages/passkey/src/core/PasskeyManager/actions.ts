import bs58 from 'bs58';
import type { AccessKeyView } from '@near-js/types';

import { DEFAULT_GAS_STRING } from '../../config';
import { ActionParams } from '../types/signer-worker';
import { VerifyAndSignTransactionResult } from '../types/webauthn';
import { ActionType } from '../types/actions';
import type { ActionArgs } from '../types/actions';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { TransactionContext, BlockInfo } from '../types/rpc';
import type { PasskeyManagerContext } from './index';
import { DEFAULT_WAIT_STATUS } from '../types/rpc';


/**
 * Core action execution function without React dependencies
 * Handles blockchain transactions with PRF-based signing
 */
export async function executeAction(
  context: PasskeyManagerContext,
  nearAccountId: string,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<ActionResult> {

  const { onEvent, onError, hooks, waitUntil } = options || {};

  // Run beforeCall hook
  await hooks?.beforeCall?.();

  // Emit started event
  onEvent?.({
    step: 1,
    phase: 'preparation',
    status: 'progress',
    timestamp: Date.now(),
    message: `Starting ${actionArgs.type} action to ${actionArgs.receiverId}`
  });

  try {
    // 1. Validation
    const transactionContext = await validateActionInputs(
      context,
      nearAccountId,
      actionArgs,
      { onEvent, onError, hooks, waitUntil }
    );

    // 2. VRF Authentication + Transaction Signing
    const signingResult = await verifyVrfAuthAndSignTransaction(
      context,
      nearAccountId,
      transactionContext,
      actionArgs,
      { onEvent, onError, hooks, waitUntil }
    );

    // 3. Transaction Broadcasting
    const actionResult = await broadcastTransaction(
      context,
      signingResult,
      { onEvent, onError, hooks, waitUntil }
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
  context: PasskeyManagerContext,
  nearAccountId: string,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<TransactionContext> {

  const { onEvent, onError, hooks } = options || {};
  const { webAuthnManager, nearClient } = context;
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
    nearClient.viewAccessKey(nearAccountId, publicKeyStr) as Promise<AccessKeyView>,
    nearClient.viewBlock({ finality: 'final' }) as Promise<BlockInfo>
  ]);
  const nonce = BigInt(accessKeyInfo.nonce) + BigInt(1);
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

/**
 * 2. VRF Authentication - Handles VRF challenge generation and WebAuthn authentication
 *  with the webauthn contract
 */
async function verifyVrfAuthAndSignTransaction(
  context: PasskeyManagerContext,
  nearAccountId: string,
  transactionContext: TransactionContext,
  actionArgs: ActionArgs,
  options?: ActionOptions,
): Promise<VerifyAndSignTransactionResult> {

  const { onEvent, onError, hooks } = options || {};
  const { webAuthnManager, nearClient } = context;

  onEvent?.({
    step: 2,
    phase: 'authentication',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Generating VRF challenge...'
  });

  console.log('[Direct Action] Using VRF authentication flow with contract verification');
  // Check if VRF session is active by trying to generate a challenge
  // This will fail if VRF is not unlocked, providing implicit status check
  console.log(`Using VRF authentication for ${nearAccountId}`);

  // const blockInfo = await nearClient.viewBlock({ finality: 'final' });

  // Generate VRF challenge
  const vrfInputData = {
    userId: nearAccountId,
    rpId: window.location.hostname,
    blockHeight: transactionContext.transactionBlockInfo.header.height,
    blockHashBytes: transactionContext.transactionBlockHashBytes,
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
      contractId: webAuthnManager.configs.contractId,
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
      contractId: webAuthnManager.configs.contractId,
      vrfChallenge: vrfChallenge,
    });

  } else {
    throw new Error(`Action type ${actionArgs.type} is not yet supported`);
  }

  return signingResult;
}

/**
 * 3. Transaction Broadcasting - Broadcasts the signed transaction to NEAR network
 */
export async function broadcastTransaction(
  context: PasskeyManagerContext,
  signingResult: VerifyAndSignTransactionResult,
  options?: ActionOptions,
): Promise<ActionResult> {

  const { onEvent, onError, hooks } = options || {};
  const { nearClient } = context;

  onEvent?.({
    step: 5,
    phase: 'broadcasting',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Broadcasting transaction...'
  });

  // The signingResult contains structured SignedTransaction with embedded raw bytes
  const signedTransaction = signingResult.signedTransaction;

  console.log('Broadcasting transaction with waitUntil:', options?.waitUntil);
  // Send the transaction using NearClient
  const transactionResult = await nearClient.sendTransaction(
    signedTransaction,
    options?.waitUntil
  );

  const actionResult: ActionResult = {
    success: true,
    transactionId: transactionResult?.transaction_outcome?.id,
    result: transactionResult
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



