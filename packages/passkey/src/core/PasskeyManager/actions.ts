import type { AccessKeyView } from '@near-js/types';
import { DEFAULT_GAS_STRING } from '../../config';
import { ActionParams } from '../types/signer-worker';
import { VerifyAndSignTransactionResult } from '../types/webauthn';
import { ActionType } from '../types/actions';
import type { ActionArgs } from '../types/actions';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { TransactionContext, BlockInfo } from '../types/rpc';
import type { PasskeyManagerContext } from './index';
import type { NearClient } from '../NearClient';
import type { VRFInputData } from '../types/vrf-worker';
import type { AccountId } from '../types/accountIds';

/**
 * Core action execution function without React dependencies
 * Handles blockchain transactions with PRF-based signing
 * Supports both single actions and batched transactions
 */
export async function executeAction(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  actionArgs: ActionArgs | ActionArgs[],
  options?: ActionOptions,
): Promise<ActionResult> {

  const { onEvent, onError, hooks, waitUntil } = options || {};

  // Normalize to array for consistent processing
  const actions = Array.isArray(actionArgs) ? actionArgs : [actionArgs];
  const isMultipleActions = actions.length > 1;

  // Run beforeCall hook
  await hooks?.beforeCall?.();

  // Emit started event
  onEvent?.({
    step: 1,
    phase: 'preparation',
    status: 'progress',
    timestamp: Date.now(),
    message: isMultipleActions
      ? `Starting batched transaction with ${actions.length} actions`
      : `Starting ${actions[0].type} action to ${actions[0].receiverId}`
  });

  try {
    // 1. Validation (use first action for account validation)
    const transactionContext = await validateActionInputs(
      context,
      nearAccountId,
      actions[0],
      { onEvent, onError, hooks, waitUntil }
    );

    // 2. VRF Authentication + Transaction Signing
    const signingResult = await verifyVrfAuthAndSignTransaction(
      context,
      nearAccountId,
      transactionContext,
      actions,
      { onEvent, onError, hooks, waitUntil }
    );

    // 3. Transaction Broadcasting
    console.log('[executeAction] Starting transaction broadcasting...');
    const actionResult = await broadcastTransaction(
      context,
      signingResult,
      { onEvent, onError, hooks, waitUntil }
    );

    console.log('[executeAction] Broadcasting completed, calling afterCall hook...', {
      hasHooks: !!hooks,
      hasAfterCall: !!hooks?.afterCall,
      actionResult
    });
    try {
      hooks?.afterCall?.(true, actionResult);
      console.log('[executeAction] afterCall hook completed successfully');
    } catch (hookError: any) {
      console.error('[executeAction] Error in afterCall hook:', hookError);
      // Don't fail the entire transaction if the hook fails
    }
    console.log('[executeAction] Returning result');
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

export async function getNonceBlockHashAndHeight({ nearClient, nearPublicKeyStr, nearAccountId }: {
  nearClient: NearClient,
  nearPublicKeyStr: string,
  nearAccountId: AccountId
}): Promise<TransactionContext> {

  // Get access key and transaction block info concurrently
  const [accessKeyInfo, txBlockInfo] = await Promise.all([
    nearClient.viewAccessKey(nearAccountId, nearPublicKeyStr) as Promise<AccessKeyView>,
    nearClient.viewBlock({ finality: 'final' }) as Promise<BlockInfo>
  ]);
  if (!accessKeyInfo || accessKeyInfo.nonce === undefined) {
    throw new Error(`Access key not found or invalid for account ${nearAccountId} with public key ${nearPublicKeyStr}. Response: ${JSON.stringify(accessKeyInfo)}`);
  }
  const nextNonce = (BigInt(accessKeyInfo.nonce) + BigInt(1)).toString();
  const txBlockHeight = txBlockInfo.header.height;
  const txBlockHash = txBlockInfo.header.hash; // Keep original base58 string

  return {
    nearPublicKeyStr,
    accessKeyInfo,
    nextNonce,
    txBlockHeight,
    txBlockHash,
  };
}

/**
 * 1. Validation - Validates inputs and prepares transaction context
 */
async function validateActionInputs(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
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

  const userData = await webAuthnManager.getUser(nearAccountId);
  // Check if user has PRF support
  const usesPrf = userData?.prfSupported === true;
  const nearPublicKeyStr = userData?.clientNearPublicKey;
  if (!nearPublicKeyStr) {
    throw new Error('Client NEAR public key not found in user data');
  }
  if (!usesPrf) {
    throw new Error('This application requires PRF support. Please use a PRF-capable authenticator.');
  }

  return getNonceBlockHashAndHeight({ nearClient, nearPublicKeyStr, nearAccountId });
}

/**
 * 2. VRF Authentication - Handles VRF challenge generation and WebAuthn authentication
 *  with the webauthn contract
 */
async function verifyVrfAuthAndSignTransaction(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  transactionContext: TransactionContext,
  actionArgs: ActionArgs[],
  options?: ActionOptions,
): Promise<VerifyAndSignTransactionResult> {

  const { onEvent, onError, hooks } = options || {};
  const { webAuthnManager } = context;

  onEvent?.({
    step: 2,
    phase: 'authentication',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Generating VRF challenge...'
  });

  // Check if VRF session is active by trying to generate a challenge
  // This will fail if VRF is not unlocked, providing implicit status check
  const vrfStatus = await webAuthnManager.checkVrfStatus();

  if (!vrfStatus.active || vrfStatus.nearAccountId !== nearAccountId) {
    throw new Error(`VRF session not active for ${nearAccountId}. Please login first. VRF status: ${JSON.stringify(vrfStatus)}`);
  }

  // Generate VRF challenge
  const vrfInputData: VRFInputData = {
    userId: nearAccountId,
    rpId: window.location.hostname,
    blockHeight: transactionContext.txBlockHeight,
    blockHash: transactionContext.txBlockHash, // Use original base58 string, not decoded bytes
    timestamp: Date.now()
  };
  // Use VRF output as WebAuthn challenge
  const vrfChallenge = await webAuthnManager.generateVrfChallenge(vrfInputData);

  onEvent?.({
    step: 2,
    phase: 'authentication',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Authenticating with VRF challenge...'
  });

  // Convert all actions to ActionParams format for batched transaction
  const actionParams: ActionParams[] = actionArgs.map(action => {
    switch (action.type) {
      case ActionType.Transfer:
        return {
          actionType: ActionType.Transfer,
          deposit: action.amount
        };

      case ActionType.FunctionCall:
        return {
          actionType: ActionType.FunctionCall,
          method_name: action.methodName,
          args: JSON.stringify(action.args),
          gas: action.gas || DEFAULT_GAS_STRING,
          deposit: action.deposit || "0"
        };

      case ActionType.AddKey:
        // Ensure access key has proper format with nonce and permission object
        const accessKey = {
          nonce: action.accessKey.nonce || 0,
          permission: action.accessKey.permission === 'FullAccess'
            ? { FullAccess: {} }
            : action.accessKey.permission // For FunctionCall permissions, pass as-is
        };
        return {
          actionType: ActionType.AddKey,
          public_key: action.publicKey,
          access_key: JSON.stringify(accessKey)
        };

      case ActionType.DeleteKey:
        return {
          actionType: ActionType.DeleteKey,
          public_key: action.publicKey
        };

      case ActionType.CreateAccount:
        return {
          actionType: ActionType.CreateAccount
        };

      case ActionType.DeleteAccount:
        return {
          actionType: ActionType.DeleteAccount,
          beneficiary_id: action.beneficiaryId
        };

      case ActionType.DeployContract:
        return {
          actionType: ActionType.DeployContract,
          code: typeof action.code === 'string' ? Array.from(new TextEncoder().encode(action.code)) : Array.from(action.code)
        };

      case ActionType.Stake:
        return {
          actionType: ActionType.Stake,
          stake: action.stake,
          public_key: action.publicKey
        };

      default:
        throw new Error(`Action type ${(action as any).type} is not supported`);
    }
  });

  // Determine receiver ID (use first action's receiver, or account if mixed)
  const receiverId = actionArgs.length === 1 ? actionArgs[0].receiverId : nearAccountId;

  // Get credential for signing
  const authenticators = await webAuthnManager.getAuthenticatorsByUser(nearAccountId);
  const credential = await webAuthnManager.touchIdPrompt.getCredentials({
    nearAccountId,
    challenge: vrfChallenge.outputAs32Bytes(),
    authenticators,
  });

  // Use the unified action-based WASM worker transaction signing
  const signingResults = await webAuthnManager.signTransactionsWithActions({
    transactions: [{
      nearAccountId: nearAccountId,
      receiverId: receiverId,
      actions: actionParams,
      nonce: transactionContext.nextNonce,
    }],
    // Common parameters
    blockHash: transactionContext.txBlockHash,
    contractId: webAuthnManager.configs.contractId,
    vrfChallenge: vrfChallenge,
    credential: credential,
    nearRpcUrl: webAuthnManager.configs.nearRpcUrl,
    // Pass through the onEvent callback for progress updates
    // Convert onProgressEvents to ActionSSEEvent by adding timestamp
    onEvent: onEvent ? (progressEvent) => {
      onEvent({
        ...progressEvent,
        timestamp: Date.now()
      } as any);
    } : undefined
  });

  // Return the first (and only) result
  return signingResults[0];
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

  // Send the transaction using NearClient
  let transactionResult;
  try {
    transactionResult = await nearClient.sendTransaction(
      signedTransaction,
      options?.waitUntil
    );
    console.log('[broadcastTransaction] Transaction result received successfully');
  } catch (error) {
    console.error('[broadcastTransaction] sendTransaction failed:', error);
    throw error;
  }

  // Extract transaction ID from NEAR FinalExecutionOutcome
  // Based on logs, the structure has transaction_outcome.id
  const transactionId = transactionResult?.transaction_outcome?.id
    || transactionResult?.transaction?.hash;

  const actionResult: ActionResult = {
    success: true,
    transactionId: transactionId,
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



