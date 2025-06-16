import bs58 from 'bs58';
import type { AccessKeyView } from '@near-js/types';

import { RPC_NODE_URL, DEFAULT_GAS_STRING } from '../../config';
import type { SerializableActionArgs } from '../../types';
import {
  determineOperationMode,
  validateModeRequirements,
  getModeDescription
} from '../utils/routing';
import type { PasskeyManager } from './index';
import type { ActionOptions, ActionResult } from './types';

interface BlockInfo {
  header: {
    hash: string;
  };
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
  actionArgs: SerializableActionArgs,
  options?: ActionOptions
): Promise<ActionResult> {
  const { optimisticAuth = true, onEvent, onError, hooks } = options || {};
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const config = passkeyManager.getConfig();
  const nearRpcProvider = passkeyManager['nearRpcProvider']; // Access private property

  // Client-side routing logic using routing utilities
  const routing = determineOperationMode({
    optimisticAuth,
    config,
    operation: 'action'
  });

  // Validate mode requirements
  const validation = validateModeRequirements(routing, nearRpcProvider, 'action');
  if (!validation.valid) {
    const error = new Error(validation.error!);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: validation.error!,
        actionType: actionArgs.method_name || 'unknown'
      }
    });
    hooks?.afterCall?.(false, error);
    return { success: false, error: validation.error! };
  }

  // Log the determined mode
  console.log(`Action: ${getModeDescription(routing)}`);

  // Emit started event
  onEvent?.({
    type: 'actionStarted',
    data: {
      actionType: actionArgs.method_name || 'unknown',
      receiverId: actionArgs.receiver_id || 'unknown'
    }
  });

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validation
    if (!nearAccountId) {
      const errorMsg = 'User not logged in or NEAR account ID not set for direct action.';
      const error = new Error(errorMsg);
      console.error('[Direct Action] Error:', errorMsg, nearAccountId);
      onError?.(error);
      onEvent?.({
        type: 'actionFailed',
        data: {
          error: errorMsg,
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    onEvent?.({
      type: 'actionProgress',
      data: {
        step: 'preparing',
        message: 'Preparing transaction...'
      }
    });

    // Check if user has PRF support
    const userData = await webAuthnManager.getUserData(nearAccountId);
    const usesPrf = userData?.prfSupported === true;

    if (!usesPrf) {
      const errorMsg = 'This application requires PRF support. Please use a PRF-capable authenticator.';
      const error = new Error(errorMsg);
      onError?.(error);
      onEvent?.({
        type: 'actionFailed',
        data: {
          error: errorMsg,
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    // Step 1: Authenticate with PRF to get PRF output
    onEvent?.({
      type: 'actionProgress',
      data: {
        step: 'authenticating',
        message: 'Authenticating with passkey...'
      }
    });

    const { credential: passkeyAssertion, prfOutput } = await webAuthnManager.authenticateWithPrfAndUrl(
      routing.serverUrl,
      nearAccountId,
      'signing'
    );

    if (!passkeyAssertion || !prfOutput) {
      const errorMsg = 'PRF authentication failed or no PRF output';
      const error = new Error(errorMsg);
      onError?.(error);
      onEvent?.({
        type: 'actionFailed',
        data: {
          error: errorMsg,
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    console.log('[Direct Action] PRF authentication successful, starting concurrent operations...');

    // Get public key
    const publicKeyStr = userData?.clientNearPublicKey;
    if (!publicKeyStr) {
      const errorMsg = 'Client NEAR public key not found in user data';
      const error = new Error(errorMsg);
      onError?.(error);
      onEvent?.({
        type: 'actionFailed',
        data: {
          error: errorMsg,
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    // Run operations concurrently for better performance
    const [
      accessKeyInfo,
      blockInfo
    ] = await Promise.all([
      nearRpcProvider.viewAccessKey(
        nearAccountId,
        publicKeyStr,
      ) as Promise<AccessKeyView>,
      nearRpcProvider.viewBlock({ finality: 'final' }) as Promise<BlockInfo>
    ]);

    const nonce = accessKeyInfo.nonce + BigInt(1);
    const blockHashString = blockInfo.header.hash;
    const blockHashBytes = Array.from(bs58.decode(blockHashString));

    // Validate required fields
    if (!actionArgs.receiver_id || !actionArgs.method_name || !actionArgs.args) {
      const errorMsg = 'Missing required action parameters: receiver_id, method_name, or args';
      const error = new Error(errorMsg);
      onError?.(error);
      onEvent?.({
        type: 'actionFailed',
        data: {
          error: errorMsg,
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    onEvent?.({
      type: 'actionProgress',
      data: {
        step: 'signing',
        message: 'Signing transaction in secure worker...'
      }
    });

    // Use the new WASM worker transaction signing
    const signingPayload = {
      nearAccountId: nearAccountId,
      receiverId: actionArgs.receiver_id,
      contractMethodName: actionArgs.method_name,
      contractArgs: JSON.parse(actionArgs.args),
      gasAmount: actionArgs.gas || DEFAULT_GAS_STRING,
      depositAmount: actionArgs.deposit || "0",
      nonce: nonce.toString(),
      blockHashBytes: blockHashBytes as number[],
    };

    // Get authentication options for challenge validation
    let challengeId: string;
    if (routing.mode === 'serverless') {
      // In serverless mode, get authentication options directly from the contract
      const authOptions = await webAuthnManager.getAuthenticationOptionsFromContract(
        nearRpcProvider,
        nearAccountId
      );
      challengeId = authOptions.challengeId;
    } else {
      const authOptions = await webAuthnManager.getAuthenticationOptionsFromServer(
        routing.serverUrl!,
        nearAccountId
      );
      challengeId = authOptions.challengeId;
    }

    const signingResult = await webAuthnManager.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      signingPayload,
      challengeId
    );

    // Broadcast transaction
    onEvent?.({
      type: 'actionProgress',
      data: {
        step: 'broadcasting',
        message: 'Broadcasting transaction...'
      }
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
        method: 'broadcast_tx_commit',
        params: [Buffer.from(signedTransactionBorsh).toString('base64')]
      })
    });

    const result: RpcResponse = await rpcResponse.json();
    if (result.error) {
      const errorMessage = result.error.data?.message ||
                         result.error.message ||
                         'RPC error';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({
        type: 'actionFailed',
        data: {
          error: errorMessage,
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    const actionResult: ActionResult = {
      success: true,
      transactionId: result.result?.transaction_outcome?.id,
      result: result.result
    };

    onEvent?.({
      type: 'actionCompleted',
      data: {
        transactionId: actionResult.transactionId,
        result: actionResult.result
      }
    });

    hooks?.afterCall?.(true, actionResult);
    return actionResult;

  } catch (error: any) {
    console.error('[Direct Action] Error during execution:', error);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: error.message,
        actionType: actionArgs.method_name || 'unknown'
      }
    });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}