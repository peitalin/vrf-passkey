import bs58 from 'bs58';
import type { AccessKeyView } from '@near-js/types';
import { TxExecutionStatus } from '@near-js/types';
import { sha256 } from 'js-sha256';

import { RPC_NODE_URL, DEFAULT_GAS_STRING } from '../../config';
import { base64UrlDecode } from '../../utils/encoders';
import type { SerializableActionArgs } from '../types';
import type { NearRpcCallParams } from '../types';

import type { PasskeyManager } from './index';
import type { ActionOptions, ActionResult, LoginEvent } from '../types/passkeyManager';
import { generateUserScopedPrfSalt } from '../../utils';

// See default finality settings
// https://github.com/near/near-api-js/blob/99f34864317725467a097dc3c7a3cc5f7a5b43d4/packages/accounts/src/account.ts#L68
// export const DEFAULT_WAIT_STATUS: TxExecutionStatus = "INCLUDED_FINAL";
export const DEFAULT_WAIT_STATUS: TxExecutionStatus = "EXECUTED_OPTIMISTIC";

// === TYPE DEFINITIONS FOR INTERNAL CONTEXT ===

interface ValidationContext {
  userData: any;
  publicKeyStr: string;
  accessKeyInfo: AccessKeyView;
  transactionBlockInfo: BlockInfo;
  nonce: bigint;
  transactionBlockHashBytes: number[];
}

interface AuthContext extends ValidationContext {
  vrfChallengeData: any;
  credential: PublicKeyCredential;
  prfOutput: ArrayBuffer;
  contractVerificationResult: any;
}

interface EventOptions {
  onEvent?: (event: any) => void;
  onError?: (error: Error) => void;
  hooks?: any;
}

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
  options?: ActionOptions,
): Promise<ActionResult> {

  const { onEvent, onError, hooks } = options || {};

  // Emit started event
  onEvent?.({
    type: 'actionStarted',
    data: {
      actionType: actionArgs.method_name || actionArgs.action_type,
      receiverId: actionArgs.receiver_id || 'unknown'
    }
  });

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // 1. Validation
    const validationContext = await validateActionInputs(
      passkeyManager,
      nearAccountId,
      actionArgs,
      { onEvent, onError, hooks }
    );

    // 2. VRF Authentication + Transaction Signing
    const signingResult = await verifyVrfAuthAndSignTransaction(
      passkeyManager,
      nearAccountId,
      validationContext,
      actionArgs,
      { onEvent, onError, hooks }
    );

    // 4. Transaction Broadcasting
    const actionResult = await broadcastTransaction(
      signingResult,
      actionArgs,
      { onEvent, onError, hooks }
    );

    hooks?.afterCall?.(true, actionResult);
    return actionResult;

  } catch (error: any) {
    console.error('[Direct Action] Error during execution:', error);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: error.message,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
    });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}

// === PRIVATE HELPER FUNCTIONS ===

/**
 * 1. Validation - Validates inputs and prepares transaction context
 */
async function validateActionInputs(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  actionArgs: SerializableActionArgs,
  eventOptions: EventOptions
): Promise<ValidationContext> {
  const { onEvent, onError, hooks } = eventOptions;
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const nearRpcProvider = passkeyManager.getNearRpcProvider();

  // Basic validation
  if (!nearAccountId) {
    const errorMsg = 'User not logged in or NEAR account ID not set for direct action.';
    const error = new Error(errorMsg);
    console.error('[Direct Action] Error:', errorMsg, nearAccountId);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
    });
    hooks?.afterCall?.(false, error);
    throw error;
  }

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'preparing',
      message: 'Preparing transaction...'
    }
  });

  // Check if user has PRF support
  const userData = await webAuthnManager.getUser(nearAccountId);
  const usesPrf = userData?.prfSupported === true;

  console.log('DEBUG: User Data from IndexDB:');
  console.log(`  - Account ID: ${nearAccountId}`);
  console.log(`  - Has user data: ${!!userData}`);
  console.log(`  - PRF supported: ${userData?.prfSupported}`);
  console.log(`  - Client NEAR public key: ${userData?.clientNearPublicKey}`);
  console.log(`  - Has VRF credentials: ${!!userData?.vrfCredentials}`);
  console.log(`  - Passkey credential ID: ${userData?.passkeyCredential?.id}`);

  if (!usesPrf) {
    const errorMsg = 'This application requires PRF support. Please use a PRF-capable authenticator.';
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
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
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
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
  if (!actionArgs.receiver_id) {
    const errorMsg = 'Missing required parameter: receiver_id';
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
    });
    hooks?.afterCall?.(false, error);
    throw error;
  }

  // Additional validation for function calls
  if (actionArgs.action_type === 'FunctionCall' && (!actionArgs.method_name || !actionArgs.args)) {
    const errorMsg = 'Missing required parameters for function call: method_name or args';
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
    });
    hooks?.afterCall?.(false, error);
    throw error;
  }

  // Additional validation for transfers
  if (actionArgs.action_type === 'Transfer' && !actionArgs.amount) {
    const errorMsg = 'Missing required parameter for transfer: amount';
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.action_type
      }
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
  validationContext: ValidationContext,
  actionArgs: SerializableActionArgs,
  eventOptions: EventOptions
): Promise<AuthContext> {
  const { onEvent, onError, hooks } = eventOptions;
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const nearRpcProvider = passkeyManager.getNearRpcProvider();

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'authenticating',
      message: 'Generating VRF challenge...'
    }
  });

  console.log('[Direct Action] Using VRF authentication flow with contract verification');

  // Get managers and check if VRF session is active
  const vrfManager = passkeyManager.getVRFManager();
  const vrfStatus = await vrfManager.getVRFStatus();

  if (!vrfStatus.active || vrfStatus.nearAccountId !== nearAccountId) {
    const errorMsg = 'VRF keypair not unlocked - please login first to unlock VRF session';
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: nearAccountId || 'unknown'
      }
    });
    hooks?.afterCall?.(false, error);
    throw error;
  }
  console.log(`VRF session active for ${nearAccountId} (${Math.round(vrfStatus.sessionDuration! / 1000)}s)`);

  const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
  // Generate VRF challenge using Service Worker
  const vrfInputData = {
    userId: nearAccountId,
    rpId: window.location.hostname,
    sessionId: crypto.randomUUID(),
    blockHeight: blockInfo.header.height,
    blockHash: new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64')),
    timestamp: Date.now()
  };
  // Use VRF output as WebAuthn challenge
  const vrfChallenge = await vrfManager.generateVRFChallenge(vrfInputData);

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'authenticating',
      message: 'Authenticating with VRF challenge...'
    }
  });

  // Get stored authenticator data
  const authenticators = await webAuthnManager.getAuthenticatorsByUser(nearAccountId);
  if (authenticators.length === 0) {
    throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
  }

  const {
    credential,
    prfOutput
  } = await webAuthnManager.touchIdPrompt.getCredentialsAndPrf({
    nearAccountId,
    challenge: vrfChallenge.outputAs32Bytes(),
    authenticators,
  });

  console.log('✅ VRF WebAuthn authentication completed');

  // Verify VRF authentication with contract
  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'authenticating',
      message: 'Verifying authentication with contract...'
    }
  });

  console.log('Verifying VRF authentication with contract before transaction signing');
  const contractVerificationResult = await webAuthnManager.verifyVrfAuthentication(
    nearRpcProvider,
    passkeyManager.getConfig().contractId,
    vrfChallenge,
    credential,
    passkeyManager.getConfig().debugMode ?? false
  );

  if (!contractVerificationResult.success || !contractVerificationResult.verified) {
    const errorMsg = `VRF authentication verification failed: ${contractVerificationResult.error || 'Unknown error'}`;
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: nearAccountId || 'unknown'
      }
    });
    hooks?.afterCall?.(false, error);
    throw error;
  }

  console.log('✅ VRF authentication verified by contract - proceeding with transaction signing');

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'authenticating',
      message: 'Authentication verified - preparing transaction...'
    }
  });

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'signing',
      message: 'Signing transaction in secure worker...'
    }
  });

  // Handle different action types
  let signingResult: any;

  if (actionArgs.action_type === 'Transfer') {
    // Use the new Transfer transaction signing with WASM worker
    const transferPayload = {
      nearAccountId: nearAccountId,
      receiverId: actionArgs.receiver_id!,
      depositAmount: actionArgs.amount!,
      nonce: validationContext.nonce.toString(),
      blockHashBytes: validationContext.transactionBlockHashBytes,
    };

    signingResult = await webAuthnManager.signTransferTransactionWithPrf(
      nearAccountId,
      prfOutput,
      transferPayload
    );

  } else if (actionArgs.action_type === 'FunctionCall') {
    // Use the existing WASM worker transaction signing for function calls
    const signingPayload = {
      nearAccountId: nearAccountId,
      receiverId: actionArgs.receiver_id!,
      contractMethodName: actionArgs.method_name!,
      contractArgs: JSON.parse(actionArgs.args!),
      gasAmount: actionArgs.gas || DEFAULT_GAS_STRING,
      depositAmount: actionArgs.deposit || "0",
      nonce: validationContext.nonce.toString(),
      blockHashBytes: validationContext.transactionBlockHashBytes,
    };

    signingResult = await webAuthnManager.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      signingPayload
    );

  } else {
    const errorMsg = `Action type ${actionArgs.action_type} is not yet supported`;
    const error = new Error(errorMsg);
    onError?.(error);
    onEvent?.({
      type: 'actionFailed',
      data: {
        error: errorMsg,
        actionType: actionArgs.action_type
      }
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
  signingResult: any,
  actionArgs: SerializableActionArgs,
  eventOptions: EventOptions
): Promise<ActionResult> {
  const { onEvent, onError, hooks } = eventOptions;

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
      type: 'actionFailed',
      data: {
        error: errorMessage,
        actionType: actionArgs.method_name || actionArgs.action_type
      }
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
    type: 'actionCompleted',
    data: {
      transactionId: actionResult.transactionId,
      result: actionResult.result
    }
  });

  return actionResult;
}


