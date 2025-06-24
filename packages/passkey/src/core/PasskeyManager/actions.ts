import bs58 from 'bs58';
import type { AccessKeyView } from '@near-js/types';
import { TxExecutionStatus } from '@near-js/types';

import { RPC_NODE_URL, DEFAULT_GAS_STRING } from '../../config';
import { base64UrlDecode } from '../../utils/encoders';
import type { SerializableActionArgs } from '../types';
import type { NearRpcCallParams } from '../types';

import type { PasskeyManager } from './index';
import type { ActionOptions, ActionResult, LoginEvent } from '../types/passkeyManager';

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

    // 2. VRF Authentication
    const authContext = await performVRFAuthentication(
      passkeyManager,
      nearAccountId,
      validationContext,
      { onEvent, onError, hooks }
    );

    // 3. Transaction Signing
    const signingResult = await signTransaction(
      passkeyManager,
      nearAccountId,
      actionArgs,
      authContext,
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
async function performVRFAuthentication(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  validationContext: ValidationContext,
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

  console.log(`✅ VRF session active for ${nearAccountId} (${Math.round(vrfStatus.sessionDuration! / 1000)}s)`);

  // Generate VRF challenge using Service Worker
  const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
  const blockHeight = blockInfo.header.height;
  const blockHashBytes = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

  const vrfInputData = {
    userId: nearAccountId,
    rpId: window.location.hostname,
    sessionId: crypto.randomUUID(),
    blockHeight,
    blockHash: blockHashBytes,
    timestamp: Date.now()
  };

  console.log('Generating VRF challenge in Worker');
  const vrfChallengeData = await vrfManager.generateVRFChallenge(vrfInputData);

  console.log('DEBUG: VRF Authentication Data:');
  console.log(`  - VRF Public Key: ${vrfChallengeData.vrfPublicKey.substring(0, 40)}...`);
  console.log(`  - RP ID: ${vrfChallengeData.rpId}`);
  console.log(`  - User ID: ${nearAccountId}`);

  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'authenticating',
      message: 'Authenticating with VRF challenge...'
    }
  });

  // Use VRF output as WebAuthn challenge
  const vrfOutputBytes = base64UrlDecode(vrfChallengeData.vrfOutput);
  const webauthnChallengeBytes = vrfOutputBytes.slice(0, 32);

  // Get stored authenticator data
  const authenticators = await webAuthnManager.getAuthenticatorsByUser(nearAccountId);
  console.log(`DEBUG: Found ${authenticators.length} authenticators for ${nearAccountId}:`);
  authenticators.forEach((auth, index) => {
    console.log(`  [${index}] Credential ID: ${auth.credentialID}`);
    console.log(`  [${index}] Name: ${auth.name}`);
    console.log(`  [${index}] Registered: ${auth.registered}`);
  });

  if (authenticators.length === 0) {
    throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
  }

  // Perform WebAuthn authentication with VRF-generated challenge
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: webauthnChallengeBytes,
      rpId: window.location.hostname,
      allowCredentials: authenticators.map(auth => ({
        id: new Uint8Array(Buffer.from(auth.credentialID, 'base64')),
        type: 'public-key' as const,
        transports: auth.transports as AuthenticatorTransport[]
      })),
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: new Uint8Array(new Array(32).fill(42))
          }
        }
      }
    } as PublicKeyCredentialRequestOptions
  }) as PublicKeyCredential;

  if (!credential) {
    throw new Error('VRF WebAuthn authentication failed or was cancelled');
  }

  // Get PRF output for NEAR key decryption
  const extensionResults = credential.getClientExtensionResults();
  const prfOutput = (extensionResults as any).prf?.results?.first;

  if (!prfOutput) {
    throw new Error('PRF output not available - required for NEAR key decryption');
  }

  console.log('✅ VRF WebAuthn authentication completed');

  // Verify VRF authentication with contract
  onEvent?.({
    type: 'actionProgress',
    data: {
      step: 'authenticating',
      message: 'Verifying authentication with contract...'
    }
  });

  console.log('📜 Verifying VRF authentication with contract before transaction signing');

  const contractVerificationResult = await webAuthnManager.verifyVrfAuthentication(
    nearRpcProvider,
    passkeyManager.getConfig().contractId,
    {
      vrfInput: vrfChallengeData.vrfInput,
      vrfOutput: vrfChallengeData.vrfOutput,
      vrfProof: vrfChallengeData.vrfProof,
      vrfPublicKey: vrfChallengeData.vrfPublicKey,
      userId: nearAccountId,
      rpId: vrfChallengeData.rpId,
      blockHeight: vrfChallengeData.blockHeight,
      blockHash: vrfChallengeData.blockHash,
    },
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

  return {
    ...validationContext,
    vrfChallengeData,
    credential,
    prfOutput,
    contractVerificationResult
  };
}

/**
 * 3. Transaction Signing - Signs the transaction using WASM worker
 */
async function signTransaction(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  actionArgs: SerializableActionArgs,
  authContext: AuthContext,
  eventOptions: EventOptions
): Promise<any> {
  const { onEvent, onError, hooks } = eventOptions;
  const webAuthnManager = passkeyManager.getWebAuthnManager();

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
    // Transfer actions are not yet implemented in the WASM worker
    const errorMsg = 'NEAR transfers are not yet supported. The current implementation only supports smart contract function calls. Transfer functionality requires extending the WASM worker to handle Transfer actions.';
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

  } else if (actionArgs.action_type === 'FunctionCall') {
    // Use the existing WASM worker transaction signing for function calls
    const signingPayload = {
      nearAccountId: nearAccountId,
      receiverId: actionArgs.receiver_id!,
      contractMethodName: actionArgs.method_name!,
      contractArgs: JSON.parse(actionArgs.args!),
      gasAmount: actionArgs.gas || DEFAULT_GAS_STRING,
      depositAmount: actionArgs.deposit || "0",
      nonce: authContext.nonce.toString(),
      blockHashBytes: authContext.transactionBlockHashBytes,
    };

    signingResult = await webAuthnManager.secureTransactionSigningWithPrf(
      nearAccountId,
      authContext.prfOutput,
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
 * 4. Transaction Broadcasting - Broadcasts the signed transaction to NEAR network
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
        wait_until: "EXECUTED_OPTIMISTIC"
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


