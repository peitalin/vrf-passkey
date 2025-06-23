import bs58 from 'bs58';
import type { AccessKeyView } from '@near-js/types';
import { TxExecutionStatus } from '@near-js/types';

import { RPC_NODE_URL, DEFAULT_GAS_STRING } from '../../config';
import { base64UrlDecode } from '../../utils/encoders';
import type { SerializableActionArgs } from '../types';
import type { NearRpcCallParams } from '../types';

import type { PasskeyManager } from './index';
import type { ActionOptions, ActionResult, LoginEvent } from '../types/passkeyManager';

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
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const nearRpcProvider = passkeyManager['nearRpcProvider']; // Access private property

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
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    // Step 1: Generate VRF challenge and verify with contract
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
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    console.log(`✅ VRF session active for ${nearAccountId} (${Math.round(vrfStatus.sessionDuration! / 1000)}s)`);

    // Step 1a: Generate VRF challenge using Service Worker (no TouchID needed)
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

    console.log('🎯 Generating VRF challenge in Service Worker (no TouchID needed)');
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

    // Step 1b: Use VRF output as WebAuthn challenge
    const vrfOutputBytes = base64UrlDecode(vrfChallengeData.vrfOutput);
    const webauthnChallengeBytes = vrfOutputBytes.slice(0, 32); // First 32 bytes as challenge

    // Get stored authenticator data for this user
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
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge: webauthnChallengeBytes, // VRF output as challenge
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
            first: new Uint8Array(new Array(32).fill(42)) // Generate PRF for NEAR key unlocking + signing in wasm-signer-worker
          }
        }
      }
    };

    const credential = await navigator.credentials.get({
      publicKey: authOptions
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

    // Step 1c: Verify VRF authentication with contract before proceeding
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
          actionType: actionArgs.method_name || 'unknown'
        }
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMsg };
    }

    console.log('✅ VRF authentication verified by contract - proceeding with transaction signing');

    onEvent?.({
      type: 'actionProgress',
      data: {
        step: 'authenticating',
        message: 'Authentication verified - preparing transaction...'
      }
    });

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
      transactionBlockInfo
    ] = await Promise.all([
      nearRpcProvider.viewAccessKey(nearAccountId, publicKeyStr) as Promise<AccessKeyView>,
      nearRpcProvider.viewBlock({ finality: 'final' }) as Promise<BlockInfo>
    ]);

    const nonce = accessKeyInfo.nonce + BigInt(1);
    const blockHashString = transactionBlockInfo.header.hash;
    const transactionBlockHashBytes = Array.from(bs58.decode(blockHashString));

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
      blockHashBytes: transactionBlockHashBytes,
    };

    // No challenge validation needed - VRF provides cryptographic freshness
    const signingResult = await webAuthnManager.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      signingPayload
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

/**
 * Handle VRF-based authentication for ongoing operations (e.g., transaction signing)
 *
 * This demonstrates the VRF authentication flow where:
 * 1. VRF generates fresh, verifiable challenges (eliminates need for server challenges)
 * 2. WebAuthn signs the VRF challenge to prove user has VRF private key
 * 3. Provides replay protection through cryptographically bound challenges
 *
 * Prerequisites: User must have completed VRF login to unlock keypair in VRF WASM Worker
 */
export async function authenticateWithVRF(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  sessionId?: string,
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  options?: {
    verifyWithContract?: boolean;
    contractId?: string;
  }
): Promise<{
  success: boolean;
  vrfChallengeData?: any;
  webauthnCredential?: PublicKeyCredential;
  contractVerification?: {
    verified: boolean;
    transactionId?: string;
  };
  error?: string;
}> {
  try {
    console.log(`🔁 Starting VRF authentication for ${nearAccountId} (single TouchID)`);

    // Step 1: Check VRF Service Worker status
    const vrfManager = passkeyManager.getVRFManager();
    const vrfStatus = await vrfManager.getVRFStatus();

    if (!vrfStatus.active || vrfStatus.nearAccountId !== nearAccountId) {
      throw new Error('VRF keypair not unlocked - please login first');
    }

    console.log(`✅ VRF session active for ${nearAccountId} (${Math.round(vrfStatus.sessionDuration! / 1000)}s)`);

    // Step 2: Get NEAR block data for VRF input freshness
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'getting-options',
        message: 'Generating VRF challenge...'
      }
    });

    const nearRpcProvider = passkeyManager['nearRpcProvider'];
    const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
    const blockHeight = blockInfo.header.height;
    const blockHashBytes = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

    console.log(`Using NEAR block ${blockHeight} for VRF input freshness`);

    // Step 3: Generate VRF challenge using Service Worker (no TouchID required)
    const vrfInputData = {
      userId: nearAccountId,
      rpId: window.location.hostname,
      sessionId: sessionId || crypto.randomUUID(),
      blockHeight,
      blockHash: blockHashBytes,
      timestamp: Date.now()
    };

    console.log('Generating VRF challenge in Service Worker (no TouchID needed)');

    const vrfChallengeData = await vrfManager.generateVRFChallenge(vrfInputData);

    console.log('✅ VRF challenge generated successfully');
    console.log('  - VRF Input:', vrfChallengeData.vrfInput.substring(0, 20) + '...');
    console.log('  - VRF Output:', vrfChallengeData.vrfOutput.substring(0, 20) + '...');

    // Step 4: Use VRF output as WebAuthn challenge and perform authentication
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'webauthn-assertion',
        message: 'Authenticating with VRF challenge...'
      }
    });

    // Decode VRF output to use as WebAuthn challenge
    const vrfOutputBytes = base64UrlDecode(vrfChallengeData.vrfOutput);
    const webauthnChallengeBytes = vrfOutputBytes.slice(0, 32); // First 32 bytes as challenge

    console.log('Using VRF output as WebAuthn challenge for authentication');

    // Get authenticator data for WebAuthn ceremony
    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const authenticators = await webAuthnManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}`);
    }

    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge: webauthnChallengeBytes, // VRF output as challenge
      rpId: window.location.hostname,
      allowCredentials: authenticators.map(auth => ({
        id: new Uint8Array(Buffer.from(auth.credentialID, 'base64')),
        type: 'public-key' as const,
        transports: auth.transports as AuthenticatorTransport[]
      })),
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000
    };

    const credential = await navigator.credentials.get({
      publicKey: authOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('VRF WebAuthn authentication failed or was cancelled');
    }

    console.log('✅ VRF authentication completed successfully');

    // Step 5: Optional contract verification
    let contractVerification: { verified: boolean; transactionId?: string } | undefined;

    if (options?.verifyWithContract && options?.contractId) {
      console.log('Verifying VRF authentication with contract...');

      onEvent?.({
        type: 'loginProgress',
        data: {
          step: 'verifying-server',
          message: 'Verifying with contract...'
        }
      });

      try {
        const webAuthnManager = passkeyManager.getWebAuthnManager();
        const verificationResult = await webAuthnManager.verifyVrfAuthentication(
          nearRpcProvider,
          options.contractId,
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
          passkeyManager.getConfig().debugMode
        );

        if (verificationResult.success && verificationResult.verified) {
          console.log('✅ Contract verification successful');
          contractVerification = {
            verified: true
          };
        } else {
          console.warn('⚠️ Contract verification failed:', verificationResult.error);
          contractVerification = {
            verified: false
          };
        }
      } catch (contractError: any) {
        console.error('❌ Contract verification error:', contractError);
        contractVerification = {
          verified: false
        };
      }
    } else {
      console.log('🔗 VRF proof and WebAuthn response ready for contract verification (not performed)');
    }

    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'verifying-server',
        message: contractVerification ?
          (contractVerification.verified ? 'Contract verification successful' : 'Contract verification failed') :
          'VRF authentication complete'
      }
    });

    return {
      success: true,
      vrfChallengeData,
      webauthnCredential: credential,
      contractVerification
    };

  } catch (error: any) {
    console.error('VRF authentication error:', error);
    onError?.(error);
    return { success: false, error: error.message };
  }
}