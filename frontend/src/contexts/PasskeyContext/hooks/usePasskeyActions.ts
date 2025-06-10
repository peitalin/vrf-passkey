import { useCallback } from 'react';
import bs58 from 'bs58';
import { webAuthnManager } from '../../../security/WebAuthnManager';
import { RPC_NODE_URL, DEFAULT_GAS_STRING } from '../../../config';
import { useRpcProvider } from './useNearRpcProvider';
import type { SerializableActionArgs } from '../../../types';
import type {
  ExecuteActionCallbacks,
  GreetingResult,
  ActionExecutionResult
} from '../types';

interface PasskeyActionsHook {
  executeDirectActionViaWorker: (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ) => Promise<void>;
}

interface AccessKeyInfo {
  nonce: number;
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
  result?: ActionExecutionResult;
}

export const usePasskeyActions = (
  isLoggedIn: boolean,
  username: string | null,
  nearAccountId: string | null,
  optimisticAuth: boolean,
  setIsProcessing: (isProcessing: boolean) => void,
  fetchCurrentGreeting: () => Promise<GreetingResult>
): PasskeyActionsHook => {
  const { getRpcProvider } = useRpcProvider();

  const executeDirectActionViaWorker = useCallback(async (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ): Promise<void> => {
    callbacks?.beforeDispatch?.();
    setIsProcessing(true);
    console.log('[Direct Action] Initiating...', { serializableActionForContract });

    if (!isLoggedIn || !username || !nearAccountId) {
      const errorMsg = 'User not logged in or NEAR account ID not set for direct action.';
      console.error('[Direct Action] Error:', errorMsg, { isLoggedIn, username, nearAccountId });
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: errorMsg });
      return;
    }

    try {
      // Check if user has PRF support
      const userData = await webAuthnManager.getUserData(username);
      const usesPrf = userData?.prfSupported === true;

      if (!usesPrf) {
        throw new Error('This application requires PRF support. Please use a PRF-capable authenticator.');
      }

      // Use the callback's auth mode if provided, otherwise fall back to global setting
      const authModeForThisAction = callbacks?.optimisticAuth ?? optimisticAuth;

      // Step 1: Authenticate with PRF to get PRF output
      const { credential: passkeyAssertion, prfOutput } = await webAuthnManager.authenticateWithPrf(
        username,
        'signing',
        authModeForThisAction
      );

      if (!passkeyAssertion || !prfOutput) {
        throw new Error('PRF authentication failed or no PRF output');
      }

      console.log('[Direct Action] PRF authentication successful, starting concurrent operations...');

      // Get provider and public key
      const provider = getRpcProvider();
      const publicKeyStr = userData?.clientNearPublicKey;
      if (!publicKeyStr) {
        throw new Error('Client NEAR public key not found in user data');
      }

      // Run operations concurrently for better performance
      const [
        { options, challengeId },
        accessKeyInfo,
        blockInfo
      ] = await Promise.all([
        webAuthnManager.getAuthenticationOptions(username, authModeForThisAction),
        provider.query({
          request_type: 'view_access_key',
          finality: 'optimistic',
          account_id: nearAccountId,
          public_key: publicKeyStr,
        }) as Promise<unknown> as Promise<AccessKeyInfo>,
        provider.viewBlock({ finality: 'final' }) as Promise<BlockInfo>
      ]);

      const nonce = accessKeyInfo.nonce + 1;
      const blockHashString = blockInfo.header.hash;
      const blockHashBytes = Array.from(bs58.decode(blockHashString));

      const signingPayload = {
        nearAccountId,
        receiverId: serializableActionForContract.receiver_id,
        contractMethodName: serializableActionForContract.method_name,
        contractArgs: JSON.parse(serializableActionForContract.args),
        gasAmount: serializableActionForContract.gas || DEFAULT_GAS_STRING,
        depositAmount: serializableActionForContract.deposit || "0",
        nonce: nonce.toString(),
        blockHashBytes: blockHashBytes,
      };

      const signingResult = await webAuthnManager.secureTransactionSigningWithPrf(
        username,
        prfOutput,
        signingPayload,
        challengeId
      );

      // Broadcast transaction
      const signedTransactionBorsh = new Uint8Array(signingResult.signedTransactionBorsh);
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
        throw new Error(errorMessage);
      }

      if (serializableActionForContract.method_name === 'set_greeting') {
        await fetchCurrentGreeting();
      }

      setIsProcessing(false);
      callbacks?.afterDispatch?.(true, result.result);

    } catch (error: any) {
      console.error('[Direct Action] Error during execution:', error);
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: error.message });
    }
  }, [
    isLoggedIn,
    username,
    nearAccountId,
    optimisticAuth,
    setIsProcessing,
    getRpcProvider,
    fetchCurrentGreeting
  ]);

  return { executeDirectActionViaWorker };
};
