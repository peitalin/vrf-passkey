import { RegistrationSSEEvent } from '../../types/passkeyManager';
import { formatLongMessage } from '../../../utils';
import { PasskeyManagerContext } from '..';
import { VRFChallenge } from '@/core/types/webauthn';
import { AccessKeyView } from 'node_modules/@near-js/types/lib/commonjs/provider/response.cjs';
import { NearClient } from '@/core/NearClient';

/**
 * Create NEAR account using testnet faucet service
 * This only works on testnet, for production use the relayer server
 */
export async function createAccountTestnetFaucet(
  nearAccountId: string,
  publicKey: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
): Promise<{ success: boolean; message: string; error?: string }> {
  try {
    console.log('Creating NEAR account via testnet faucet service');

    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating NEAR account via faucet service...'
    });

    // Call NEAR testnet faucet service to create account
    const faucetResponse = await fetch('https://helper.nearprotocol.com/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        newAccountId: nearAccountId,
        newAccountPublicKey: publicKey
      })
    });

    if (!faucetResponse.ok) {
      const errorData = await faucetResponse.json().catch(() => ({}));
      throw new Error(`Faucet service error: ${faucetResponse.status} - ${errorData.message || 'Unknown error'}`);
    }

    const faucetResult = await faucetResponse.json();
    console.log('Faucet service response:', faucetResult);
    console.log('DEBUG: Faucet response status:', faucetResult.status);
    console.log('DEBUG: Faucet final_execution_status:', faucetResult.final_execution_status);
    console.log('DEBUG: Faucet transaction_outcome:', faucetResult.transaction_outcome);

    // Check if the transaction actually succeeded on-chain
    if (faucetResult.status?.Failure) {
      const failure = faucetResult.status.Failure;
      console.error('Faucet transaction failed on-chain:', failure);

      // Extract error details
      let errorMessage = 'Transaction failed on-chain';
      if (failure.ActionError?.kind) {
        const errorKind = failure.ActionError.kind;
        const contractId = nearAccountId.split('.').slice(1).join('.');
        if (errorKind.CreateAccountNotAllowed) {
          errorMessage = formatLongMessage(`
            Account creation for ${errorKind.CreateAccountNotAllowed.account_id} not allowed.
            Must be done through the ${contractId} account (via the relay server, not the testnet faucet).
          `);
        } else if (errorKind.AccountAlreadyExists) {
          errorMessage = `Account ${errorKind.AccountAlreadyExists.account_id} already exists`;
        } else {
          errorMessage = `${Object.keys(errorKind)[0]}`;
        }
      }
      throw new Error(errorMessage);
    }

    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: `NEAR account ${nearAccountId} created successfully via faucet`
    } as RegistrationSSEEvent);

    return {
      success: true,
      message: `Account ${nearAccountId} created successfully via faucet`
    };

  } catch (faucetError: any) {
    console.error('Faucet service error:', faucetError);
    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: 'Account creation via faucet failed',
      error: faucetError.message
    } as RegistrationSSEEvent);

    return {
      success: false,
      message: 'Faucet service failed, continuing with local registration',
      error: faucetError.message
    };
  }
}

/**
 * Create account and register user using testnet faucet (sequential flow)
 * This is the traditional flow: create account -> verify access key -> register with contract
 */
export async function createAccountAndRegisterWithTestnetFaucet(
  context: PasskeyManagerContext,
  nearAccountId: string,
  publicKey: string,
  credential: PublicKeyCredential,
  vrfChallenge: VRFChallenge,
  deterministicVrfPublicKey: string,
  onEvent?: (event: RegistrationSSEEvent) => void
): Promise<{
  success: boolean;
  transactionId?: string;
  error?: string;
  preSignedDeleteTransaction?: any;
}> {
  const { webAuthnManager, nearClient } = context;

  try {
    // Step 1: Create account using testnet faucet
    const accountCreationResult = await createAccountTestnetFaucet(
      nearAccountId,
      publicKey,
      onEvent
    );

    if (!accountCreationResult.success) {
      throw new Error(accountCreationResult.error || 'Account creation failed');
    }

    // Step 2: Wait for access key to be available
    const accessKeyInfo = await waitForAccessKey(
      nearClient,
      nearAccountId,
      publicKey,
      10, // max retries
      1000 // 1 second delay
    );

    onEvent?.({
      step: 4,
      phase: 'account-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account creation verified successfully'
    });

    // Step 3: Register with contract
    const contractRegistrationResult = await webAuthnManager.signVerifyAndRegisterUser({
      contractId: webAuthnManager.configs.contractId,
      credential: credential,
      vrfChallenge: vrfChallenge,
      deterministicVrfPublicKey: deterministicVrfPublicKey,
      signerAccountId: nearAccountId,
      nearAccountId: nearAccountId,
      publicKeyStr: publicKey,
      nearClient: nearClient,
      onEvent: (progress) => {
        onEvent?.({
          step: 5,
          phase: 'contract-registration',
          status: 'progress',
          timestamp: Date.now(),
          message: `VRF registration: ${progress.message}`
        });
      },
    });

    if (!contractRegistrationResult.verified || !contractRegistrationResult.signedTransaction) {
      throw new Error('Contract verification failed');
    }

    // Broadcast the signed transaction
    onEvent?.({
      step: 5,
      phase: 'contract-registration',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Broadcasting registration transaction...'
    });

    const transactionResult = await nearClient.sendTransaction(contractRegistrationResult.signedTransaction);
    const transactionId = transactionResult?.transaction_outcome?.id;

    onEvent?.({
      step: 5,
      phase: 'contract-registration',
      status: 'success',
      timestamp: Date.now(),
      message: `VRF registration successful, transaction ID: ${transactionId}`
    });

    return {
      success: true,
      transactionId: transactionId,
      preSignedDeleteTransaction: contractRegistrationResult.preSignedDeleteTransaction
    };

  } catch (error: any) {
    console.error('Sequential registration failed:', error);

    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: `Registration failed: ${error.message}`,
      error: error.message
    });

    return {
      success: false,
      error: error.message,
      preSignedDeleteTransaction: null
    };
  }
}

/**
 * Wait for access key to be available with retry logic
 * Account creation via faucet may have propagation delays
 */
async function waitForAccessKey(
  nearClient: NearClient,
  nearAccountId: string,
  nearPublicKey: string,
  maxRetries: number = 10,
  delayMs: number = 1000
): Promise<AccessKeyView> {
  console.log(`Waiting for access key to be available for ${nearAccountId}...`);
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const accessKeyInfo = await nearClient.viewAccessKey(
        nearAccountId,
        nearPublicKey,
      ) as AccessKeyView;

      console.log(`Access key found on attempt ${attempt}`);
      console.log(`DEBUG: Access key response:`, JSON.stringify(accessKeyInfo, null, 2));
      return accessKeyInfo;
    } catch (error: any) {
      console.log(`Access key not available yet (attempt ${attempt}/${maxRetries}):`, error.message);

      if (attempt === maxRetries) {
        console.error(`Access key still not available after ${maxRetries} attempts`);
        throw new Error(`Access key not available after ${maxRetries * delayMs}ms. Account creation may have failed.`);
      }

      // Wait before next attempt with exponential backoff
      const delay = delayMs * Math.pow(1.5, attempt - 1);
      console.debug(`   Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('Unexpected error in waitForAccessKey');
}