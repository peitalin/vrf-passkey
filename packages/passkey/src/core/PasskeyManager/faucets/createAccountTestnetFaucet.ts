import { RegistrationSSEEvent } from '../../types/passkeyManager';
import { formatLongMessage } from '../../../utils';

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
      step: 3,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account creation via faucet failed, but registration will continue locally'
    } as RegistrationSSEEvent);

    return {
      success: false,
      message: 'Faucet service failed, continuing with local registration',
      error: faucetError.message
    };
  }
}
