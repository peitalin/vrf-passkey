import { RegistrationSSEEvent } from '../../types/passkeyManager';

/**
 * Create NEAR account using testnet faucet service
 * This only works on testnet, for production use the relayer server
 */
export async function createAccountTestnetFaucet(
  nearAccountId: string,
  publicKey: string,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
): Promise<{ success: boolean; message: string; error?: string }> {
  try {
    console.log('🌊 Creating NEAR account via testnet faucet service');

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
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

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
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

    // Check if account already exists
    if (faucetError.message?.includes('already exists') || faucetError.message?.includes('AccountAlreadyExists')) {
      console.log('Account already exists, continuing with registration...');
      onEvent?.({
        step: 3,
        sessionId: tempSessionId,
        phase: 'access-key-addition',
        status: 'success',
        timestamp: Date.now(),
        message: `Account ${nearAccountId} already exists - continuing with registration`
      } as RegistrationSSEEvent);

      return {
        success: true,
        message: `Account ${nearAccountId} already exists`
      };
    } else {
      // For other errors, we'll continue but warn the user
      console.warn('Faucet service failed, but continuing with local registration:', faucetError.message);
      onEvent?.({
        step: 3,
        sessionId: tempSessionId || 'unknown',
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
}
