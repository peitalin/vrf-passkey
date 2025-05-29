import { getTestnetRpcProvider } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import { KeyPair } from 'near-api-js';
import { SERVER_URL } from '../config';

// https://github.com/near/near-api-js/blob/94efe047/packages/client/src/funded_account.ts

const TESTNET_HELPER_URL = 'https://helper.testnet.near.org';
const MAINNET_HELPER_URL = 'https://helper.mainnet.near.org';

interface CreateAccountResult {
  success: boolean;
  accountId?: string;
  publicKey?: string;
  transactionId?: string;
  error?: string;
}

/**
 * Creates a top-level account using the relay server
 * The relay server will use its funded account to create the new account
 */
export async function createTopLevelAccount(
  accountId: string,
  publicKey: string,
  isTestnet: boolean = true
): Promise<CreateAccountResult> {
  try {
    console.log('[createTopLevelAccount] Creating account:', accountId, 'with public key:', publicKey);

    const response = await fetch(`${SERVER_URL}/api/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        accountId,
        publicKey,
        isTestnet
      }),
    });

    const result = await response.json();

    if (!response.ok) {
      console.error('[createTopLevelAccount] Server error:', result);

      // Check if account already exists
      if (result.error?.includes('already exists')) {
        console.log('[createTopLevelAccount] Account already exists, considering it a success');
        return {
          success: true,
          accountId,
          publicKey,
        };
      }

      throw new Error(result.error || `Failed to create account: ${response.statusText}`);
    }

    console.log('[createTopLevelAccount] Account created successfully:', result);

    return {
      success: true,
      accountId,
      publicKey,
      transactionId: result.transactionId
    };
  } catch (error: any) {
    console.error('[createTopLevelAccount] Error:', error);
    return {
      success: false,
      error: error.message || 'Failed to create account',
    };
  }
}

/**
 * Checks if an account exists on NEAR
 */
export async function checkAccountExists(
  accountId: string,
  provider?: Provider
): Promise<boolean> {
  try {
    const rpcProvider = provider || getTestnetRpcProvider();

    const account = await rpcProvider.query({
      request_type: 'view_account',
      finality: 'final',
      account_id: accountId,
    });

    return !!account;
  } catch (error: any) {
    // Account doesn't exist if we get an error
    if (error.message?.includes('does not exist') ||
        error.message?.includes('doesn\'t exist') ||
        error.type === 'AccountDoesNotExist' ||
        error.toString().includes('does not exist') ||
        error.toString().includes('doesn\'t exist')) {
      return false;
    }
    // Re-throw other errors
    throw error;
  }
}

/**
 * Helper to determine which account creation method to use based on environment
 */
export async function createNearAccount(
  accountId: string,
  publicKey: string,
  isProduction: boolean = false
): Promise<CreateAccountResult> {
  // Use createTopLevelAccount for both production and testnet
  return createTopLevelAccount(accountId, publicKey, !isProduction);
}