import { Account } from '@near-js/accounts';
import { PublicKey } from '@near-js/crypto';
import { actionCreators } from '@near-js/transactions';
import { nearClient } from '../nearService';

const INITIAL_BALANCE = BigInt('20000000000000000000000'); // 0.02 NEAR

export interface AccountCreationResult {
  success: boolean;
  transactionHash?: string;
  accountId?: string;
  error?: string;
  message?: string;
}

export interface AccountCreationRequest {
  accountId: string;
  publicKey: string;
}

export class AccountCreationService {
  private isInitialized = false;

  // Transaction queue to prevent nonce conflicts
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  async init(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    // Ensure nearClient is initialized
    await nearClient.init();
    this.isInitialized = true;
    console.log('AccountCreationService initialized');
  }

  async createAccount(request: AccountCreationRequest): Promise<AccountCreationResult> {
    await this.init();

    return this.queueTransaction(async () => {
      try {
        console.log(`Creating account: ${request.accountId}`);
        console.log(`Public key: ${request.publicKey}`);

        // Validate account ID format
        if (!this.isValidAccountId(request.accountId)) {
          throw new Error(`Invalid account ID format: ${request.accountId}`);
        }

        // Parse the public key
        const publicKey = PublicKey.fromString(request.publicKey);
        console.log(`Parsed public key: ${publicKey.toString()}`);

        // Get the relayer account from nearClient
        const relayerAccount = await nearClient.init();
        if (!relayerAccount) {
          throw new Error('Relayer account not available');
        }

        console.log(`Creating account ${request.accountId} using relayer: ${relayerAccount.accountId}`);

        // Create the account using the standard NEAR pattern:
        // 1. CreateAccount action
        // 2. Transfer action (initial balance)
        // 3. AddKey action (add the user's public key)

        const result = await relayerAccount.signAndSendTransaction({
          receiverId: request.accountId,
          actions: [
            actionCreators.createAccount(),
            actionCreators.transfer(INITIAL_BALANCE),
            actionCreators.addKey(publicKey, actionCreators.fullAccessKey())
          ]
        });

        console.log(`Account created successfully: ${result.transaction.hash}`);

        return {
          success: true,
          transactionHash: result.transaction.hash,
          accountId: request.accountId,
          message: `Account ${request.accountId} created successfully with 1 NEAR initial balance`
        };

      } catch (error: any) {
        console.error(`Account creation failed for ${request.accountId}:`, error);
        return {
          success: false,
          error: error.message || 'Unknown account creation error',
          message: `Failed to create account ${request.accountId}: ${error.message}`
        };
      }
    }, `create account ${request.accountId}`);
  }

  private isValidAccountId(accountId: string): boolean {
    // Basic NEAR account ID validation
    if (!accountId || accountId.length < 2 || accountId.length > 64) {
      return false;
    }

    // Check for valid characters and format
    const validPattern = /^[a-z0-9_.-]+$/;
    return validPattern.test(accountId);
  }

  /**
   * Queue a transaction to prevent nonce conflicts
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    console.log(`[AccountCreationService] Queueing transaction: ${description} (pending: ${this.queueStats.pending})`);

    // Chain this operation to the existing queue
    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          console.log(`️ [AccountCreationService] Executing transaction: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          console.log(`[AccountCreationService] Completed transaction: ${description} (pending: ${this.queueStats.pending}, completed: ${this.queueStats.completed})`);
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          console.error(`❌ [AccountCreationService] Failed transaction: ${description} (pending: ${this.queueStats.pending}, failed: ${this.queueStats.failed}):`, error?.message || error);
          throw error;
        }
      })
      .catch((error) => {
        // Ensure the queue continues even if this transaction fails
        throw error;
      });

    return this.transactionQueue;
  }
}

// Export singleton instance
export const accountCreationService = new AccountCreationService();