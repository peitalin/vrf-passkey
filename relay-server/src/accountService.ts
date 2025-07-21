import { Account } from '@near-js/accounts';
import { getSignerFromKeystore, view } from '@near-js/client';
import { KeyPairEd25519, PublicKey } from '@near-js/crypto';
import { InMemoryKeyStore, type KeyStore } from '@near-js/keystores';
import { JsonRpcProvider, type Provider } from '@near-js/providers';
import type { Signer } from '@near-js/signers';
import { actionCreators } from '@near-js/transactions';
import type { FinalExecutionOutcome } from '@near-js/types';

import * as dotenv from 'dotenv';
dotenv.config();
import type {
  SSEEventEmitter,
  NearExecutionFailure,
  NearReceiptOutcomeWithId,
  CreateAccountAndRegisterResult,
  CreateAccountAndRegisterRequest,
  AccountCreationRequest,
  AccountCreationResult
} from './types';
import config, { type AppConfig } from './config';

class AccountService {
  private config: AppConfig;
  private keyStore: KeyStore;
  private isInitialized = false;
  private rpcProvider: Provider;
  private relayerAccount: Account = null!;
  private signer: Signer = null!;

  // Add transaction queue to prevent nonce conflicts
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  constructor(config: AppConfig) {
    this.config = config;
    if (!config.relayerAccountId || !config.relayerPrivateKey) {
      throw new Error('Missing NEAR environment variables for relayer account.');
    }
    this.keyStore = new InMemoryKeyStore();
    if (!config.relayerPrivateKey.startsWith('ed25519:')) {
      throw new Error('Relayer private key must be in format "ed25519:base58privatekey"');
    }
    // Initialize rpcProvider with JsonRpcProvider and a specific URL
    this.rpcProvider = new JsonRpcProvider({ url: config.nearRpcUrl });
    console.log(`AccountService initialized with RPC URL: ${config.nearRpcUrl}`);
  }

  async getRelayerAccount(): Promise<Account> {
    await this._ensureSignerAndRelayerAccount();
    return this.relayerAccount;
  }

  private async _ensureSignerAndRelayerAccount(): Promise<void> {
    if (this.isInitialized) {
      return;
    }
    const privateKeyString = this.config.relayerPrivateKey.substring(8);
    const keyPair = new KeyPairEd25519(privateKeyString);
    await this.keyStore.setKey(this.config.networkId, this.config.relayerAccountId, keyPair);

    this.signer = await getSignerFromKeystore(this.config.relayerAccountId, this.config.networkId, this.keyStore);
    this.relayerAccount = new Account(this.config.relayerAccountId, this.rpcProvider, this.signer);
    this.isInitialized = true;
    console.log(`AccountService signer and relayer account initialized for network: ${this.config.networkId}, relayer: ${this.config.relayerAccountId}`);
  }

  /**
   * Create a new account with the specified balance
   *
   * @param request - Account creation parameters
   * @param onEvent - Optional SSE event emitter for real-time updates
   * @returns Promise<AccountCreationResult> with success status and details
   */
  async createAccount(
    request: AccountCreationRequest,
    onEvent?: SSEEventEmitter,
  ): Promise<AccountCreationResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        if (!this.isValidAccountId(request.accountId)) {
          throw new Error(`Invalid account ID format: ${request.accountId}`);
        }

        // Check if account already exists before attempting creation
        console.log(`Checking if account ${request.accountId} already exists...`);
        const accountExists = await this.checkAccountExists(request.accountId);
        if (accountExists) {
          throw new Error(`Account ${request.accountId} already exists. Cannot create duplicate account.`);
        }
        console.log(`Account ${request.accountId} is available for creation`);

        // Parse initial balance or use default
        const initialBalance = this.config.defaultInitialBalance;

        // Parse the public key
        const publicKey = PublicKey.fromString(request.publicKey);
        console.log(`Creating account: ${request.accountId}`);
        console.log(`Parsed public key: ${publicKey.toString()}`);
        console.log(`Initial balance: ${initialBalance.toString()} yoctoNEAR`);
        console.log(`Creating account ${request.accountId} using relayer: ${this.relayerAccount.accountId}`);

        // Create account using actionCreators (simpler and cleaner)
        const result: FinalExecutionOutcome = await this.relayerAccount.signAndSendTransaction({
          receiverId: request.accountId,
          actions: [
            actionCreators.createAccount(),
            actionCreators.transfer(initialBalance),
            actionCreators.addKey(publicKey, actionCreators.fullAccessKey()),
          ]
        });

        console.log(`Account creation completed successfully: ${result.transaction.hash}`);
        const nearAmount = (Number(initialBalance) / 1e24).toFixed(6);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          accountId: request.accountId,
          message: `Account ${request.accountId} created successfully with ${nearAmount} NEAR initial balance`
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

  /**
   * Create account and register user with WebAuthn in a single atomic transaction
   * Calls the contract's create_account_and_register_user function
   * @param request - Account creation and registration parameters
   * @param onEvent - Optional SSE event emitter callback for progress updates
   * @param sessionId - Optional session ID for SSE tracking
   * @returns Promise resolving to atomic operation result
   */
  async createAccountAndRegisterUser(
    request: CreateAccountAndRegisterRequest,
    onEvent?: SSEEventEmitter,
  ): Promise<CreateAccountAndRegisterResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        if (!this.isValidAccountId(request.new_account_id)) {
          throw new Error(`Invalid account ID format: ${request.new_account_id}`);
        }

        // Check if account already exists before attempting creation
        console.log(`Checking if account ${request.new_account_id} already exists...`);
        const accountExists = await this.checkAccountExists(request.new_account_id);
        if (accountExists) {
          throw new Error(`Account ${request.new_account_id} already exists. Cannot create duplicate account.`);
        }
        console.log(`Account ${request.new_account_id} is available for atomic creation and registration`);

        // Parse the public key
        const publicKey = PublicKey.fromString(request.new_public_key);
        console.log(`Atomic registration for account: ${request.new_account_id}`);
        console.log(`Public key: ${publicKey.toString()}`);
        console.log(`Contract: ${this.config.webAuthnContractId}`);

        // Prepare the contract arguments
        const contractArgs = {
          new_account_id: request.new_account_id,
          new_public_key: request.new_public_key,
          vrf_data: request.vrf_data,
          webauthn_registration: request.webauthn_registration,
          deterministic_vrf_public_key: request.deterministic_vrf_public_key || null,
        };

        // Call the contract's atomic function
        const result: FinalExecutionOutcome = await this.relayerAccount.signAndSendTransaction({
          receiverId: this.config.webAuthnContractId,
          actions: [
            actionCreators.functionCall(
              'create_account_and_register_user',
              contractArgs,
              BigInt('300000000000000'), // 300 TGas for account creation + verification
              this.config.defaultInitialBalance // 0.05 NEAR for account creation
            )
          ]
        });

        // Parse contract execution results to detect failures
        const contractError = this.parseContractExecutionError(result, request.new_account_id);
        if (contractError) {
          console.error(`Contract execution failed for ${request.new_account_id}:`, contractError);
          throw new Error(contractError);
        }

        console.log(`Atomic registration completed successfully: ${result.transaction.hash}`);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          message: `Account ${request.new_account_id} created and registered successfully`,
          contractResult: result,
        };

      } catch (error: any) {
        console.error(`Atomic registration failed for ${request.new_account_id}:`, error);
        return {
          success: false,
          error: error.message || 'Unknown atomic registration error',
          message: `Failed to create and register account ${request.new_account_id}: ${error.message}`
        };
      }
    }, `atomic create and register ${request.new_account_id}`);
  }

  /**
   * Parse contract execution results to detect specific failure types
   * Uses runtime-tested types based on actual NEAR on-chain error structures
   * @param result - The transaction execution result from @near-js/types
   * @param accountId - The account ID being created (for context)
   * @returns Error message if contract execution failed, null if successful
   */
  private parseContractExecutionError(result: FinalExecutionOutcome, accountId: string): string | null {
    try {
      // Check main transaction status first
      if (result.status && typeof result.status === 'object' && 'Failure' in result.status) {
        console.log(`Transaction failed:`, result.status.Failure);
        return `Transaction failed: ${JSON.stringify(result.status.Failure)}`;
      }

      // Check receipts for failures using our runtime-tested types
      const receipts = (result.receipts_outcome || []) as NearReceiptOutcomeWithId[];
      for (const receipt of receipts) {
        const status = receipt.outcome?.status;

        // Check receipt failure status
        if (status?.Failure) {
          const failure: NearExecutionFailure = status.Failure;
          console.log(`Receipt failure detected:`, failure);

          // Check for ActionError with proper typing
          if (failure.ActionError?.kind) {
            const actionKind = failure.ActionError.kind;

            // AccountAlreadyExists is an object with accountId property
            if (actionKind.AccountAlreadyExists) {
              const existingAccountId = actionKind.AccountAlreadyExists.accountId;
              return `Account ${existingAccountId} already exists on NEAR network`;
            }

            // AccountDoesNotExist is an object with account_id property
            if (actionKind.AccountDoesNotExist) {
              const missingAccountId = actionKind.AccountDoesNotExist.account_id;
              return `Referenced account ${missingAccountId} does not exist`;
            }

            // InsufficientStake is an object with account_id, stake, minimum_stake
            if (actionKind.InsufficientStake) {
              const stakeInfo = actionKind.InsufficientStake;
              return `Insufficient stake for account creation: ${stakeInfo.account_id} (has: ${stakeInfo.stake}, needs: ${stakeInfo.minimum_stake})`;
            }

            // LackBalanceForState is an object with account_id, balance
            if (actionKind.LackBalanceForState) {
              const balanceInfo = actionKind.LackBalanceForState;
              return `Insufficient balance for account state: ${balanceInfo.account_id} (balance: ${balanceInfo.balance})`;
            }

            // Generic action error
            return `Account creation failed: ${JSON.stringify(actionKind)}`;
          }

          // Generic failure
          return `Contract execution failed: ${JSON.stringify(failure)}`;
        }

        // Check logs for error keywords
        const logs = receipt.outcome?.logs || [];
        for (const log of logs) {
          if (typeof log === 'string') {
            if (log.includes('AccountAlreadyExists') || log.includes('account already exists')) {
              return `Account ${accountId} already exists`;
            }
            if (log.includes('AccountDoesNotExist')) {
              return `Referenced account does not exist`;
            }
          }
        }
      }

      // No errors detected
      return null;

    } catch (parseError: any) {
      console.warn(`Error parsing contract execution results:`, parseError);
      return null; // Don't fail the transaction due to parsing issues
    }
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

  async checkAccountExists(accountId: string): Promise<boolean> {
    await this._ensureSignerAndRelayerAccount();
    try {
      await this.rpcProvider.query({
        request_type: 'view_account',
        finality: 'final',
        account_id: accountId,
      });
      return true; // Account exists
    } catch (error: any) {
      if (error.type === 'AccountDoesNotExist' || // Legacy check
          (error.cause && error.cause.name === 'UNKNOWN_ACCOUNT')) { // @near-js/providers specific
        return false; // Account does not exist
      }
      console.error(`Error checking account existence for ${accountId} (unexpected error type):`, error);
      throw error; // Rethrow other errors
    }
  }

  /**
   * Queue a transaction to prevent nonce conflicts
   * All transactions from the relayer account must go through this queue
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    console.log(`[AccountService] Queueing transaction: ${description} (pending: ${this.queueStats.pending})`);

    // Chain this operation to the existing queue
    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          console.log(`️[AccountService] Executing transaction: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          console.log(`[AccountService] Completed transaction: ${description} (pending: ${this.queueStats.pending}, completed: ${this.queueStats.completed})`);
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          console.error(`[AccountService] Failed transaction: ${description} (pending: ${this.queueStats.pending}, failed: ${this.queueStats.failed}):`, error?.message || error);
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

export const nearAccountService = new AccountService(config);
