import { Account } from '@near-js/accounts';
import { getSignerFromKeystore, view } from '@near-js/client';
import { KeyPairEd25519, PublicKey } from '@near-js/crypto';
import { InMemoryKeyStore, type KeyStore } from '@near-js/keystores';
import { JsonRpcProvider, type Provider } from '@near-js/providers';
import type { Signer } from '@near-js/signers';
import { actionCreators } from '@near-js/transactions';
import { FinalExecutionOutcome } from '@near-js/types';

import * as dotenv from 'dotenv';
dotenv.config();
import type { SSEEventEmitter } from './types';
import config, { type AppConfig } from './config';

// Interfaces for relay server API
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
   * Simplified account creation for relay server API
   * Creates account with actionCreators (cleaner than LocalAccountCreator)
   * @param request - Account creation parameters
   * @param request.accountId - The desired NEAR account ID
   * @param request.publicKey - The public key to associate with the account (ed25519:...)
   * @param onEvent - Optional SSE event emitter callback for progress updates
   * @param sessionId - Optional session ID for SSE tracking
   * @returns Promise resolving to account creation result with success status and transaction details
   */
  async createAccount(
    request: AccountCreationRequest,
    onEvent?: SSEEventEmitter,
    sessionId?: string
  ): Promise<AccountCreationResult> {
    await this._ensureSignerAndRelayerAccount();

    const currentSessionId = sessionId || `relay_${Date.now()}_${Math.random().toString(36).substring(2)}`;

    return this.queueTransaction(async () => {
      try {
        // Emit user ready event
        onEvent?.({
          step: 2,
          sessionId: currentSessionId,
          phase: 'user-ready',
          status: 'success',
          timestamp: Date.now(),
          message: 'Relay server ready to create account',
          verified: true,
          nearAccountId: request.accountId,
          clientNearPublicKey: request.publicKey,
          mode: 'relay-server'
        });

        if (!this.isValidAccountId(request.accountId)) {
          throw new Error(`Invalid account ID format: ${request.accountId}`);
        }

        // Emit access key addition start event
        onEvent?.({
          step: 3,
          sessionId: currentSessionId,
          phase: 'access-key-addition',
          status: 'progress',
          timestamp: Date.now(),
          message: 'Starting account creation with access key...'
        });

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
            actionCreators.addKey(publicKey, actionCreators.fullAccessKey())
          ]
        });

        // Emit access key addition success event
        onEvent?.({
          step: 3,
          sessionId: currentSessionId,
          phase: 'access-key-addition',
          status: 'success',
          timestamp: Date.now(),
          message: `Account ${request.accountId} created successfully with access key`
        });

        // Emit account verification event
        onEvent?.({
          step: 4,
          sessionId: currentSessionId,
          phase: 'account-verification',
          status: 'success',
          timestamp: Date.now(),
          message: 'Account creation verified on NEAR blockchain'
        });

        // Emit registration complete event
        onEvent?.({
          step: 7,
          sessionId: currentSessionId,
          phase: 'registration-complete',
          status: 'success',
          timestamp: Date.now(),
          message: 'Account creation completed successfully!'
        });

        console.log(`Account created successfully: ${result.transaction.hash}`);
        const nearAmount = (Number(initialBalance) / 1e24).toFixed(4);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          accountId: request.accountId,
          message: `Account ${request.accountId} created successfully with ${nearAmount} NEAR initial balance`
        };

      } catch (error: any) {
        console.error(`Account creation failed for ${request.accountId}:`, error);

        // Emit error event
        onEvent?.({
          step: 0,
          sessionId: currentSessionId,
          phase: 'registration-error',
          status: 'error',
          timestamp: Date.now(),
          message: `Account creation failed: ${error.message}`,
          error: error.message || 'Unknown account creation error'
        });

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
