/**
 * MockNearRpc - Realistic NEAR RPC provider simulation
 *
 * This mock simulates NEAR blockchain interactions including:
 * - Block data with realistic structure
 * - Account creation and access key management
 * - Transaction broadcasting and confirmation
 * - Realistic timing and error scenarios
 */

import type { Provider } from '@near-js/providers';
import type { AccessKeyView } from '@near-js/types';

export interface MockBlockInfo {
  header: {
    height: number;
    hash: string;
    prev_hash: string;
    timestamp: number;
  };
}

export interface MockAccount {
  accountId: string;
  balance: string;
  accessKeys: Map<string, AccessKeyView>;
  exists: boolean;
  createdAt: number;
}

export interface MockTransaction {
  hash: string;
  signer_id: string;
  receiver_id: string;
  actions: any[];
  status: 'pending' | 'success' | 'failure';
  block_height: number;
  timestamp: number;
}

export class MockNearRpc {
  private accounts: Map<string, MockAccount> = new Map();
  private transactions: Map<string, MockTransaction> = new Map();
  private currentBlockHeight = 1000000;
  private currentBlockHash = 'EkbKK1DJKhcF9hjLjE3CaPzCrSkPEaA9FgWj2v8xP2GJ';
  private shouldFailNext: string[] = [];
  private networkDelay = 100; // ms

  constructor() {
    // Initialize with some test accounts
    this.initializeTestAccounts();
  }

  /**
   * Mock viewBlock - returns current block information
   */
  async viewBlock({ finality }: { finality: string }): Promise<MockBlockInfo> {
    if (this.shouldFailNext.includes('viewBlock')) {
      this.removeFailureFlag('viewBlock');
      throw new Error('Network error: Unable to fetch block information');
    }

    await this.simulateNetworkDelay();

    // Increment block height over time
    this.currentBlockHeight += Math.floor(Math.random() * 3) + 1;
    this.currentBlockHash = this.generateBlockHash();

    return {
      header: {
        height: this.currentBlockHeight,
        hash: this.currentBlockHash,
        prev_hash: 'DkbKK1DJKhcF9hjLjE3CaPzCrSkPEaA9FgWj2v8xP2GJ',
        timestamp: Date.now() * 1000000 // NEAR uses nanoseconds
      }
    };
  }

  /**
   * Mock viewAccessKey - returns access key information
   */
  async viewAccessKey(accountId: string, publicKey: string): Promise<AccessKeyView> {
    if (this.shouldFailNext.includes('viewAccessKey')) {
      this.removeFailureFlag('viewAccessKey');
      throw new Error(`Access key ${publicKey} not found for account ${accountId}`);
    }

    await this.simulateNetworkDelay();

    const account = this.accounts.get(accountId);
    if (!account || !account.exists) {
      throw new Error(`Account ${accountId} does not exist`);
    }

    const accessKey = account.accessKeys.get(publicKey);
    if (!accessKey) {
      throw new Error(`Access key ${publicKey} not found for account ${accountId}`);
    }

    return accessKey;
  }

  /**
   * Mock account creation via faucet
   */
  async createTestnetAccount(accountId: string, publicKey: string): Promise<void> {
    if (this.shouldFailNext.includes('createAccount')) {
      this.removeFailureFlag('createAccount');
      throw new Error(`Failed to create account ${accountId}: Network timeout`);
    }

    // Simulate account creation delay
    await this.simulateNetworkDelay(2000);

    if (this.accounts.has(accountId)) {
      throw new Error(`Account ${accountId} already exists`);
    }

    const accessKey: AccessKeyView = {
      nonce: BigInt(0),
      permission: {
        FunctionCall: {
          allowance: '1000000000000000000000000',
          receiver_id: accountId,
          method_names: []
        }
      },
      block_height: this.currentBlockHeight,
      block_hash: this.currentBlockHash
    };

    const account: MockAccount = {
      accountId,
      balance: '100000000000000000000000000', // 100 NEAR
      accessKeys: new Map([[publicKey, accessKey]]),
      exists: true,
      createdAt: Date.now()
    };

    this.accounts.set(accountId, account);
    console.log(`✅ Mock account created: ${accountId}`);
  }

  /**
   * Mock transaction broadcasting
   */
  async broadcastTransaction(signedTransactionBase64: string): Promise<any> {
    if (this.shouldFailNext.includes('broadcastTransaction')) {
      this.removeFailureFlag('broadcastTransaction');
      throw new Error('Transaction broadcast failed: Network congestion');
    }

    await this.simulateNetworkDelay(1500);

    // Generate mock transaction hash
    const txHash = this.generateTransactionHash();

    const transaction: MockTransaction = {
      hash: txHash,
      signer_id: 'test.testnet',
      receiver_id: 'web3-authn.testnet',
      actions: [{ FunctionCall: { method_name: 'verify_registration_response' } }],
      status: 'success',
      block_height: this.currentBlockHeight,
      timestamp: Date.now()
    };

    this.transactions.set(txHash, transaction);

    // Return realistic NEAR RPC response
    return {
      transaction_outcome: {
        id: txHash,
        outcome: {
          status: { SuccessValue: '' },
          gas_burnt: 2428000000000,
          logs: []
        }
      },
      receipts_outcome: [{
        outcome: {
          status: { SuccessValue: '' },
          gas_burnt: 424555062500,
          logs: []
        }
      }]
    };
  }

  /**
   * Mock transaction status query
   */
  async getTransactionStatus(txHash: string): Promise<any> {
    await this.simulateNetworkDelay();

    const transaction = this.transactions.get(txHash);
    if (!transaction) {
      throw new Error(`Transaction ${txHash} not found`);
    }

    return {
      status: { SuccessValue: '' },
      transaction: {
        hash: transaction.hash,
        signer_id: transaction.signer_id,
        receiver_id: transaction.receiver_id,
        actions: transaction.actions
      },
      receipts_outcome: [{
        outcome: {
          status: { SuccessValue: '' },
          gas_burnt: 424555062500,
          logs: []
        }
      }]
    };
  }

  /**
   * Check if account exists
   */
  async accountExists(accountId: string): Promise<boolean> {
    await this.simulateNetworkDelay(50);
    const account = this.accounts.get(accountId);
    return account?.exists === true;
  }

  /**
   * Get account balance
   */
  async getAccountBalance(accountId: string): Promise<string> {
    await this.simulateNetworkDelay();
    const account = this.accounts.get(accountId);
    if (!account || !account.exists) {
      throw new Error(`Account ${accountId} does not exist`);
    }
    return account.balance;
  }

  /**
   * Test utilities
   */
  simulateFailure(operation: string): void {
    this.shouldFailNext.push(operation);
  }

  setNetworkDelay(delayMs: number): void {
    this.networkDelay = delayMs;
  }

  clearAllAccounts(): void {
    this.accounts.clear();
    this.initializeTestAccounts();
  }

  clearAllTransactions(): void {
    this.transactions.clear();
  }

  getAccount(accountId: string): MockAccount | undefined {
    return this.accounts.get(accountId);
  }

  getAllTransactions(): MockTransaction[] {
    return Array.from(this.transactions.values());
  }

  addAccessKey(accountId: string, publicKey: string): void {
    const account = this.accounts.get(accountId);
    if (account) {
      const accessKey: AccessKeyView = {
        nonce: BigInt(account.accessKeys.size),
        permission: {
          FunctionCall: {
            allowance: '1000000000000000000000000',
            receiver_id: accountId,
            method_names: []
          }
        },
        block_height: this.currentBlockHeight,
        block_hash: this.currentBlockHash
      };
      account.accessKeys.set(publicKey, accessKey);
    }
  }

  /**
   * Private methods
   */
  private async simulateNetworkDelay(customDelay?: number): Promise<void> {
    const delay = customDelay || this.networkDelay;
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  private generateBlockHash(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 44; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private generateTransactionHash(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 44; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private removeFailureFlag(operation: string): void {
    const index = this.shouldFailNext.indexOf(operation);
    if (index > -1) {
      this.shouldFailNext.splice(index, 1);
    }
  }

  private initializeTestAccounts(): void {
    // Add some pre-existing test accounts
    const testAccounts = [
      'web3-authn.testnet',
      'faucet.testnet',
      'existing-user.testnet'
    ];

    testAccounts.forEach(accountId => {
      const account: MockAccount = {
        accountId,
        balance: '1000000000000000000000000000', // 1000 NEAR
        accessKeys: new Map(),
        exists: true,
        createdAt: Date.now() - 86400000 // 1 day ago
      };
      this.accounts.set(accountId, account);
    });
  }
}