import { getSignerFromKeystore, view } from '@near-js/client';
import { JsonRpcProvider } from '@near-js/providers';
import { Account, LocalAccountCreator } from '@near-js/accounts';
import { KeyPairEd25519, PublicKey } from '@near-js/crypto';
import { InMemoryKeyStore } from '@near-js/keystores';
import type { KeyStore } from '@near-js/keystores';
import type { Signer } from '@near-js/signers';
import type { Provider } from '@near-js/providers';
import { type CreateAccountResult } from './types';


const PASSKEY_CONTROLLER_CONTRACT_ID = process.env.PASSKEY_CONTROLLER_CONTRACT_ID!;
const RELAYER_ACCOUNT_ID = process.env.RELAYER_ACCOUNT_ID!;
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY!;
const NEAR_NETWORK_ID = process.env.NEAR_NETWORK_ID || 'testnet';
const WEBAUTHN_CONTRACT_ID = process.env.WEBAUTHN_CONTRACT_ID!;
const NEAR_RPC_URL = process.env.NEAR_RPC_URL || 'https://rpc.testnet.near.org';


class NearClient {
  private keyStore: KeyStore;
  private rpcProvider: Provider;
  private signer: Signer = null!;
  private relayerAccount: Account = null!;
  private isInitialized = false;

  // Add transaction queue to prevent nonce conflicts
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  constructor() {
    if (!RELAYER_ACCOUNT_ID || !RELAYER_PRIVATE_KEY) {
      throw new Error('Missing NEAR environment variables for relayer account.');
    }
    if (!PASSKEY_CONTROLLER_CONTRACT_ID) {
      throw new Error('Missing NEAR environment variables for passkey controller.');
    }
    this.keyStore = new InMemoryKeyStore();
    if (!RELAYER_PRIVATE_KEY.startsWith('ed25519:')) {
      throw new Error('Relayer private key must be in format "ed25519:base58privatekey"');
    }

    // Initialize rpcProvider with JsonRpcProvider and a specific URL
    this.rpcProvider = new JsonRpcProvider({ url: NEAR_RPC_URL });
    console.log(`NearClient initialized with RPC URL: ${NEAR_RPC_URL}`);
  }

  public getProvider(): Provider {
    return this.rpcProvider;
  }

  public getRelayerAccount(): Account {
    return this.relayerAccount;
  }

  private async _ensureSignerAndRelayerAccount(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    const privateKeyString = RELAYER_PRIVATE_KEY.substring(8);
    const keyPair = new KeyPairEd25519(privateKeyString);
    await this.keyStore.setKey(NEAR_NETWORK_ID, RELAYER_ACCOUNT_ID, keyPair);

    this.signer = await getSignerFromKeystore(RELAYER_ACCOUNT_ID, NEAR_NETWORK_ID, this.keyStore);
    this.relayerAccount = new Account(RELAYER_ACCOUNT_ID, this.rpcProvider, this.signer);
    this.isInitialized = true;
    console.log(`NearClient signer and relayer account initialized for network: ${NEAR_NETWORK_ID}, relayer: ${RELAYER_ACCOUNT_ID}`);
    // console.log(`Passkey Controller Contract ID: ${PASSKEY_CONTROLLER_CONTRACT_ID}`);
  }

  public async callFunction(receiverId: string, methodName: string, args: Record<string, any>, gas: string, deposit: string): Promise<any> {
    await this._ensureSignerAndRelayerAccount();

    const description = `${methodName} on ${receiverId}`;

    return this.queueTransaction(async () => {
      console.log(`NearClient: Relayer ${this.relayerAccount.accountId} calling contract: ${receiverId}, method: ${methodName} with args:`, args);

      try {
        const result = await this.relayerAccount.signAndSendTransaction({
          receiverId,
          actions: [
            // @ts-ignore
            {
              functionCall: {
                methodName,
                args: Buffer.from(JSON.stringify(args)),
                gas: BigInt(gas),
                deposit: BigInt(deposit)
              }
            }
          ]
        });
        return result;
      } catch (error) {
        console.error(`NearClient: Error during functionCall for ${methodName} on ${receiverId}:`, error);
        throw error;
      }
    }, description);
  }

  private async _executeFunctionCallAction(receiverId: string, methodName: string, args: Record<string, any>, gas: bigint, deposit: bigint): Promise<any> {
    await this._ensureSignerAndRelayerAccount();

    const description = `${methodName} on ${receiverId} (via _executeFunctionCallAction)`;

    return this.queueTransaction(async () => {
      console.log(`NearClient: Relayer ${this.relayerAccount.accountId} calling contract: ${receiverId}, method: ${methodName} with args:`, args);

      try {
        return await this.relayerAccount.callFunction({
          contractId: receiverId,
          methodName: methodName,
          args: args,
          gas: gas,
          deposit: deposit
        });
      } catch (error) {
        console.error(`NearClient: Error during functionCall for ${methodName} on ${this.relayerAccount.accountId}:`, error);
        throw error;
      }
    }, description);
  }

  async getTrustedRelayer(): Promise<string> {
    await this._ensureSignerAndRelayerAccount();
    return view({
      account: PASSKEY_CONTROLLER_CONTRACT_ID,
      method: 'get_trusted_relayer',
      args: {},
      deps: { rpcProvider: this.rpcProvider },
    });
  }

  // async getOwnerId(): Promise<string> {
  //   await this._ensureSignerAndRelayerAccount();
  //   return view({
  //     account: PASSKEY_CONTROLLER_CONTRACT_ID,
  //     method: 'get_owner_id',
  //     args: {},
  //     deps: { rpcProvider: this.rpcProvider },
  //   });
  // }

  // async addPasskeyPk(passkeyPk: string): Promise<any> {
  //   await this._ensureSignerAndRelayerAccount();
  //   return this._executeFunctionCallAction(
  //     PASSKEY_CONTROLLER_CONTRACT_ID,
  //     'add_passkey_pk',
  //     { passkey_pk: passkeyPk },
  //     BigInt('30000000000000'),
  //     BigInt('0')
  //   );
  // }

  // async removePasskeyPk(passkeyPk: string): Promise<any> {
  //   await this._ensureSignerAndRelayerAccount();
  //   return this._executeFunctionCallAction(
  //     PASSKEY_CONTROLLER_CONTRACT_ID,
  //     'remove_passkey_pk',
  //     { passkey_pk: passkeyPk },
  //     BigInt('30000000000000'),
  //     BigInt('0')
  //   );
  // }

  // async executeActions(
  //   passkeyPkUsed: string,
  //   actionToExecute: SerializableActionArgs
  // ): Promise<any> {
  //   await this._ensureSignerAndRelayerAccount();

  //   const argsForContractMethod = {
  //     passkey_pk_used: passkeyPkUsed,
  //     action_to_execute: actionToExecute
  //   };

  //   return this._executeFunctionCallAction(
  //     PASSKEY_CONTROLLER_CONTRACT_ID,
  //     'execute_delegated_actions',
  //     argsForContractMethod,
  //     BigInt('300000000000000'),
  //     BigInt('0')
  //   );
  // }

  async getGreeting(): Promise<string> {
    await this._ensureSignerAndRelayerAccount();
    console.log(`NearClient: Calling get_greeting on ${WEBAUTHN_CONTRACT_ID}`);
    try {
      const result = await view({
        account: WEBAUTHN_CONTRACT_ID,
        method: 'get_greeting',
        args: {},
        deps: { rpcProvider: this.rpcProvider },
      });
      return result as string;
    } catch (error) {
      console.error('NearClient: Error calling get_greeting:', error);
      throw error;
    }
  }

  async setGreeting(greeting: string): Promise<any> {
    await this._ensureSignerAndRelayerAccount();
    console.log(`NearClient: Calling set_greeting on ${WEBAUTHN_CONTRACT_ID} with greeting: "${greeting}"`);
    return this._executeFunctionCallAction(
      WEBAUTHN_CONTRACT_ID,
      'set_greeting',
      { greeting: greeting },
      BigInt('30000000000000'),
      BigInt('0')
    );
  }

  async createAccount(
    accountId: string,
    publicKeyString: string,
    initialBalance: bigint = BigInt('20000000000000000000000') // Changed to 0.02 NEAR
  ): Promise<CreateAccountResult> {
    await this._ensureSignerAndRelayerAccount();

    if (!this.relayerAccount || !this.relayerAccount.accountId) {
        throw new Error("Relayer account details not initialized in NearClient.");
    }
    if (!accountId.endsWith(`.${this.relayerAccount.accountId}`)) {
      const errMsg = `NearClient: createAccount can only create subaccounts of ${this.relayerAccount.accountId}. Received: ${accountId}`;
      console.error(errMsg);
      // Throwing error here is consistent with strict validation,
      return { success: false, message: errMsg, error: new Error(errMsg) };
    }

    try {
      PublicKey.fromString(publicKeyString);
    } catch (e: any) {
      const errMsg = `Invalid public key format: ${publicKeyString}. Error: ${e.message}`;
      console.error("NearClient: Invalid public key format for createAccount", publicKeyString, e.message);
      return { success: false, message: errMsg, error: e };
    }

    const description = `createAccount ${accountId}`;

    return this.queueTransaction(async () => {
      console.log(`NearClient: Creating account ${accountId} with public key ${publicKeyString} and balance ${initialBalance.toString()} yoctoNEAR`);

      try {
        const accountCreator = new LocalAccountCreator(
          this.relayerAccount,
          initialBalance
        );
        // accountCreator.createAccount is void according to user's recent diff note
        await accountCreator.createAccount(accountId, PublicKey.fromString(publicKeyString));
        console.log(`NearClient: Account creation call for ${accountId} completed.`);
        return {
          success: true,
          message: 'Account created successfully via NearClient.',
          result: {
            accountId: accountId,
            publicKey: publicKeyString,
          }
        };
      } catch (error: any) {
        console.error(`NearClient: Error creating account ${accountId}:`, error);
        let msg = error.message || 'Failed to create account in NearClient.';
        if (error.message && error.message.includes("CreateAccountNotAllowed")) {
           msg = `Error creating account ${accountId}: ${error.message}`;
        } else if (error.message && error.message.includes("does not have enough balance")) {
            msg = `Error creating account ${accountId}: Relayer account ${this.relayerAccount.accountId} does not have enough balance. Full error: ${error.message}`;
        }
        return { success: false, message: msg, error: error };
      }
    }, description);
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

  async addAccessKey(
    accountId: string,
    publicKeyString: string,
    allowance?: bigint
  ): Promise<CreateAccountResult> {
    await this._ensureSignerAndRelayerAccount();

    try {
      PublicKey.fromString(publicKeyString);
    } catch (e: any) {
      const errMsg = `Invalid public key format: ${publicKeyString}. Error: ${e.message}`;
      console.error("NearClient: Invalid public key format for addAccessKey", publicKeyString, e.message);
      return { success: false, message: errMsg, error: e };
    }

    const description = `addAccessKey ${publicKeyString} to ${accountId}`;

    return this.queueTransaction(async () => {
      console.log(`NearClient: Adding access key ${publicKeyString} to account ${accountId}`);

      try {
        const publicKey = PublicKey.fromString(publicKeyString);

        // Use the relayer account to add the access key to the target account
        // The relayer has permission to manage subaccount keys
        const result = await this.relayerAccount.signAndSendTransaction({
          receiverId: accountId,
          actions: [
            // @ts-ignore: enum action-type typings mismatch
            {
              addKey: {
                publicKey: publicKey,
                accessKey: {
                  nonce: BigInt(0),
                  // @ts-ignore: enum permission typings mismatch
                  permission: { fullAccess: {} }
                }
              }
            }
          ]
        });

        console.log(`NearClient: Successfully added access key to ${accountId}`);
        return {
          success: true,
          message: 'Access key added successfully',
          result: {
            accountId: accountId,
            publicKey: publicKeyString,
          }
        };
      } catch (error: any) {
        console.error(`NearClient: Error adding access key to ${accountId}:`, error);
        const msg = error.message || 'Failed to add access key';
        return { success: false, message: msg, error: error };
      }
    }, description);
  }

  /**
   * Queue a transaction to prevent nonce conflicts
   * All transactions from the relayer account must go through this queue
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    console.log(`🔄 [NearClient] Queueing transaction: ${description} (pending: ${this.queueStats.pending})`);

    // Chain this operation to the existing queue
    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          console.log(`▶️ [NearClient] Executing transaction: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          console.log(`✅ [NearClient] Completed transaction: ${description} (pending: ${this.queueStats.pending}, completed: ${this.queueStats.completed})`);
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          console.error(`❌ [NearClient] Failed transaction: ${description} (pending: ${this.queueStats.pending}, failed: ${this.queueStats.failed}):`, error?.message || error);
          throw error;
        }
      })
      .catch((error) => {
        // Ensure the queue continues even if this transaction fails
        throw error;
      });

    return this.transactionQueue;
  }

  /**
   * Get transaction queue diagnostics
   */
  getQueueDiagnostics() {
    return {
      ...this.queueStats,
      queueEmpty: this.queueStats.pending === 0,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Wait for all pending transactions to complete
   */
  async waitForQueueEmpty(): Promise<void> {
    console.log(`🔄 [NearClient] Waiting for transaction queue to empty (pending: ${this.queueStats.pending})`);
    try {
      await this.transactionQueue;
      console.log(`✅ [NearClient] Transaction queue is now empty`);
    } catch (error) {
      console.log(`✅ [NearClient] Transaction queue processed (some transactions may have failed)`);
    }
  }
}

export const nearClient = new NearClient();
