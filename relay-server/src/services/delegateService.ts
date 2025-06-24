import { SignedTransactionComposer, getSignerFromKeystore } from '@near-js/client';
import { JsonRpcProvider } from '@near-js/providers';
import { InMemoryKeyStore } from '@near-js/keystores';
import { KeyPairEd25519 } from '@near-js/crypto';
import { actionCreators, SCHEMA } from '@near-js/transactions';
import { Account } from '@near-js/accounts';
import { deserialize } from 'borsh';
import config from '../config';

// Decode signed delegate and create proper action
function createSignedDelegateAction(encodedSignedDelegate: Uint8Array) {
  console.log(`📦 Creating signedDelegate action from ${encodedSignedDelegate.length} bytes`);

  try {
    // Decode using Borsh deserialization
    const decoded = deserialize(SCHEMA.SignedDelegate, encodedSignedDelegate) as any;
    console.log(`🔍 Decoded signed delegate:`, {
      senderId: decoded.delegateAction?.senderId,
      receiverId: decoded.delegateAction?.receiverId,
      actionsCount: decoded.delegateAction?.actions?.length
    });

    // Validate decoded structure
    if (!decoded.delegateAction || !decoded.signature) {
      throw new Error('Invalid decoded delegate structure: missing delegateAction or signature');
    }

    // Use actionCreators.signedDelegate to create proper action
    console.log(`🔨 Creating action with actionCreators.signedDelegate...`);
    const action = actionCreators.signedDelegate({
      delegateAction: decoded.delegateAction,
      signature: decoded.signature
    });

    console.log(`✅ Successfully created signedDelegate action`);
    return action;

  } catch (error) {
    console.error(`❌ Failed to create signedDelegate action:`, error);
    throw new Error(`Failed to create signedDelegate action: ${(error as Error).message}`);
  }
}

export interface DelegateActionResult {
  success: boolean;
  transactionHash?: string;
  receiverId?: string;
  senderId?: string;
  error?: string;
  message?: string;
}

export interface DelegateActionRequest {
  encodedSignedDelegate: Uint8Array;
  description?: string;
  newAccountId?: string; // For account creation, specify the account to be created
}

export class DelegateService {
  private keyStore: InMemoryKeyStore;
  private rpcProvider: JsonRpcProvider;
  private signer: any;
  private relayerAccount: Account | null = null;
  private isInitialized = false;

  // Transaction queue to prevent nonce conflicts (same pattern as NearClient)
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  constructor() {
    this.keyStore = new InMemoryKeyStore();
    this.rpcProvider = new JsonRpcProvider({ url: config.nodeUrl });
  }

  async init(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      // Set up relayer keystore
      const privateKeyString = config.relayerPrivateKey.substring(8); // Remove 'ed25519:' prefix
      const keyPair = new KeyPairEd25519(privateKeyString);
      await this.keyStore.setKey(config.networkId, config.relayerAccountId, keyPair);

      // Initialize signer
      this.signer = await getSignerFromKeystore(
        config.relayerAccountId,
        config.networkId,
        this.keyStore
      );

      // Initialize relayer account for transaction signing
      this.relayerAccount = new Account(
        config.relayerAccountId,
        this.rpcProvider,
        this.signer
      );

      this.isInitialized = true;
      console.log(`DelegateService initialized for relayer: ${config.relayerAccountId}`);
    } catch (error: any) {
      console.error('Failed to initialize DelegateService:', error);
      throw new Error(`DelegateService initialization failed: ${error.message}`);
    }
  }

  async processDelegateAction(request: DelegateActionRequest): Promise<DelegateActionResult> {
    await this.init();

    const description = request.description || 'delegate action';

    return this.queueTransaction(async () => {
      try {
        console.log(`📥 Received encoded delegate (${request.encodedSignedDelegate.length} bytes)`);

        // First, decode to get the delegate action details
        const decoded = deserialize(SCHEMA.SignedDelegate, request.encodedSignedDelegate) as any;

        // Create the signed delegate action
        const signedDelegateAction = createSignedDelegateAction(request.encodedSignedDelegate);

        console.log(`Processing delegate action: ${description}`);
        console.log(`Delegate sender: ${decoded.delegateAction.senderId}`);
        console.log(`Delegate receiver: ${decoded.delegateAction.receiverId}`);
        console.log(`✅ Created signedDelegate action successfully`);

        if (!this.relayerAccount) {
          throw new Error('Relayer account not initialized');
        }

        console.log(`Executing signed delegate action via relayer account: ${this.relayerAccount.accountId}`);
        console.log(`Transaction receiver will be: ${decoded.delegateAction.receiverId}`);

        // Execute the delegate action by sending a transaction to the delegate's receiver
        // The relayer sends the transaction, but to the delegate action's intended receiver
        const result = await this.relayerAccount.signAndSendTransaction({
          receiverId: decoded.delegateAction.receiverId, // Send to delegate action's receiver
          actions: [signedDelegateAction] // The action contains the user's signed delegate
        });

        console.log(`✅ Delegate action transaction executed successfully:`, result.transaction.hash);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          message: `Successfully executed delegate action: ${description}`
        };

      } catch (error: any) {
        console.error(`❌ Delegate action failed: ${description}:`, error);
        return {
          success: false,
          error: error.message || 'Unknown delegate action error',
          message: `Failed to process delegate action: ${error.message}`
        };
      }
    }, description);
  }

  // Validation is now handled by the actionCreators.signedDelegate approach

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
   * Same pattern as NearClient for consistency
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    console.log(`🔄 [DelegateService] Queueing transaction: ${description} (pending: ${this.queueStats.pending})`);

    // Chain this operation to the existing queue
    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          console.log(`▶️ [DelegateService] Executing transaction: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          console.log(`✅ [DelegateService] Completed transaction: ${description} (pending: ${this.queueStats.pending}, completed: ${this.queueStats.completed})`);
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          console.error(`❌ [DelegateService] Failed transaction: ${description} (pending: ${this.queueStats.pending}, failed: ${this.queueStats.failed}):`, error?.message || error);
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
export const delegateService = new DelegateService();