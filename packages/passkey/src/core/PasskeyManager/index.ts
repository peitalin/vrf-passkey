import { WebAuthnManager } from '../WebAuthnManager';
import { indexDBManager } from '../IndexDBManager';
import { RELAYER_ACCOUNT_ID, RPC_NODE_URL } from '../../config';
import { registerPasskey } from './registration';
import { loginPasskey } from './login';
import { executeAction } from './actions';
import bs58 from 'bs58';
import type {
  PasskeyManagerConfig,
  RegistrationOptions,
  RegistrationResult,
  LoginOptions,
  LoginResult,
  ActionOptions,
  ActionResult
} from './types';
import type { SerializableActionArgs } from '../../types';

import { getSignerFromKeystore, getTestnetRpcProvider } from '@near-js/client';
import { SignedTransaction } from '@near-js/transactions';
import type { Provider } from '@near-js/providers';
import { AccessKeyView, FinalExecutionOutcome, TxExecutionStatus } from '@near-js/types';
import { KeyPairEd25519 } from '@near-js/crypto';
import type { Signer } from '@near-js/signers';
import { BrowserLocalStorageKeyStore } from '@near-js/keystores-browser';

// See default finality settings
// https://github.com/near/near-api-js/blob/99f34864317725467a097dc3c7a3cc5f7a5b43d4/packages/accounts/src/account.ts#L68
export const DEFAULT_WAIT_STATUS: TxExecutionStatus = "INCLUDED_FINAL";

/**
 * Main PasskeyManager class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class PasskeyManager {
  private webAuthnManager: WebAuthnManager;
  private nearRpcProvider: Provider;
  private config: PasskeyManagerConfig;

  constructor(
    config: PasskeyManagerConfig,
    nearRpcProvider: Provider
  ) {
    this.config = config;
    this.webAuthnManager = new WebAuthnManager();
    this.nearRpcProvider = nearRpcProvider;
  }

  /**
   * Register a new passkey for the given NEAR account ID
   */
  async registerPasskey(
    nearAccountId: string,
    options: RegistrationOptions
  ): Promise<RegistrationResult> {
    return registerPasskey(this, nearAccountId, options);
  }

  /**
   * Login with an existing passkey
   */
  async loginPasskey(
    nearAccountId: string,
    options?: LoginOptions
  ): Promise<LoginResult> {
    return loginPasskey(this, nearAccountId, options);
  }

  /**
   * Execute a blockchain action/transaction
   */
  async executeAction(
    nearAccountId: string,
    actionArgs: SerializableActionArgs,
    options?: ActionOptions
  ): Promise<ActionResult> {
    if (!this.nearRpcProvider) {
      throw new Error('NEAR RPC provider is required for action execution');
    }

    return executeAction(this, nearAccountId, actionArgs, options);
  }

  /**
   * Set the NEAR RPC provider
   */
  setNearRpcProvider(provider: any): void {
    this.nearRpcProvider = provider;
  }

  /**
   * Get the current configuration
   */
  getConfig(): PasskeyManagerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<PasskeyManagerConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get access to the underlying WebAuthnManager for advanced operations
   */
  getWebAuthnManager(): WebAuthnManager {
    return this.webAuthnManager;
  }

  /**
   * Export private key using PRF-based decryption
   */
  async exportPrivateKey(nearAccountId?: string): Promise<string> {
    // If no nearAccountId provided, try to get the last used account
    if (!nearAccountId) {
      const lastUsedNearAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
      if (!lastUsedNearAccountId) {
        throw new Error('No NEAR account ID provided and no last used account found');
      }
      nearAccountId = lastUsedNearAccountId;
    }

    // Get user data to verify user exists
    const userData = await this.webAuthnManager.getUserData(nearAccountId);
    if (!userData) {
      throw new Error(`No user data found for ${nearAccountId}`);
    }

    if (!userData.prfSupported) {
      throw new Error('PRF is required for private key export but not supported by this user\'s authenticator');
    }

    console.log(`🔐 Exporting private key for account: ${nearAccountId}`);

    // Check if serverUrl is configured for authentication
    if (!this.config.serverUrl) {
      throw new Error('serverUrl is required in config for private key export operations');
    }

    // Authenticate with PRF to get PRF output
    const { credential: passkeyAssertion, prfOutput } = await this.webAuthnManager.authenticateWithPrfAndUrl(
      this.config.serverUrl,
      nearAccountId,
      'encryption'
    );

    if (!passkeyAssertion || !prfOutput) {
      throw new Error('PRF authentication failed - required for key export');
    }

    // Get authentication options for challenge validation
    const { challengeId } = await this.webAuthnManager.getAuthenticationOptionsFromServer(
      this.config.serverUrl,
      nearAccountId
    );

    // Use WASM worker to decrypt private key
    const decryptionResult = await this.webAuthnManager.securePrivateKeyDecryptionWithPrf(
      nearAccountId,
        prfOutput,
        challengeId
      );

    console.log(`✅ Private key exported successfully for account: ${nearAccountId}`);
    return decryptionResult.decryptedPrivateKey;
  }

  /**
   * Export key pair (both private and public keys)
   */
  async exportKeyPair(nearAccountId?: string): Promise<{
    userAccountId: string;
    privateKey: string;
    publicKey: string
  }> {
    // If no nearAccountId provided, try to get the last used account
    if (!nearAccountId) {
      const lastUsedNearAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
      if (!lastUsedNearAccountId) {
        throw new Error('No NEAR account ID provided and no last used account found');
      }
      nearAccountId = lastUsedNearAccountId;
    }

    // Get user data to retrieve public key
    const userData = await this.webAuthnManager.getUserData(nearAccountId);
    if (!userData) {
      throw new Error(`No user data found for ${nearAccountId}`);
    }

    if (!userData.clientNearPublicKey) {
      throw new Error(`No NEAR public key found for account ${nearAccountId}`);
    }

    // Export private key using the method above
    const privateKey = await this.exportPrivateKey(nearAccountId);

    return {
      userAccountId: nearAccountId,
      privateKey,
      publicKey: userData.clientNearPublicKey
    };
  }

  // /**
  //  * Export a NEAR signer instance for the user
  //  */
  // async exportSigner(nearAccountId?: string): Promise<{ userAccountId: string, signer: Signer }> {
  //   // If no nearAccountId provided, try to get the last used account
  //   if (!nearAccountId) {
  //     const lastUsedNearAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
  //     if (!lastUsedNearAccountId) {
  //       throw new Error('No NEAR account ID provided and no last used account found');
  //     }
  //     nearAccountId = lastUsedNearAccountId;
  //   }
  //   const { userAccountId, privateKey } = await this.exportKeyPair(nearAccountId);
  //   // Extract the private key string (remove "ed25519:" prefix if present)
  //   const privateKeyString = privateKey.startsWith('ed25519:')
  //     ? privateKey.substring(8)
  //     : privateKey;
  //   const keyPair = new KeyPairEd25519(privateKeyString);
  //   const keyStore = new BrowserLocalStorageKeyStore();
  //   await keyStore.setKey(this.config.nearNetwork, userAccountId, keyPair);
  //   const signer = await getSignerFromKeystore(userAccountId, this.config.nearNetwork, keyStore);
  //   return { userAccountId, signer };
  // }

  /**
   * Get public key for the current or specified user
   */
  async getPublicKey(nearAccountId?: string): Promise<string | null> {
    // If no nearAccountId provided, try to get the last used account
    if (!nearAccountId) {
      const lastUsedNearAccountId = await this.webAuthnManager.getLastUsedNearAccountId();
      if (!lastUsedNearAccountId) {
        return null;
      }
      nearAccountId = lastUsedNearAccountId;
    }

    try {
      const userData = await this.webAuthnManager.getUserData(nearAccountId);
      return userData?.clientNearPublicKey || null;
    } catch (error) {
      console.warn(`Error getting public key for account ${nearAccountId}:`, error);
      return null;
    }
  }

  /**
   * Unified contract call function that intelligently handles all scenarios:
   * - View functions (no auth required)
   * - State-changing functions (with auth)
   * - Batch operations (with PRF reuse)
   *
   * @param options - All call parameters and options
   */
  async callContract(options: {
    /** Contract to call */
    contractId: string;
    /** Method name to call */
    methodName: string;
    /** Method arguments */
    args: any;
    /** Gas amount for state-changing calls */
    gas?: string;
    /** Attached deposit for state-changing calls */
    attachedDeposit?: string;
    /** NEAR account ID for authentication (auto-detected if not provided) */
    nearAccountId?: string;
    /** Pre-obtained PRF output for batch operations */
    prfOutput?: ArrayBuffer;
    /** Force view mode (read-only, no authentication) */
    viewOnly?: boolean;
    /** Force state-changing mode (requires authentication) */
    requiresAuth?: boolean;
    /** Force server mode (optimisticAuth==true) or serverless mode (optimisticAuth==false) */
    optimisticAuth?: boolean;
  }): Promise<any> {
    const {
      contractId,
      methodName,
      args,
      gas = '50000000000000',
      attachedDeposit = '0',
      nearAccountId,
      prfOutput,
      viewOnly = false,
      requiresAuth = false,
      optimisticAuth
    } = options;

    // 1. Handle explicit view-only calls
    if (viewOnly) {
      return this._executeViewCall(contractId, methodName, args);
    }

    // 2. Handle state-changing calls
    console.log(`Executing state-changing call: ${methodName}`);

    // 2a. Use pre-obtained PRF if available (batch mode)
    if (prfOutput) {
      const targetNearAccountId = nearAccountId || await this.webAuthnManager.getLastUsedNearAccountId();
      if (!targetNearAccountId) {
        throw new Error('NEAR account ID required for authenticated contract calls');
      }
      return this._executeAuthenticatedCallWithPrf(
        contractId,
        methodName,
        args,
        gas,
        attachedDeposit,
        targetNearAccountId,
        prfOutput
      );
    }

    // 2b. Regular authenticated call (triggers TouchID)
    return this._executeAuthenticatedCall(
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit,
      nearAccountId,
      optimisticAuth
    );
  }

  /**
   * Execute a view call (read-only, no authentication)
   */
  private async _executeViewCall(
    contractId: string,
    methodName: string,
    args: any
  ): Promise<any> {
    console.log(`Calling contract view function: ${methodName}`);

    const result = await this.nearRpcProvider.query({
      request_type: 'call_function',
      account_id: contractId,
      method_name: methodName,
      args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
      finality: 'optimistic'
    });

    return result;
  }

  /**
   * Execute an authenticated call (triggers TouchID)
   */
  private async _executeAuthenticatedCall(
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string,
    nearAccountId?: string,
    optimisticAuth?: boolean
  ): Promise<FinalExecutionOutcome> {
    // Get the current user if nearAccountId not provided
    const targetNearAccountId = nearAccountId || await this.webAuthnManager.getLastUsedNearAccountId();
    if (!targetNearAccountId) {
      throw new Error('No NEAR account ID provided and no previous user found. NEAR account ID required for contract calls.');
    }

    // First authenticate to get PRF output and challenge
    let challengeId: string;
    let prfOutput: ArrayBuffer;

    if (optimisticAuth) {
      // Server mode: get challenge from server
      if (!this.config.serverUrl) {
        throw new Error('Server URL is required for server mode authentication.');
      }

      const { credential, prfOutput: authPrfOutput } = await this.webAuthnManager.authenticateWithPrfAndUrl(
        this.config.serverUrl,
        targetNearAccountId,
        'signing'
      );

      if (!credential || !authPrfOutput) {
        throw new Error('Authentication failed - PRF output required for contract calls.');
      }

      // Get the challenge from the authentication options
      const { challengeId: authChallengeId } = await this.webAuthnManager.getAuthenticationOptionsFromServer(
        this.config.serverUrl,
        targetNearAccountId
      );

      challengeId = authChallengeId;
      prfOutput = authPrfOutput;
    } else {
      // Serverless mode: authenticate directly without contract challenge
      if (!this.nearRpcProvider) {
        throw new Error('NEAR RPC provider is required for serverless contract calls.');
      }

      // Authenticate with PRF (no server URL needed)
      const { credential, prfOutput: authPrfOutput } = await this.webAuthnManager.authenticateWithPrf(
        targetNearAccountId,
        'signing'
      );

      if (!credential || !authPrfOutput) {
        throw new Error('Authentication failed - PRF output required for contract calls.');
      }

      // For serverless mode, we use a dummy challenge ID since we're not using the contract's challenge system
      challengeId = 'serverless-' + crypto.randomUUID();
      prfOutput = authPrfOutput;
    }

    return this._signAndSubmitTransaction(
      targetNearAccountId,
      prfOutput,
      challengeId,
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit
    );
  }

  /**
   * Execute an authenticated call with pre-obtained PRF (no additional TouchID)
   */
  private async _executeAuthenticatedCallWithPrf(
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string,
    nearAccountId: string,
    prfOutput: ArrayBuffer
  ): Promise<FinalExecutionOutcome> {
    // For serverless mode with pre-obtained PRF, use a dummy challenge ID
    const challengeId = 'serverless-reused-prf-' + crypto.randomUUID();

    console.log("callContract (with PRF): secureTransactionSigningWithPrf", challengeId);

    return this._signAndSubmitTransaction(
      nearAccountId,
      prfOutput,
      challengeId,
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit
    );
  }

  /**
   * Common transaction signing and submission logic
   */
  private async _signAndSubmitTransaction(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    challengeId: string,
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string
  ): Promise<FinalExecutionOutcome> {
    // Get user data to retrieve public key for nonce lookup
    const userData = await this.webAuthnManager.getUserData(nearAccountId);
    if (!userData?.clientNearPublicKey) {
      throw new Error('Client NEAR public key not found in user data');
    }

    // Get current nonce and block info concurrently
    const [accessKeyInfo, blockInfo] = await Promise.all([
      this.nearRpcProvider.viewAccessKey(
        nearAccountId,
        userData.clientNearPublicKey,
      ) as Promise<AccessKeyView>,
      this.nearRpcProvider.viewBlock({ finality: 'final' })
    ]);

    const nonce = accessKeyInfo.nonce + BigInt(1); // Proper nonce calculation

    console.log("callContract: secureTransactionSigningWithPrf", challengeId);
    // Use WASM worker to sign and execute the contract call
    const signedTxResult = await this.webAuthnManager.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      {
        nearAccountId,
        receiverId: contractId,
        contractMethodName: methodName,
        contractArgs: args,
        gasAmount: gas,
        depositAmount: attachedDeposit,
        nonce: nonce.toString(),
        blockHashBytes: Array.from(bs58.decode(blockInfo.header.hash))
      },
      challengeId
    );

    // Create a SignedTransaction object from the Borsh bytes
    const signedTransaction = SignedTransaction.decode(Buffer.from(signedTxResult.signedTransactionBorsh));

    try {
      // Submit the transaction asynchronously to avoid RPC timeouts
      console.log("Submitting transaction with optimistic execution...");
      const finalResult = await this.nearRpcProvider.sendTransactionUntil(
        signedTransaction,
        DEFAULT_WAIT_STATUS // "INCLUDED_FINAL"
      );

      console.log("Transaction successful:", finalResult);
      return finalResult;

    } catch (error: any) {
      console.error("Transaction failed:", error);
      throw new Error(`Transaction submission failed: ${error.message}`);
    }
  }
}


// Re-export types for convenience
export type {
  PasskeyManagerConfig,
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  LoginOptions,
  LoginResult,
  LoginEvent,
  ActionOptions,
  ActionResult,
  ActionEvent,
  EventCallback,
  OperationHooks
} from './types';