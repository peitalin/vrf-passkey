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
   * Register a new passkey for the given username
   */
  async registerPasskey(
    username: string,
    options: RegistrationOptions
  ): Promise<RegistrationResult> {
    return registerPasskey(this, username, options);
  }

  /**
   * Login with an existing passkey
   */
  async loginPasskey(
    username?: string,
    options?: LoginOptions
  ): Promise<LoginResult> {
    return loginPasskey(this, username, options);
  }

  /**
   * Execute a blockchain action/transaction
   */
  async executeAction(
    currentUser: {
      isLoggedIn: boolean;
      username: string | null;
      nearAccountId: string | null;
    },
    actionArgs: SerializableActionArgs,
    options?: ActionOptions
  ): Promise<ActionResult> {
    if (!this.nearRpcProvider) {
      throw new Error('NEAR RPC provider is required for action execution');
    }

    return executeAction(this, currentUser, actionArgs, options);
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
  async exportPrivateKey(username?: string): Promise<string> {
    // If no username provided, try to get the last used username
    if (!username) {
      const lastUsedUsername = await this.webAuthnManager.getLastUsedUsername();
      if (!lastUsedUsername) {
        throw new Error('No username provided and no last used username found');
      }
      username = lastUsedUsername;
    }

    // Get user data to verify user exists
    const userData = await this.webAuthnManager.getUserData(username);
    if (!userData) {
      throw new Error(`No user data found for ${username}`);
    }

    if (!userData.prfSupported) {
      throw new Error('PRF is required for private key export but not supported by this user\'s authenticator');
    }

    console.log(`🔐 Exporting private key for user: ${username}`);

    // Check if serverUrl is configured for authentication
    if (!this.config.serverUrl) {
      throw new Error('serverUrl is required in config for private key export operations');
    }

    // Authenticate with PRF to get PRF output
    const { credential: passkeyAssertion, prfOutput } = await this.webAuthnManager.authenticateWithPrfAndUrl(
      this.config.serverUrl,
      username,
      'encryption'
    );

    if (!passkeyAssertion || !prfOutput) {
      throw new Error('PRF authentication failed - required for key export');
    }

    // Get authentication options for challenge validation
    const { challengeId } = await this.webAuthnManager.getAuthenticationOptionsFromServer(
      this.config.serverUrl,
      username
    );

    // Use WASM worker to decrypt private key
    const decryptionResult = await this.webAuthnManager.securePrivateKeyDecryptionWithPrf(
      username,
        prfOutput,
        challengeId
      );

    console.log(`✅ Private key exported successfully for user: ${username}`);
    return decryptionResult.decryptedPrivateKey;
  }

  /**
   * Export key pair (both private and public keys)
   */
  async exportKeyPair(username?: string): Promise<{
    userAccountId: string;
    privateKey: string;
    publicKey: string
  }> {
    // If no username provided, try to get the last used username
    if (!username) {
      const lastUsedUsername = await this.webAuthnManager.getLastUsedUsername();
      if (!lastUsedUsername) {
        throw new Error('No username provided and no last used username found');
      }
      // relayerAccount is the top-level account that creates the account for users,
      // hence the username is username.relayerAccount
      username = lastUsedUsername;
    }

    // Get user data to retrieve public key
    const userData = await this.webAuthnManager.getUserData(username);
    if (!userData) {
      throw new Error(`No user data found for ${username}`);
    }

    if (!userData.clientNearPublicKey) {
      throw new Error(`No NEAR public key found for user ${username}`);
    }

    // Export private key using the method above
    const privateKey = await this.exportPrivateKey(username);
    const userAccountId = `${username}.${this.config.relayerAccount}`;

    return {
      userAccountId,
      privateKey,
      publicKey: userData.clientNearPublicKey
    };
  }

  /**
   * Export signer using PRF-based decryption and create a KeyPairEd25519
   */
  async exportSigner(username?: string): Promise<{ userAccountId: string, signer: Signer }> {
    // Export the key pair first
    const { userAccountId, privateKey, publicKey } = await this.exportKeyPair(username);

    // Extract the private key string (remove "ed25519:" prefix if present)
    const privateKeyString = privateKey.startsWith('ed25519:')
      ? privateKey.substring(8)
      : privateKey;

    // Create KeyPairEd25519 from the private key string
    const keyPair = new KeyPairEd25519(privateKeyString);

    let keyStore = new BrowserLocalStorageKeyStore();
    await keyStore.setKey(this.config.nearNetwork, userAccountId, keyPair);

    let signer = await getSignerFromKeystore(userAccountId, this.config.nearNetwork, keyStore);
    console.log(`✅ Signer created successfully for user account: ${userAccountId}`);

    return {
      userAccountId,
      signer,
    };
  }

  /**
   * Get public key for the current or specified user
   */
  async getPublicKey(username?: string): Promise<string | null> {
    // If no username provided, try to get the last used username
    if (!username) {
      const lastUsedUsername = await this.webAuthnManager.getLastUsedUsername();
      if (!lastUsedUsername) {
        return null;
      }
      username = lastUsedUsername;
    }

    try {
      const userData = await this.webAuthnManager.getUserData(username);
      return userData?.clientNearPublicKey || null;
    } catch (error) {
      console.warn(`Error getting public key for user ${username}:`, error);
      return null;
    }
  }


  /**
   * Call a contract function using WASM worker to sign the transaction
   * This provides the same API as near-js callFunction but uses the WASM worker
   */
  async callFunction2(
    contractId: string,
    methodName: string,
    args: any,
    gas: string = '50000000000000',
    attachedDeposit: string = '0',
    username?: string
  ): Promise<FinalExecutionOutcome> {
    // Get the current user if username not provided
    const targetUsername = username || await this.webAuthnManager.getLastUsedUsername();
    if (!targetUsername) {
      throw new Error('No username provided and no previous user found. Username required for contract calls.');
    }

    const targetNearAccountId = indexDBManager.generateNearAccountId(targetUsername, this.config.relayerAccount);

    // First authenticate to get PRF output and challenge
    let challengeId: string;
    let prfOutput: ArrayBuffer;

    if (this.config.optimisticAuth && this.config.serverUrl) {
      // Server mode: get challenge from server
      const { credential, prfOutput: authPrfOutput } = await this.webAuthnManager.authenticateWithPrfAndUrl(
        this.config.serverUrl,
        targetUsername,
        'signing'
      );

      if (!credential || !authPrfOutput) {
        throw new Error('Authentication failed - PRF output required for contract calls.');
      }

      console.log(">>>>>>optimisticAuth: ", this.config.optimisticAuth);
      console.log("serverUrl: ", this.config.serverUrl);

      // Get the challenge from the authentication options
      const { challengeId: authChallengeId } = await this.webAuthnManager.getAuthenticationOptionsFromServer(
        this.config.serverUrl,
        targetUsername
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
        targetUsername,
        'signing'
      );

      if (!credential || !authPrfOutput) {
        throw new Error('Authentication failed - PRF output required for contract calls.');
      }

      // For serverless mode, we use a dummy challenge ID since we're not using the contract's challenge system
      challengeId = 'serverless-' + crypto.randomUUID();
      prfOutput = authPrfOutput;
    }

    // Get user data to retrieve public key for nonce lookup
    const userData = await this.webAuthnManager.getUserData(targetUsername);
    if (!userData?.clientNearPublicKey) {
      throw new Error('Client NEAR public key not found in user data');
    }

    // Get current nonce and block info concurrently
    const [accessKeyInfo, blockInfo] = await Promise.all([
      this.nearRpcProvider.viewAccessKey(
        targetNearAccountId,
        userData.clientNearPublicKey,
      ) as Promise<AccessKeyView>,
      this.nearRpcProvider.viewBlock({ finality: 'final' })
    ]);

    const nonce = accessKeyInfo.nonce + BigInt(1); // Proper nonce calculation

    console.log("callFunction: secureTransactionSigningWithPrf", challengeId);
    // Use WASM worker to sign and execute the contract call
    const signedTxResult = await this.webAuthnManager.secureTransactionSigningWithPrf(
      targetUsername,
      prfOutput,
      {
        nearAccountId: targetNearAccountId,
        receiverId: contractId,
        contractMethodName: methodName,
        contractArgs: args,
        gasAmount: gas,
        depositAmount: attachedDeposit,
        nonce: nonce.toString(),
        blockHashBytes: Array.from(bs58.decode(blockInfo.header.hash))
      },
      challengeId // Use the challenge from server, or the dummy challenge in serverless mode
      // dummy challenge prompts contract to generate a real challenge
    );

    // Submit the signed transaction to the network
    const signedTransactionBorsh = new Uint8Array(signedTxResult.signedTransactionBorsh);
    console.log("callFunction: sending transaction", signedTransactionBorsh);
    console.log("Transaction size:", signedTransactionBorsh.length, "bytes");
    console.log("Transaction base64 preview:", Buffer.from(signedTransactionBorsh).toString('base64').substring(0, 100) + "...");

    try {
      console.log("Using NEAR JS provider to submit transaction...");

      // Create a SignedTransaction object from the Borsh bytes
      const signedTransaction = SignedTransaction.decode(Buffer.from(signedTransactionBorsh));

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