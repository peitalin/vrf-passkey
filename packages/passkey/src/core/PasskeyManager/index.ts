import { WebAuthnManager } from '../WebAuthnManager';
import { registerPasskey } from './registration';
import { loginPasskey } from './login';
import { executeAction } from './actions';
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

/**
 * Main PasskeyManager class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class PasskeyManager {
  private webAuthnManager: WebAuthnManager;
  private nearRpcProvider: any;
  private config: PasskeyManagerConfig;

  constructor(
    config: PasskeyManagerConfig,
    nearRpcProvider?: any
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
    return registerPasskey(this.webAuthnManager, username, options, this.config, this.nearRpcProvider);
  }

  /**
   * Login with an existing passkey
   */
  async loginPasskey(
    username?: string,
    options?: LoginOptions
  ): Promise<LoginResult> {
    return loginPasskey(this.webAuthnManager, username, options, this.config, this.nearRpcProvider);
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

    return executeAction(
      this.webAuthnManager,
      this.nearRpcProvider,
      currentUser,
      actionArgs,
      options,
      this.config
    );
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
      'encryption',
      this.config.optimisticAuth
    );

    if (!passkeyAssertion || !prfOutput) {
      throw new Error('PRF authentication failed - required for key export');
    }

    // Get authentication options for challenge validation
    const { challengeId } = await this.webAuthnManager.getAuthenticationOptionsFromServer(
      this.config.serverUrl,
      username,
      this.config.optimisticAuth
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