import { WebAuthnManager } from './WebAuthnManager';
import { indexDBManager } from './IndexDBManager';
import {
  AuthenticationError,
  RegistrationError,
  TransactionError
} from './types';
import type {
  PasskeyConfig,
  RegisterResult,
  LoginResult,
  SignTransactionResult,
  TransactionParams,
  UserData
} from './types';

/**
 * PasskeyManager - Main SDK interface for NEAR passkey authentication
 *
 * This class provides a framework-agnostic interface for:
 * - User registration and login with passkeys
 * - Transaction signing using PRF-enabled passkeys
 * - User state management
 * - Configuration management
 */
export class PasskeyManager {
  private webAuthnManager: WebAuthnManager;
  private config: PasskeyConfig;
  private currentUser: UserData | null = null;

  constructor(config: PasskeyConfig) {
    this.config = { ...config };
    this.webAuthnManager = new WebAuthnManager();

    // Initialize with current user if available
    this.loadCurrentUser();
  }

  // === CONFIGURATION ===

  /**
   * Update configuration
   */
  updateConfig(config: Partial<PasskeyConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration
   */
  getConfig(): PasskeyConfig {
    return { ...this.config };
  }

  // === AUTHENTICATION ===

  /**
   * Register a new user with passkey
   */
  async register(username: string, options?: {
    optimisticAuth?: boolean;
  }): Promise<RegisterResult> {
    try {
      const useOptimistic = options?.optimisticAuth ?? this.config.optimisticAuth ?? true;

      // Generate NEAR account ID
      const nearAccountId = indexDBManager.generateNearAccountId(username, this.config.relayerAccount);

      // Perform WebAuthn registration with PRF
      const { credential, prfEnabled, commitmentId } = await this.webAuthnManager.registerWithPrf(
        username,
        useOptimistic
      );

      if (!prfEnabled) {
        throw new RegistrationError('PRF is required for this registration flow but not enabled/supported by authenticator.');
      }

      // Extract PRF output and perform secure registration
      const extensionResults = credential.getClientExtensionResults();
      const registrationPrfOutput = (extensionResults as any).prf?.results?.first;

      if (!registrationPrfOutput) {
        throw new RegistrationError('PRF output not available from registration.');
      }

      // Generate and encrypt NEAR keypair using PRF
      const prfRegistrationResult = await this.webAuthnManager.secureRegistrationWithPrf(
        username,
        registrationPrfOutput,
        { nearAccountId },
        undefined,
        true // Skip challenge validation as WebAuthn ceremony just completed
      );

      if (!prfRegistrationResult.success) {
        throw new RegistrationError('Client-side key generation/encryption with PRF failed.');
      }

      // Store user data locally
      const userData: UserData = {
        username,
        nearAccountId,
        clientNearPublicKey: prfRegistrationResult.publicKey,
        prfSupported: prfEnabled,
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: credential.id,
          rawId: this.arrayBufferToBase64(credential.rawId)
        }
      };

      await this.webAuthnManager.storeUserData(userData);

      // Update IndexDBManager
      await indexDBManager.registerUser(username, this.config.relayerAccount, {
        preferences: {
          optimisticAuth: useOptimistic,
        },
      });

      this.currentUser = userData;

      return {
        success: true,
        nearAccountId,
        publicKey: prfRegistrationResult.publicKey,
        clientNearPublicKey: prfRegistrationResult.publicKey
      };

    } catch (error: any) {
      if (error instanceof RegistrationError) {
        throw error;
      }
      throw new RegistrationError(`Registration failed: ${error.message}`, error);
    }
  }

  /**
   * Login with passkey
   */
  async login(username?: string, options?: {
    optimisticAuth?: boolean;
  }): Promise<LoginResult> {
    try {
      const useOptimistic = options?.optimisticAuth ?? this.config.optimisticAuth ?? true;

      // Authenticate with PRF
      const { credential, prfOutput } = await this.webAuthnManager.authenticateWithPrf(
        username,
        'signing',
        useOptimistic
      );

      if (!credential || !prfOutput) {
        throw new AuthenticationError('PRF authentication failed or no PRF output');
      }

      // Get user data from credential
      let userData: UserData | null = null;
      if (username) {
        userData = await this.webAuthnManager.getUserData(username);
      } else {
        // For discoverable credentials, we need to identify the user
        // This would typically be done via server verification
        const allUsers = await this.webAuthnManager.getAllUserData();
        userData = allUsers.find(user => user.passkeyCredential?.id === credential.id) || null;
      }

      if (!userData) {
        throw new AuthenticationError('User data not found for authenticated credential');
      }

      // Update last login
      if (userData.nearAccountId) {
        await indexDBManager.updateLastLogin(userData.nearAccountId);
      }

      this.currentUser = userData;

      return {
        success: true,
        loggedInUsername: userData.username,
        clientNearPublicKey: userData.clientNearPublicKey,
        nearAccountId: userData.nearAccountId
      };

    } catch (error: any) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new AuthenticationError(`Login failed: ${error.message}`, error);
    }
  }

  /**
   * Logout current user
   */
  async logout(): Promise<void> {
    this.currentUser = null;
  }

  // === TRANSACTION SIGNING ===

  /**
   * Sign a NEAR transaction using passkey
   */
  async signTransaction(params: TransactionParams): Promise<SignTransactionResult> {
    try {
      if (!this.currentUser) {
        throw new TransactionError('No user logged in');
      }

      if (!this.currentUser.nearAccountId || !this.currentUser.username) {
        throw new TransactionError('User data incomplete');
      }

      // Check if user has PRF support
      if (!this.currentUser.prfSupported) {
        throw new TransactionError('This application requires PRF support');
      }

      // Authenticate with PRF for signing
      const { credential, prfOutput } = await this.webAuthnManager.authenticateWithPrf(
        this.currentUser.username,
        'signing',
        this.config.optimisticAuth ?? true
      );

      if (!credential || !prfOutput) {
        throw new TransactionError('PRF authentication failed for transaction signing');
      }

      // Get authentication options for challenge
      const { challengeId } = await this.webAuthnManager.getAuthenticationOptions(
        this.currentUser.username,
        this.config.optimisticAuth ?? true
      );

      // TODO: Get nonce and block hash from NEAR network
      // For now, we'll need to implement proper NEAR network communication
      const signingPayload = {
        nearAccountId: this.currentUser.nearAccountId,
        receiverId: params.receiverId,
        contractMethodName: params.methodName,
        contractArgs: params.args,
        gasAmount: params.gas || "30000000000000",
        depositAmount: params.deposit || "0",
        nonce: "1", // TODO: Get actual nonce
        blockHashBytes: [] // TODO: Get actual block hash
      };

      const signingResult = await this.webAuthnManager.secureTransactionSigningWithPrf(
        this.currentUser.username,
        prfOutput,
        signingPayload,
        challengeId
      );

      return {
        success: true,
        signedTransactionBorsh: signingResult.signedTransactionBorsh,
        nearAccountId: signingResult.nearAccountId
      };

    } catch (error: any) {
      if (error instanceof TransactionError) {
        throw error;
      }
      throw new TransactionError(`Transaction signing failed: ${error.message}`, error);
    }
  }

  // === STATE MANAGEMENT ===

  /**
   * Get current user data
   */
  async getCurrentUser(): Promise<UserData | null> {
    return this.currentUser;
  }

  /**
   * Check if user is logged in
   */
  async isLoggedIn(): Promise<boolean> {
    return this.currentUser !== null;
  }

  /**
   * Get user by username
   */
  async getUser(username: string): Promise<UserData | null> {
    return this.webAuthnManager.getUserData(username);
  }

  /**
   * Check if passkey credential exists for username
   */
  async hasPasskeyCredential(username: string): Promise<boolean> {
    return this.webAuthnManager.hasPasskeyCredential(username);
  }

  /**
   * Get last used username
   */
  async getLastUsedUsername(): Promise<string | null> {
    return this.webAuthnManager.getLastUsedUsername();
  }

  // === PRIVATE METHODS ===

  private async loadCurrentUser(): Promise<void> {
    try {
      const lastUser = await indexDBManager.getLastUser();
      if (lastUser) {
        const userData = await this.webAuthnManager.getUserData(lastUser.username);
        this.currentUser = userData;
      }
    } catch (error) {
      // Silent fail - user will need to login
      console.warn('Failed to load current user:', error);
    }
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}