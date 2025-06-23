import { WebAuthnManager } from '../WebAuthnManager';
import { indexDBManager } from '../IndexDBManager';
import { VRFManager } from '../WebAuthnManager/vrf-manager';

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
} from '../types/passkeyManager';
import type { SerializableActionArgs } from '../types';
import type { Provider } from '@near-js/providers';
import { TxExecutionStatus } from '@near-js/types';

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
  private vrfManager: VRFManager;
  private vrfInitializationPromise: Promise<void> | null = null;

  constructor(
    config: PasskeyManagerConfig,
    nearRpcProvider: Provider
  ) {
    this.config = config;
    this.webAuthnManager = new WebAuthnManager();
    this.nearRpcProvider = nearRpcProvider;
    this.vrfManager = new VRFManager();

    // Initialize VRF Web Worker automatically in the background
    this.vrfInitializationPromise = this.initializeVRFWorkerInternal();
  }

  /**
   * Internal VRF Web Worker initialization that runs automatically
   * This abstracts VRF implementation details away from users
   */
  private async initializeVRFWorkerInternal(): Promise<void> {
    try {
      console.log('PasskeyManager: Auto-initializing VRF Web Worker...');
      await this.vrfManager.initialize();
      console.log('PasskeyManager: VRF Web Worker auto-initialized successfully');
    } catch (error: any) {
      console.warn('️ PasskeyManager: VRF Web Worker auto-initialization failed:', error.message);
      // Don't throw - VRF is optional, passkey operations can still work without it
    }
  }

  /**
   * Ensure VRF Web Worker is ready (used internally by VRF operations)
   */
  private async ensureVRFReady(): Promise<void> {
    if (this.vrfInitializationPromise) {
      await this.vrfInitializationPromise;
    }
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
    // Ensure VRF Web Worker is ready for VRF operations
    await this.ensureVRFReady();

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

    // Ensure VRF Web Worker is ready for VRF operations
    await this.ensureVRFReady();

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
   * Get access to the VRF manager
   */
  getVRFManager(): VRFManager {
    return this.vrfManager;
  }

  /**
   * Get comprehensive login state information
   * This is the preferred method for frontend components to check login status
   */
  async getLoginState(nearAccountId?: string): Promise<{
    isLoggedIn: boolean;
    nearAccountId: string | null;
    publicKey: string | null;
    vrfActive: boolean;
    userData: any | null;
    vrfSessionDuration?: number;
  }> {
    try {
      // Determine target account ID
      let targetAccountId = nearAccountId;

      if (!targetAccountId) {
        // Try to get the last used account
        targetAccountId = await this.webAuthnManager.getLastUsedNearAccountId() || undefined;
      }

      if (!targetAccountId) {
        return {
          isLoggedIn: false,
          nearAccountId: null,
          publicKey: null,
          vrfActive: false,
          userData: null
        };
      }

      // Get user data from IndexedDB
      const userData = await this.webAuthnManager.getUserData(targetAccountId);
      const indexDBUser = await indexDBManager.getUser(targetAccountId);

      // Check VRF Web Worker status
      await this.ensureVRFReady();
      const vrfStatus = await this.vrfManager.getVRFStatus();
      const vrfActive = vrfStatus.active && vrfStatus.nearAccountId === targetAccountId;

      // Get public key
      const publicKey = userData?.clientNearPublicKey || null;

      // Determine if user is considered "logged in"
      // User is logged in if they have user data and either VRF is active OR they have valid credentials
      const isLoggedIn = !!(userData && (vrfActive || userData.clientNearPublicKey));

      return {
        isLoggedIn,
        nearAccountId: targetAccountId,
        publicKey,
        vrfActive,
        userData: indexDBUser,
        vrfSessionDuration: vrfStatus.sessionDuration
      };

    } catch (error: any) {
      console.warn('Error getting login state:', error);
      return {
        isLoggedIn: false,
        nearAccountId: nearAccountId || null,
        publicKey: null,
        vrfActive: false,
        userData: null
      };
    }
  }

  /**
   * Export private key using PRF-based decryption
   *
   * SECURITY MODEL: Local random challenge is sufficient for private key export because:
   * - User must possess physical authenticator device
   * - Device enforces biometric/PIN verification before PRF access
   * - No network communication or replay attack surface
   * - Challenge only needs to be random to prevent pre-computation
   * - Security comes from device possession + biometrics, not challenge validation
   */
  async exportPrivateKey(nearAccountId?: string, optimisticAuth?: boolean): Promise<string> {
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

    // For private key export, we can use direct WebAuthn authentication with local random challenge
    // This is secure because the security comes from device possession + biometrics, not challenge validation
    console.log('🔐 Using local authentication for private key export (no server coordination needed)');

    // Get stored authenticator data for this user
    const authenticators = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    // Generate local random challenge - this is sufficient for local key export security
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    // Build authentication options using stored credential
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge, // Local random challenge - no server coordination needed
      rpId: window.location.hostname,
      allowCredentials: authenticators.map((auth: any) => ({
        id: new Uint8Array(Buffer.from(auth.credentialID, 'base64')),
        type: 'public-key' as const,
        transports: auth.transports as AuthenticatorTransport[]
      })),
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: new Uint8Array(new Array(32).fill(42)) // Consistent PRF salt for deterministic key derivation
          }
        }
      }
    };

    // Authenticate to get PRF output
    const credential = await navigator.credentials.get({
      publicKey: authOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn authentication failed or was cancelled');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    if (!prfOutput) {
      throw new Error('PRF output not available - required for private key export');
    }

    // Use WASM worker to decrypt private key
    // challengeId parameter is kept for API compatibility but not used for validation
    const localChallengeId = `local-export-${Date.now()}`;
    const decryptionResult = await this.webAuthnManager.securePrivateKeyDecryptionWithPrf(
      nearAccountId,
      prfOutput as ArrayBuffer,
      localChallengeId
    );

    console.log(`✅ Private key exported successfully for account: ${nearAccountId}`);
    return decryptionResult.decryptedPrivateKey;
  }

  /**
   * Export key pair (both private and public keys)
   */
  async exportKeyPair(nearAccountId?: string, optimisticAuth: boolean = false): Promise<{
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
    const privateKey = await this.exportPrivateKey(nearAccountId, optimisticAuth);

    return {
      userAccountId: nearAccountId,
      privateKey,
      publicKey: userData.clientNearPublicKey
    };
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
    if (!this.nearRpcProvider) {
      throw new Error('NEAR RPC provider is required for contract calls');
    }

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
      return this.webAuthnManager.callContract(this.nearRpcProvider, {
        contractId,
        methodName,
        args,
        viewOnly: true
      });
    }

    // 2. Handle calls with pre-obtained PRF (batch mode)
    if (prfOutput) {
      const targetNearAccountId = nearAccountId || await this.webAuthnManager.getLastUsedNearAccountId();
      if (!targetNearAccountId) {
        throw new Error('NEAR account ID required for authenticated contract calls');
      }
      return this.webAuthnManager.callContract(this.nearRpcProvider, {
        contractId,
        methodName,
        args,
        gas,
        attachedDeposit,
        nearAccountId: targetNearAccountId,
        prfOutput
      });
    }

    // 3. Handle state-changing calls that require authentication
    console.log(`Executing state-changing call: ${methodName}`);

    // Get the target account ID
    const targetAccountId = nearAccountId || await this.webAuthnManager.getLastUsedNearAccountId();
    if (!targetAccountId) {
      throw new Error('NEAR account ID required for authenticated contract calls');
    }

    // Determine authentication mode
    let authPrfOutput: ArrayBuffer;

    // Serverless mode: authenticate directly
    console.log('Using serverless mode authentication...');
    const { credential, prfOutput: serverlessPrfOutput } = await this.webAuthnManager.authenticateWithPrf(
      targetAccountId,
      'signing'
    );

    if (!credential || !serverlessPrfOutput) {
      throw new Error('Serverless authentication failed - PRF output required for contract calls.');
    }

    authPrfOutput = serverlessPrfOutput;

    // Execute the contract call with obtained PRF
    return this.webAuthnManager.callContract(this.nearRpcProvider, {
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit,
      nearAccountId: targetAccountId,
      prfOutput: authPrfOutput
    });
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
} from '../types/passkeyManager';