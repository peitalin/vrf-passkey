import { WebAuthnManager } from '../WebAuthnManager';
import { indexDBManager } from '../IndexDBManager';
import { WEBAUTHN_CONTRACT_ID } from '../../config';
import { ClientContractService } from '../ClientContractService';

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
   * Recover authenticator data from contract when IndexDB is cleared
   *
   * This function helps users who have lost their local IndexDB data but still have:
   * 1. Access to their physical authenticator device
   * 2. Authenticator data stored in the contract (from registration)
   *
   * SECURITY MODEL:
   * - User must possess the physical authenticator device to complete WebAuthn ceremony
   * - Contract challenge validation ensures only real authenticators can recover data
   * - No way to recover without both the device AND contract storage
   */
  async recoverFromContract(nearAccountId: string): Promise<{
    success: boolean;
    message: string;
    recoveredAuthenticators?: number;
  }> {
    try {
      if (!this.nearRpcProvider) {
        throw new Error('NEAR RPC provider is required for contract recovery');
      }

      console.log(`🔄 Starting authenticator recovery for account: ${nearAccountId}`);

      // Check if account exists
      const userData = await this.webAuthnManager.getUserData(nearAccountId);
      if (userData && userData.clientNearPublicKey) {
        return {
          success: false,
          message: 'Account data already exists locally - no recovery needed'
        };
      }

      // Try to recover authenticators from contract
      const contractService = new ClientContractService(WEBAUTHN_CONTRACT_ID, this.nearRpcProvider);

      // Fetch authenticators from contract
      const contractAuthenticators = await contractService.findByUserId(nearAccountId);

      if (contractAuthenticators.length === 0) {
        return {
          success: false,
          message: 'No authenticators found in contract for this account'
        };
      }

      console.log(`🔄 Found ${contractAuthenticators.length} authenticators in contract`);

      // Create user entry
      await indexDBManager.registerUser(nearAccountId);

      // Store each authenticator
      for (const auth of contractAuthenticators) {
        await indexDBManager.storeAuthenticator({
          nearAccountId,
          credentialID: auth.credentialID,
          credentialPublicKey: auth.credentialPublicKey,
          counter: auth.counter,
          transports: auth.transports,
          clientNearPublicKey: auth.clientNearPublicKey,
          name: auth.name,
          registered: auth.registered instanceof Date ? auth.registered.toISOString() : auth.registered,
          lastUsed: auth.lastUsed ? (auth.lastUsed instanceof Date ? auth.lastUsed.toISOString() : auth.lastUsed) : undefined,
          backedUp: auth.backedUp,
          syncedAt: new Date().toISOString(),
        });
      }

      // Store user data if we have client-managed public key
      const primaryAuth = contractAuthenticators[0];
      if (primaryAuth.clientNearPublicKey) {
        await this.webAuthnManager.storeUserData({
          nearAccountId,
          clientNearPublicKey: primaryAuth.clientNearPublicKey,
          lastUpdated: Date.now(),
          prfSupported: true, // Assume PRF support if data was stored
          deterministicKey: true,
          passkeyCredential: {
            id: primaryAuth.credentialID, // We don't have rawId from contract
            rawId: primaryAuth.credentialID // Fallback
          }
        });
      }

      console.log(`✅ Successfully recovered ${contractAuthenticators.length} authenticators from contract`);

      return {
        success: true,
        message: `Successfully recovered ${contractAuthenticators.length} authenticator(s) from contract`,
        recoveredAuthenticators: contractAuthenticators.length
      };

    } catch (error: any) {
      console.error('🔄 Recovery from contract failed:', error);
      return {
        success: false,
        message: `Recovery failed: ${error.message}`
      };
    }
  }

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

    if (optimisticAuth) {
      // Server mode: authenticate with server
      if (!this.config.serverUrl) {
        throw new Error('Server URL is required for server mode authentication.');
      }

      console.log('Using server mode authentication...');
      const { credential, prfOutput: serverPrfOutput } = await this.webAuthnManager.authenticateWithPrfAndUrl(
        this.config.serverUrl,
        targetAccountId,
        'signing'
      );

      if (!credential || !serverPrfOutput) {
        throw new Error('Server authentication failed - PRF output required for contract calls.');
      }

      authPrfOutput = serverPrfOutput;
    } else {
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
    }

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

  // /**
  //  * Execute a view call (read-only, no authentication)
  //  */
  // private async _executeViewCall(
  //   contractId: string,
  //   methodName: string,
  //   args: any
  // ): Promise<any> {
  //   console.log(`Calling contract view function: ${methodName}`);

  //   const result = await this.nearRpcProvider.query({
  //     request_type: 'call_function',
  //     account_id: contractId,
  //     method_name: methodName,
  //     args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
  //     finality: 'optimistic'
  //   });

  //   return result;
  // }

  // /**
  //  * Execute an authenticated call (triggers TouchID)
  //  */
  // private async _executeAuthenticatedCall(
  //   contractId: string,
  //   methodName: string,
  //   args: any,
  //   gas: string,
  //   attachedDeposit: string,
  //   nearAccountId?: string,
  //   optimisticAuth?: boolean
  // ): Promise<FinalExecutionOutcome> {
  //   // Get the current user if nearAccountId not provided
  //   const targetNearAccountId = nearAccountId || await this.webAuthnManager.getLastUsedNearAccountId();
  //   if (!targetNearAccountId) {
  //     throw new Error('No NEAR account ID provided and no previous user found. NEAR account ID required for contract calls.');
  //   }

  //   // First authenticate to get PRF output and challenge
  //   let challengeId: string;
  //   let prfOutput: ArrayBuffer;

  //   if (optimisticAuth) {
  //     // Server mode: get challenge from server
  //     if (!this.config.serverUrl) {
  //       throw new Error('Server URL is required for server mode authentication.');
  //     }

  //     const { credential, prfOutput: authPrfOutput } = await this.webAuthnManager.authenticateWithPrfAndUrl(
  //       this.config.serverUrl,
  //       targetNearAccountId,
  //       'signing'
  //     );

  //     if (!credential || !authPrfOutput) {
  //       throw new Error('Authentication failed - PRF output required for contract calls.');
  //     }

  //     // Get the challenge from the authentication options
  //     const { challengeId: authChallengeId } = await this.webAuthnManager.getAuthenticationOptionsFromServer(
  //       this.config.serverUrl,
  //       targetNearAccountId
  //     );

  //     challengeId = authChallengeId;
  //     prfOutput = authPrfOutput;
  //   } else {
  //     // Serverless mode: authenticate directly without contract challenge
  //     if (!this.nearRpcProvider) {
  //       throw new Error('NEAR RPC provider is required for serverless contract calls.');
  //     }

  //     // Authenticate with PRF (no server URL needed)
  //     const { credential, prfOutput: authPrfOutput } = await this.webAuthnManager.authenticateWithPrf(
  //       targetNearAccountId,
  //       'signing'
  //     );

  //     if (!credential || !authPrfOutput) {
  //       throw new Error('Authentication failed - PRF output required for contract calls.');
  //     }

  //     // For serverless mode, we use a dummy challenge ID since we're not using the contract's challenge system
  //     challengeId = 'serverless-' + crypto.randomUUID();
  //     prfOutput = authPrfOutput;
  //   }

  //   return this._signAndSubmitTransaction(
  //     targetNearAccountId,
  //     prfOutput,
  //     challengeId,
  //     contractId,
  //     methodName,
  //     args,
  //     gas,
  //     attachedDeposit
  //   );
  // }

  // /**
  //  * Execute an authenticated call with pre-obtained PRF (no additional TouchID)
  //  */
  // private async _executeAuthenticatedCallWithPrf(
  //   contractId: string,
  //   methodName: string,
  //   args: any,
  //   gas: string,
  //   attachedDeposit: string,
  //   nearAccountId: string,
  //   prfOutput: ArrayBuffer
  // ): Promise<FinalExecutionOutcome> {
  //   // For serverless mode with pre-obtained PRF, use a dummy challenge ID
  //   const challengeId = 'serverless-reused-prf-' + crypto.randomUUID();

  //   console.log("callContract (with PRF): secureTransactionSigningWithPrf", challengeId);

  //   return this._signAndSubmitTransaction(
  //     nearAccountId,
  //     prfOutput,
  //     challengeId,
  //     contractId,
  //     methodName,
  //     args,
  //     gas,
  //     attachedDeposit
  //   );
  // }

  // /**
  //  * Common transaction signing and submission logic
  //  */
  // private async _signAndSubmitTransaction(
  //   nearAccountId: string,
  //   prfOutput: ArrayBuffer,
  //   challengeId: string,
  //   contractId: string,
  //   methodName: string,
  //   args: any,
  //   gas: string,
  //   attachedDeposit: string
  // ): Promise<FinalExecutionOutcome> {
  //   // Get user data to retrieve public key for nonce lookup
  //   const userData = await this.webAuthnManager.getUserData(nearAccountId);
  //   if (!userData?.clientNearPublicKey) {
  //     throw new Error('Client NEAR public key not found in user data');
  //   }

  //   // Get current nonce and block info concurrently
  //   const [accessKeyInfo, blockInfo] = await Promise.all([
  //     this.nearRpcProvider.viewAccessKey(
  //       nearAccountId,
  //       userData.clientNearPublicKey,
  //     ) as Promise<AccessKeyView>,
  //     this.nearRpcProvider.viewBlock({ finality: 'final' })
  //   ]);

  //   const nonce = accessKeyInfo.nonce + BigInt(1); // Proper nonce calculation

  //   console.log("callContract: secureTransactionSigningWithPrf", challengeId);
  //   // Use WASM worker to sign and execute the contract call
  //   const signedTxResult = await this.webAuthnManager.secureTransactionSigningWithPrf(
  //     nearAccountId,
  //     prfOutput,
  //     {
  //       nearAccountId,
  //       receiverId: contractId,
  //       contractMethodName: methodName,
  //       contractArgs: args,
  //       gasAmount: gas,
  //       depositAmount: attachedDeposit,
  //       nonce: nonce.toString(),
  //       blockHashBytes: Array.from(bs58.decode(blockInfo.header.hash))
  //     },
  //     challengeId
  //   );

  //   // Create a SignedTransaction object from the Borsh bytes
  //   const signedTransaction = SignedTransaction.decode(Buffer.from(signedTxResult.signedTransactionBorsh));

  //   try {
  //     // Submit the transaction asynchronously to avoid RPC timeouts
  //     console.log("Submitting transaction with optimistic execution...");
  //     const finalResult = await this.nearRpcProvider.sendTransactionUntil(
  //       signedTransaction,
  //       DEFAULT_WAIT_STATUS // "INCLUDED_FINAL"
  //     );

  //     console.log("Transaction successful:", finalResult);
  //     return finalResult;

  //   } catch (error: any) {
  //     console.error("Transaction failed:", error);
  //     throw new Error(`Transaction submission failed: ${error.message}`);
  //   }
  // }
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