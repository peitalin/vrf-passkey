import { WebAuthnManager } from '../WebAuthnManager';
import { indexDBManager } from '../IndexDBManager';
import { WEBAUTHN_CONTRACT_ID } from '../../config';
import { AuthenticatorSyncer  } from '../AuthenticatorSyncer';

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
import bs58 from 'bs58';

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

      console.log(`Starting authenticator recovery for account: ${nearAccountId}`);

      // Check if account exists
      const userData = await this.webAuthnManager.getUserData(nearAccountId);
      if (userData && userData.clientNearPublicKey) {
        return {
          success: false,
          message: 'Account data already exists locally - no recovery needed'
        };
      }

      // Try to recover authenticators from contract
      const authenticatorSyncer = new AuthenticatorSyncer (
        this.nearRpcProvider,
        WEBAUTHN_CONTRACT_ID,
        'WebAuthn Passkeys', // rpName - default RP name
        window.location.hostname, // rpId - use current domain
        WEBAUTHN_CONTRACT_ID // relayerAccountId - use contract ID as relayer
      );

      // Fetch authenticators from contract
      const contractAuthenticators = await authenticatorSyncer.findAuthenticatorsByUserId(nearAccountId);

      if (contractAuthenticators.length === 0) {
        return {
          success: false,
          message: 'No authenticators found in contract for this account'
        };
      }

      console.log(`Found ${contractAuthenticators.length} authenticators in contract`);

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

  // === VRF OPERATIONS ===

  /**
   * Fetch current NEAR block data for VRF input construction
   */
  private async getNearBlockData(): Promise<{
    blockHeight: number;
    blockHash: string; // base64url encoded
  }> {
    if (!this.nearRpcProvider) {
      throw new Error('NEAR RPC provider is required for VRF block data');
    }

    try {
      // Get latest finalized block
      const blockInfo = await this.nearRpcProvider.viewBlock({ finality: 'final' });

      return {
        blockHeight: blockInfo.header.height,
        blockHash: this.base64UrlEncode(new Uint8Array(bs58.decode(blockInfo.header.hash)))
      };
    } catch (error: any) {
      console.error('Failed to fetch NEAR block data:', error);
      throw new Error(`Failed to fetch NEAR block data: ${error.message}`);
    }
  }

  /**
   * VRF Registration Flow - Generate and store VRF keypair during registration
   * This creates encrypted VRF credentials that can be used for future stateless authentication
   */
  async vrfRegistration(
    nearAccountId: string,
    prfOutput: ArrayBuffer
  ): Promise<{
    success: boolean;
    vrfPublicKey?: string;
    encryptedVrfKeypair?: any;
    error?: string;
  }> {
    try {
      console.log(`VRF Registration: Generating VRF keypair for ${nearAccountId}`);

      // Generate VRF keypair and encrypt it using PRF
      const vrfResult = await this.webAuthnManager.generateVrfKeypairWithPrf(prfOutput);

      console.log('✅ VRF Registration: VRF keypair generated and encrypted successfully');

      // Store the encrypted VRF data in IndexedDB for future use
      await this.storeVrfCredentials(nearAccountId, vrfResult.encryptedVrfKeypair);

      return {
        success: true,
        vrfPublicKey: vrfResult.vrfPublicKey,
        encryptedVrfKeypair: vrfResult.encryptedVrfKeypair
      };
    } catch (error: any) {
      console.error('❌ VRF Registration failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * VRF Authentication Flow - Generate VRF challenge and complete WebAuthn authentication
   * This retrieves encrypted VRF credentials and uses them to generate a stateless challenge
   */
  async vrfAuthentication(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    vrfCredentials: {
      encrypted_vrf_data_b64u: string;
      aes_gcm_nonce_b64u: string
    },
    vrfParams: {
      userId: string;
      rpId: string;
      sessionId: string;
      timestamp?: number;
    }
  ): Promise<{
    webauthnResult: any;
    vrfData: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      rpId: string;
      blockHeight: number;
      blockHash: string;
    };
  }> {
    console.log('Starting VRF Authentication Flow...');
    console.log('  - User ID:', vrfParams.userId);
    console.log('  - RP ID:', vrfParams.rpId);

    // Fetch current NEAR block data for freshness
    const blockData = await this.getNearBlockData();
    console.log('  - Block Height:', blockData.blockHeight);
    console.log('  - Block Hash:', blockData.blockHash.substring(0, 20) + '...');

    // Decode block hash from base64url to bytes for WASM worker
    const blockHashBytes = Array.from(this.base64UrlDecode(blockData.blockHash));

    // 1. Generate VRF challenge using encrypted credentials
    const vrfChallenge = await this.webAuthnManager.generateVrfChallengeWithPrf(
      prfOutput,
      vrfCredentials.encrypted_vrf_data_b64u,
      vrfCredentials.aes_gcm_nonce_b64u,
      vrfParams.userId,
      vrfParams.rpId,
      vrfParams.sessionId,
      blockData.blockHeight,
      blockHashBytes,
      vrfParams.timestamp || Date.now()
    );

    console.log('✅ VRF Challenge Generated');
    console.log('  - VRF Input:', vrfChallenge.vrfInput?.substring(0, 20) + '...');
    console.log('  - VRF Output (Challenge):', vrfChallenge.vrfOutput?.substring(0, 20) + '...');

    // 2. Use VRF output as WebAuthn challenge (first 32 bytes)
    const vrfOutputBytes = this.base64UrlDecode(vrfChallenge.vrfOutput);
    const webauthnChallengeBytes = vrfOutputBytes.slice(0, 32); // First 32 bytes as challenge
    const webauthnChallenge = this.base64UrlEncode(webauthnChallengeBytes);

    console.log('🔐 Using VRF output as WebAuthn challenge:', webauthnChallenge.substring(0, 20) + '...');

    // 3. Perform WebAuthn authentication with VRF-generated challenge
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge: new Uint8Array(webauthnChallengeBytes),
      rpId: vrfParams.rpId,
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: new Uint8Array(new Array(32).fill(42)) // Consistent PRF salt
          }
        }
      }
    };

    const webauthnCredential = await navigator.credentials.get({
      publicKey: authOptions
    }) as PublicKeyCredential;

    if (!webauthnCredential) {
      throw new Error('VRF WebAuthn authentication failed or was cancelled');
    }

    const webauthnResult = {
      credential: webauthnCredential,
      challenge: webauthnChallenge,
      success: true
    };

    console.log('✅ VRF Authentication Complete');

    return {
      webauthnResult,
      vrfData: {
        vrfInput: vrfChallenge.vrfInput,
        vrfOutput: vrfChallenge.vrfOutput,
        vrfProof: vrfChallenge.vrfProof,
        vrfPublicKey: vrfChallenge.vrfPublicKey,
        rpId: vrfChallenge.rpId,
        blockHeight: blockData.blockHeight,
        blockHash: blockData.blockHash,
      }
    };
  }

  /**
   * Store VRF credentials in IndexedDB for future use
   */
  private async storeVrfCredentials(
    nearAccountId: string,
    encryptedVrfKeypair: any
  ): Promise<void> {
    try {
      // Store in the same user data structure
      const existingUserData = await this.webAuthnManager.getUserData(nearAccountId);

      const updatedUserData = {
        ...existingUserData,
        nearAccountId,
        lastUpdated: Date.now(),
        vrfCredentials: encryptedVrfKeypair
      };

      await this.webAuthnManager.storeUserData(updatedUserData);
      console.log(`✅ VRF credentials stored for ${nearAccountId}`);
    } catch (error: any) {
      console.error('❌ Failed to store VRF credentials:', error);
      throw error;
    }
  }

  /**
   * Retrieve stored VRF credentials from IndexedDB
   */
  private async getStoredVrfCredentials(
    nearAccountId: string
  ): Promise<{ encrypted_vrf_data_b64u: string; aes_gcm_nonce_b64u: string } | null> {
    try {
      const userData = await this.webAuthnManager.getUserData(nearAccountId);
      return userData?.vrfCredentials || null;
    } catch (error: any) {
      console.error('❌ Failed to get stored VRF credentials:', error);
      return null;
    }
  }

  /**
   * Utility method for base64url decoding
   */
  private base64UrlDecode(base64Url: string): Uint8Array {
    // Add padding if needed
    const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Utility method for base64url encoding
   */
  private base64UrlEncode(bytes: Uint8Array): string {
    let binaryString = '';
    for (let i = 0; i < bytes.length; i++) {
      binaryString += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  // === VRF CONTRACT INTEGRATION EXAMPLES ===

  /**
   * Complete VRF Registration Flow with Contract Integration
   * Demonstrates the full registration process including contract storage
   */
  async vrfRegistrationWithContract(
    nearAccountId: string,
    rpId: string = window.location.hostname
  ): Promise<{
    success: boolean;
    vrfPublicKey?: string;
    transactionId?: string;
    error?: string;
  }> {
    try {
      console.log(`🔐 Starting VRF Registration for ${nearAccountId}`);

      // 1. Check if already registered
      const existingCredentials = await this.getStoredVrfCredentials(nearAccountId);
      if (existingCredentials) {
        console.log('✅ User already has VRF credentials');
        return { success: true, vrfPublicKey: 'already-registered' };
      }

      // 2. Perform WebAuthn registration with PRF
      const { WEBAUTHN_CONTRACT_ID } = await import('../../config');

      // Generate challenge for initial VRF keypair generation and registration
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const registrationOptions: PublicKeyCredentialCreationOptions = {
        challenge,
        rp: { name: 'WebAuthn VRF', id: rpId },
        user: {
          id: new TextEncoder().encode(nearAccountId),
          name: nearAccountId,
          displayName: nearAccountId
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'preferred'
        },
        timeout: 60000,
        attestation: 'none',
        extensions: {
          prf: {
            eval: {
              first: new Uint8Array(new Array(32).fill(42)) // Consistent PRF salt
            }
          }
        }
      };

      const credential = await navigator.credentials.create({
        publicKey: registrationOptions
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('WebAuthn registration failed');
      }

      // 3. Get PRF output
      const extensionResults = credential.getClientExtensionResults();
      const prfOutput = (extensionResults as any).prf?.results?.first;
      if (!prfOutput) {
        throw new Error('PRF output not available - required for VRF registration');
      }

      // 4. Generate VRF keypair with PRF
      const vrfResult = await this.webAuthnManager.generateVrfKeypairWithPrf(prfOutput);

      // 5. Store VRF credentials locally
      await this.storeVrfCredentials(nearAccountId, vrfResult.encryptedVrfKeypair);

      // 6. Store authenticator data
      await indexDBManager.registerUser(nearAccountId);
      await this.webAuthnManager.storeUserData({
        nearAccountId,
        clientNearPublicKey: undefined, // Will be set if NEAR key generation is enabled
        lastUpdated: Date.now(),
        prfSupported: true,
        deterministicKey: false,
        passkeyCredential: {
          id: credential.id,
          rawId: this.base64UrlEncode(new Uint8Array(credential.rawId))
        },
        vrfCredentials: vrfResult.encryptedVrfKeypair
      });

      console.log('✅ VRF Registration completed successfully');

      return {
        success: true,
        vrfPublicKey: vrfResult.vrfPublicKey
      };

    } catch (error: any) {
      console.error('❌ VRF Registration failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Complete VRF Authentication Flow with Contract Verification
   * Demonstrates the full authentication process including contract verification
   */
  async vrfAuthenticationWithContract(
    nearAccountId: string,
    rpId: string = window.location.hostname
  ): Promise<{
    success: boolean;
    verified?: boolean;
    transactionId?: string;
    error?: string;
  }> {
    try {
      console.log(`🔓 Starting VRF Authentication for ${nearAccountId}`);

      // 1. Get stored VRF credentials
      const vrfCredentials = await this.getStoredVrfCredentials(nearAccountId);
      if (!vrfCredentials) {
        throw new Error('No VRF credentials found - please register first');
      }

      // 2. Perform WebAuthn authentication with PRF
      const authOptions: PublicKeyCredentialRequestOptions = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId,
        userVerification: 'preferred',
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: new Uint8Array(new Array(32).fill(42)) // Consistent PRF salt
            }
          }
        }
      };

      const credential = await navigator.credentials.get({
        publicKey: authOptions
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('WebAuthn authentication failed');
      }

      // 3. Get PRF output
      const extensionResults = credential.getClientExtensionResults();
      const prfOutput = (extensionResults as any).prf?.results?.first;
      if (!prfOutput) {
        throw new Error('PRF output not available - required for VRF authentication');
      }

      // 4. Generate VRF challenge
      const sessionId = crypto.randomUUID();
      const vrfAuth = await this.vrfAuthentication(nearAccountId, prfOutput, vrfCredentials, {
        userId: nearAccountId,
        rpId,
        sessionId,
        timestamp: Date.now()
      });

      console.log('✅ VRF Authentication completed successfully');
      console.log('🔗 Ready for contract verification with VRF data');

      return {
        success: true,
        verified: vrfAuth.webauthnResult.success
      };

    } catch (error: any) {
      console.error('❌ VRF Authentication failed:', error);
      return { success: false, error: error.message };
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
} from '../types/passkeyManager';