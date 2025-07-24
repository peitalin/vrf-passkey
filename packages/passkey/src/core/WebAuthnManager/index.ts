import type { PasskeyManagerConfigs } from '../types/passkeyManager';
import type { onProgressEvents, VerifyAndSignTransactionResult, VRFChallenge } from '../types/webauthn';
import type { AccountId } from '../types/accountIds';
import { ActionType } from '../types/actions';
import { validateAccountId } from '../types/accountIds';
import {
  IndexedDBManager,
  type ClientUserData,
  type ClientAuthenticatorData,
} from '../IndexedDBManager';
import {
  type NearClient,
  SignedTransaction
} from '../NearClient';
import { SignerWorkerManager } from './signerWorkerManager';
import { VrfWorkerManager } from './vrfWorkerManager';
import { TouchIdPrompt } from './touchIdPrompt';
import { base64UrlEncode } from '../../utils/encoders';
import {
  type UserData,
  type ActionParams,
} from '../types/signer-worker';
import { extractDualPrfOutputs } from '../types/signer-worker';
import { EncryptedVRFKeypair, VRFInputData } from '../types/vrf-worker';

// Define interfaces that are missing
export interface VRFWorkerStatus {
  active: boolean;
  nearAccountId: AccountId | null;
  sessionDuration?: number;
}

/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - signerWorkerManager: NEAR transaction signing, and VRF Web3Authn verification RPC calls
 * - vrfWorkerManager: VRF keypair generation, challenge generation
 * - touchIdPrompt: TouchID prompt for biometric authentication
 */
export class WebAuthnManager {
  private readonly vrfWorkerManager: VrfWorkerManager;
  private readonly signerWorkerManager: SignerWorkerManager;
  readonly configs: PasskeyManagerConfigs;
  readonly touchIdPrompt: TouchIdPrompt;

  constructor(configs: PasskeyManagerConfigs) {
    this.vrfWorkerManager = new VrfWorkerManager();
    this.signerWorkerManager = new SignerWorkerManager();
    this.touchIdPrompt = new TouchIdPrompt();
    this.configs = configs;

    // VRF worker initializes on-demand with proper error propagation
    console.debug('WebAuthnManager: Constructor complete, VRF worker will initialize on-demand');
  }

  ///////////////////////////////////////
  // VRF MANAGER FUNCTIONS
  ///////////////////////////////////////

  async generateVrfChallenge(vrfInputData: VRFInputData): Promise<VRFChallenge> {
    return this.vrfWorkerManager.generateVrfChallenge(vrfInputData);
  }

  /**
   * Generate VRF keypair for bootstrapping - stores in memory unencrypted temporarily
   * This is used during registration to generate a VRF keypair that will be used for
   * WebAuthn ceremony and later encrypted with the real PRF output
   *
   * @param saveInMemory - Whether to persist the generated VRF keypair in WASM worker memory
   * @param vrfInputParams - Optional parameters to generate VRF challenge/proof in same call
   * @returns VRF public key and optionally VRF challenge data
   */
  async generateVrfKeypair(
    saveInMemory: boolean,
    vrfInputData: VRFInputData
  ): Promise<{
    vrfPublicKey: string;
    vrfChallenge: VRFChallenge;
  }> {
    const result = await this.vrfWorkerManager.generateVrfKeypair(vrfInputData, saveInMemory);
    if (!result.vrfChallenge) {
      throw new Error('VRF challenge generation failed');
    }
    return {
      vrfPublicKey: result.vrfPublicKey,
      vrfChallenge: result.vrfChallenge
    };
  }

  /**
   * Derive deterministic VRF keypair from PRF output for recovery
   * Optionally generates VRF challenge if input parameters are provided
   * This enables deterministic VRF key derivation from WebAuthn credentials
   *
   * @param credential - WebAuthn credential containing PRF outputs
   * @param nearAccountId - NEAR account ID for key derivation salt
   * @param vrfInputParams - Optional VRF input parameters for challenge generation
   * @returns Deterministic VRF public key, optional VRF challenge, and encrypted VRF keypair for storage
   */
  async deriveVrfKeypairFromPrf({
    credential,
    nearAccountId,
    vrfInputData
  }: {
    credential: PublicKeyCredential;
    nearAccountId: AccountId;
    vrfInputData?: VRFInputData;
  }): Promise<{
    success: boolean;
    vrfPublicKey: string;
    vrfChallenge?: VRFChallenge;
    encryptedVrfKeypair?: EncryptedVRFKeypair;
  }> {
    try {
      console.debug('WebAuthnManager: Deriving deterministic VRF keypair from PRF output');
      // Extract PRF outputs from credential
      const dualPrfOutputs = extractDualPrfOutputs(credential);

      // Use the first PRF output for VRF keypair derivation (AES PRF output)
      // This ensures deterministic derivation: same PRF + same account = same VRF keypair
      const vrfResult = await this.vrfWorkerManager.deriveVrfKeypairFromSeed({
        prfOutput: dualPrfOutputs.aesPrfOutput,
        nearAccountId,
        vrfInputData
      });

      console.debug(`Derived VRF public key: ${vrfResult.vrfPublicKey}`);
      if (vrfResult.vrfChallenge) {
        console.debug(`Generated VRF challenge with output: ${vrfResult.vrfChallenge.vrfOutput.substring(0, 20)}...`);
      }
      if (vrfResult.encryptedVrfKeypair) {
        console.debug(`Generated encrypted VRF keypair for storage`);
      }
      console.debug('WebAuthnManager: Deterministic VRF keypair derived successfully');

      const result: {
        success: boolean;
        vrfPublicKey: string;
        vrfChallenge?: VRFChallenge;
        encryptedVrfKeypair?: EncryptedVRFKeypair;
      } = {
        success: true,
        vrfPublicKey: vrfResult.vrfPublicKey
      };

      if (vrfResult.vrfChallenge) {
        result.vrfChallenge = vrfResult.vrfChallenge;
      }

      if (vrfResult.encryptedVrfKeypair) {
        result.encryptedVrfKeypair = vrfResult.encryptedVrfKeypair;
      }

      return result;

    } catch (error: any) {
      console.error('WebAuthnManager: VRF keypair derivation from PRF error:', error);
      throw new Error(`VRF keypair derivation from PRF failed ${error.message}`);
    }
  }

  /**
   * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
   * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
   *
   * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
   * @param prfOutput - PRF output from WebAuthn ceremony for encryption
   * @returns Encrypted VRF keypair data ready for storage
   */
  async encryptVrfKeypairWithCredentials({
    credential,
    vrfPublicKey,
  }: {
    credential: PublicKeyCredential,
    vrfPublicKey: string,
  }): Promise<{
    vrfPublicKey: string;
    encryptedVrfKeypair: EncryptedVRFKeypair;
  }> {
    return await this.vrfWorkerManager.encryptVrfKeypairWithCredentials(vrfPublicKey, credential);
  }

  /**
   * Unlock VRF keypair in memory using PRF output
   * This is called during login to decrypt and load the VRF keypair in-memory
   */
  async unlockVRFKeypair({
    nearAccountId,
    encryptedVrfKeypair,
    credential,
  }: {
    nearAccountId: AccountId;
    encryptedVrfKeypair: EncryptedVRFKeypair;
    credential: PublicKeyCredential;
  }): Promise<{ success: boolean; error?: string }> {
    try {
      console.debug('WebAuthnManager: Unlocking VRF keypair');

      const prfOutput = credential.getClientExtensionResults()?.prf?.results?.first as ArrayBuffer;
      if (!prfOutput) {
        throw new Error('PRF output not found in WebAuthn credentials');
      }

      const unlockResult = await this.vrfWorkerManager.unlockVrfKeypair({
        touchIdPrompt: this.touchIdPrompt,
        nearAccountId,
        encryptedVrfKeypair,
        authenticators: [], // Empty array since we already have the credential
        prfOutput: prfOutput
      });

      if (!unlockResult.success) {
        console.error('WebAuthnManager: VRF keypair unlock failed');
        return { success: false, error: 'VRF keypair unlock failed' };
      }

      console.debug('WebAuthnManager: VRF keypair unlocked successfully');
      return { success: true };

    } catch (error: any) {
      console.error('WebAuthnManager: VRF keypair unlock failed:', error.message);
      return { success: false, error: error.message };
    }
  }

  async clearVrfSession(): Promise<void> {
    return await this.vrfWorkerManager.clearVrfSession();
  }

  ///////////////////////////////////////
  // INDEXEDDB OPERATIONS
  ///////////////////////////////////////

  async storeUserData(userData: UserData): Promise<void> {
    await IndexedDBManager.clientDB.storeWebAuthnUserData(userData);
  }

  async getUser(nearAccountId: AccountId): Promise<ClientUserData | null> {
    return await IndexedDBManager.clientDB.getUser(nearAccountId);
  }

  async getAllUserData(): Promise<UserData[]> {
    const allUsers = await IndexedDBManager.clientDB.getAllUsers();
    return allUsers.map(user => ({
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: user.clientNearPublicKey,
      lastUpdated: user.lastUpdated,
      prfSupported: user.prfSupported,
      deterministicKey: true,
      passkeyCredential: user.passkeyCredential,
      encryptedVrfKeypair: user.encryptedVrfKeypair
    }));
  }

  async getAllUsers(): Promise<ClientUserData[]> {
    return await IndexedDBManager.clientDB.getAllUsers();
  }

  async getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return await IndexedDBManager.clientDB.getAuthenticatorsByUser(nearAccountId);
  }

  async updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return await IndexedDBManager.clientDB.updateLastLogin(nearAccountId);
  }

  async registerUser(nearAccountId: AccountId, additionalData?: Partial<ClientUserData>): Promise<ClientUserData> {
    return await IndexedDBManager.clientDB.registerUser(nearAccountId, additionalData);
  }

  async storeAuthenticator(authenticatorData: {
    credentialId: string;
    credentialPublicKey: Uint8Array;
    transports?: string[];
    name?: string;
    nearAccountId: AccountId;
    registered: string;
    syncedAt: string;
    vrfPublicKey: string;
    deviceNumber?: number;
  }): Promise<void> {
    const authData = {
      ...authenticatorData,
      nearAccountId: validateAccountId(authenticatorData.nearAccountId),
      deviceNumber: authenticatorData.deviceNumber || 1 // Default to device 1 (1-indexed)
    };
    return await IndexedDBManager.clientDB.storeAuthenticator(authData);
  }

  extractUsername(nearAccountId: AccountId): string {
    return IndexedDBManager.clientDB.extractUsername(nearAccountId);
  }

  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await IndexedDBManager.clientDB.atomicOperation(callback);
  }

  async rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return await IndexedDBManager.clientDB.rollbackUserRegistration(nearAccountId);
  }

  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return await IndexedDBManager.clientDB.hasPasskeyCredential(nearAccountId);
  }

  async getLastUsedNearAccountId(): Promise<{
    nearAccountId: AccountId;
    deviceNumber: number;
  } | null> {
    const lastUser = await IndexedDBManager.clientDB.getLastUser();
    if (!lastUser) return null;
    return {
      nearAccountId: lastUser.nearAccountId,
      deviceNumber: lastUser.deviceNumber,
    };
  }

  ///////////////////////////////////////
  // SIGNER WASM WORKER OPERATIONS
  ///////////////////////////////////////

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   * Optionally signs a verify_and_register_user transaction if VRF data is provided
   */
  async deriveNearKeypairAndEncrypt({
    nearAccountId,
    credential,
    options
  }: {
    credential: PublicKeyCredential;
    nearAccountId: AccountId;
    options?: {
      vrfChallenge: VRFChallenge;
      deterministicVrfPublicKey: string; // Add VRF public key for registration transactions
      contractId: string;
      nonce: string;
      blockHash: string;
    };
  }): Promise<{
    success: boolean;
    nearAccountId: AccountId;
    publicKey: string;
    signedTransaction?: SignedTransaction;
  }> {
    return await this.signerWorkerManager.deriveNearKeypairAndEncrypt(
      credential,
      nearAccountId,
      options
    );
  }

  /**
   * Export private key using PRF-based decryption
   * Requires TouchId
   *
   * SECURITY MODEL: Local random challenge is sufficient for private key export because:
   * - User must possess physical authenticator device
   * - Device enforces biometric/PIN verification before PRF access
   * - No network communication or replay attack surface
   * - Challenge only needs to be random to prevent pre-computation
   * - Security comes from device possession + biometrics, not challenge validation
   */
  async exportNearKeypairWithTouchId(nearAccountId: AccountId): Promise<{
    accountId: string,
    publicKey: string,
    privateKey: string
  }> {
    console.debug(`🔐 Exporting private key for account: ${nearAccountId}`);
    // Get user data to verify user exists
    const userData = await this.getUser(nearAccountId);
    if (!userData) {
      throw new Error(`No user data found for ${nearAccountId}`);
    }
    if (!userData.clientNearPublicKey) {
      throw new Error(`No public key found for ${nearAccountId}`);
    }
    // Get stored authenticator data for this user
    const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    // Use WASM worker to decrypt private key
    const decryptionResult = await this.signerWorkerManager.decryptPrivateKeyWithPrf(
      this.touchIdPrompt,
      nearAccountId,
      authenticators,
    );

    return {
      accountId: userData.nearAccountId,
      publicKey: userData.clientNearPublicKey,
      privateKey: decryptionResult.decryptedPrivateKey,
    }
  }

  /**
   * Transaction signing with contract verification and progress updates.
   * Demonstrates the "streaming" worker pattern similar to SSE.
   *
   * Requires a successful TouchID/biometric prompt before transaction signing in wasm worker
   * Automatically verifies the authentication with the web3authn contract.
   *
   * @param transactions - Transaction payload containing:
   *   - nearAccountId: NEAR account ID performing the transaction
   *   - receiverId: NEAR account ID receiving the transaction
   *   - actions: Array of NEAR actions to execute
   *   - nonce: Transaction nonce
   * @param blockHashBytes: Recent block hash for transaction freshness
   * @param contractId: Web3Authn contract ID for verification
   * @param vrfChallenge: VRF challenge used in authentication
   * @param credential: WebAuthn credential from TouchID prompt
   * @param onEvent - Optional callback for progress updates during signing
   */
  async signTransactionsWithActions({
    transactions,
    blockHash,
    contractId,
    vrfChallenge,
    credential,
    nearRpcUrl,
    onEvent,
  }: {
    transactions: Array<{
      nearAccountId: AccountId;
      receiverId: string;
      actions: ActionParams[];
      nonce: string;
    }>,
    // Common parameters for all transactions
    blockHash: string,
    contractId: string,
    vrfChallenge: VRFChallenge,
    credential: PublicKeyCredential,
    nearRpcUrl: string,
    onEvent?: (update: onProgressEvents) => void
  }): Promise<VerifyAndSignTransactionResult[]> {

    if (transactions.length === 0) {
      throw new Error('No payloads provided for signing');
    }

    onEvent?.({
      step: 2,
      phase: 'authentication',
      status: 'progress',
      message: 'Authenticating with VRF challenge...'
    });

    console.debug('VRF WebAuthn authentication completed');
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      message: 'Authentication verified - preparing transactions...'
    });

    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      message: `Signing ${transactions.length} transactions in secure worker...`
    });

    return await this.signerWorkerManager.signTransactionsWithActions(
      {
        transactions,
        blockHash,
        contractId,
        vrfChallenge,
        credential,
        nearRpcUrl,
        onEvent
      },
    );
  }

  // === COSE OPERATIONS (Delegated to WebAuthnWorkers) ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return await this.signerWorkerManager.extractCosePublicKey(attestationObjectBase64url);
  }

  ///////////////////////////////////////
  // REGISTRATION
  ///////////////////////////////////////

  async checkCanRegisterUser({
    contractId,
    credential,
    vrfChallenge,
    onEvent,
  }: {
    contractId: string,
    credential: PublicKeyCredential,
    vrfChallenge: VRFChallenge,
    onEvent?: (update: onProgressEvents) => void
  }): Promise<{
    success: boolean;
    verified?: boolean;
    registrationInfo?: any;
    logs?: string[];
    signedTransactionBorsh?: number[];
    error?: string;
  }> {
    return await this.signerWorkerManager.checkCanRegisterUser({
      contractId,
      credential,
      vrfChallenge,
      onEvent,
      nearRpcUrl: this.configs.nearRpcUrl,
    });
  }

  /**
   * DUAL VRF REGISTRATION FLOW
   *
   * Implements the architectural solution to the chicken-and-egg problem:
   * 1. Generate bootstrap VRF keypair (random) → creates VRF challenge
   * 2. Single TouchID ceremony with VRF challenge → get dual PRF outputs
   * 3. Derive deterministic VRF keypair from PRF output #1
   * 4. Register BOTH VRF keys on-chain in vrf_public_keys array:
   *    - vrf_public_keys[0] = Bootstrap VRF key (cryptographically bound to WebAuthn)
   *    - vrf_public_keys[1] = Deterministic VRF key (for recovery/future use)
   *
   * Benefits:
   * ✅ Single TouchID ceremony during registration
   * ✅ Cryptographic binding preserved (bootstrap key)
   * ✅ Deterministic recovery (deterministic key)
   * ✅ No chicken-and-egg problems during recovery
   * ✅ Future-proof architecture (can use either key for authentication)
   */
  async dualVrfRegistrationFlow({
    nearAccountId,
    vrfInputData,
    onEvent,
  }: {
    nearAccountId: AccountId;
    vrfInputData: VRFInputData;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    bootstrapVrfPublicKey: string;
    deterministicVrfPublicKey: string;
    vrfChallenge: VRFChallenge;
    registrationCredential: PublicKeyCredential;
    encryptedBootstrapVrfKeypair: EncryptedVRFKeypair;
    dualPrfOutputs: {
      aesPrfOutput: string;
      ed25519PrfOutput: string;
    };
  }> {
    try {
      console.debug('WebAuthnManager: Starting dual VRF registration flow');

      onEvent?.({
        step: 1,
        phase: 'preparation',
        status: 'progress',
        message: 'Generating bootstrap VRF keypair and challenge...'
      });

      // Step 1: Generate bootstrap VRF keypair (random) and VRF challenge
      console.debug('Step 1: Generating bootstrap VRF keypair + challenge');
      const bootstrapResult = await this.generateVrfKeypair(true, vrfInputData);
      const bootstrapVrfPublicKey = bootstrapResult.vrfPublicKey;
      const vrfChallenge = bootstrapResult.vrfChallenge;

      console.debug(`Bootstrap VRF public key: ${bootstrapVrfPublicKey.substring(0, 20)}...`);
      console.debug(`VRF challenge generated with bootstrap keypair`);

      onEvent?.({
        step: 2,
        phase: 'authentication',
        status: 'progress',
        message: 'Performing TouchID ceremony with VRF challenge...'
      });

      // Step 2: Single TouchID ceremony with VRF challenge → get dual PRF outputs
      console.debug('Step 2: TouchID ceremony with VRF challenge');
      const registrationCredential = await this.touchIdPrompt.generateRegistrationCredentials({
        nearAccountId: nearAccountId,
        challenge: vrfChallenge.outputAs32Bytes(),
      });

      // Extract dual PRF outputs from the registration credential
      const dualPrfOutputs = extractDualPrfOutputs(registrationCredential);

      onEvent?.({
        step: 3,
        phase: 'preparation',
        status: 'progress',
        message: 'Deriving deterministic VRF keypair from PRF output...'
      });

      // Step 3: Derive deterministic VRF keypair from PRF output #1 (AES PRF)
      console.debug('Step 3: Deriving deterministic VRF keypair from PRF output');
      const deterministicResult = await this.deriveVrfKeypairFromPrf({
        credential: registrationCredential,
        nearAccountId
      });

      if (!deterministicResult.success) {
        throw new Error('Failed to derive deterministic VRF keypair from PRF output');
      }

      const deterministicVrfPublicKey = deterministicResult.vrfPublicKey;
      console.debug(`Deterministic VRF public key: ${deterministicVrfPublicKey.substring(0, 20)}...`);

      onEvent?.({
        step: 4,
        phase: 'preparation',
        status: 'progress',
        message: 'Encrypting bootstrap VRF keypair with PRF output...'
      });

      // Step 4: Encrypt bootstrap VRF keypair with PRF output for storage
      console.debug('Step 4: Encrypting bootstrap VRF keypair with PRF output');
      const encryptionResult = await this.encryptVrfKeypairWithCredentials({
        credential: registrationCredential,
        vrfPublicKey: bootstrapVrfPublicKey,
      });

      console.debug('Bootstrap VRF keypair encrypted and ready for storage');

      onEvent?.({
        step: 5,
        phase: 'action-complete',
        status: 'success',
        message: 'Dual VRF registration flow completed successfully'
      });

      console.debug('Dual VRF registration flow completed successfully');
      console.debug(`Bootstrap VRF key (cryptographically bound): ${bootstrapVrfPublicKey.substring(0, 20)}...`);
      console.debug(`Deterministic VRF key (for recovery): ${deterministicVrfPublicKey.substring(0, 20)}...`);

      return {
        bootstrapVrfPublicKey,
        deterministicVrfPublicKey,
        vrfChallenge,
        registrationCredential,
        encryptedBootstrapVrfKeypair: encryptionResult.encryptedVrfKeypair,
        dualPrfOutputs,
      };

    } catch (error: any) {
      console.error('WebAuthnManager: Dual VRF registration flow error:', error);

      onEvent?.({
        step: 0,
        phase: 'action-error',
        status: 'error',
        message: `Dual VRF registration failed: ${error.message}`
      });

      throw new Error(`Dual VRF registration flow failed: ${error.message}`);
    }
  }

  /**
   * Register user on-chain with transaction (STATE-CHANGING)
   * This performs the actual on-chain registration transaction
   */
  async signVerifyAndRegisterUser({
    contractId,
    credential,
    vrfChallenge,
    deterministicVrfPublicKey,
    signerAccountId,
    nearAccountId,
    nearPublicKeyStr,
    nearClient,
    deviceNumber = 1, // Default to device number 1 for first device (1-indexed)
    onEvent,
  }: {
    contractId: string,
    credential: PublicKeyCredential,
    vrfChallenge: VRFChallenge,
    deterministicVrfPublicKey: string, // deterministic VRF key for key recovery
    signerAccountId: string;
    nearAccountId: AccountId;
    nearPublicKeyStr: string;
    nearClient: NearClient;
    deviceNumber?: number; // Device number for multi-device support (defaults to 1)
    onEvent?: (update: onProgressEvents) => void
  }): Promise<{
    success: boolean;
    verified: boolean;
    registrationInfo?: any;
    logs?: string[];
    signedTransaction: SignedTransaction;
    preSignedDeleteTransaction: SignedTransaction;
    error?: string;
  }> {
    try {
      const registrationResult = await this.signerWorkerManager.signVerifyAndRegisterUser({
        vrfChallenge,
        credential,
        contractId,
        deterministicVrfPublicKey, // Pass through the deterministic VRF key
        signerAccountId,
        nearAccountId,
        nearPublicKeyStr,
        nearClient,
        deviceNumber, // Pass device number for multi-device support
        onEvent,
        nearRpcUrl: this.configs.nearRpcUrl,
      });

      console.debug("On-chain registration completed:", registrationResult);

      if (registrationResult.verified) {
        console.debug('On-chain user registration successful');
        return {
          success: true,
          verified: registrationResult.verified,
          registrationInfo: registrationResult.registrationInfo,
          logs: registrationResult.logs,
          signedTransaction: registrationResult.signedTransaction,
          preSignedDeleteTransaction: registrationResult.preSignedDeleteTransaction,
        };
      } else {
        console.warn('On-chain user registration failed - WASM worker returned unverified result');
        // Note: This should never happen since WASM worker throws on failure
        // But if it does, we don't have access to preSignedDeleteTransaction
        throw new Error('On-chain registration transaction failed');
      }
    } catch (error: any) {
      console.error('WebAuthnManager: On-chain registration error:', error);
      throw error;
    }
  }

  /**
   * Atomically store all registration data (user, authenticator, VRF credentials)
   */
  async atomicStoreRegistrationData({
    nearAccountId,
    credential,
    publicKey,
    encryptedVrfKeypair,
    vrfPublicKey,
    onEvent
  }: {
    nearAccountId: AccountId;
    credential: PublicKeyCredential;
    publicKey: string;
    encryptedVrfKeypair: EncryptedVRFKeypair;
    vrfPublicKey: string;
    onEvent?: (event: any) => void;
  }): Promise<void> {

    await this.atomicOperation(async (db) => {
      // Register user in IndexDB
      await this.registerUser(nearAccountId);

      // Store credential for authentication
      const credentialId = base64UrlEncode(credential.rawId);
      const response = credential.response as AuthenticatorAttestationResponse;

      await this.storeAuthenticator({
        credentialId: credentialId,
        credentialPublicKey: await this.extractCosePublicKey(
          base64UrlEncode(response.attestationObject)
        ),
        transports: response.getTransports?.() || [],
        name: `VRF Passkey for ${this.extractUsername(nearAccountId)}`,
        nearAccountId,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
        vrfPublicKey: vrfPublicKey,
      });

      // Store WebAuthn user data with encrypted VRF credentials
      await this.storeUserData({
        nearAccountId,
        clientNearPublicKey: publicKey,
        lastUpdated: Date.now(),
        prfSupported: true,
        deterministicKey: true,
        passkeyCredential: {
          id: credential.id,
          rawId: credentialId
        },
        encryptedVrfKeypair
      });

      console.debug('✅ registration data stored atomically');
      return true;
    });

    onEvent?.({
      step: 5,
      phase: 'database-storage',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF registration data stored successfully'
    });
  }

  ///////////////////////////////////////
  // ACCOUNT RECOVERY
  ///////////////////////////////////////

  /**
   * Recover keypair from authentication credential for account recovery
   * Uses dual PRF outputs to re-derive the same NEAR keypair and re-encrypt it
   * @param challenge - Random challenge for WebAuthn authentication ceremony
   * @param authenticationCredential - The authentication credential with dual PRF outputs
   * @param accountIdHint - Optional account ID hint for recovery
   * @returns Public key and encrypted private key for secure storage
   */
  async recoverKeypairFromPasskey(
    challenge: Uint8Array<ArrayBuffer>,
    authenticationCredential: PublicKeyCredential,
    accountIdHint?: string,
  ): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    iv: string;
    accountIdHint?: string;
    stored?: boolean;
  }> {
    try {
      console.debug('WebAuthnManager: recovering keypair from authentication credential with dual PRF outputs');

      // Verify we have an authentication credential (not registration)
      if (!authenticationCredential) {
        throw new Error(
          'Authentication credential required for account recovery. ' +
          'Use an existing credential with dual PRF outputs to re-derive the same NEAR keypair.'
        );
      }

      // Verify dual PRF outputs are available
      const prfResults = authenticationCredential.getClientExtensionResults()?.prf?.results;
      if (!prfResults?.first || !prfResults?.second) {
        throw new Error('Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available');
      }

      // Call the WASM worker to derive and encrypt the keypair using dual PRF
      const result = await this.signerWorkerManager.recoverKeypairFromPasskey(
        authenticationCredential,
        base64UrlEncode(challenge),
        accountIdHint
      );

       console.debug('WebAuthnManager: Deterministic keypair derivation successful');
       return result;

    } catch (error: any) {
      console.error('WebAuthnManager: Deterministic keypair derivation error:', error);
      throw new Error(`Deterministic keypair derivation failed: ${error.message}`);
    }
  }

  /**
   * Add VRF public key to authenticator (for recovery scenarios)
   * This enables adding new VRF keys to the FIFO queue on the contract
   */
  async addVrfKeyToAuthenticator({
    nearAccountId,
    contractId,
    credentialId,
    vrfPublicKey,
    nonce,
    blockHash,
    vrfChallenge,
    credential,
    nearRpcUrl,
    onEvent
  }: {
    nearAccountId: AccountId;
    contractId: string;
    credentialId: string;
    vrfPublicKey: Uint8Array | number[];
    nonce: string;
    blockHash: string;
    vrfChallenge: VRFChallenge;
    credential: PublicKeyCredential;
    nearRpcUrl: string;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[]
  }> {
    console.debug('WebAuthnManager: Starting VRF key addition to authenticator');

    onEvent?.({
      step: 1,
      phase: 'preparation',
      status: 'progress',
      message: 'Adding VRF public key to authenticator...'
    });

    try {

      const functionCallAction: ActionParams = {
        actionType: ActionType.FunctionCall,
        method_name: 'add_vrf_key_to_authenticator',
        args: JSON.stringify({
          user_id: nearAccountId,
          credential_id: credentialId,
          new_vrf_key: Array.from(vrfPublicKey)
        }),
        gas: '30000000000000', // 30 TGas
        deposit: '0'
      };

      const result = await this.signerWorkerManager.signTransactionsWithActions({
        transactions: [{
          nearAccountId: nearAccountId,
          receiverId: contractId,
          actions: [functionCallAction],
          nonce: nonce,
        }],
        blockHash: blockHash,
        contractId: contractId,
        vrfChallenge: vrfChallenge,
        credential: credential,
        nearRpcUrl: nearRpcUrl,
        onEvent: onEvent,
      });

      console.debug('WebAuthnManager: VRF key addition completed successfully');

      onEvent?.({
        step: 2,
        phase: 'transaction-signing',
        status: 'success',
        message: 'VRF public key added to authenticator successfully'
      });

      return {
        signedTransaction: result[0].signedTransaction,
        nearAccountId: validateAccountId(result[0].nearAccountId),
        logs: result[0].logs
      };

    } catch (error: any) {
      console.error('WebAuthnManager: VRF key addition error:', error);

      onEvent?.({
        step: 0,
        phase: 'action-error',
        status: 'error',
        message: `VRF key addition failed: ${error.message}`
      });

      throw new Error(`VRF key addition failed: ${error.message}`);
    }
  }

  /**
   * Sign transaction with raw private key
   * for key replacement in device linking
   * No TouchID/PRF required - uses provided private key directly
   */
  async signTransactionWithKeyPair({
    nearPrivateKey,
    signerAccountId,
    receiverId,
    nonce,
    blockHash,
    actions
  }: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionParams[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    return await this.signerWorkerManager.signTransactionWithKeyPair({
      nearPrivateKey,
      signerAccountId,
      receiverId,
      nonce,
      blockHash,
      actions
    });
  }

  /**
   * Check VRF worker status
   */
  async checkVrfStatus(): Promise<{ active: boolean; nearAccountId: AccountId | null; sessionDuration?: number }> {
    return this.vrfWorkerManager.checkVrfStatus();
  }

}