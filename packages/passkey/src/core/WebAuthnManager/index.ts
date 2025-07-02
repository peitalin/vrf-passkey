import type { NearClient } from '../NearClient';
import { SignerWorkerManager } from './signerWorkerManager';
import { IndexedDBManager } from '../IndexedDBManager';
import { VrfWorkerManager, VRFWorkerStatus } from './vrfWorkerManager';
import { TouchIdPrompt } from './touchIdPrompt';
import type { UserData, ActionParams } from '../types/signer-worker';
import type { ClientUserData, ClientAuthenticatorData } from '../IndexedDBManager';
import type { onProgressEvents, VerifyAndSignTransactionResult, VRFChallenge } from '../types/webauthn';
import type { EncryptedVRFKeypair, VRFInputData } from './vrfWorkerManager';
import type { PasskeyManagerConfigs } from '../types/passkeyManager';
import { base64UrlEncode } from '../../utils/encoders';
import { SignedTransaction } from "../NearClient";
import { serializeRegistrationCredentialAndCreatePRF } from '../types/signer-worker';

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
  }

  ///////////////////////////////////////
  // VRF MANAGER FUNCTIONS
  ///////////////////////////////////////

  async initializeVrfWorkerManager(): Promise<void> {
    return this.vrfWorkerManager.initialize();
  }

  async getVrfWorkerStatus(): Promise<VRFWorkerStatus> {
    return this.vrfWorkerManager.getVrfWorkerStatus();
  }

  async clearVrfSession(): Promise<void> {
    return this.vrfWorkerManager.clearVrfSession();
  }

  async generateVRFChallenge(vrfInputData: VRFInputData): Promise<VRFChallenge> {
    return this.vrfWorkerManager.generateVRFChallenge(vrfInputData);
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
    vrfInputParams: {
      userId: string;
      rpId: string;
      blockHeight: number;
      blockHashBytes: number[];
      timestamp: number;
    }
  ): Promise<{
    vrfPublicKey: string;
    vrfChallenge: VRFChallenge;
  }> {
    return await this.vrfWorkerManager.generateVrfKeypair(saveInMemory, vrfInputParams);
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
    encryptedVrfKeypair: any;
  }> {
    return await this.vrfWorkerManager.encryptVrfKeypairWithCredentials(vrfPublicKey, credential);
  }

  /**
   * Unlock VRF keypair in VRF Worker memory using PRF output from WebAuthn ceremony
   * This decrypts the stored VRF keypair and keeps it in memory for challenge generation
   * requires touchId (conditional - only if credential not provided)
   *
   * @param nearAccountId - NEAR account ID associated with the VRF keypair
   * @param encryptedVrfKeypair - Encrypted VRF keypair data from storage
   * @param credential - WebAuthn credential from TouchID prompt (optional)
   * If not provided, will do a TouchID prompt (e.g. login flow)
   * @returns Success status and optional error message
   */
  async unlockVRFKeypair({
    nearAccountId,
    encryptedVrfKeypair,
    credential,
    authenticators,
    onEvent
  }: {
    nearAccountId: string,
    encryptedVrfKeypair: EncryptedVRFKeypair,
    credential?: PublicKeyCredential,
    authenticators?: ClientAuthenticatorData[],
    onEvent?: (event: { type: string, data: { step: string, message: string } }) => void,
  }): Promise<{ success: boolean; error?: string }> {

    if (!authenticators) {
      authenticators = await this.getAuthenticatorsByUser(nearAccountId);
      if (!authenticators || authenticators.length === 0) {
        throw new Error('No authenticators found for account ' + nearAccountId + '. Please register.');
      }
    }

    if (!credential) {
      credential = await this.touchIdPrompt.getCredentials({
        nearAccountId,
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        authenticators,
      });
    }

    const prfOutput = credential.getClientExtensionResults().prf?.results?.first as ArrayBuffer;
    if (!prfOutput) {
      throw new Error('PRF output not found in WebAuthn credentials');
    }

    return await this.vrfWorkerManager.unlockVRFKeypair({
      touchIdPrompt: this.touchIdPrompt,
      nearAccountId: nearAccountId,
      encryptedVrfKeypair: encryptedVrfKeypair,
      authenticators,
      prfOutput,
      onEvent,
    });
  }

  ///////////////////////////////////////
  // INDEXEDDB OPERATIONS
  ///////////////////////////////////////

  async storeUserData(userData: UserData): Promise<void> {
    await IndexedDBManager.clientDB.storeWebAuthnUserData(userData);
  }

  async getUser(nearAccountId: string): Promise<ClientUserData | null> {
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

  async getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]> {
    return await IndexedDBManager.clientDB.getAuthenticatorsByUser(nearAccountId);
  }

  async updateLastLogin(nearAccountId: string): Promise<void> {
    return await IndexedDBManager.clientDB.updateLastLogin(nearAccountId);
  }

  async registerUser(nearAccountId: string, additionalData?: Partial<ClientUserData>): Promise<ClientUserData> {
    return await IndexedDBManager.clientDB.registerUser(nearAccountId, additionalData);
  }

  async storeAuthenticator(authenticatorData: {
    nearAccountId: string;
    credentialId: string;
    credentialPublicKey: Uint8Array;
    transports?: string[];
    clientNearPublicKey?: string;
    name?: string;
    registered: string;
    syncedAt: string;
  }): Promise<void> {
    return await IndexedDBManager.clientDB.storeAuthenticator(authenticatorData);
  }

  extractUsername(nearAccountId: string): string {
    return IndexedDBManager.clientDB.extractUsername(nearAccountId);
  }

  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await IndexedDBManager.clientDB.atomicOperation(callback);
  }

  async rollbackUserRegistration(nearAccountId: string): Promise<void> {
    return await IndexedDBManager.clientDB.rollbackUserRegistration(nearAccountId);
  }

  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return await IndexedDBManager.clientDB.hasPasskeyCredential(nearAccountId);
  }

  async getLastUsedNearAccountId(): Promise<string | null> {
    const lastUser = await IndexedDBManager.clientDB.getLastUser();
    return lastUser?.nearAccountId || null;
  }

  ///////////////////////////////////////
  // SIGNER WASM WORKER OPERATIONS
  ///////////////////////////////////////

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async deriveNearKeypairAndEncrypt({
    credential,
    nearAccountId,
  }: {
    credential: PublicKeyCredential,
    nearAccountId: string,
  }): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    return await this.signerWorkerManager.deriveNearKeypairAndEncrypt(
      credential,
      nearAccountId,
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
  async exportNearKeypairWithTouchId(nearAccountId: string): Promise<{
    accountId: string,
    publicKey: string,
    privateKey: string
  }> {
    console.log(`🔐 Exporting private key for account: ${nearAccountId}`);
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
   * Sign a NEAR Transfer transaction using PRF
   * Requires TouchId
   *
   * Enhanced Transfer transaction signing with contract verification and progress updates
   * Uses the new verify+sign WASM function for secure, efficient transaction processing
   */
  async signTransferTransaction(
    payload: {
      nearAccountId: string;
      receiverId: string;
      depositAmount: string;
      nonce: string;
      blockHashBytes: number[];
      contractId: string;
      vrfChallenge: VRFChallenge;
    },
    onEvent?: (update: onProgressEvents) => void
  ): Promise<VerifyAndSignTransactionResult> {

    const { nearAccountId, vrfChallenge } = payload;

    onEvent?.({
      step: 2,
      phase: 'authentication',
      status: 'progress',
      message: 'Authenticating with VRF challenge...'
    });

    // Get stored authenticator data
    const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    const credential = await this.touchIdPrompt.getCredentials({
      nearAccountId,
      challenge: vrfChallenge.outputAs32Bytes(),
      authenticators,
    });

    console.log('✅ VRF WebAuthn authentication completed');
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      message: 'Authentication verified - preparing transaction...'
    });

    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      message: 'Signing transaction in secure worker...'
    });

    return await this.signerWorkerManager.signTransferTransaction(
      {
        ...payload,
        credential: credential,
        nearRpcUrl: this.configs.nearRpcUrl,
      },
      onEvent
    );
  }

  /**
   * Transaction signing with contract verification and progress updates.
   * Demonstrates the "streaming" worker pattern similar to SSE.
   *
   * Requires a successful TouchID/biometric prompt before transaction signing in wasm worker
   * Automatically verifies the authentication with the web3authn contract.
   *
   * @param payload - Transaction payload containing:
   *   - nearAccountId: NEAR account ID performing the transaction
   *   - receiverId: NEAR account ID receiving the transaction
   *   - actions: Array of NEAR actions to execute
   *   - nonce: Transaction nonce
   *   - blockHashBytes: Recent block hash for transaction freshness
   *   - contractId: Web3Authn contract ID for verification
   *   - vrfChallenge: VRF challenge used in authentication
   *   - credential: WebAuthn credential from TouchID prompt
   * @param onEvent - Optional callback for progress updates during signing
   */
  async signTransactionWithActions(
    payload: {
      nearAccountId: string;
      receiverId: string;
      actions: ActionParams[];
      nonce: string;
      blockHashBytes: number[];
      // Additional parameters for contract verification
      contractId: string;
      vrfChallenge: VRFChallenge;
    },
    onEvent?: (update: onProgressEvents) => void
  ): Promise<VerifyAndSignTransactionResult> {

    const { nearAccountId, vrfChallenge } = payload;

    onEvent?.({
      step: 2,
      phase: 'authentication',
      status: 'progress',
      message: 'Authenticating with VRF challenge...'
    });

    // Get stored authenticator data
    const authenticators = await this.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    const credential = await this.touchIdPrompt.getCredentials({
      nearAccountId,
      challenge: vrfChallenge.outputAs32Bytes(),
      authenticators,
    });

    console.log('✅ VRF WebAuthn authentication completed');
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      message: 'Authentication verified - preparing transaction...'
    });

    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      message: 'Signing transaction in secure worker...'
    });

    return await this.signerWorkerManager.signTransactionWithActions(
      {
        ...payload,
        credential: credential,
        nearRpcUrl: this.configs.nearRpcUrl,
      },
      onEvent
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
   * Register user on-chain with transaction (STATE-CHANGING)
   * This performs the actual on-chain registration transaction
   */
  async signVerifyAndRegisterUser({
    contractId,
    credential,
    vrfChallenge,
    signerAccountId,
    nearAccountId,
    publicKeyStr,
    nearClient,
    onEvent,
  }: {
    contractId: string,
    credential: PublicKeyCredential,
    vrfChallenge: VRFChallenge,
    signerAccountId: string;
    nearAccountId: string;
    publicKeyStr: string;
    nearClient: NearClient;
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
        signerAccountId,
        nearAccountId,
        publicKeyStr,
        nearClient,
        onEvent,
      });

      console.debug("On-chain registration completed:", registrationResult);

      if (registrationResult.verified) {
        console.debug('✅ On-chain user registration successful');
        return {
          success: true,
          verified: registrationResult.verified,
          registrationInfo: registrationResult.registrationInfo,
          logs: registrationResult.logs,
          signedTransaction: registrationResult.signedTransaction,
          preSignedDeleteTransaction: registrationResult.preSignedDeleteTransaction,
        };
      } else {
        console.warn('❌ On-chain user registration failed - WASM worker returned unverified result');
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
    onEvent
  }: {
    nearAccountId: string;
    credential: PublicKeyCredential;
    publicKey: string;
    encryptedVrfKeypair: any;
    onEvent?: (event: any) => void;
  }): Promise<void> {

    await this.atomicOperation(async (db) => {
      // Register user in IndexDB
      await this.registerUser(nearAccountId);

      // Store credential for authentication
      const credentialId = base64UrlEncode(credential.rawId);
      const response = credential.response as AuthenticatorAttestationResponse;

      await this.storeAuthenticator({
        nearAccountId,
        credentialId: credentialId,
        credentialPublicKey: await this.extractCosePublicKey(
          base64UrlEncode(response.attestationObject)
        ),
        transports: response.getTransports?.() || [],
        clientNearPublicKey: publicKey,
        name: `VRF Passkey for ${this.extractUsername(nearAccountId)}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
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

      console.log('✅ registration data stored atomically');
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
   * Recover keypair from registration credential for account recovery
   * Uses the attestation object to extract COSE public key and deterministically generate the same NEAR keypair
   * @param challenge - The VRF challenge used in the WebAuthn registration ceremony
   * @param registrationCredential - The original registration credential with attestation object
   * @returns Public key for account lookup during recovery
   */
  async recoverKeypairFromPasskey(
    challenge: Uint8Array<ArrayBuffer>,
    registrationCredential: PublicKeyCredential,
    accountIdHint?: string,
  ): Promise<{
    publicKey: string;
    accountIdHint?: string;
  }> {
    try {
      console.log('WebAuthnManager: recovering keypair from registration credential');

      // If no registration credential provided, we need to get the original registration data
      // In a real implementation, this would be stored during initial registration
      if (!registrationCredential) {
        throw new Error(
          'Registration credential required for deterministic keypair derivation. ' +
          'The original registration credential (with attestation object) must be provided or stored during registration.'
        );
      }

      // Serialize the registration credential for the worker
      const serializedCredential = serializeRegistrationCredentialAndCreatePRF(registrationCredential);

      // Call the WASM worker to derive the deterministic keypair
      const result = await this.signerWorkerManager.recoverKeypairFromPasskey(
        serializedCredential,
        base64UrlEncode(challenge),
        undefined
      );

       console.log('WebAuthnManager: Deterministic keypair derivation successful');
       return result;

    } catch (error: any) {
      console.error('WebAuthnManager: Deterministic keypair derivation error:', error);
      throw new Error(`Deterministic keypair derivation failed: ${error.message}`);
    }
  }

  ///////////////////////////////////////
  // KEY MANAGEMENT METHODS (Phase 2)
  ///////////////////////////////////////

  /**
   * Add a new device key to an existing account using the AddKey action
   * This enables multi-device access by adding the current device as an additional access key
   *
   * @param params Configuration for adding device key
   * @returns Transaction result with transaction ID
   */
  async addDeviceKey({
    accountId,
    existingPrivateKey,
    newDevicePublicKey,
    accessKeyPermission = 'FullAccess',
    gas
  }: {
    accountId: string;
    existingPrivateKey: string;
    newDevicePublicKey: string;
    accessKeyPermission?: 'FullAccess' | { receiver_id: string; method_names: string[]; allowance?: string };
    gas?: string;
  }): Promise<{ transactionId: string }> {
    try {
      console.log('WebAuthnManager: Starting add device key operation');

      // TODO: This is a placeholder implementation
      // The full implementation would:
      // 1. Use the existing private key to derive the keypair
      // 2. Create and sign an AddKey transaction
      // 3. Broadcast the transaction to NEAR network
      // 4. Return the transaction ID

      // For now, return a placeholder transaction ID
      console.log('WebAuthnManager: Add device key operation completed (placeholder)');
      return {
        transactionId: 'placeholder-add-key-tx-id'
      };

    } catch (error: any) {
      console.error('WebAuthnManager: Add device key error:', error);
      throw new Error(`Add device key failed: ${error.message}`);
    }
  }

}