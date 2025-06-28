import type { Provider } from '@near-js/providers';
import { SignerWorkerManager } from './signerWorkerManager';
import { IndexedDBManager } from '../IndexedDBManager';
import { VrfWorkerManager, VRFWorkerStatus } from './vrfWorkerManager';
import { TouchIdPrompt } from './touchIdPrompt';
import type { UserData, ActionParams } from '../types/signer-worker';
import type { ClientUserData, ClientAuthenticatorData } from '../IndexedDBManager';
import type { onProgressEvents, VerifyAndSignTransactionResult, VRFChallenge } from '../types/webauthn';
import type { EncryptedVRFData, VRFInputData } from './vrfWorkerManager';

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
  readonly touchIdPrompt: TouchIdPrompt;

  constructor() {
    this.vrfWorkerManager = new VrfWorkerManager();
    this.signerWorkerManager = new SignerWorkerManager();
    this.touchIdPrompt = new TouchIdPrompt();
    console.log("PRIVATE: this.signerWorkerManager", this.signerWorkerManager);
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

  async forceCleanupVrfManager(): Promise<void> {
    return this.vrfWorkerManager.forceCleanupVrfManager();
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
  async encryptVrfKeypairWithPrf(
    expectedPublicKey: string,
    prfOutput: ArrayBuffer
  ): Promise<{
    vrfPublicKey: string;
    encryptedVrfKeypair: any;
  }> {
    return await this.vrfWorkerManager.encryptVrfKeypairWithPrf(expectedPublicKey, prfOutput);
  }

  /**
   * Unlock VRF keypair in VRF Worker memory using PRF output from WebAuthn ceremony
   * This decrypts the stored VRF keypair and keeps it in memory for challenge generation
   *
   * @param nearAccountId - NEAR account ID associated with the VRF keypair
   * @param vrfCredentials - Encrypted VRF keypair data from storage
   * @param prfOutput - PRF output from WebAuthn ceremony for decryption
   * @returns Success status and optional error message
   */
  async unlockVRFKeypair({
    nearAccountId,
    vrfCredentials,
    prfOutput,
    authenticators,
    onEvent
  }: {
    nearAccountId: string,
    vrfCredentials: EncryptedVRFData,
    prfOutput?: ArrayBuffer,
    authenticators?: ClientAuthenticatorData[],
    onEvent?: (event: { type: string, data: { step: string, message: string } }) => void,
  }): Promise<{ success: boolean; error?: string }> {
    if (!authenticators) {
      authenticators = await this.getAuthenticatorsByUser(nearAccountId);
      if (!authenticators || authenticators.length === 0) {
        throw new Error('No authenticators found for account ' + nearAccountId + '. Please register.');
      }
    }
    return await this.vrfWorkerManager.unlockVRFKeypair({
      touchIdPrompt: this.touchIdPrompt,
      nearAccountId: nearAccountId,
      encryptedVrfData: vrfCredentials,
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
      vrfCredentials: user.vrfCredentials
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
    credentialID: string;
    credentialPublicKey: Uint8Array;
    transports?: string[];
    clientNearPublicKey?: string;
    name?: string;
    registered: string;
    lastUsed?: string;
    backedUp: boolean;
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
  async deriveNearKeypairAndEncrypt(
    prfOutput: ArrayBuffer,
    payload: { nearAccountId: string },
    attestationObject: AuthenticatorAttestationResponse,
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    return await this.signerWorkerManager.deriveNearKeypairAndEncrypt(
      prfOutput,
      payload,
      attestationObject,
    );
  }

  /**
   * Secure private key decryption with PRF
   */
  async decryptPrivateKeyWithPrf(
    nearAccountId: string,
    authenticators: ClientAuthenticatorData[],
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    return await this.signerWorkerManager.decryptPrivateKeyWithPrf(
      this.touchIdPrompt,
      nearAccountId,
      authenticators,
    );
  }

  /**
   * Sign a NEAR Transfer transaction using PRF
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
      // Additional parameters for contract verification
      contractId: string;
      vrfChallenge: VRFChallenge;
      webauthnCredential: PublicKeyCredential;
    },
    onEvent?: (update: onProgressEvents) => void
  ): Promise<VerifyAndSignTransactionResult> {
    return await this.signerWorkerManager.signTransferTransaction(
      payload,
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
   *   - webauthnCredential: WebAuthn credential from TouchID prompt
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
      webauthnCredential: PublicKeyCredential;
    },
    onEvent?: (update: onProgressEvents) => void
  ): Promise<VerifyAndSignTransactionResult> {
    return await this.signerWorkerManager.signTransactionWithActions(
      payload,
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
    webauthnCredential,
    vrfChallenge,
    onEvent,
  }: {
    contractId: string,
    webauthnCredential: PublicKeyCredential,
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
      webauthnCredential,
      vrfChallenge,
      onEvent,
    });
  }

  /**
   * Register user on-chain with transaction (STATE-CHANGING)
   * This performs the actual on-chain registration transaction
   */
  async signVerifyAndRegisterUser({
    contractId,
    webauthnCredential,
    vrfChallenge,
    signerAccountId,
    nearAccountId,
    publicKeyStr,
    nearRpcProvider,
    onEvent,
  }: {
    contractId: string,
    webauthnCredential: PublicKeyCredential,
    vrfChallenge: VRFChallenge,
    signerAccountId: string;
    nearAccountId: string;
    publicKeyStr: string;
    nearRpcProvider: Provider;
    onEvent?: (update: onProgressEvents) => void
  }): Promise<{
    success: boolean;
    verified?: boolean;
    registrationInfo?: any;
    logs?: string[];
    signedTransactionBorsh?: number[];
    error?: string;
  }> {
    try {
      const registrationResult = await this.signerWorkerManager.signVerifyAndRegisterUser({
        vrfChallenge,
        webauthnCredential,
        contractId,
        signerAccountId,
        nearAccountId,
        publicKeyStr,
        nearRpcProvider,
        onEvent,
      });

      console.debug("On-chain registration completed:", registrationResult);

      if (registrationResult.verified) {
        console.debug('✅ On-chain user registration successful');
        return {
          success: true,
          verified: true,
          registrationInfo: registrationResult.registrationInfo,
          logs: registrationResult.logs,
          signedTransactionBorsh: registrationResult.signedTransactionBorsh,
        };
      } else {
        console.warn('❌ On-chain user registration failed');
        return {
          success: false,
          verified: false,
          error: 'On-chain registration transaction failed',
        };
      }
    } catch (error: any) {
      console.error('WebAuthnManager: On-chain registration error:', error);
      return {
        success: false,
        verified: false,
        error: error.message || 'On-chain registration failed',
      };
    }
  }
}