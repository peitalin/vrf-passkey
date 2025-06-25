import type { Provider } from '@near-js/providers';
import { WebAuthnWorkers } from './webauthn-workers';
import { WebAuthnContractCalls } from './contract-calls';
import { IndexedDBManager } from '../IndexedDBManager';
import { VRFManager } from './vrfManager';
import { TouchIdPrompt } from './touchIdPrompt';
import { generateUserScopedPrfSalt } from '../../utils';
import type { UserData } from '../types/worker';
import type { WebAuthnAuthenticationWithPrf } from '../types/webauthn';
import type { ClientUserData, ClientAuthenticatorData } from '../IndexedDBManager';
import type { VRFChallenge } from './vrfManager';

/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - webauthn-workers.ts: PRF, challenges, workers, COSE operations
 * - network-calls.ts: Server/contract communication
 * - contract-calls.ts: Contract calling functionality
 * - indexedDB-calls.ts: IndexedDB data access facade
 */
export class WebAuthnManager {
  private readonly webauthnWorkers: WebAuthnWorkers;
  private readonly contractCalls: WebAuthnContractCalls;
  private readonly vrfManager: VRFManager;
  readonly touchIdPrompt: TouchIdPrompt;

  constructor() {
    this.webauthnWorkers = new WebAuthnWorkers();
    this.contractCalls = new WebAuthnContractCalls(this.webauthnWorkers);
    this.vrfManager = new VRFManager();
    this.touchIdPrompt = new TouchIdPrompt();
  }

  getVRFManager(): VRFManager {
    return this.vrfManager;
  }

  // === INDEXDB OPERATIONS (Now using WebAuthnindexedDBCalls facade) ===

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

  /**
   * Get all users (comprehensive data)
   */
  async getAllUsers(): Promise<ClientUserData[]> {
    return await IndexedDBManager.clientDB.getAllUsers();
  }

  /**
   * Get all authenticators for a user
   */
  async getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]> {
    return await IndexedDBManager.clientDB.getAuthenticatorsByUser(nearAccountId);
  }

  /**
   * Update user's last login timestamp
   */
  async updateLastLogin(nearAccountId: string): Promise<void> {
    return await IndexedDBManager.clientDB.updateLastLogin(nearAccountId);
  }

  /**
   * Register a new user
   */
  async registerUser(nearAccountId: string, additionalData?: Partial<ClientUserData>): Promise<ClientUserData> {
    return await IndexedDBManager.clientDB.registerUser(nearAccountId, additionalData);
  }

  /**
   * Store an authenticator
   */
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

  /**
   * Extract username from NEAR account ID
   */
  extractUsername(nearAccountId: string): string {
    return IndexedDBManager.clientDB.extractUsername(nearAccountId);
  }

  /**
   * Perform an atomic operation
   */
  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await IndexedDBManager.clientDB.atomicOperation(callback);
  }

  /**
   * Rollback user registration
   */
  async rollbackUserRegistration(nearAccountId: string): Promise<void> {
    return await IndexedDBManager.clientDB.rollbackUserRegistration(nearAccountId);
  }

  // === CONVENIENCE METHODS ===

  /**
   * Check if a passkey credential exists for a NEAR account ID
   */
  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return await IndexedDBManager.clientDB.hasPasskeyCredential(nearAccountId);
  }

  /**
   * Get the last used NEAR account ID from stored user data
   */
  async getLastUsedNearAccountId(): Promise<string | null> {
    const lastUser = await IndexedDBManager.clientDB.getLastUser();
    return lastUser?.nearAccountId || null;
  }

  // === PRF OPERATIONS (Delegated to WebAuthnWorkers) ===

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async deriveNearKeypairAndEncrypt(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: { nearAccountId: string },
    attestationObject: AuthenticatorAttestationResponse,
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    return await this.webauthnWorkers.deriveNearKeypairAndEncrypt(
      nearAccountId,
      prfOutput,
      payload,
      attestationObject,
    );
  }

  /**
   * Secure transaction signing with PRF: WebAuthn + WASM worker signing using PRF
   */
  async decryptAndSignTransactionWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: {
      nearAccountId: string;
      receiverId: string;
      contractMethodName: string;
      contractArgs: Record<string, any>;
      gasAmount: string;
      depositAmount: string;
      nonce: string;
      blockHashBytes: number[];
    }
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    return await this.webauthnWorkers.decryptAndSignTransactionWithPrf(
      nearAccountId,
      prfOutput,
      payload
    );
  }

  /**
   * Sign a NEAR Transfer transaction using PRF
   */
  async signTransferTransaction(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: {
      nearAccountId: string;
      receiverId: string;
      depositAmount: string;
      nonce: string;
      blockHashBytes: number[];
    }
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    return await this.webauthnWorkers.signTransferTransaction(
      nearAccountId,
      prfOutput,
      payload
    );
  }

  /**
   * Sign a NEAR transaction with multiple actions using PRF
   */
  async signTransactionWithActions(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: {
      nearAccountId: string;
      receiverId: string;
      actions: any[];
      nonce: string;
      blockHashBytes: number[];
    }
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    return await this.webauthnWorkers.signTransactionWithActions(
      nearAccountId,
      prfOutput,
      payload
    );
  }

  /**
   * Secure private key decryption with PRF
   */
  async decryptPrivateKeyWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    return await this.webauthnWorkers.decryptPrivateKeyWithPrf(
      nearAccountId,
      prfOutput
    );
  }

  // === COSE OPERATIONS (Delegated to WebAuthnWorkers) ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return await this.webauthnWorkers.extractCosePublicKey(attestationObjectBase64url);
  }

  // === VRF OPERATIONS (Delegated to WebAuthnWorkers) ===

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
      sessionId: string;
      blockHeight: number;
      blockHashBytes: number[];
      timestamp: number;
    }
  ): Promise<{
    vrfPublicKey: string;
    vrfChallenge: VRFChallenge;
  }> {
    return await this.vrfManager.generateVrfKeypair(saveInMemory, vrfInputParams);
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
    return await this.vrfManager.encryptVrfKeypairWithPrf(expectedPublicKey, prfOutput);
  }

  // === CONTRACT OPERATIONS (Delegated to WebAuthnContractCalls) ===

  /**
   * Verify VRF authentication with the WebAuthn contract (gas-free view call)
   *
   * This calls verify_authentication_response to perform:
   * 1. VRF proof verification (proves fresh challenge + user has VRF private key)
   * 2. WebAuthn response verification (proves user authenticated with VRF challenge)
   *
   * Note: This is now a view function that doesn't require gas or PRF output
   */
  async verifyVrfAuthentication(
    nearRpcProvider: Provider,
    contractId: string,
    vrfChallenge: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      userId: string;
      rpId: string;
      blockHeight: number;
      blockHash: string;
    },
    webauthnCredential: PublicKeyCredential,
    debugMode: boolean = false,
  ): Promise<{
    success: boolean;
    verified?: boolean;
    error?: string;
  }> {
    return await this.contractCalls.verifyVrfAuthentication(
      nearRpcProvider,
      contractId,
      vrfChallenge,
      webauthnCredential,
      debugMode
    );
  }

  /**
   * Verify VRF registration with the WebAuthn contract
   * Calls verify_registration_response on the contract
   */
  async verifyVrfAndRegisterUserOnContract(
    nearRpcProvider: Provider,
    contractId: string,
    vrfChallenge: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      userId: string;
      rpId: string;
      blockHeight: number;
      blockHash: string;
    },
    webauthnCredential: PublicKeyCredential,
    nearAccountId: string,
    registrationData?: {
      nearPublicKey: string;
      prfOutput: ArrayBuffer;
    }
  ): Promise<{
    success: boolean;
    verified?: boolean;
    transactionId?: string;
    error?: string;
  }> {
    return await this.contractCalls.verifyVrfAndRegisterUserOnContract(
      nearRpcProvider,
      contractId,
      vrfChallenge,
      webauthnCredential,
      nearAccountId,
      registrationData
    );
  }
}