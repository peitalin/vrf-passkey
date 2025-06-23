import type { Provider } from '@near-js/providers';
import { WebAuthnWorkers } from './webauthn-workers';
import { WebAuthnNetworkCalls } from './network-calls';
import { WebAuthnContractCalls } from './contract-calls';
import { WebAuthnIndexedDBCalls } from './indexedDB-calls';
import { VRFManager } from './vrfManager';
import type { UserData } from '../types/worker';
import type { WebAuthnAuthenticationWithPrf } from '../types/webauthn';
import type { ClientUserData, ClientAuthenticatorData } from '../IndexedDBManager';

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
  private readonly networkCalls: WebAuthnNetworkCalls;
  private readonly contractCalls: WebAuthnContractCalls;
  private readonly indexedDBCalls: WebAuthnIndexedDBCalls;
  private readonly vrfManager: VRFManager;

  constructor() {
    this.webauthnWorkers = new WebAuthnWorkers();
    this.networkCalls = new WebAuthnNetworkCalls(this.webauthnWorkers);
    this.indexedDBCalls = new WebAuthnIndexedDBCalls();
    this.contractCalls = new WebAuthnContractCalls(this.webauthnWorkers, this.networkCalls, this.indexedDBCalls);
    this.vrfManager = new VRFManager();
  }

  // === INDEXDB OPERATIONS (Now using WebAuthnindexedDBCalls facade) ===

  /**
   * Store user data using IndexedDB facade
   */
  async storeUserData(userData: UserData): Promise<void> {
    await this.indexedDBCalls.storeWebAuthnUserData(userData);
  }

  /**
   * Get complete user data (preferred method)
   * This replaces both getUserData() and getUser() with a single comprehensive method
   */
  async getUser(nearAccountId: string): Promise<ClientUserData | null> {
    return await this.indexedDBCalls.getUser(nearAccountId);
  }

  /**
   * Check if user has WebAuthn/passkey data configured
   */
  async hasWebAuthnData(nearAccountId: string): Promise<boolean> {
    const user = await this.getUser(nearAccountId);
    return !!(user?.clientNearPublicKey && user?.passkeyCredential);
  }

  /**
   * Get all user data using IndexedDB facade
   */
  async getAllUserData(): Promise<UserData[]> {
    const allUsers = await this.indexedDBCalls.getAllUsers();
    return allUsers.map(user => ({
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: user.clientNearPublicKey,
      lastUpdated: user.lastUpdated,
      prfSupported: user.prfSupported,
      deterministicKey: false, // VRF mode doesn't use deterministic keys
      passkeyCredential: user.passkeyCredential,
      vrfCredentials: user.vrfCredentials
    }));
  }

  /**
   * Get all users (comprehensive data)
   */
  async getAllUsers(): Promise<ClientUserData[]> {
    return await this.indexedDBCalls.getAllUsers();
  }

  /**
   * Get all authenticators for a user
   */
  async getAuthenticatorsByUser(nearAccountId: string): Promise<ClientAuthenticatorData[]> {
    return await this.indexedDBCalls.getAuthenticatorsByUser(nearAccountId);
  }

  /**
   * Update user's last login timestamp
   */
  async updateLastLogin(nearAccountId: string): Promise<void> {
    return await this.indexedDBCalls.updateLastLogin(nearAccountId);
  }

  /**
   * Register a new user
   */
  async registerUser(nearAccountId: string, additionalData?: Partial<ClientUserData>): Promise<ClientUserData> {
    return await this.indexedDBCalls.registerUser(nearAccountId, additionalData);
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
    return await this.indexedDBCalls.storeAuthenticator(authenticatorData);
  }

  /**
   * Extract username from NEAR account ID
   */
  extractUsername(nearAccountId: string): string {
    return this.indexedDBCalls.extractUsername(nearAccountId);
  }

  /**
   * Perform an atomic operation
   */
  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await this.indexedDBCalls.atomicOperation(callback);
  }

  /**
   * Rollback user registration
   */
  async rollbackUserRegistration(nearAccountId: string): Promise<void> {
    return await this.indexedDBCalls.rollbackUserRegistration(nearAccountId);
  }

  // === VRF MANAGER ACCESS ===

  /**
   * Get the VRF manager instance
   */
  getVRFManager(): VRFManager {
    return this.vrfManager;
  }

  // === CONVENIENCE METHODS ===

  /**
   * Check if a passkey credential exists for a NEAR account ID
   */
  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return await this.indexedDBCalls.hasPasskeyCredential(nearAccountId);
  }

  /**
   * Get the last used NEAR account ID from stored user data
   */
  async getLastUsedNearAccountId(): Promise<string | null> {
    const lastUser = await this.indexedDBCalls.getLastUser();
    return lastUser?.nearAccountId || null;
  }

  // === WEBAUTHN AUTHENTICATION & REGISTRATION ===

  /**
   * Authenticate with PRF - generate local challenge for serverless mode
   */
  async authenticateWithPrf(
    nearAccountId?: string,
    purpose: 'encryption' | 'signing' = 'signing',
    useOptimistic: boolean = true
  ): Promise<WebAuthnAuthenticationWithPrf> {
    // For serverless mode, create local challenge
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const authenticationOptions: PublicKeyCredentialRequestOptions = {
      challenge,
      timeout: 60000,
      rpId: window.location.hostname,
      userVerification: 'preferred',
      extensions: {
        prf: {
          eval: {
            first: this.webauthnWorkers.getPrfSalts().nearKeyEncryption
          }
        }
      }
    };

    const credential = await navigator.credentials.get({
      publicKey: authenticationOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn authentication failed');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    return { credential, prfOutput };
  }

  // === PRF OPERATIONS (Delegated to WebAuthnWorkers) ===

  /**
   * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
   */
  async secureRegistrationWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    payload: { nearAccountId: string },
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    return await this.webauthnWorkers.secureRegistrationWithPrf(
      nearAccountId,
      prfOutput,
      payload,
    );
  }

  /**
   * Secure transaction signing with PRF: WebAuthn + WASM worker signing using PRF
   */
  async secureTransactionSigningWithPrf(
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
    return await this.webauthnWorkers.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      payload
    );
  }

  /**
   * Secure private key decryption with PRF
   */
  async securePrivateKeyDecryptionWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    return await this.webauthnWorkers.securePrivateKeyDecryptionWithPrf(
      nearAccountId,
      prfOutput
    );
  }

  // === COSE OPERATIONS (Delegated to WebAuthnWorkers) ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKeyFromAttestation(attestationObjectBase64url: string): Promise<Uint8Array> {
    return await this.webauthnWorkers.extractCosePublicKeyFromAttestation(attestationObjectBase64url);
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
    vrfInputParams?: {
      userId: string;
      rpId: string;
      sessionId: string;
      blockHeight: number;
      blockHashBytes: number[];
      timestamp: number;
    }
  ): Promise<{
    vrfPublicKey: string;
    // Optional VRF challenge data (only if vrfInputParams provided)
    vrfChallengeData?: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      rpId: string;
    };
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

  /**
   * Generate VRF keypair and encrypt it using PRF output
   *
   * @param prfOutput - PRF output from WebAuthn ceremony for encryption
   * @param saveInMemory - Whether to persist the generated VRF keypair in WASM worker memory
   * @param vrfInputParams - Optional parameters to generate VRF challenge/proof in same call
   * @returns VRF keypair data and optionally VRF challenge data
   */
  async generateVrfKeypairWithPrf(
    prfOutput: ArrayBuffer,
    saveInMemory: boolean,
    vrfInputParams?: {
      userId: string;
      rpId: string;
      sessionId: string;
      blockHeight: number;
      blockHashBytes: number[];
      timestamp: number;
    }
  ): Promise<{
    vrfPublicKey: string;
    encryptedVrfKeypair: any;
    // Optional VRF challenge data (only if vrfInputParams provided)
    vrfChallengeData?: {
      vrfInput: string;
      vrfOutput: string;
      vrfProof: string;
      vrfPublicKey: string;
      rpId: string;
    };
  }> {
    return await this.vrfManager.generateVrfKeypairWithPrf(prfOutput, saveInMemory, vrfInputParams);
  }

  /**
   * Generate VRF challenge and proof using encrypted VRF keypair
   * This is used during authentication to create WebAuthn challenges
   */
  async generateVrfChallengeWithPrf(
    prfOutput: ArrayBuffer,
    encryptedVrfData: string,
    encryptedVrfNonce: string,
    userId: string,
    rpId: string,
    sessionId: string,
    blockHeight: number,
    blockHashBytes: number[],
    timestamp: number
  ): Promise<{
    vrfInput: string;
    vrfOutput: string;
    vrfProof: string;
    vrfPublicKey: string;
    rpId: string;
  }> {
    return await this.vrfManager.generateVrfChallengeWithPrf(
      prfOutput,
      encryptedVrfData,
      encryptedVrfNonce,
      userId,
      rpId,
      sessionId,
      blockHeight,
      blockHashBytes,
      timestamp
    );
  }

  // === CONTRACT OPERATIONS (Delegated to WebAuthnContractCalls) ===

  /**
   * Call a smart contract method (simple delegation to contract calls module)
   */
  async callContract(
    nearRpcProvider: Provider,
    options: {
      contractId: string;
      methodName: string;
      args: any;
      gas?: string;
      attachedDeposit?: string;
      nearAccountId?: string;
      prfOutput?: ArrayBuffer;
      viewOnly?: boolean;
      requiresAuth?: boolean;
    }
  ): Promise<any> {
    return await this.contractCalls.callContract(nearRpcProvider, options);
  }

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
    vrfChallengeData: {
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
  ): Promise<{
    success: boolean;
    verified?: boolean;
    error?: string;
  }> {
    return await this.contractCalls.verifyVrfAuthentication(
      nearRpcProvider,
      contractId,
      vrfChallengeData,
      webauthnCredential,
    );
  }

  /**
   * Verify VRF registration with the WebAuthn contract
   * Calls verify_registration_response on the contract
   */
  async verifyVrfRegistration(
    nearRpcProvider: Provider,
    contractId: string,
    vrfChallengeData: {
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
    return await this.contractCalls.verifyVrfRegistration(
      nearRpcProvider,
      contractId,
      vrfChallengeData,
      webauthnCredential,
      nearAccountId,
      registrationData
    );
  }
}