// Core dependencies
import { KeyPairEd25519, PublicKey } from '@near-js/crypto';
import { actionCreators, Transaction, createTransaction, Signature } from '@near-js/transactions';

// Internal types
import type { PasskeyManagerContext } from '../PasskeyManager';
import type { PasskeyManagerConfigs } from '../types/passkeyManager';
import type { onProgressEvents, VerifyAndSignTransactionResult, VRFChallenge } from '../types/webauthn';
import { ActionType } from '../types/actions';
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
import {
  type EncryptedVRFKeypair,
  type VRFInputData,
  type VRFWorkerStatus,
  VrfWorkerManager
} from './vrfWorkerManager';
import { TouchIdPrompt } from './touchIdPrompt';
import { base64UrlEncode, base58Decode } from '../../utils/encoders';
import {
  type UserData,
  type ActionParams,
} from '../types/signer-worker';

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
    encryptedVrfKeypair: EncryptedVRFKeypair;
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
    credentialId: string;
    credentialPublicKey: Uint8Array;
    transports?: string[];
    name?: string;
    nearAccountId: string;
    registered: string;
    syncedAt: string;
    vrfPublicKey: string;
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

    console.log('VRF WebAuthn authentication completed');
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
    vrfPublicKey,
    onEvent
  }: {
    nearAccountId: string;
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
      console.log('WebAuthnManager: recovering keypair from authentication credential with dual PRF outputs');

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

       console.log('WebAuthnManager: Deterministic keypair derivation successful');
       return result;

    } catch (error: any) {
      console.error('WebAuthnManager: Deterministic keypair derivation error:', error);
      throw new Error(`Deterministic keypair derivation failed: ${error.message}`);
    }
  }

  ///////////////////////////////////////
  // KEY MANAGEMENT METHODS (Add New Devices to Accounts)
  ///////////////////////////////////////

  /**
   * Add a new device key to an existing account using the AddKey action
   * This enables multi-device access by adding the current device as an additional access key
   *
   * @param params Configuration for adding device key
   * @returns Transaction result with transaction ID
   */
  async signAddKeyToDevice({
    context,
    accountId,
    newDevicePublicKey,
    importedPrivateKey,
    accessKeyPermission = 'FullAccess',
  }: {
    context: PasskeyManagerContext,
    accountId: string,
    newDevicePublicKey: string,
    importedPrivateKey: string,
    accessKeyPermission?: 'FullAccess' | { receiver_id: string; method_names: string[]; allowance?: string },
  }): Promise<VerifyAndSignTransactionResult> {
    const { nearClient } = context;
    try {
      console.log('WebAuthnManager: Starting add device key operation');

      // Step 1: Create KeyPair from imported private key
      const keyPair = new KeyPairEd25519(importedPrivateKey);
      const publicKeyStr = keyPair.getPublicKey().toString();

      // Step 2: Fetch nonce and block hash for the account
      const [accessKeyInfo, transactionBlockInfo] = await Promise.all([
        nearClient.viewAccessKey(accountId, publicKeyStr),
        nearClient.viewBlock({ finality: 'final' })
      ]);

      const nonce = BigInt(accessKeyInfo.nonce) + BigInt(1);
      const blockHashString = transactionBlockInfo.header.hash;

      // Step 3: Create AddKey action
      const addKeyAction = actionCreators.addKey(
        PublicKey.fromString(newDevicePublicKey),
        accessKeyPermission === 'FullAccess'
          ? actionCreators.fullAccessKey()
          : actionCreators.functionCallAccessKey(
              accessKeyPermission.receiver_id,
              accessKeyPermission.method_names,
              accessKeyPermission.allowance ? BigInt(accessKeyPermission.allowance) : undefined
            )
      );

      // Step 4: Create and sign transaction
      const transaction = createTransaction(
        accountId,           // signerId
        keyPair.getPublicKey(), // signer public key
        accountId,           // receiverId
        nonce,               // nonce
        [addKeyAction],      // actions
        base58Decode(blockHashString) // blockHash
      );

      // Sign the transaction manually using the keyPair
      const serializedTx = transaction.encode();
      const signature: Signature = keyPair.sign(serializedTx) as any;

      console.log('WebAuthnManager: Add device key operation completed successfully');

      return {
        signedTransaction: new SignedTransaction({
          transaction: transaction,
          signature: signature,
          borsh_bytes: Array.from(serializedTx)
        }),
        nearAccountId: accountId,
        logs: ['Transaction signed with imported private key']
      };

    } catch (error: any) {
      console.error('WebAuthnManager: Add device key error:', error);
      throw new Error(`Add device key failed: ${error.message}`);
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
    blockHashBytes,
    vrfChallenge,
    credential,
    nearRpcUrl,
    onEvent
  }: {
    nearAccountId: string;
    contractId: string;
    credentialId: string;
    vrfPublicKey: Uint8Array | number[];
    nonce: string;
    blockHashBytes: number[];
    vrfChallenge: VRFChallenge;
    credential: PublicKeyCredential;
    nearRpcUrl: string;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    signedTransaction: SignedTransaction;
    nearAccountId: string;
    logs?: string[]
  }> {
    console.log('WebAuthnManager: Starting VRF key addition to authenticator');

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

      const result = await this.signerWorkerManager.signTransactionWithActions({
        nearAccountId: nearAccountId,
        receiverId: contractId,
        actions: [functionCallAction],
        nonce: nonce,
        blockHashBytes: blockHashBytes,
        contractId: contractId,
        vrfChallenge: vrfChallenge,
        credential: credential,
        nearRpcUrl: nearRpcUrl
      }, onEvent);

      console.log('WebAuthnManager: VRF key addition completed successfully');

      onEvent?.({
        step: 2,
        phase: 'transaction-signing',
        status: 'success',
        message: 'VRF public key added to authenticator successfully'
      });

      return result;

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

}