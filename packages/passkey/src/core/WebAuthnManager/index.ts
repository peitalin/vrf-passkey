import type { Provider } from '@near-js/providers';
import { WebAuthnWorkers } from './webauthn-workers';
import { WebAuthnNetworkCalls } from './network-calls';
import { WebAuthnContractCalls } from './contract-calls';
import { VRFManager } from './vrf-manager';
import { indexDBManager } from '../IndexDBManager';
import { bufferEncode, bufferDecode } from '../../utils/encoders';
import type { UserData } from '../types/worker';
import type {
  WebAuthnRegistrationWithPrf,
  WebAuthnAuthenticationWithPrf,
  RegistrationOptions,
  GenerateRegistrationOptionsRequest,
  GenerateRegistrationOptionsResponse,
  GenerateAuthenticationOptionsRequest,
  GenerateAuthenticationOptionsResponse,
  PublicKeyCredentialRequestOptionsJSON
} from '../types/webauthn';

/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - webauthn-workers.ts: PRF, challenges, workers, COSE operations
 * - network-calls.ts: Server/contract communication
 * - contract-calls.ts: Contract calling functionality
 */
export class WebAuthnManager {
  private readonly webauthnWorkers: WebAuthnWorkers;
  private readonly networkCalls: WebAuthnNetworkCalls;
  private readonly contractCalls: WebAuthnContractCalls;
  private readonly vrfManager: VRFManager;

  constructor() {
    this.webauthnWorkers = new WebAuthnWorkers();
    this.networkCalls = new WebAuthnNetworkCalls(this.webauthnWorkers);
    this.contractCalls = new WebAuthnContractCalls(this.webauthnWorkers, this.networkCalls);
    this.vrfManager = new VRFManager();
  }

  // === INDEXDB OPERATIONS (Now using unified IndexDBManager) ===

  /**
   * Store user data using unified IndexDBManager
   */
  async storeUserData(userData: UserData): Promise<void> {
    await indexDBManager.storeWebAuthnUserData(userData);
  }

  /**
   * Retrieve user data using unified IndexDBManager
   */
  async getUserData(nearAccountId: string): Promise<UserData | null> {
    return await indexDBManager.getWebAuthnUserData(nearAccountId);
  }

  /**
   * Get all user data using unified IndexDBManager
   */
  async getAllUserData(): Promise<UserData[]> {
    const allUsers = await indexDBManager.getAllUsers();
    return allUsers.map(user => ({
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: user.clientNearPublicKey,
      lastUpdated: user.lastUpdated,
      prfSupported: user.prfSupported,
      passkeyCredential: user.passkeyCredential
    }));
  }

  // === CONVENIENCE METHODS ===

  /**
   * Check if a passkey credential exists for a NEAR account ID
   */
  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return await indexDBManager.hasPasskeyCredential(nearAccountId);
  }

  /**
   * Get the last used NEAR account ID from stored user data
   */
  async getLastUsedNearAccountId(): Promise<string | null> {
    return await indexDBManager.getLastUser().then(user => user?.nearAccountId || null);
  }

  // === CHALLENGE MANAGEMENT (Delegated to WebAuthnWorkers) ===

  clearAllChallenges(): void {
    this.webauthnWorkers.clearAllChallenges();
  }

  // === WEBAUTHN AUTHENTICATION & REGISTRATION ===

  /**
   * Convert PublicKeyCredentialRequestOptionsJSON to PublicKeyCredentialRequestOptions
   * Helper method for WebAuthn API conversion
   */
  private convertAuthenticationOptions(
    options: PublicKeyCredentialRequestOptionsJSON
  ): PublicKeyCredentialRequestOptions {
    return {
      challenge: bufferDecode(options.challenge),
      timeout: options.timeout,
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map(cred => ({
        id: typeof cred.id === 'string' ? bufferDecode(cred.id) : cred.id as BufferSource,
        type: 'public-key' as const,
        transports: cred.transports as AuthenticatorTransport[]
      })),
      userVerification: options.userVerification,
      extensions: options.extensions
    };
  }


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
    challengeId?: string,
    skipChallengeValidation: boolean = false
  ): Promise<{ success: boolean; nearAccountId: string; publicKey: string }> {
    return await this.webauthnWorkers.secureRegistrationWithPrf(
      nearAccountId,
      prfOutput,
      payload,
      challengeId,
      skipChallengeValidation
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
    },
    challengeId: string
  ): Promise<{ signedTransactionBorsh: number[]; nearAccountId: string }> {
    return await this.webauthnWorkers.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      payload,
      challengeId
    );
  }

  /**
   * Secure private key decryption with PRF
   */
  async securePrivateKeyDecryptionWithPrf(
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    challengeId: string
  ): Promise<{ decryptedPrivateKey: string; nearAccountId: string }> {
    return await this.webauthnWorkers.securePrivateKeyDecryptionWithPrf(
      nearAccountId,
      prfOutput,
      challengeId
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