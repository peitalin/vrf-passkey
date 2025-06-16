import type { Provider } from '@near-js/providers';
import { WebAuthnWorkers } from './webauthn-workers';
import { WebAuthnNetworkCalls } from './network-calls';
import { WebAuthnContractCalls } from './contract-calls';
import { indexDBManager } from '../IndexDBManager';
import { bufferEncode, bufferDecode } from '../../utils/encoders';
import type {
  GenerateRegistrationOptionsRequest,
  GenerateRegistrationOptionsResponse,
  GenerateAuthenticationOptionsRequest,
  GenerateAuthenticationOptionsResponse,
  PublicKeyCredentialRequestOptionsJSON
} from '../../types/endpoints';

// === TYPE DEFINITIONS ===

interface UserData {
  nearAccountId: string;
  clientNearPublicKey?: string;
  lastUpdated: number;
  prfSupported?: boolean;
  deterministicKey?: boolean;
  passkeyCredential?: {
    id: string;
    rawId: string;
  };
}

interface WebAuthnRegistrationWithPrf {
  credential: PublicKeyCredential;
  prfEnabled: boolean;
  commitmentId?: string;
}

interface WebAuthnAuthenticationWithPrf {
  credential: PublicKeyCredential;
  prfOutput?: ArrayBuffer;
}

interface RegistrationOptions {
  options: PublicKeyCredentialCreationOptions;
  challengeId: string;
  commitmentId?: string;
}

interface AuthenticationOptions {
  options: PublicKeyCredentialRequestOptions;
  challengeId: string;
}

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

  constructor() {
    this.webauthnWorkers = new WebAuthnWorkers();
    this.networkCalls = new WebAuthnNetworkCalls(this.webauthnWorkers);
    this.contractCalls = new WebAuthnContractCalls(this.webauthnWorkers, this.networkCalls);
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

  // === SERVER COMMUNICATION (Delegated to WebAuthnNetworkCalls) ===

  /**
   * Get registration options from server with custom URL and register challenge
   */
  async getRegistrationOptionsFromServer(
    serverUrl: string,
    nearAccountId: string
  ): Promise<RegistrationOptions> {
    try {
      const requestData: GenerateRegistrationOptionsRequest = {
        accountId: nearAccountId
      };

      const response = await fetch(`${serverUrl}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to fetch registration options'
        }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const serverResponseObject: GenerateRegistrationOptionsResponse = await response.json();

      if (!serverResponseObject?.options?.challenge ||
          typeof serverResponseObject.options.challenge !== 'string') {
        console.error("[FRONTEND ERROR] Invalid or missing options.challenge in server response:",
                     serverResponseObject);
        throw new Error('Invalid or missing options.challenge in server response.');
      }

      if (serverResponseObject.options.excludeCredentials &&
          !Array.isArray(serverResponseObject.options.excludeCredentials)) {
        console.error("[FRONTEND ERROR] options.excludeCredentials is not an array:",
                     serverResponseObject.options.excludeCredentials);
      }

      // Convert JSON format to WebAuthn API format
      const convertedOptions: PublicKeyCredentialCreationOptions = {
        challenge: bufferDecode(serverResponseObject.options.challenge),
        rp: serverResponseObject.options.rp,
        user: {
          id: typeof serverResponseObject.options.user.id === 'string'
            ? new TextEncoder().encode(serverResponseObject.options.user.id)
            : serverResponseObject.options.user.id as BufferSource,
          name: serverResponseObject.options.user.name,
          displayName: serverResponseObject.options.user.displayName
        },
        pubKeyCredParams: serverResponseObject.options.pubKeyCredParams,
        excludeCredentials: serverResponseObject.options.excludeCredentials?.map(c => ({
          id: typeof c.id === 'string' ? bufferDecode(c.id) : c.id as BufferSource,
          type: 'public-key' as const,
          transports: c.transports as AuthenticatorTransport[]
        })),
        authenticatorSelection: serverResponseObject.options.authenticatorSelection,
        timeout: serverResponseObject.options.timeout,
        attestation: serverResponseObject.options.attestation,
        extensions: serverResponseObject.options.extensions
      };

      const challengeId = this.webauthnWorkers.registerServerChallenge(serverResponseObject.options.challenge, 'registration');
      const commitmentId = serverResponseObject.commitmentId;

      return { options: convertedOptions, challengeId, commitmentId };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get registration options:', error);
      throw error;
    }
  }

  /**
   * Get authentication options from server with custom URL and register challenge
   */
  async getAuthenticationOptionsFromServer(
    serverUrl: string,
    nearAccountId?: string
  ): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> {
    try {
      const requestData: GenerateAuthenticationOptionsRequest = {
        accountId: nearAccountId ? indexDBManager.extractUsername(nearAccountId) : undefined
      };

      const response = await fetch(`${serverUrl}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          error: 'Failed to fetch authentication options'
        }));
        throw new Error(errorData.error || `Server error ${response.status}`);
      }

      const options: GenerateAuthenticationOptionsResponse = await response.json();
      const challengeId = this.webauthnWorkers.registerServerChallenge(options.challenge, 'authentication');

      return {
        options: options,
        challengeId: challengeId,
      };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get authentication options:', error);
      throw error;
    }
  }

  /**
   * Get authentication options from contract for serverless mode
   */
  async getAuthenticationOptionsFromContract(
    nearRpcProvider: Provider,
    nearAccountId: string
  ): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> {
    const { WEBAUTHN_CONTRACT_ID } = await import('../../config');

    return await this.networkCalls.getAuthenticationOptionsFromContract(
      nearRpcProvider,
      WEBAUTHN_CONTRACT_ID,
      {
        nearAccountId,
        receiverId: WEBAUTHN_CONTRACT_ID,
        contractMethodName: 'auth',
        contractArgs: {},
        gasAmount: '100000000000000',
        depositAmount: '0'
      }
    );
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
   * Register with PRF using server URL for challenge generation
   */
  async registerWithPrfAndUrl(
    serverUrl: string | undefined,
    nearAccountId: string,
    useOptimistic?: boolean
  ): Promise<WebAuthnRegistrationWithPrf> {
    if (!serverUrl) {
      throw new Error('Server URL is required for server-based registration');
    }

    const { options, challengeId, commitmentId } = await this.getRegistrationOptionsFromServer(
      serverUrl,
      nearAccountId
    );

    // Add PRF extension
    options.extensions = {
      ...options.extensions,
      prf: {
        eval: {
          first: this.webauthnWorkers.getPrfSalts().nearKeyEncryption
        }
      }
    };

    const credential = await navigator.credentials.create({
      publicKey: options
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn registration failed');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfResults = (extensionResults as any).prf;
    const prfOutput = prfResults?.results?.first;
    const prfEnabled = !!prfOutput;

    return { credential, prfEnabled, commitmentId };
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
    const challengeB64 = bufferEncode(challenge);

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

  /**
   * Authenticate with PRF using server URL for challenge generation
   */
  async authenticateWithPrfAndUrl(
    serverUrl: string | undefined,
    nearAccountId?: string,
    purpose: 'encryption' | 'signing' = 'signing',
    useOptimistic: boolean = true
  ): Promise<WebAuthnAuthenticationWithPrf> {
    if (!serverUrl) {
      throw new Error('Server URL is required for server-based authentication');
    }

    const { options, challengeId } = await this.getAuthenticationOptionsFromServer(
      serverUrl,
      nearAccountId
    );

    // Convert and add PRF extension
    const authenticationOptions = this.convertAuthenticationOptions(options);
    authenticationOptions.extensions = {
      ...authenticationOptions.extensions,
      prf: {
        eval: {
          first: this.webauthnWorkers.getPrfSalts().nearKeyEncryption
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

  /**
   * Validate COSE key format using WASM worker
   */
  async validateCoseKeyFormat(coseKeyBytes: Uint8Array): Promise<{ valid: boolean; info: any }> {
    return await this.webauthnWorkers.validateCoseKeyFormat(coseKeyBytes);
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
}