import type { SerializableActionArgs } from './index';
import type { PasskeyErrorCode } from './errors';

// =================================================================
// 0. CORE WEBAUTHN & BROWSER-API TYPES
// =================================================================

/** Transport modes for authenticators */
export type AuthenticatorTransport = 'ble' | 'hybrid' | 'internal' | 'nfc' | 'usb';

/** JSON-compatible version of PublicKeyCredentialCreationOptions */
export interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: {
    name: string;
    id?: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{
    type: 'public-key';
    alg: number;
  }>;
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey?: 'discouraged' | 'preferred' | 'required';
    requireResidentKey?: boolean;
    userVerification?: 'discouraged' | 'preferred' | 'required';
  };
  timeout?: number;
  attestation?: 'none' | 'indirect' | 'direct' | 'enterprise';
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  extensions?: Record<string, any>;
}

/** JSON-compatible version of PublicKeyCredentialRequestOptions */
export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  userVerification?: 'discouraged' | 'preferred' | 'required';
  extensions?: Record<string, any>;
}

/** JSON-compatible version of a registration response */
export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
    transports?: AuthenticatorTransport[];
  };
  authenticatorAttachment?: string;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
}

/** JSON-compatible version of an authentication response */
export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
}


// =================================================================
// 1. HIGH-LEVEL WRAPPERS & OPTIONS
// =================================================================

/** Options for a WebAuthn registration ceremony */
export interface RegistrationOptions {
  options: PublicKeyCredentialCreationOptions;
  challengeId: string;
  commitmentId?: string;
  expiresAt?: number;
}

/** Options for a WebAuthn authentication ceremony */
export interface AuthenticationOptions {
  options: PublicKeyCredentialRequestOptions;
  challengeId: string;
  commitmentId?: string;
  expiresAt?: number;
}

/** Enhanced WebAuthn registration result that includes PRF details */
export interface WebAuthnRegistrationWithPrf {
  credential: PublicKeyCredential;
  prfEnabled: boolean;
  prfOutput?: ArrayBuffer;
  commitmentId?: string;
  extensionResults?: AuthenticationExtensionsClientOutputs;
}

/** Enhanced WebAuthn authentication result that includes PRF details */
export interface WebAuthnAuthenticationWithPrf {
  credential: PublicKeyCredential;
  prfOutput?: ArrayBuffer;
  challengeId?: string;
  extensionResults?: AuthenticationExtensionsClientOutputs;
}


// =================================================================
// 2. CHALLENGE & PRF MANAGEMENT
// =================================================================

/** Represents a WebAuthn challenge for a specific operation */
export interface WebAuthnChallenge {
  id: string;
  challenge: string;
  timestamp: number;
  used: boolean;
  operation: 'registration' | 'authentication';
  timeout: number;
  source?: 'server' | 'local' | 'contract';
  metadata?: Record<string, any>;
}

/** The result of validating a WebAuthn challenge */
export interface ChallengeValidationResult {
  valid: boolean;
  challenge?: WebAuthnChallenge;
  error?: string;
  consumed?: boolean;
}

/** Configuration for PRF salts used in deterministic key derivation */
export interface PrfSaltConfig {
  nearKeyEncryption: Uint8Array;
  [key: string]: Uint8Array;
}

/** A PRF evaluation request for WebAuthn extensions */
export interface PrfEvaluationRequest {
  first: Uint8Array;
  second?: Uint8Array;
}

/** The result of a PRF evaluation from the WebAuthn API */
export interface PrfEvaluationResult {
  first?: ArrayBuffer;
  second?: ArrayBuffer;
}


// =================================================================
// 3. AUTHENTICATOR & STORAGE TYPES
// =================================================================

/** Stored authenticator information, normalized for client-side use */
export interface StoredAuthenticator {
  credentialID: string;
  credentialPublicKey: Uint8Array;
  counter: number;
  transports?: AuthenticatorTransport[];
  userId: string;
  name?: string;
  registered: Date;
  lastUsed?: Date;
  backedUp: boolean;
  clientNearPublicKey?: string;
}


// =================================================================
// 4. NETWORK & SERVER COMMUNICATION
// =================================================================

// ~~~ Generic Request / Response ~~~
export interface BaseRequest {}
export interface BaseResponse {
  success?: boolean;
  error?: string;
}

// ~~~ Registration Endpoints ~~~
export interface GenerateRegistrationOptionsRequest extends BaseRequest {
  accountId: string;
}
export interface GenerateRegistrationOptionsResponse extends BaseResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId?: string;
  commitmentId?: string;
}
export interface VerifyRegistrationRequest {
  accountId: string;
  attestationResponse: RegistrationResponseJSON;
  commitmentId?: string;
  clientNearPublicKey?: string;
}

// ~~~ Authentication Endpoints ~~~
export interface GenerateAuthenticationOptionsRequest extends BaseRequest {
  accountId?: string;
}
export interface GenerateAuthenticationOptionsResponse extends BaseResponse {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  userVerification?: 'discouraged' | 'preferred' | 'required';
  extensions?: {
    appid?: string;
    credProps?: boolean;
    hmacCreateSecret?: boolean;
    minPinLength?: boolean;
  };
  nearAccountId?: string;
  commitmentId?: string;
}
export interface VerifyAuthenticationRequest {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
  commitmentId?: string;
}
export interface VerifyAuthenticationResponse extends BaseResponse {
  verified: boolean;
  nearAccountId: string;
}

// ~~~ Action Signing Endpoint ~~~
export interface ActionChallengeRequest {
  accountId: string;
  actionDetails: SerializableActionArgs;
}
export interface ActionChallengeResponse extends BaseResponse {
  challenge: string;
  rpId: string;
  allowCredentials: Array<{
    type: 'public-key';
    id: string;
  }>;
  userVerification: 'preferred';
  timeout: number;
}

// ~~~ Server Options ~~~
/** Options for server-based authentication, typically fetched from a backend */
export interface ServerAuthenticationOptions {
  challenge: string;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: string;
    transports: AuthenticatorTransport[];
  }>;
  userVerification?: UserVerificationRequirement;
  timeout?: number;
}


// =================================================================
// 5. CONTRACT & WORKER PAYLOADS
// =================================================================

// ~~~ Contract Integration ~~~
/** Authenticator format compatible with the smart contract */
export interface ContractAuthenticator {
  credential_public_key: number[];
  counter: number;
  transports?: string[];
  client_managed_near_public_key?: string;
  name?: string;
  registered: string;
  last_used?: string;
  backed_up: boolean;
}
export interface ContractRegistrationArgs {
  rp_name: string;
  rp_id: string;
  user_name: string;
  user_id: string;
  challenge: string | null;
  [key: string]: any;
}
export interface ContractAuthenticationArgs {
  rp_id: string | null;
  allow_credentials: Array<{
    id: string;
    type: string;
    transports?: string[];
  }> | null;
  challenge: string | null;
  authenticator: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    transports?: string[];
  };
  [key: string]: any;
}

export interface ContractGenerateOptionsArgs {
  rp_name: string;
  rp_id: string;
  user_name: string;
  user_id: string;
  challenge: string | null;
  user_display_name: string | null;
  timeout: number | null;
  attestation_type: string | null;
  exclude_credentials: { id: string; type: string; transports?: string[] }[] | null;
  authenticator_selection: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  } | null;
  extensions: { cred_props?: boolean } | null;
  supported_algorithm_ids: number[] | null;
  preferred_authenticator_type: string | null;
}

export interface ContractCompleteRegistrationArgs {
  registration_response: RegistrationResponseJSON;
  commitment_id: string;
}

export interface ContractGenerateAuthOptionsArgs {
  rp_id: string | null;
  allow_credentials: { id: string; type: string; transports?: string[] }[] | null;
  challenge: string | null;
  timeout: number | null;
  user_verification: 'discouraged' | 'preferred' | 'required' | null;
  extensions: {
    appid?: string;
    cred_props?: boolean;
    hmac_create_secret?: boolean;
    min_pin_length?: boolean
  } | null;
  authenticator: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    transports?: string[];
  };
}

export interface ContractVerifyAuthArgs {
  authentication_response: AuthenticationResponseJSON;
  commitment_id: string;
}

export interface ContractRegistrationOptionsResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId: string | undefined;
  commitmentId: string | null;
}

export interface ContractCallPreparation {
  nearAccountId: string;
  contractId: string;
  methodName: string;
  args: any;
  gas: string;
  deposit: string;
  nonce: string;
  blockHash: Uint8Array;
  publicKey: string;
}

// ~~~ Worker Payloads ~~~
/** Payload for a PRF-based registration in the WASM worker */
export interface PrfRegistrationPayload {
  nearAccountId: string;
  prfOutput: ArrayBuffer;
  challengeId?: string;
  skipChallengeValidation?: boolean;
}
/** Payload for a PRF-based transaction signing in the WASM worker */
export interface PrfSigningPayload {
  nearAccountId: string;
  prfOutput: ArrayBuffer;
  receiverId: string;
  contractMethodName: string;
  contractArgs: Record<string, any>;
  gasAmount: string;
  depositAmount: string;
  nonce: string;
  blockHashBytes: number[];
  challengeId: string;
}
/** Payload for a PRF-based key decryption in the WASM worker */
export interface PrfDecryptionPayload {
  nearAccountId: string;
  prfOutput: ArrayBuffer;
  challengeId: string;
}


// =================================================================
// 6. VALIDATION & UTILITIES
// =================================================================

/** Context for validating a WebAuthn response */
export interface WebAuthnValidationContext {
  expectedOrigin: string;
  expectedRpId: string;
  expectedChallenge: string;
  requireUserVerification: boolean;
  allowedCredentials?: string[];
  timestamp: number;
}

/** The result of a WebAuthn validation check */
export interface WebAuthnValidationResult {
  valid: boolean;
  errorCode?: PasskeyErrorCode;
  errorMessage?: string;
  validationDetails?: {
    originValid: boolean;
    rpIdValid: boolean;
    challengeValid: boolean;
    signatureValid: boolean;
    userVerificationValid: boolean;
    counterValid: boolean;
  };
}

/** Creates a new WebAuthn challenge object */
export function createWebAuthnChallenge(
  operation: 'registration' | 'authentication',
  source: 'server' | 'local' | 'contract' = 'local',
  timeout: number = 300000
): WebAuthnChallenge {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengeB64 = btoa(String.fromCharCode(...challenge));

  return {
    id: `${operation}_${Date.now()}_${Math.random().toString(36).substring(2)}`,
    challenge: challengeB64,
    timestamp: Date.now(),
    used: false,
    operation,
    timeout,
    source
  };
}

/** Converts a contract-formatted authenticator to the client-side format */
export function contractToClientAuthenticator(
  contractAuth: ContractAuthenticator,
  credentialId: string,
  nearAccountId: string
): StoredAuthenticator {
  return {
    credentialID: credentialId,
    credentialPublicKey: new Uint8Array(contractAuth.credential_public_key),
    counter: contractAuth.counter,
    transports: contractAuth.transports as AuthenticatorTransport[],
    userId: nearAccountId,
    name: contractAuth.name,
    registered: new Date(contractAuth.registered),
    lastUsed: contractAuth.last_used ? new Date(contractAuth.last_used) : undefined,
    backedUp: contractAuth.backed_up,
    clientNearPublicKey: contractAuth.client_managed_near_public_key,
  };
}

/** Converts a client-side authenticator to the contract-compatible format */
export function clientToContractAuthenticator(auth: StoredAuthenticator): ContractAuthenticator {
  return {
    credential_public_key: Array.from(auth.credentialPublicKey),
    counter: auth.counter,
    transports: auth.transports?.map(t => t.toString()),
    client_managed_near_public_key: auth.clientNearPublicKey,
    name: auth.name,
    registered: auth.registered.toISOString(),
    last_used: auth.lastUsed?.toISOString(),
    backed_up: auth.backedUp,
  };
}

/** Creates metadata for an operation, including duration */
export function createOperationMetadata(
  operationType: 'registration' | 'authentication' | 'key-generation',
  mode: 'server' | 'serverless' | 'hybrid',
  startTime: number
) {
  return {
    operationType,
    timestamp: Date.now(),
    duration: Date.now() - startTime,
    mode
  };
}