// =================================================================
// 0. CORE WEBAUTHN & BROWSER-API TYPES
// =================================================================

/** Transport modes for authenticators */
export type AuthenticatorTransport = 'ble' | 'hybrid' | 'internal' | 'nfc' | 'usb';

/** User verification requirement for WebAuthn operations */
export type UserVerificationRequirement = 'discouraged' | 'preferred' | 'required';

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

// =================================================================
// 1. HIGH-LEVEL WRAPPERS & OPTIONS
// =================================================================

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
  extensionResults?: AuthenticationExtensionsClientOutputs;
}


// =================================================================
// 2. PRF MANAGEMENT
// =================================================================
// Note: Challenge management removed - VRF provides cryptographic freshness

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
  transports?: AuthenticatorTransport[];
  userId: string;
  name?: string;
  registered: Date;
  lastUsed?: Date;
  backedUp: boolean;
  clientNearPublicKey?: string;
}


// =================================================================
// 4. CONTRACT CALL TYPES
// =================================================================

/** VRF challenge data structure used in contract verification */
export interface VrfChallengeData {
  vrfInput: string;
  vrfOutput: string;
  vrfProof: string;
  vrfPublicKey: string;
  userId: string;
  rpId: string;
  blockHeight: number;
  blockHash: string;
}

/** Registration data provided during registration contract calls */
export interface RegistrationData {
  nearPublicKey: string;
  prfOutput: ArrayBuffer;
}

/** User data structure for transaction operations */
export interface UserDataForTransaction {
  clientNearPublicKey?: string;
}

/** Result of contract verification operations */
export interface ContractVerificationResponse {
  verified: boolean;
  transaction_id?: string;
  error?: string;
}

/** Result of VRF authentication verification */
export interface VrfAuthenticationResult {
  success: boolean;
  verified?: boolean;
  error?: string;
}

/** Result of VRF registration verification */
export interface VrfRegistrationResult {
  success: boolean;
  verified?: boolean;
  transactionId?: string;
  error?: string;
}

/** Result of checking call permissions for an account */
export interface CallPermissionsResult {
  hasPermission: boolean;
  allowedReceivers?: string[];
  allowedMethods?: string[];
}

/** Network information for transaction building */
export interface NetworkInfo {
  latest_block_height: number;
  latest_block_hash: string;
  node_version: string;
  protocol_version: number;
  chain_id: string;
}

/** WebAuthn authentication data structure for contract calls */
export interface WebAuthnAuthenticationData {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
  };
  authenticatorAttachment?: string | null;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
}

/** WebAuthn registration data structure for contract calls */
export interface WebAuthnRegistrationData {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  authenticatorAttachment?: string | null;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
}

/** VRF data structure for contract verification calls */
export interface ContractVrfData {
  vrf_input_data: number[];
  vrf_output: number[];
  vrf_proof: number[];
  public_key: number[];
  user_id: string;
  rp_id: string;
  block_height: number;
  block_hash: number[];
}

