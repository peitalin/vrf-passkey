import { SignedTransaction } from "../NearClient";
import { base64UrlDecode } from "../../utils/encoders";
import type { BaseSSEActionEvent } from './passkeyManager';
import { ActionStatus, RegistrationStatus, LoginStatus, DeviceLinkingStatus } from './passkeyManager';

// =================================================================
// 0. CORE WEBAUTHN & BROWSER-API TYPES
// =================================================================

export interface onProgressEvents extends BaseSSEActionEvent {
  step: number;
  status: ActionStatus;
  message: string;
  data?: any;
  logs?: string[];
}

export interface VerifyAndSignTransactionResult {
  signedTransaction: SignedTransaction;
  nearAccountId: string;
  logs?: string[];
}

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
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports: AuthenticatorTransport[];
  userId: string;
  name?: string;
  registered: Date;
  vrfPublicKeys?: string[];
  deviceNumber?: number;
}

// =================================================================
// 4. CONTRACT CALL TYPES
// =================================================================

/** VRF challenge data structure used in contract verification */
// export interface VrfChallengeData {
// }

export class VRFChallenge {
  vrfInput: string;
  vrfOutput: string;
  vrfProof: string;
  vrfPublicKey: string;
  userId: string;
  rpId: string;
  blockHeight: number;
  blockHash: string;

  constructor(vrfChallengeData: {
    vrfInput: string;
    vrfOutput: string;
    vrfProof: string;
    vrfPublicKey: string;
    userId: string;
    rpId: string;
    blockHeight: number;
    blockHash: string;
  }) {
    this.vrfInput = vrfChallengeData.vrfInput;
    this.vrfOutput = vrfChallengeData.vrfOutput;
    this.vrfProof = vrfChallengeData.vrfProof;
    this.vrfPublicKey = vrfChallengeData.vrfPublicKey;
    this.userId = vrfChallengeData.userId;
    this.rpId = vrfChallengeData.rpId;
    this.blockHeight = vrfChallengeData.blockHeight;
    this.blockHash = vrfChallengeData.blockHash;
  }

  /**
   * Decode VRF output and use first 32 bytes as WebAuthn challenge
   * @returns 32-byte Uint8Array
   */
  outputAs32Bytes(): Uint8Array {
    let vrfOutputBytes = base64UrlDecode(this.vrfOutput);
    return vrfOutputBytes.slice(0, 32);
  }
}


/** Registration data provided during registration contract calls */
export interface RegistrationData {
  nearPublicKey: string;
  prfOutput: ArrayBuffer;
}

/** Result of contract verification operations */
export interface ContractVerificationResponse {
  verified: boolean;
  transaction_id?: string;
  error?: string;
}

/** Result of VRF registration verification */
export interface VrfRegistrationResult {
  success: boolean;
  verified?: boolean;
  transactionId?: string;
  error?: string;
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
  clientExtensionResults?: AuthenticationExtensionsClientOutputs;
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
  clientExtensionResults?: AuthenticationExtensionsClientOutputs;
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

// === WEBAUTHN EXTENSION TYPES (Based on WebAuthn Level 2 Specification) ===
// These match the Rust structures in webauthn-contract/src/verify_authentication_response.rs

/**
 * WebAuthn Client Extension Outputs
 * Equivalent to AuthenticationExtensionsClientOutputs in Rust
 */
export interface AuthenticationExtensionsClientOutputs {
  /** Application Identifier Extension output */
  appid?: boolean;

  /** Credential Properties Extension output */
  credProps?: CredentialPropertiesOutput;

  /** HMAC Secret Extension output */
  hmacCreateSecret?: boolean;

  /** PRF (Pseudo-Random Function) Extension output */
  prf?: AuthenticationExtensionsPRFOutputs;
}

/**
 * PRF Extension Outputs
 * Equivalent to AuthenticationExtensionsPRFOutputs in Rust
 */
export interface AuthenticationExtensionsPRFOutputs {
  /** Whether PRF extension was enabled/supported */
  enabled?: boolean;

  /** PRF evaluation results (the actual PRF outputs) */
  results?: AuthenticationExtensionsPRFValues;
}

/**
 * PRF Extension Values
 * Equivalent to AuthenticationExtensionsPRFValues in Rust
 */
export interface AuthenticationExtensionsPRFValues {
  /** First PRF output (Base64URL encoded) */
  first: string;

  /** Optional second PRF output (Base64URL encoded) */
  second?: string;
}

/**
 * Credential Properties Extension Output
 * Equivalent to CredentialPropertiesOutput in Rust
 */
export interface CredentialPropertiesOutput {
  /** Resident key property */
  rk?: boolean;
}
