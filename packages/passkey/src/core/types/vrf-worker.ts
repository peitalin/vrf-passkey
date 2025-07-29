/**
 * VRF Types for Web Worker Communication
 */

export interface VRFKeypairData {
  /** Bincode-serialized ECVRFKeyPair (includes both private key and public key) */
  keypair_bytes: Uint8Array;
  /** Base64url-encoded public key for convenience */
  public_key_base64: string;
}

export interface EncryptedVRFKeypair {
  encrypted_vrf_data_b64u: string;
  chacha20_nonce_b64u: string;
}

export interface VRFInputData {
  userId: string;
  rpId: string;
  blockHeight: number;
  blockHash: string;
}

export interface VRFChallengeData {
  vrfInput: string;
  vrfOutput: string;
  vrfProof: string;
  vrfPublicKey: string;
  userId: string;
  rpId: string;
  blockHeight: number;
  blockHash: string;
}

export interface VRFWorkerMessage {
  type: 'PING'
      | 'UNLOCK_VRF_KEYPAIR'
      | 'GENERATE_VRF_CHALLENGE'
      | 'GENERATE_VRF_KEYPAIR_BOOTSTRAP'
      | 'ENCRYPT_VRF_KEYPAIR_WITH_PRF'
      | 'DERIVE_VRF_KEYPAIR_FROM_PRF'
      | 'CHECK_VRF_STATUS'
      | 'LOGOUT';
  id?: string;
  data?: any;
}

export interface VRFWorkerResponse {
  id?: string;
  success: boolean;
  data?: any;
  error?: string;
}

export interface VRFKeypairBootstrapResponse {
  vrfPublicKey: string;
  vrfChallengeData?: VRFChallengeData;
}

export interface EncryptedVRFKeypairResponse {
  vrfPublicKey: string;
  encryptedVrfKeypair: EncryptedVRFKeypair;
}