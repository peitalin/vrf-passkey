/**
 * VRF Manager
 * Uses Web Workers for VRF keypair management with client-hosted worker files.
 */

import { VRFChallenge } from '../types/webauthn';
import { EncryptedVRFKeypair } from '../types/vrf-worker';
import { base64UrlDecode } from '../../utils';

// === CONFIGURATION ===
const CONFIG = {
  TIMEOUTS: {
    VRF_WORKER: 30_000,   // 30s for VRF operations
  }
} as const;

// === VRF WORKER TYPES ===

export interface VRFWorkerMessage {
  type: string;
  id?: string;
  data?: any;
}

export interface VRFWorkerResponse {
  id?: string;
  success: boolean;
  data?: any;
  error?: string;
}

export interface VRFInputData {
  user_id: string;
  rp_id: string;
  block_height: number;
  block_hash: number[];
  timestamp?: number;
}

// === VRF WORKER MANAGER ===

export class VrfWorkerManager {
  private vrfWorker: Worker | null = null;
  private messageId = 0;
  private pendingMessages = new Map<string, {
    resolve: (value: VRFWorkerResponse) => void;
    reject: (error: Error) => void;
  }>();

  constructor() {
    this.initializeWorker();
  }

  private initializeWorker(): void {
    try {
      this.vrfWorker = new Worker(
        new URL('../../core/web3authn-vrf.worker.ts', import.meta.url),
        { type: 'module' }
      );

      this.vrfWorker.onmessage = (event) => {
        const response: VRFWorkerResponse = event.data;
        const messageId = response.id;

        if (messageId && this.pendingMessages.has(messageId)) {
          const { resolve } = this.pendingMessages.get(messageId)!;
          this.pendingMessages.delete(messageId);
          resolve(response);
        }
      };

      this.vrfWorker.onerror = (error) => {
        console.error('VRF Worker error:', error);
        // Reject all pending messages
        for (const [messageId, { reject }] of this.pendingMessages) {
          reject(new Error(`VRF Worker error: ${error.message}`));
          this.pendingMessages.delete(messageId);
        }
      };

      console.log('VRF Worker initialized successfully');
    } catch (error) {
      console.error('Failed to initialize VRF Worker:', error);
      throw error;
    }
  }

  private generateMessageId(): string {
    return `vrf-${++this.messageId}-${Date.now()}`;
  }

  private async sendMessage(message: VRFWorkerMessage): Promise<VRFWorkerResponse> {
    if (!this.vrfWorker) {
      throw new Error('VRF Worker not initialized');
    }

    return new Promise((resolve, reject) => {
      const messageId = message.id || this.generateMessageId();
      message.id = messageId;

      this.pendingMessages.set(messageId, { resolve, reject });

      // Set timeout for message
      setTimeout(() => {
        if (this.pendingMessages.has(messageId)) {
          this.pendingMessages.delete(messageId);
          reject(new Error(`VRF Worker message timeout: ${message.type}`));
        }
      }, CONFIG.TIMEOUTS.VRF_WORKER);

      this.vrfWorker!.postMessage(message);
    });
  }

  /**
   * Generate VRF keypair for bootstrapping (stored in memory unencrypted)
   * Optionally generates VRF challenge if input parameters are provided
   */
  async generateVrfKeypairBootstrap(vrfInputParams?: {
    userId: string;
    rpId: string;
    blockHeight: number;
    blockHashBytes: number[];
    timestamp: number;
  }): Promise<{
    vrfPublicKey: string;
    vrfChallenge?: VRFChallenge;
  }> {
    console.log('VRF Manager: Generating bootstrap VRF keypair');
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      const messageData: any = {};

      // Add VRF input parameters if provided for challenge generation
      if (vrfInputParams) {
        messageData.vrfInputParams = {
          user_id: vrfInputParams.userId,
          rp_id: vrfInputParams.rpId,
          block_height: vrfInputParams.blockHeight,
          block_hash: vrfInputParams.blockHashBytes,
          timestamp: vrfInputParams.timestamp
        };
      }

      const message: VRFWorkerMessage = {
        type: 'GENERATE_VRF_KEYPAIR_BOOTSTRAP',
        id: this.generateMessageId(),
        data: messageData
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF keypair bootstrap failed: ${response.error}`);
      }

      const result: {
        vrfPublicKey: string;
        vrfChallenge?: VRFChallenge;
      } = {
        vrfPublicKey: response.data.vrf_public_key
      };

      // Add VRF challenge if it was generated
      if (response.data.vrf_challenge_data) {
        result.vrfChallenge = new VRFChallenge({
          vrfInput: response.data.vrf_challenge_data.vrfInput,
          vrfOutput: response.data.vrf_challenge_data.vrfOutput,
          vrfProof: response.data.vrf_challenge_data.vrfProof,
          vrfPublicKey: response.data.vrf_challenge_data.vrfPublicKey,
          userId: response.data.vrf_challenge_data.userId,
          rpId: response.data.vrf_challenge_data.rpId,
          blockHeight: response.data.vrf_challenge_data.blockHeight,
          blockHash: response.data.vrf_challenge_data.blockHash,
        });
      }

      console.log('VRF Manager: Bootstrap VRF keypair generated successfully');
      return result;
    } catch (error: any) {
      console.error('VRF Manager: Bootstrap VRF keypair generation failed:', error);
      throw new Error(`Failed to generate bootstrap VRF keypair: ${error.message}`);
    }
  }

  /**
   * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
   * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
   *
   * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
   * @param prfOutput - Base64url-encoded PRF output for encryption
   * @returns Encrypted VRF keypair data ready for storage
   */
  async encryptVrfKeypairWithPrfOutput(
    expectedPublicKey: string,
    prfOutput: string
  ): Promise<{
    vrfPublicKey: string;
    encryptedVrfKeypair: EncryptedVRFKeypair;
  }> {
    console.log('VRF Manager: Encrypting in-memory VRF keypair with PRF output');
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'ENCRYPT_VRF_KEYPAIR_WITH_PRF',
        id: this.generateMessageId(),
        data: {
          expectedPublicKey: expectedPublicKey,
          prfKey: prfOutput // Base64url string directly
        }
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF keypair encryption failed: ${response.error}`);
      }

      const result = {
        vrfPublicKey: response.data.vrf_public_key,
        encryptedVrfKeypair: response.data.encrypted_vrf_keypair
      };

      console.log('VRF Manager: VRF keypair encryption successful');
      return result;
    } catch (error: any) {
      console.error('VRF Manager: VRF keypair encryption failed:', error);
      throw new Error(`Failed to encrypt VRF keypair: ${error.message}`);
    }
  }

  /**
   * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
   * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
   *
   * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
   * @param credential - WebAuthn credentials for encryption
   * @returns Encrypted VRF keypair data ready for storage
   */
  async encryptVrfKeypairWithCredentials(
    expectedPublicKey: string,
    credential: PublicKeyCredential
  ): Promise<{
    vrfPublicKey: string;
    encryptedVrfKeypair: EncryptedVRFKeypair;
  }> {
    console.log('VRF Manager: Encrypting in-memory VRF keypair with PRF output');
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    const prfOutput = credential.getClientExtensionResults()?.prf?.results?.first as ArrayBuffer;
    if (!prfOutput) {
      throw new Error('PRF output not found in WebAuthn credentials');
    }

    // Convert ArrayBuffer to base64url string for consistent processing
    const prfOutputBase64 = base64UrlEncode(prfOutput);

    return this.encryptVrfKeypairWithPrfOutput(expectedPublicKey, prfOutputBase64);
  }

  /**
   * Derive deterministic VRF keypair from PRF output for account recovery
   * Optionally generates VRF challenge if input parameters are provided
   * This enables deterministic VRF key derivation without needing stored VRF keypairs
   *
   * @param prfOutput - Base64url-encoded PRF output from WebAuthn credential (PRF Output 1)
   * @param nearAccountId - NEAR account ID for key derivation salt
   * @param vrfInputParams - Optional VRF input parameters for challenge generation
   * @returns Deterministic VRF public key, optional VRF challenge, and encrypted VRF keypair for storage
   */
  async deriveVrfKeypairFromSeed({
    prfOutput,
    nearAccountId,
    vrfInputParams
  }: {
    prfOutput: string;
    nearAccountId: string;
    vrfInputParams?: {
      userId: string;
      rpId: string;
      blockHeight: number;
      blockHashBytes: number[];
      timestamp: number;
    };
  }): Promise<{
    success: boolean;
    vrfPublicKey: string;
    vrfChallenge?: VRFChallenge;
    encryptedVrfKeypair?: EncryptedVRFKeypair;
  }> {
    console.log('VRF Manager: Deriving deterministic VRF keypair from PRF output');

    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      // Pass base64url string directly - VRF worker handles conversion internally
      const messageData: any = {
        prfOutput: prfOutput, // Base64url string directly
        nearAccountId: nearAccountId
      };

      // Add VRF input parameters if provided for challenge generation
      if (vrfInputParams) {
        messageData.vrfInputParams = {
          user_id: vrfInputParams.userId,
          rp_id: vrfInputParams.rpId,
          block_height: vrfInputParams.blockHeight,
          block_hash: vrfInputParams.blockHashBytes,
          timestamp: vrfInputParams.timestamp
        };
      }

      const message: VRFWorkerMessage = {
        type: 'DERIVE_VRF_KEYPAIR_FROM_PRF',
        id: this.generateMessageId(),
        data: messageData
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF keypair derivation failed: ${response.error}`);
      }

      console.log('VRF Manager: Deterministic VRF keypair derivation successful');

      const result: {
        success: boolean;
        vrfPublicKey: string;
        vrfChallenge?: VRFChallenge;
        encryptedVrfKeypair?: EncryptedVRFKeypair;
      } = {
        success: response.data.success,
        vrfPublicKey: response.data.vrf_public_key
      };

      // Add VRF challenge if it was generated
      if (response.data.vrf_challenge_data) {
        result.vrfChallenge = new VRFChallenge({
          vrfInput: response.data.vrf_challenge_data.vrfInput,
          vrfOutput: response.data.vrf_challenge_data.vrfOutput,
          vrfProof: response.data.vrf_challenge_data.vrfProof,
          vrfPublicKey: response.data.vrf_challenge_data.vrfPublicKey,
          userId: response.data.vrf_challenge_data.userId,
          rpId: response.data.vrf_challenge_data.rpId,
          blockHeight: response.data.vrf_challenge_data.blockHeight,
          blockHash: response.data.vrf_challenge_data.blockHash,
        });
      }

      // Add encrypted VRF keypair if it was generated
      if (response.data.encrypted_vrf_keypair) {
        result.encryptedVrfKeypair = response.data.encrypted_vrf_keypair;
      }

      return result;
    } catch (error: any) {
      console.error('VRF Manager: Deterministic VRF keypair derivation failed:', error);
      throw new Error(`Failed to derive VRF keypair from PRF: ${error.message}`);
    }
  }

  /**
   * Unlock VRF keypair with encrypted data and PRF output
   */
  async unlockVrfKeypair(
    nearAccountId: string,
    encryptedVrfKeypair: EncryptedVRFKeypair,
    prfOutput: string
  ): Promise<{ success: boolean }> {
    console.log('VRF Manager: Unlocking VRF keypair');
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'UNLOCK_VRF_KEYPAIR',
        id: this.generateMessageId(),
        data: {
          nearAccountId,
          encryptedVrfKeypair,
          prfKey: prfOutput // Base64url string directly
        }
      };

      const response = await this.sendMessage(message);

      if (!response.success) {
        throw new Error(`VRF keypair unlock failed: ${response.error}`);
      }

      console.log('VRF Manager: VRF keypair unlocked successfully');
      return { success: true };
    } catch (error: any) {
      console.error('VRF Manager: VRF keypair unlock failed:', error);
      throw new Error(`Failed to unlock VRF keypair: ${error.message}`);
    }
  }

  /**
   * Generate VRF challenge using unlocked keypair
   */
  async generateVrfChallenge(inputData: {
    userId: string;
    rpId: string;
    blockHeight: number;
    blockHashBytes: number[];
    timestamp?: number;
  }): Promise<VRFChallenge> {
    console.log('VRF Manager: Generating VRF challenge');
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'GENERATE_VRF_CHALLENGE',
        id: this.generateMessageId(),
        data: {
          user_id: inputData.userId,
          rp_id: inputData.rpId,
          block_height: inputData.blockHeight,
          block_hash: inputData.blockHashBytes,
          timestamp: inputData.timestamp
        }
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF challenge generation failed: ${response.error}`);
      }

      const challengeData = response.data;
      const vrfChallenge = new VRFChallenge({
        vrfInput: challengeData.vrfInput,
        vrfOutput: challengeData.vrfOutput,
        vrfProof: challengeData.vrfProof,
        vrfPublicKey: challengeData.vrfPublicKey,
        userId: challengeData.userId,
        rpId: challengeData.rpId,
        blockHeight: challengeData.blockHeight,
        blockHash: challengeData.blockHash,
      });

      console.log('VRF Manager: VRF challenge generated successfully');
      return vrfChallenge;
    } catch (error: any) {
      console.error('VRF Manager: VRF challenge generation failed:', error);
      throw new Error(`Failed to generate VRF challenge: ${error.message}`);
    }
  }

  /**
   * Check VRF worker status
   */
  async checkVrfStatus(): Promise<{ active: boolean; sessionDuration: number }> {
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'CHECK_VRF_STATUS',
        id: this.generateMessageId()
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF status check failed: ${response.error}`);
      }

      return {
        active: response.data.active,
        sessionDuration: response.data.sessionDuration
      };
    } catch (error: any) {
      console.error('VRF Manager: VRF status check failed:', error);
      throw new Error(`Failed to check VRF status: ${error.message}`);
    }
  }

  /**
   * Logout and clear VRF keypair from memory
   */
  async logout(): Promise<{ success: boolean }> {
    console.log('VRF Manager: Logging out and clearing VRF keypair');
    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'LOGOUT',
        id: this.generateMessageId()
      };

      const response = await this.sendMessage(message);

      if (!response.success) {
        throw new Error(`VRF logout failed: ${response.error}`);
      }

      console.log('VRF Manager: VRF logout successful');
      return { success: true };
    } catch (error: any) {
      console.error('VRF Manager: VRF logout failed:', error);
      throw new Error(`Failed to logout VRF: ${error.message}`);
    }
  }

  /**
   * Terminate VRF worker
   */
  terminate(): void {
    if (this.vrfWorker) {
      this.vrfWorker.terminate();
      this.vrfWorker = null;
      console.log('VRF Worker terminated');
    }
  }
}

// Helper function to encode ArrayBuffer to base64url
function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}