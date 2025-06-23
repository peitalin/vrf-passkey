/**
 * VRF Manager - Web Worker Implementation
 *
 * Uses Web Workers for VRF keypair management with client-hosted worker files.
 * Requires copying worker files to your public directory.
 *
 * Benefits:
 * + Simple Web Worker setup without Worker complexity
 * + Direct communication without MessageChannel
 * + No scope or registration issues
 * + Session-based persistence
 */

import type {
  VRFKeypairData,
  EncryptedVRFData,
  VRFInputData,
  VRFChallengeData,
  VRFWorkerMessage,
  VRFWorkerResponse
} from '../types/vrf';

export interface VRFManagerConfig {
  /**
   * URL to the VRF Web Worker file
   * Defaults to client-hosted worker file
   *
   * Examples:
   * - undefined (uses default: '/workers/wasm_vrf_worker.js')
   * - '/workers/wasm_vrf_worker.js' (client-hosted)
   * - '/custom/path/wasm_vrf_worker.js' (custom location)
   */
  vrfWorkerUrl?: string;

  /**
   * Timeout for Web Worker initialization (ms)
   */
  workerTimeout?: number;

  /**
   * Whether to enable debug logging
   */
  debug?: boolean;
}

export interface VRFWorkerStatus {
  active: boolean;
  nearAccountId: string | null;
  sessionDuration?: number;
}

/**
 * VRF Manager - Web Worker Implementation
 *
 * This class manages VRF operations using Web Workers for:
 * - VRF keypair unlocking (login)
 * - VRF challenge generation (authentication)
 * - Session management (browser session only)
 * - Client-hosted worker files
 */
export class VRFManager {
  private vrfWorker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private messageId = 0;
  private config: VRFManagerConfig;
  private currentVrfAccountId: string | null = null;

  constructor(config: VRFManagerConfig = {}) {
    this.config = {
      // Default to client-hosted worker file
      vrfWorkerUrl: '/workers/web3authn-vrf.worker.js',
      workerTimeout: 10000,
      debug: false,
      ...config
    };
    console.log('VRF Manager: Initializing with client-hosted Web Worker...');
  }

    /**
   * Initialize VRF functionality using Web Workers
   */
  async initialize(): Promise<void> {
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    this.initializationPromise = this.initializeWebWorker();
    return this.initializationPromise;
  }

  /**
   * Check if VRF Web Worker is ready for use
   */
  async isReady(): Promise<boolean> {
    try {
      if (!this.vrfWorker) {
        return false;
      }

      const response = await this.sendMessage({
        type: 'PING',
        id: this.generateMessageId(),
        data: {}
      }, 5000);

      return response.success;
    } catch (error) {
      console.warn('VRF Manager: Web Worker readiness check failed:', error);
      return false;
    }
  }

  /**
   * Unlock VRF keypair in Web Worker memory using PRF output
   * This is called during login to decrypt and load the VRF keypair in-memory
   */
  async unlockVRFKeypair(
    nearAccountId: string,
    encryptedVrfData: EncryptedVRFData,
    prfOutput: ArrayBuffer
  ): Promise<VRFWorkerResponse> {
    console.log(`VRF Manager: Unlocking VRF keypair for ${nearAccountId}`);

    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    const message: VRFWorkerMessage = {
      type: 'UNLOCK_VRF_KEYPAIR',
      id: this.generateMessageId(),
      data: {
      nearAccountId,
      encryptedVrfData,
        prfKey: Array.from(new Uint8Array(prfOutput))
      }
    };

    const response = await this.sendMessage(message);

    if (response.success) {
      // Track the current VRF session account at TypeScript level
      this.currentVrfAccountId = nearAccountId;
      console.log(`✅ VRF Manager: VRF keypair unlocked for ${nearAccountId}`);
    } else {
      console.error('❌ VRF Manager: Failed to unlock VRF keypair:', response.error);
    }

    return response;
  }

  /**
   * Generate VRF challenge using in-memory VRF keypair
   * This is called during authentication to create WebAuthn challenges
   */
  async generateVRFChallenge(inputData: VRFInputData): Promise<VRFChallengeData> {
    console.log('VRF Manager: Generating VRF challenge...');

    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    const message: VRFWorkerMessage = {
      type: 'GENERATE_VRF_CHALLENGE',
      id: this.generateMessageId(),
      data: {
        user_id: inputData.userId,
        rp_id: inputData.rpId,
        session_id: inputData.sessionId,
        block_height: inputData.blockHeight,
        block_hash: Array.from(inputData.blockHash),
        timestamp: inputData.timestamp
      }
    };

    const response = await this.sendMessage(message);

    if (!response.success || !response.data) {
      throw new Error(`VRF challenge generation failed: ${response.error}`);
    }

    console.log('✅ VRF Manager: VRF challenge generated successfully');
    return response.data as VRFChallengeData;
  }

  /**
   * Get current VRF session status
   */
  async getVRFStatus(): Promise<{
    active: boolean;
    nearAccountId?: string;
    sessionDuration?: number;
  }> {
    if (!this.vrfWorker) {
      return { active: false };
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'CHECK_VRF_STATUS',
        id: this.generateMessageId(),
        data: {}
      };

      const response = await this.sendMessage(message);

      if (response.success && response.data) {
        return {
          active: response.data.active,
          nearAccountId: this.currentVrfAccountId || undefined,
          sessionDuration: response.data.sessionDuration
        };
      }

      return { active: false };
    } catch (error) {
      console.warn('VRF Manager: Failed to get VRF status:', error);
      return { active: false };
    }
  }

  /**
   * Logout and clear VRF session
   */
  async logout(): Promise<void> {
    console.log('🚪 VRF Manager: Logging out...');

    if (!this.vrfWorker) {
      return;
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'LOGOUT',
        id: this.generateMessageId(),
        data: {}
      };

      const response = await this.sendMessage(message);

      if (response.success) {
        // Clear the TypeScript-tracked account ID
        this.currentVrfAccountId = null;
        console.log('✅ VRF Manager: Logout successful - VRF keypair securely zeroized');
      } else {
        console.warn('⚠️ VRF Manager: Logout failed:', response.error);
      }
    } catch (error) {
      console.warn('VRF Manager: Logout error:', error);
    }
  }

  /**
   * Force cleanup of VRF Web Worker and sessions (for error recovery)
   */
  async forceCleanup(): Promise<void> {
    console.log('🧹 VRF Manager: Force cleanup initiated...');

    try {
      // First try to logout gracefully
      await this.logout();

      // Terminate the worker
      if (this.vrfWorker) {
        this.vrfWorker.terminate();
        this.vrfWorker = null;
      }

      // Reset initialization state
      this.initializationPromise = null;

      // Clear the TypeScript-tracked account ID
      this.currentVrfAccountId = null;

      console.log('✅ VRF Manager: Force cleanup completed');
    } catch (error) {
      console.warn('VRF Manager: Force cleanup partial failure:', error);
    }
  }

  // === VRF OPERATIONS ===

  /**
   * Generate VRF keypair for bootstrapping - stores in memory unencrypted temporarily
   * This is used during registration to generate a VRF keypair that will be used for
   * WebAuthn ceremony and later encrypted with the real PRF output
   *
   * @param saveInMemory - Always true for bootstrap (VRF keypair stored in memory)
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
    console.log('VRF Manager: Generating bootstrap VRF keypair', {
      saveInMemory,
      withChallenge: !!vrfInputParams
    });

    if (!this.vrfWorker) {
      await this.initialize();
    }

    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized after initialization attempt');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'GENERATE_VRF_KEYPAIR_BOOTSTRAP',
        id: this.generateMessageId(),
        data: {
          // Include VRF input parameters if provided for challenge generation
          vrfInputParams: vrfInputParams ? {
            user_id: vrfInputParams.userId,
            rp_id: vrfInputParams.rpId,
            session_id: vrfInputParams.sessionId,
            block_height: vrfInputParams.blockHeight,
            block_hash: vrfInputParams.blockHashBytes,
            timestamp: vrfInputParams.timestamp
          } : undefined
        }
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF bootstrap keypair generation failed: ${response.error}`);
      }

      const result: {
        vrfPublicKey: string;
        vrfChallengeData?: {
          vrfInput: string;
          vrfOutput: string;
          vrfProof: string;
          vrfPublicKey: string;
          rpId: string;
        };
      } = {
        vrfPublicKey: response.data.vrf_public_key
      };

      // If VRF challenge data was also generated, include it in the result
      if (response.data.vrf_challenge_data) {
        // Track the account ID for this VRF session if saving in memory
        if (vrfInputParams && saveInMemory) {
          this.currentVrfAccountId = vrfInputParams.userId;
        }

        result.vrfChallengeData = {
          vrfInput: response.data.vrf_challenge_data.vrfInput,
          vrfOutput: response.data.vrf_challenge_data.vrfOutput,
          vrfProof: response.data.vrf_challenge_data.vrfProof,
          vrfPublicKey: response.data.vrf_challenge_data.vrfPublicKey,
          rpId: response.data.vrf_challenge_data.rpId
        };
        console.log('✅ VRF Manager: Bootstrap VRF keypair + challenge generation successful', {
          saveInMemory,
          accountTracked: saveInMemory ? vrfInputParams?.userId : undefined
        });
      } else {
        console.log('✅ VRF Manager: Bootstrap VRF keypair generation successful', {
          saveInMemory
        });
      }

      return result;
    } catch (error: any) {
      console.error('❌ VRF Manager: Bootstrap VRF keypair generation failed:', error);
      throw new Error(`Failed to generate bootstrap VRF keypair: ${error.message}`);
    }
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
          prfKey: Array.from(new Uint8Array(prfOutput))
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

      console.log('✅ VRF Manager: VRF keypair encryption successful');
      return result;
    } catch (error: any) {
      console.error('❌ VRF Manager: VRF keypair encryption failed:', error);
      throw new Error(`Failed to encrypt VRF keypair: ${error.message}`);
    }
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
    console.log('VRF Manager: Generating VRF keypair with PRF', {
      saveInMemory,
      withChallenge: !!vrfInputParams
    });

    if (!this.vrfWorker) {
      await this.initialize();
    }

    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized after initialization attempt');
    }

    try {
      const message: VRFWorkerMessage = {
        type: 'GENERATE_VRF_KEYPAIR',
        id: this.generateMessageId(),
        data: {
          prfKey: Array.from(new Uint8Array(prfOutput)),
          saveInMemory: saveInMemory,
          // Include VRF input parameters if provided for challenge generation
          vrfInputParams: vrfInputParams ? {
            user_id: vrfInputParams.userId,
            rp_id: vrfInputParams.rpId,
            session_id: vrfInputParams.sessionId,
            block_height: vrfInputParams.blockHeight,
            block_hash: vrfInputParams.blockHashBytes,
            timestamp: vrfInputParams.timestamp
          } : undefined
        }
      };

      const response = await this.sendMessage(message);

      if (!response.success || !response.data) {
        throw new Error(`VRF keypair generation failed: ${response.error}`);
      }

      const result: {
        vrfPublicKey: string;
        encryptedVrfKeypair: any;
        vrfChallengeData?: {
          vrfInput: string;
          vrfOutput: string;
          vrfProof: string;
          vrfPublicKey: string;
          rpId: string;
        };
      } = {
        vrfPublicKey: response.data.vrf_public_key,
        encryptedVrfKeypair: response.data.encrypted_vrf_keypair
      };

      // If VRF challenge data was also generated, include it in the result
      if (response.data.vrf_challenge_data) {
        // Track the account ID for this VRF session if saving in memory
        if (vrfInputParams && saveInMemory) {
          this.currentVrfAccountId = vrfInputParams.userId;
        }

        result.vrfChallengeData = {
          vrfInput: response.data.vrf_challenge_data.vrfInput,
          vrfOutput: response.data.vrf_challenge_data.vrfOutput,
          vrfProof: response.data.vrf_challenge_data.vrfProof,
          vrfPublicKey: response.data.vrf_challenge_data.vrfPublicKey,
          rpId: response.data.vrf_challenge_data.rpId
        };
        console.log('✅ VRF Manager: VRF keypair + challenge generation successful', {
          saveInMemory,
          accountTracked: saveInMemory ? vrfInputParams?.userId : undefined
        });
      } else {
        console.log('✅ VRF Manager: VRF keypair generation successful', {
          saveInMemory
        });
      }

      return result;
    } catch (error: any) {
      console.error('❌ VRF Manager: VRF keypair generation failed:', error);
      throw new Error(`Failed to generate VRF keypair: ${error.message}`);
    }
  }

  /**
   * Generate VRF challenge and proof using encrypted VRF keypair
   * This method uses the Web Worker for in-memory VRF operations during authentication
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
    console.log('VRF Manager: Generating VRF challenge with Web Worker');

    if (!this.vrfWorker) {
      throw new Error('VRF Web Worker not initialized');
    }

    try {
      // First unlock the VRF keypair in Web Worker if not already done
      const vrfStatus = await this.getVRFStatus();
      if (!vrfStatus.active) {
        // Unlock VRF keypair with encrypted data
        const unlockResult = await this.unlockVRFKeypair(
          userId,
          {
            encrypted_vrf_data_b64u: encryptedVrfData,
            aes_gcm_nonce_b64u: encryptedVrfNonce
          },
          prfOutput
        );

        if (!unlockResult.success) {
          throw new Error(`Failed to unlock VRF keypair: ${unlockResult.error}`);
        }
      }

      // Generate VRF challenge using Web Worker
      const inputData: VRFInputData = {
        userId,
        rpId,
        sessionId,
        blockHeight,
        blockHash: new Uint8Array(blockHashBytes),
        timestamp
      };

      const challengeData = await this.generateVRFChallenge(inputData);

      console.log('✅ VRF Manager: VRF challenge generation successful');
      return {
        vrfInput: challengeData.vrfInput,
        vrfOutput: challengeData.vrfOutput,
        vrfProof: challengeData.vrfProof,
        vrfPublicKey: challengeData.vrfPublicKey,
        rpId: challengeData.rpId
      };
    } catch (error: any) {
      console.error('❌ VRF Manager: VRF challenge generation failed:', error);
      throw new Error(`Failed to generate VRF challenge: ${error.message}`);
    }
  }

    // === PRIVATE METHODS ===

  /**
   * Initialize Web Worker with client-hosted VRF worker
   */
  private async initializeWebWorker(): Promise<void> {
    try {
      console.log('🔧 VRF Manager: Starting Web Worker initialization...');
      console.log('🔧 VRF Manager: Worker URL:', this.config.vrfWorkerUrl);

      // Create Web Worker from client-hosted file
      this.vrfWorker = new Worker(this.config.vrfWorkerUrl!, { type: 'module' });

      // Set up error handling
      this.vrfWorker.onerror = (error) => {
        console.error('❌ VRF Manager: Web Worker error:', error);
      };

      // Test communication with the Web Worker
      console.log('🔍 VRF Manager: Testing Web Worker communication...');
      await this.testWebWorkerCommunication();
      console.log('✅ VRF Manager: Web Worker initialized successfully');

    } catch (error: any) {
      console.error('❌ VRF Manager: Web Worker initialization failed:', error);
      throw new Error(`VRF Web Worker initialization failed: ${error.message}`);
    }
  }

  /**
   * Test Web Worker communication with progressive retry
   */
  private async testWebWorkerCommunication(): Promise<void> {
    const maxAttempts = 3;
    const baseDelay = 1000;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        console.log(`🔍 VRF Manager: Communication test attempt ${attempt}/${maxAttempts}`);

        const timeoutMs = attempt === 1 ? 8000 : 5000;

        const pingResponse = await this.sendMessage({
          type: 'PING',
          id: this.generateMessageId(),
          data: {}
        }, timeoutMs);

        console.log('📨 VRF Manager: PING response received:', pingResponse);

        if (!pingResponse.success) {
          throw new Error(`VRF Web Worker PING failed: ${pingResponse.error}`);
        }

        console.log('✅ VRF Manager: Web Worker communication verified');
        return;
      } catch (error: any) {
        console.warn(`⚠️ VRF Manager: Communication test attempt ${attempt} failed:`, error.message);

        if (attempt === maxAttempts) {
          throw new Error(`Communication test failed after ${maxAttempts} attempts: ${error.message}`);
        }

        const delay = baseDelay * attempt;
        console.log(`   Waiting ${delay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  /**
   * Send message to Web Worker and wait for response
   */
  private async sendMessage(message: VRFWorkerMessage, customTimeout?: number): Promise<VRFWorkerResponse> {
    return new Promise((resolve, reject) => {
      if (!this.vrfWorker) {
        reject(new Error('VRF Web Worker not available'));
        return;
      }

      const timeoutMs = customTimeout || 30000;
      const timeout = setTimeout(() => {
        reject(new Error(`VRF Web Worker communication timeout (${timeoutMs}ms) for message type: ${message.type}`));
      }, timeoutMs);

      const handleMessage = (event: MessageEvent) => {
        const response = event.data as VRFWorkerResponse;
        if (response.id === message.id) {
          clearTimeout(timeout);
          this.vrfWorker!.removeEventListener('message', handleMessage);
          resolve(response);
        }
      };

      this.vrfWorker.addEventListener('message', handleMessage);
      this.vrfWorker.postMessage(message);
    });
  }

  /**
   * Generate unique message ID
   */
  private generateMessageId(): string {
    return `vrf_${Date.now()}_${++this.messageId}`;
  }
}

// Export types
export type {
  VRFKeypairData,
  EncryptedVRFData,
  VRFInputData,
  VRFChallengeData
};