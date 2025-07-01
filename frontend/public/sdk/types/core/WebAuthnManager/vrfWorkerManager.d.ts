/**
 * VRF Manager
 * Uses Web Workers for VRF keypair management with client-hosted worker files.
 */
import { ClientAuthenticatorData } from '../IndexedDBManager/passkeyClientDB';
import type { VRFKeypairData, EncryptedVRFKeypair, VRFInputData, VRFChallengeData, VRFWorkerResponse } from '../types/vrf-worker';
import { VRFChallenge } from '../types/webauthn';
import { TouchIdPrompt } from './touchIdPrompt';
export interface VrfWorkerManagerConfig {
    vrfWorkerUrl?: string;
    workerTimeout?: number;
    debug?: boolean;
}
export interface VRFWorkerStatus {
    active: boolean;
    nearAccountId: string | null;
    sessionDuration?: number;
}
/**
 * VRF Worker Manager
 *
 * This class manages VRF operations using Web Workers for:
 * - VRF keypair unlocking (login)
 * - VRF challenge generation (authentication)
 * - Session management (browser session only)
 * - Client-hosted worker files
 */
export declare class VrfWorkerManager {
    private vrfWorker;
    private initializationPromise;
    private messageId;
    private config;
    private currentVrfAccountId;
    constructor(config?: VrfWorkerManagerConfig);
    /**
   * Initialize VRF functionality using Web Workers
   */
    initialize(): Promise<void>;
    /**
     * Initialize Web Worker with client-hosted VRF worker
     */
    private createVrfWorker;
    /**
     * Send message to Web Worker and wait for response
     */
    private sendMessage;
    /**
     * Generate unique message ID
     */
    private generateMessageId;
    /**
     * Unlock VRF keypair in Web Worker memory using PRF output
     * This is called during login to decrypt and load the VRF keypair in-memory
     */
    unlockVRFKeypair({ touchIdPrompt, nearAccountId, encryptedVrfKeypair, authenticators, prfOutput, onEvent, }: {
        touchIdPrompt: TouchIdPrompt;
        nearAccountId: string;
        encryptedVrfKeypair: EncryptedVRFKeypair;
        authenticators: ClientAuthenticatorData[];
        prfOutput?: ArrayBuffer;
        onEvent?: (event: {
            type: string;
            data: {
                step: string;
                message: string;
            };
        }) => void;
    }): Promise<VRFWorkerResponse>;
    /**
     * Generate VRF challenge using in-memory VRF keypair
     * This is called during authentication to create WebAuthn challenges
     */
    generateVRFChallenge(inputData: VRFInputData): Promise<VRFChallenge>;
    /**
     * Get current VRF session status
     */
    getVrfWorkerStatus(): Promise<VRFWorkerStatus>;
    /**
     * Logout and clear VRF session
     */
    clearVrfSession(): Promise<void>;
    /**
     * Generate VRF keypair for bootstrapping - stores in memory unencrypted temporarily
     * This is used during registration to generate a VRF keypair that will be used for
     * WebAuthn ceremony and later encrypted with the real PRF output
     *
     * @param saveInMemory - Always true for bootstrap (VRF keypair stored in memory)
     * @param vrfInputParams - Optional parameters to generate VRF challenge/proof in same call
     * @returns VRF public key and optionally VRF challenge data
     */
    generateVrfKeypair(saveInMemory: boolean, vrfInputParams: {
        userId: string;
        rpId: string;
        blockHeight: number;
        blockHashBytes: number[];
        timestamp: number;
    }): Promise<{
        vrfPublicKey: string;
        vrfChallenge: VRFChallenge;
    }>;
    /**
     * Encrypt VRF keypair with PRF output - looks up in-memory keypair and encrypts it
     * This is called after WebAuthn ceremony to encrypt the same VRF keypair with real PRF
     *
     * @param expectedPublicKey - Expected VRF public key to verify we're encrypting the right keypair
     * @param credential - WebAuthn credentials for encryption
     * @returns Encrypted VRF keypair data ready for storage
     */
    encryptVrfKeypairWithCredentials(expectedPublicKey: string, credential: PublicKeyCredential): Promise<{
        vrfPublicKey: string;
        encryptedVrfKeypair: any;
    }>;
    /**
     * Test Web Worker communication with progressive retry
     */
    private testWebWorkerCommunication;
}
export type { VRFKeypairData, EncryptedVRFKeypair, VRFInputData, VRFChallengeData };
//# sourceMappingURL=vrfWorkerManager.d.ts.map