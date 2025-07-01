import type { Provider } from '@near-js/providers';
import type { ActionParams } from '../types/signer-worker';
import { ClientAuthenticatorData } from '../IndexedDBManager';
import { TouchIdPrompt } from "./touchIdPrompt";
import { VRFChallenge } from '../types/webauthn';
import type { onProgressEvents } from '../types/webauthn';
/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: Challenge store removed as VRF provides cryptographic freshness
 * without needing centralized challenge management
 */
export declare class SignerWorkerManager {
    constructor();
    createSecureWorker(): Worker;
    /**
     * === UNIFIED WORKER OPERATION METHOD ===
     * Execute worker operation with optional progress updates (handles both single and multiple response patterns)
     *
     * FEATURES:
     * ✅ Single-response operations (traditional request-response)
     * ✅ Multi-response operations with progress updates (streaming SSE-like pattern)
     * ✅ Consistent error handling and timeouts
     * ✅ Fallback behavior for backward compatibility
     */
    private executeWorkerOperation;
    /**
     * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
     */
    deriveNearKeypairAndEncrypt(credential: PublicKeyCredential, nearAccountId: string): Promise<{
        success: boolean;
        nearAccountId: string;
        publicKey: string;
    }>;
    /**
     * Secure private key decryption with PRF
     *
     * For local private key export, we're just decrypting locally stored encrypted private keys
     *    - No network communication with servers
     *    - No transaction signing or blockchain interaction
     *    - No replay attack surface since nothing is transmitted
     *    - Security comes from device possession + biometrics
     *    - This is equivalent to: "If you can unlock your phone, you can access your local keychain"
     *
     * PRF DETERMINISTIC KEY DERIVATION: WebAuthn PRF provides cryptographic guarantees
     *    - Same SALT + same authenticator = same PRF output (deterministic)
     *    - Different SALT + same authenticator = different PRF output
     *    - Use a fixed user-scoped salt (sha256(`prf-salt:${accountId}`)) for deterministic PRF output
     *    - Impossible to derive PRF output without the physical authenticator
     */
    decryptPrivateKeyWithPrf(touchIdPrompt: TouchIdPrompt, nearAccountId: string, authenticators: ClientAuthenticatorData[]): Promise<{
        decryptedPrivateKey: string;
        nearAccountId: string;
    }>;
    /**
     * Extract COSE public key from WebAuthn attestation object using WASM worker
     */
    extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array>;
    /**
     * Validate COSE key format using WASM worker
     */
    validateCoseKey(coseKeyBytes: Uint8Array): Promise<{
        valid: boolean;
        info: any;
    }>;
    checkCanRegisterUser({ vrfChallenge, webauthnCredential, contractId, onEvent, }: {
        vrfChallenge: VRFChallenge;
        webauthnCredential: PublicKeyCredential;
        contractId: string;
        onEvent?: (update: onProgressEvents) => void;
    }): Promise<{
        success: boolean;
        verified?: boolean;
        registrationInfo?: any;
        logs?: string[];
        signedTransactionBorsh?: number[];
        error?: string;
    }>;
    /**
     * Actually register user on-chain with transaction (STATE-CHANGING)
     * This function performs the complete registration transaction including:
     * 1. Get transaction metadata (nonce, block hash)
     * 2. Decrypt NEAR keys with PRF
     * 3. Build and sign registration transaction
     * 4. Return signed transaction for main thread to dispatch
     */
    signVerifyAndRegisterUser({ vrfChallenge, webauthnCredential, contractId, signerAccountId, nearAccountId, publicKeyStr, nearRpcProvider, onEvent, }: {
        vrfChallenge: VRFChallenge;
        webauthnCredential: PublicKeyCredential;
        contractId: string;
        signerAccountId: string;
        nearAccountId: string;
        publicKeyStr: string;
        nearRpcProvider: Provider;
        onEvent?: (update: onProgressEvents) => void;
    }): Promise<{
        verified: boolean;
        registrationInfo?: any;
        logs?: string[];
        signedTransactionBorsh?: number[];
    }>;
    /**
     * Enhanced transaction signing with contract verification and progress updates
     * Demonstrates the "streaming" worker pattern similar to SSE
     */
    signTransactionWithActions(payload: {
        nearAccountId: string;
        receiverId: string;
        actions: ActionParams[];
        nonce: string;
        blockHashBytes: number[];
        contractId: string;
        vrfChallenge: VRFChallenge;
        webauthnCredential: PublicKeyCredential;
    }, onEvent?: (update: onProgressEvents) => void): Promise<{
        signedTransactionBorsh: number[];
        nearAccountId: string;
        logs?: string[];
    }>;
    /**
     * Enhanced Transfer transaction signing with contract verification and progress updates
     * Uses the new verify+sign WASM function for secure, efficient transaction processing
     */
    signTransferTransaction(payload: {
        nearAccountId: string;
        receiverId: string;
        depositAmount: string;
        nonce: string;
        blockHashBytes: number[];
        contractId: string;
        vrfChallenge: VRFChallenge;
        webauthnCredential: PublicKeyCredential;
    }, onEvent?: (update: onProgressEvents) => void): Promise<{
        signedTransactionBorsh: number[];
        nearAccountId: string;
        logs?: string[];
    }>;
}
//# sourceMappingURL=signerWorkerManager.d.ts.map