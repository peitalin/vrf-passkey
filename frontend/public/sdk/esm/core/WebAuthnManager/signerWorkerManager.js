import { bufferEncode } from '../../utils/encoders.js';
import { WorkerResponseType, WorkerRequestType, isEncryptionSuccess, isDecryptionSuccess, isCoseKeySuccess, isCoseValidationSuccess, serializeRegistrationCredentialAndCreatePRF, isRegistrationSuccess, validateActionParams, serializeCredentialAndCreatePRF } from '../types/signer-worker.js';
import { ActionType } from '../types/actions.js';
import { RPC_NODE_URL } from '../../config.js';

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: Challenge store removed as VRF provides cryptographic freshness
 * without needing centralized challenge management
 */
class SignerWorkerManager {
    constructor() { }
    createSecureWorker() {
        // Simple path resolution - build:all copies worker files to /workers/
        const workerUrl = new URL('/workers/web3authn-signer.worker.js', window.location.origin);
        console.log('Creating secure worker from:', workerUrl.href);
        try {
            const worker = new Worker(workerUrl, {
                type: 'module',
                name: 'Web3AuthnSignerWorker'
            });
            // Add error handling
            worker.onerror = (event) => {
                console.error('Worker error:', event);
            };
            return worker;
        }
        catch (error) {
            console.error('Failed to create worker:', error);
            throw new Error(`Failed to create secure worker: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
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
    async executeWorkerOperation({ message, onEvent, timeoutMs = 30000 // 30s
     }) {
        const worker = this.createSecureWorker();
        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                worker.terminate();
                reject(new Error(`Worker operation timed out after ${timeoutMs}ms`));
            }, timeoutMs);
            let finalResponse = null;
            worker.onmessage = (event) => {
                const response = event.data;
                // Handle progress updates
                if (response.type === WorkerResponseType.VERIFICATION_PROGRESS ||
                    response.type === WorkerResponseType.SIGNING_PROGRESS ||
                    response.type === WorkerResponseType.REGISTRATION_PROGRESS) {
                    const payload = response.payload;
                    onEvent?.(payload);
                    return; // Continue listening for more messages
                }
                // Handle completion messages
                if (response.type === WorkerResponseType.VERIFICATION_COMPLETE) {
                    const verificationResult = response.payload;
                    onEvent?.(verificationResult);
                    if (!verificationResult.success) {
                        clearTimeout(timeoutId);
                        worker.terminate();
                        reject(new Error(`Verification failed: ${verificationResult.error}`));
                        return;
                    }
                    return; // Continue listening for signing messages
                }
                // Handle final completion
                if (response.type === WorkerResponseType.SIGNING_COMPLETE ||
                    response.type === WorkerResponseType.REGISTRATION_COMPLETE) {
                    clearTimeout(timeoutId);
                    worker.terminate();
                    finalResponse = response;
                    resolve(finalResponse);
                    return;
                }
                // Handle errors
                if (response.type === WorkerResponseType.ERROR) {
                    clearTimeout(timeoutId);
                    worker.terminate();
                    reject(new Error(response.payload.error));
                    return;
                }
                // Handle other completion types (fallback to existing behavior)
                if (response.type.includes('SUCCESS') || response.type.includes('FAILURE')) {
                    clearTimeout(timeoutId);
                    worker.terminate();
                    resolve(response);
                }
            };
            worker.onerror = (event) => {
                clearTimeout(timeoutId);
                worker.terminate();
                const errorMessage = event.error?.message || event.message || 'Unknown worker error';
                console.error('Worker error details (progress):', {
                    message: errorMessage,
                    filename: event.filename,
                    lineno: event.lineno,
                    colno: event.colno,
                    error: event.error
                });
                reject(new Error(`Worker error: ${errorMessage}`));
            };
            worker.postMessage(message);
        });
    }
    // === PRF OPERATIONS ===
    /**
     * Secure registration flow with PRF: WebAuthn + WASM worker encryption using PRF
     */
    async deriveNearKeypairAndEncrypt(credential, nearAccountId) {
        const attestationObject = credential.response;
        const prfOutput = credential.getClientExtensionResults()?.prf?.results?.first;
        if (!prfOutput) {
            throw new Error('PRF output not found in WebAuthn credentials');
        }
        try {
            console.log('WebAuthnManager: Starting secure registration with PRF using deterministic derivation');
            const response = await this.executeWorkerOperation({
                message: {
                    type: WorkerRequestType.DERIVE_NEAR_KEYPAIR_AND_ENCRYPT,
                    payload: {
                        prfOutput: bufferEncode(prfOutput),
                        nearAccountId: nearAccountId,
                        attestationObjectBase64url: bufferEncode(attestationObject.attestationObject)
                    }
                }
            });
            if (isEncryptionSuccess(response)) {
                console.log('WebAuthnManager: PRF registration successful with deterministic derivation');
                return {
                    success: true,
                    nearAccountId: nearAccountId,
                    publicKey: response.payload.publicKey
                };
            }
            else {
                console.error('WebAuthnManager: PRF registration failed:', response);
                return {
                    success: false,
                    nearAccountId: nearAccountId,
                    publicKey: ''
                };
            }
        }
        catch (error) {
            console.error('WebAuthnManager: PRF registration error:', error);
            return {
                success: false,
                nearAccountId: nearAccountId,
                publicKey: ''
            };
        }
    }
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
    async decryptPrivateKeyWithPrf(touchIdPrompt, nearAccountId, authenticators) {
        try {
            console.log('WebAuthnManager: Starting private key decryption with PRF (local operation)');
            console.log('WebAuthnManager: Security enforced by device possession + biometrics + PRF cryptography');
            // For private key export, no VRF challenge is needed.
            // we can use local random challenge for WebAuthn authentication.
            // Security comes from device possession + biometrics, not challenge validation
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            // TouchID prompt
            const { prfOutput } = await touchIdPrompt.getCredentialsAndPrf({
                nearAccountId,
                challenge,
                authenticators,
            });
            const response = await this.executeWorkerOperation({
                message: {
                    type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF,
                    payload: {
                        nearAccountId: nearAccountId,
                        prfOutput: bufferEncode(prfOutput)
                    }
                }
            });
            if (isDecryptionSuccess(response)) {
                console.log('WebAuthnManager: PRF private key decryption successful');
                return {
                    decryptedPrivateKey: response.payload.decryptedPrivateKey,
                    nearAccountId: nearAccountId
                };
            }
            else {
                console.error('WebAuthnManager: PRF private key decryption failed:', response);
                throw new Error('Private key decryption failed');
            }
        }
        catch (error) {
            console.error('WebAuthnManager: PRF private key decryption error:', error);
            throw error;
        }
    }
    // === COSE OPERATIONS ===
    /**
     * Extract COSE public key from WebAuthn attestation object using WASM worker
     */
    async extractCosePublicKey(attestationObjectBase64url) {
        console.log('WebAuthnManager: Extracting COSE public key from attestation object');
        const response = await this.executeWorkerOperation({
            message: {
                type: WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY,
                payload: {
                    attestationObjectBase64url
                }
            }
        });
        if (isCoseKeySuccess(response)) {
            console.log('WebAuthnManager: COSE public key extraction successful');
            return new Uint8Array(response.payload.cosePublicKeyBytes);
        }
        else {
            console.error('WebAuthnManager: COSE public key extraction failed:', response);
            throw new Error('Failed to extract COSE public key from attestation object');
        }
    }
    /**
     * Validate COSE key format using WASM worker
     */
    async validateCoseKey(coseKeyBytes) {
        console.log('WebAuthnManager: Validating COSE key format');
        const response = await this.executeWorkerOperation({
            message: {
                type: WorkerRequestType.VALIDATE_COSE_KEY,
                payload: {
                    coseKeyBytes: Array.from(coseKeyBytes)
                }
            }
        });
        if (isCoseValidationSuccess(response)) {
            console.log('WebAuthnManager: COSE key validation successful');
            return {
                valid: response.payload.valid,
                info: response.payload.info
            };
        }
        else {
            console.error('WebAuthnManager: COSE key validation failed:', response);
            throw new Error('Failed to validate COSE key format');
        }
    }
    async checkCanRegisterUser({ vrfChallenge, webauthnCredential, contractId, onEvent, }) {
        try {
            console.log('WebAuthnManager: Checking if user can be registered on-chain');
            const response = await this.executeWorkerOperation({
                message: {
                    type: WorkerRequestType.CHECK_CAN_REGISTER_USER,
                    payload: {
                        vrfChallenge,
                        webauthnCredential: serializeRegistrationCredentialAndCreatePRF(webauthnCredential),
                        contractId,
                        nearRpcUrl: RPC_NODE_URL
                    }
                },
                onEvent,
                timeoutMs: 60000 // Longer timeout for contract verification
            });
            if (isRegistrationSuccess(response)) {
                console.log('WebAuthnManager: User can be registered on-chain');
                return {
                    success: true,
                    verified: response.payload.verified,
                    registrationInfo: response.payload.registrationInfo,
                    logs: response.payload.logs,
                    signedTransactionBorsh: response.payload.signedTransactionBorsh
                };
            }
            else {
                console.error('WebAuthnManager: User cannot be registered on-chain:', response);
                return {
                    success: false,
                    error: 'User cannot be registered - registration check failed'
                };
            }
        }
        catch (error) {
            console.error('WebAuthnManager: User cannot be registered on-chain:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    /**
     * Actually register user on-chain with transaction (STATE-CHANGING)
     * This function performs the complete registration transaction including:
     * 1. Get transaction metadata (nonce, block hash)
     * 2. Decrypt NEAR keys with PRF
     * 3. Build and sign registration transaction
     * 4. Return signed transaction for main thread to dispatch
     */
    async signVerifyAndRegisterUser({ vrfChallenge, webauthnCredential, contractId, signerAccountId, nearAccountId, publicKeyStr, nearRpcProvider, onEvent, }) {
        try {
            console.log('WebAuthnManager: Starting on-chain user registration with transaction');
            // Step 1: Get transaction metadata
            onEvent?.({
                step: 1,
                phase: 'preparation',
                status: 'progress',
                message: 'Preparing transaction metadata...',
            });
            if (!publicKeyStr) {
                throw new Error('Client NEAR public key not provided - cannot get access key nonce');
            }
            // Get access key and transaction block info concurrently
            const [accessKeyInfo, transactionBlockInfo] = await Promise.all([
                nearRpcProvider.viewAccessKey(signerAccountId, publicKeyStr),
                nearRpcProvider.viewBlock({ finality: 'final' })
            ]);
            const nonce = accessKeyInfo.nonce + BigInt(1);
            const blockHashString = transactionBlockInfo.header.hash;
            // Convert base58 block hash to bytes for WASM
            const bs58 = (await import('bs58')).default;
            const transactionBlockHashBytes = Array.from(bs58.decode(blockHashString));
            console.log('WebAuthnManager: Transaction metadata prepared', {
                nonce: nonce.toString(),
                blockHash: blockHashString,
                blockHashBytesLength: transactionBlockHashBytes.length
            });
            // Step 2: Execute registration transaction via WASM
            const response = await this.executeWorkerOperation({
                message: {
                    type: WorkerRequestType.SIGN_VERIFY_AND_REGISTER_USER,
                    payload: {
                        vrfChallenge,
                        webauthnCredential: serializeRegistrationCredentialAndCreatePRF(webauthnCredential),
                        contractId,
                        signerAccountId,
                        nearAccountId,
                        nonce: nonce.toString(),
                        blockHashBytes: transactionBlockHashBytes
                    }
                },
                onEvent,
                timeoutMs: 90000 // Extended timeout for transaction processing
            });
            if (isRegistrationSuccess(response)) {
                console.log('WebAuthnManager: On-chain user registration transaction successful');
                return {
                    verified: response.payload.verified,
                    registrationInfo: response.payload.registrationInfo,
                    logs: response.payload.logs,
                    signedTransactionBorsh: response.payload.signedTransactionBorsh
                };
            }
            else {
                console.error('WebAuthnManager: On-chain user registration transaction failed:', response);
                throw new Error('On-chain user registration transaction failed');
            }
        }
        catch (error) {
            console.error('WebAuthnManager: On-chain user registration error:', error);
            throw error;
        }
    }
    // === ACTION-BASED SIGNING METHODS ===
    /**
     * Enhanced transaction signing with contract verification and progress updates
     * Demonstrates the "streaming" worker pattern similar to SSE
     */
    async signTransactionWithActions(payload, onEvent) {
        try {
            console.log('WebAuthnManager: Starting enhanced transaction signing with verification');
            payload.actions.forEach((action, index) => {
                try {
                    validateActionParams(action);
                }
                catch (error) {
                    throw new Error(`Action ${index} validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
                }
            });
            const response = await this.executeWorkerOperation({
                message: {
                    type: WorkerRequestType.SIGN_TRANSACTION_WITH_ACTIONS,
                    payload: {
                        nearAccountId: payload.nearAccountId,
                        receiverId: payload.receiverId,
                        actions: JSON.stringify(payload.actions), // Convert actions array to JSON string
                        nonce: payload.nonce,
                        blockHashBytes: payload.blockHashBytes,
                        // Contract verification parameters
                        contractId: payload.contractId,
                        vrfChallenge: payload.vrfChallenge,
                        // Serialize credential right before sending - minimal exposure time
                        webauthnCredential: serializeCredentialAndCreatePRF(payload.webauthnCredential),
                        nearRpcUrl: RPC_NODE_URL
                    }
                },
                onEvent, // onEvent callback for wasm-worker events
                timeoutMs: 60000 // Longer timeout for contract verification + signing
            });
            if (response.type === WorkerResponseType.SIGNING_COMPLETE && response.payload.success) {
                console.log('WebAuthnManager: Enhanced transaction signing successful with verification logs');
                return {
                    signedTransactionBorsh: response.payload.data.signedTransactionBorsh,
                    nearAccountId: payload.nearAccountId,
                    logs: response.payload.data.verificationLogs
                };
            }
            else {
                console.error('WebAuthnManager: Enhanced transaction signing failed:', response);
                throw new Error('Enhanced transaction signing failed');
            }
        }
        catch (error) {
            console.error('WebAuthnManager: Enhanced transaction signing error:', error);
            throw error;
        }
    }
    /**
     * Enhanced Transfer transaction signing with contract verification and progress updates
     * Uses the new verify+sign WASM function for secure, efficient transaction processing
     */
    async signTransferTransaction(payload, onEvent) {
        try {
            console.log('WebAuthnManager: Starting enhanced transfer transaction signing with verification');
            const transferAction = {
                actionType: ActionType.Transfer,
                deposit: payload.depositAmount
            };
            validateActionParams(transferAction);
            const response = await this.executeWorkerOperation({
                message: {
                    type: WorkerRequestType.SIGN_TRANSFER_TRANSACTION,
                    payload: {
                        nearAccountId: payload.nearAccountId,
                        receiverId: payload.receiverId,
                        depositAmount: payload.depositAmount,
                        nonce: payload.nonce,
                        blockHashBytes: payload.blockHashBytes,
                        // Contract verification parameters
                        contractId: payload.contractId,
                        vrfChallenge: payload.vrfChallenge,
                        // Serialize credential right before sending - minimal exposure time
                        webauthnCredential: serializeCredentialAndCreatePRF(payload.webauthnCredential),
                        nearRpcUrl: RPC_NODE_URL
                    }
                },
                onEvent, // onEvent callback for wasm-worker events
                timeoutMs: 60000 // Longer timeout for contract verification + signing
            });
            if (response.type === WorkerResponseType.SIGNING_COMPLETE && response.payload.success) {
                console.log('WebAuthnManager: Enhanced transfer transaction signing successful with verification logs');
                return {
                    signedTransactionBorsh: response.payload.data.signedTransactionBorsh,
                    nearAccountId: payload.nearAccountId,
                    logs: response.payload.data.verificationLogs
                };
            }
            else {
                console.error('WebAuthnManager: Enhanced transfer transaction signing failed:', response);
                throw new Error('Enhanced transfer transaction signing failed');
            }
        }
        catch (error) {
            console.error('WebAuthnManager: Enhanced transfer transaction signing error:', error);
            throw error;
        }
    }
}

export { SignerWorkerManager };
//# sourceMappingURL=signerWorkerManager.js.map
