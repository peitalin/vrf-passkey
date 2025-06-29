import type { Provider } from '@near-js/providers';
import type { AccessKeyView } from '@near-js/types';

import { bufferEncode } from '../../../utils/encoders';
import { validateNearAccountId } from '../../utils/validation';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  OperationHooks,
} from '../../types/passkeyManager';
import { createAccountRelayServer } from './createAccountRelayServer';
import { createAccountTestnetFaucet } from './createAccountTestnetFaucet';
import { WebAuthnManager } from '../../WebAuthnManager';
import { VRFChallenge } from '../../types/webauthn';
import { RPC_NODE_URL } from '../../../config';
import type { PasskeyManagerContext } from '../index';

/**
 * Generate a VRF keypair + challenge in VRF wasm worker for WebAuthn registration ceremony bootstrapping
 *
 * ARCHITECTURE: This function solves the chicken-and-egg problem with a single VRF keypair:
 * 1. Generate VRF keypair + challenge (no PRF needed)
 * 2. Persist VRF keypair in worker memory (NOT encrypted yet)
 * 3. Use VRF challenge for WebAuthn ceremony → get PRF output
 * 4. Encrypt the SAME VRF keypair (still in memory) with PRF
 *
 * @param webAuthnManager - WebAuthn manager instance
 * @param nearAccountId - NEAR account ID for VRF input
 * @param blockHeight - Current NEAR block height for freshness
 * @param blockHashBytes - Current NEAR block hash bytes for entropy
 * @returns VRF challenge data (VRF keypair persisted in worker memory)
 */
async function generateBootstrapVrfChallenge(
  webAuthnManager: WebAuthnManager,
  nearAccountId: string,
  blockHeight: number,
  blockHashBytes: Uint8Array,
): Promise<VRFChallenge> {
  console.log('Generating VRF keypair for registration');
  // Generate VRF keypair and persist in worker memory
  const vrfResult = await webAuthnManager.generateVrfKeypair(
    true, // saveInMemory: true - this VRF keypair is persisted in worker memory until PRF encryption
    {
      userId: nearAccountId,
      rpId: window.location.hostname,
      blockHeight: blockHeight,
      blockHashBytes: Array.from(blockHashBytes),
      timestamp: Date.now()
    }
  );

  if (!vrfResult.vrfChallenge) {
    throw new Error('Registration VRF keypair generation failed');
  }
  console.log('VRF keypair generated and persisted in worker memory');
  return vrfResult.vrfChallenge;
}

/**
 * Core registration function that handles passkey registration
 */
export async function registerPasskey(
  context: PasskeyManagerContext,
  nearAccountId: string,
  options: RegistrationOptions
): Promise<RegistrationResult> {

  const { onEvent, onError, hooks } = options;

  // Emit started event
  onEvent?.({
    step: 1,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: `Starting registration for ${nearAccountId}`
  } as RegistrationSSEEvent);

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validate registration inputs
    validateRegistrationInputs(nearAccountId, onEvent, onError, hooks);

    console.log('⚡ Registration: Optimized VRF registration with single WebAuthn ceremony');
    return await handleRegistration(
      context,
      nearAccountId,
      onEvent,
      onError,
      hooks,
    );

  } catch (err: any) {
    console.error('Registration error:', err.message, err.stack);
    const errorMessage = err.message?.includes('one of the credentials already registered')
      ? `A passkey for '${nearAccountId}' already exists. Please try logging in instead.`
      : err.message;

    const error = new Error(errorMessage);
    onError?.(error);

    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: errorMessage,
      error: errorMessage
    } as RegistrationSSEEvent);

    hooks?.afterCall?.(false, err);
    return {
      success: false,
      error: errorMessage
    };
  }
}

const validateRegistrationInputs = (
  nearAccountId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
) => {

  onEvent?.({
    step: 1,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Validating registration inputs...'
  } as RegistrationSSEEvent);

  // Validation
  if (!nearAccountId) {
    const error = new Error('NEAR account ID is required for registration.');
    onError?.(error);
    throw error;
  }
  // Validate the account ID format
  const validation = validateNearAccountId(nearAccountId);
  if (!validation.valid) {
    const error = new Error(`Invalid NEAR account ID: ${validation.error}`);
    onError?.(error);
    throw error;
  }
  if (!window.isSecureContext) {
    const error = new Error('Passkey operations require a secure context (HTTPS or localhost).');
    onError?.(error);
    throw error;
  }
}

/**
 * Handle VRF registration following the specification in docs/vrf_challenges.md
 *
 * VRF Registration Flow (Single VRF Keypair):
 * 1. Generate VRF keypair (ed25519) using crypto.randomUUID() + persist in worker memory
 * 2. Generate VRF proof + output using the VRF keypair
 *    - VRF input with domain separator + NEAR block height + hash
 * 3. Use VRF output as WebAuthn challenge in registration ceremony
 * 4. Derive AES key from WebAuthn PRF output and encrypt the SAME VRF keypair
 * 5. Store encrypted VRF keypair in IndexedDB
 * 6. Call contract verify_registration_response with VRF proof + WebAuthn registration payload
 * 7. Contract verifies VRF proof and WebAuthn registration (challenges match!)
 * 8. Contract stores VRF pubkey + authenticator credentials on-chain for
 *    future stateless authentication
 */
async function handleRegistration(
  context: PasskeyManagerContext,
  nearAccountId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
): Promise<RegistrationResult> {

  const { webAuthnManager, nearRpcProvider, configs } = context;

  try {

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Generating VRF credentials...'
    });

    // Step 1: Get latest NEAR block for VRF input construction
    console.log('Registration Step 1: Get NEAR block data');

    const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
    const blockHeight = blockInfo.header.height;
    const blockHashBytes = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

    // Step 2: Generate bootstrap VRF keypair + challenge for registration
    console.log('Registration Step 2: Generating VRF keypair + challenge for registration');

    const vrfChallenge = await generateBootstrapVrfChallenge(
      webAuthnManager,
      nearAccountId,
      blockHeight,
      blockHashBytes,
    );

    // Step 3: Use VRF output as WebAuthn challenge
    console.log('Registration Step 3: Use VRF output as WebAuthn challenge');
    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    // Step 4: WebAuthn registration ceremony with PRF (TouchID)
    console.log('Registration Step 4: WebAuthn registration ceremony with VRF challenge');

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Performing WebAuthn registration with VRF challenge...'
    });

    const {
      credential
    } = await webAuthnManager.touchIdPrompt.generateRegistrationCredentialsAndPrf({
      nearAccountId,
      challenge: vrfChallengeBytes,
    });

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'WebAuthn ceremony successful, PRF output obtained'
    });

    // Step 5: Encrypt the existing VRF keypair with real PRF for storage and future authentication
    console.log('Registration Step 5: Encrypting existing VRF keypair with real PRF for storage');
    // Encrypt the VRF keypair that generated the WebAuthn challenge (in VRF worker memory)
    const encryptedVrfResult = await webAuthnManager.encryptVrfKeypairWithCredentials({
      credential,
      vrfPublicKey: vrfChallenge.vrfPublicKey,
    });

    // Step 6: Generate NEAR keypair and encrypt using PRF (for NEAR transactions)
    console.log('Registration Step 6: Generating NEAR keypair with PRF');
    const keyGenResult = await webAuthnManager.deriveNearKeypairAndEncrypt({
      credential,
      nearAccountId,
    });
    if (!keyGenResult.success || !keyGenResult.publicKey) {
      throw new Error('Failed to generate NEAR keypair with PRF');
    }

    onEvent?.({
      step: 2,
      phase: 'user-ready',
      status: 'success',
      timestamp: Date.now(),
      message: 'Registration completed with challenge consistency!',
      verified: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey: keyGenResult.publicKey,
      mode: 'VRF'
    });

    // Step 7: Create account using faucet service (before storing data)
    console.log('Registration Step 7: Creating NEAR account via faucet service');

    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating NEAR account...'
    });

    // First check if the user can be registered on-chain
    const canRegisterUserResult = await webAuthnManager.checkCanRegisterUser({
      contractId: webAuthnManager.configs.contractId,
      webauthnCredential: credential,
      vrfChallenge: vrfChallenge,
      onEvent: (progress) => {
        console.debug(`Registration progress: ${progress.step} - ${progress.message}`);
        onEvent?.({
          step: 4,
          phase: 'account-verification',
          status: 'progress',
          timestamp: Date.now(),
          message: `Checking registration: ${progress.message}`
        });
      },
    });

    if (!canRegisterUserResult.verified) {
      throw new Error(`Registration check failed: ${canRegisterUserResult.error}`);
    }

    // Create account using faucet service
    const accountCreationResult = await createAccountTestnetFaucet(
      nearAccountId,
      keyGenResult.publicKey,
      onEvent
    );

    if (!accountCreationResult.success) {
      console.error('❌ Account creation failed, initiating complete rollback');
      throw new Error(`Account creation failed: ${accountCreationResult.error || 'Unknown error'}`);
    }

    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: 'NEAR account created successfully'
    });

    // Check for access key to be available
    await waitForAccessKey(nearRpcProvider, nearAccountId, keyGenResult.publicKey);

    onEvent?.({
      step: 4,
      phase: 'account-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account creation verified successfully'
    });

    // Step 8: Contract verification and registration transaction
    console.log('Registration Step 8: Contract verification and registration transaction');
    let contractVerified = false;
    let contractTransactionId: string | null = null;

    const contractRegistrationResult = await webAuthnManager.signVerifyAndRegisterUser({
      contractId: webAuthnManager.configs.contractId,
      webauthnCredential: credential,
      vrfChallenge: vrfChallenge,
      signerAccountId: nearAccountId,
      nearAccountId: nearAccountId,
      publicKeyStr: keyGenResult.publicKey,
      nearRpcProvider: nearRpcProvider,
      onEvent: (progress) => {
        console.debug(`Registration progress: ${progress.step} - ${progress.message}`);
        onEvent?.({
          step: 6,
          phase: 'contract-registration',
          status: 'progress',
          timestamp: Date.now(),
          message: `VRF registration: ${progress.message}`
        });
      },
    });

    contractVerified = contractRegistrationResult.verified || false;
    const signedTransactionBorsh = contractRegistrationResult.signedTransactionBorsh;

    if (contractVerified && signedTransactionBorsh) {
      // Broadcast the signed transaction
      console.log('Broadcasting registration transaction...');

      onEvent?.({
        step: 6,
        phase: 'contract-registration',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Broadcasting registration transaction...'
      });

      const transactionResult = await broadcastSignedTransaction(signedTransactionBorsh!);
      contractTransactionId = transactionResult.transactionId;

      onEvent?.({
        step: 6,
        phase: 'contract-registration',
        status: 'success',
        timestamp: Date.now(),
        message: `VRF registration successful, transaction ID: ${contractTransactionId}`
      });
    } else {
      console.warn(`Contract verification failed: ${contractRegistrationResult.error}`);
      throw new Error(contractRegistrationResult.error || 'Registration verification failed');
    }

    // Step 9: Store user data with VRF credentials atomically
    console.log('Registration Step 9: Storing VRF registration data atomically');
    onEvent?.({
      step: 5,
      phase: 'database-storage',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Storing VRF registration data atomically...'
    });

    try {
      await webAuthnManager.atomicOperation(async (db) => {
        // Register user in IndexDB
        await webAuthnManager.registerUser(nearAccountId);

        // Store credential for authentication
        const credentialId = bufferEncode(credential.rawId);
        const response = credential.response as AuthenticatorAttestationResponse;

        await webAuthnManager.storeAuthenticator({
          nearAccountId,
          credentialID: credentialId,
          credentialPublicKey: await webAuthnManager.extractCosePublicKey(
            bufferEncode(response.attestationObject)
          ),
          transports: response.getTransports?.() || [],
          clientNearPublicKey: keyGenResult.publicKey,
          name: `VRF Passkey for ${webAuthnManager.extractUsername(nearAccountId)}`,
          registered: new Date().toISOString(),
          lastUsed: undefined,
          backedUp: false,
          syncedAt: new Date().toISOString(),
        });

        // Store WebAuthn user data with encrypted VRF credentials
        // Note: We store the same VRF keypair that generated the WebAuthn challenge
        // to ensure consistency between registration and authentication
        await webAuthnManager.storeUserData({
          nearAccountId,
          clientNearPublicKey: keyGenResult.publicKey,
          lastUpdated: Date.now(),
          prfSupported: true,
          deterministicKey: true,
          passkeyCredential: {
            id: credential.id,
            rawId: credentialId
          },
          encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair
        });

        console.log('✅ registration data stored atomically');
        return true;
      });

      onEvent?.({
        step: 5,
        phase: 'database-storage',
        status: 'success',
        timestamp: Date.now(),
        message: 'VRF registration data stored successfully'
      });

    } catch (storageError: any) {
      console.error('Storage operation failed:', storageError);
      // If storage fails after account creation, we have a problem
      // The account exists but local data is inconsistent
      const error = new Error(`Registration data storage failed: ${storageError.message}`);
      onError?.(error);
      hooks?.afterCall?.(false, error);

      return {
        success: false,
        error: `Registration failed during data storage: ${storageError.message}`
      };
    }

    // Step 10: Unlock VRF keypair in memory for immediate login state
    console.log('Registration Step 10: Unlocking VRF keypair for immediate login');

    try {
      const unlockResult = await webAuthnManager.unlockVRFKeypair({
        nearAccountId: nearAccountId,
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
        webauthnCredential: credential,
      });

      if (!unlockResult.success) {
        console.warn('VRF keypair unlock failed:', unlockResult.error);
        // Non-fatal error - registration is still successful
      }

      onEvent?.({
        step: 7,
        phase: 'registration-complete',
        status: 'success',
        timestamp: Date.now(),
        message: 'Registration completed successfully'
      });

      hooks?.afterCall?.(true, {
        success: true,
        nearAccountId: nearAccountId,
        clientNearPublicKey: keyGenResult.publicKey,
        transactionId: contractTransactionId,
        vrfRegistration: {
          success: true,
          vrfPublicKey: vrfChallenge.vrfPublicKey,
          encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
          contractVerified: contractVerified
        }
      });

      return {
        success: true,
        nearAccountId: nearAccountId,
        clientNearPublicKey: keyGenResult.publicKey,
        transactionId: contractTransactionId,
        vrfRegistration: {
          success: true,
          vrfPublicKey: vrfChallenge.vrfPublicKey,
          encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
          contractVerified: contractVerified
        }
      };

    } catch (unlockError: any) {
      console.warn('VRF keypair unlock failed:', unlockError);
      // Non-fatal error - registration is still successful

      onEvent?.({
        step: 7,
        phase: 'registration-complete',
        status: 'success',
        timestamp: Date.now(),
        message: 'Registration completed successfully (VRF session not unlocked)'
      });

      hooks?.afterCall?.(true, {
        success: true,
        nearAccountId: nearAccountId,
        clientNearPublicKey: keyGenResult.publicKey,
        transactionId: contractTransactionId,
        vrfRegistration: {
          success: true,
          vrfPublicKey: vrfChallenge.vrfPublicKey,
          encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
          contractVerified: contractVerified,
          error: `VRF session unlock failed: ${unlockError.message}`
        }
      });

      return {
        success: true,
        nearAccountId: nearAccountId,
        clientNearPublicKey: keyGenResult.publicKey,
        transactionId: contractTransactionId,
        vrfRegistration: {
          success: true,
          vrfPublicKey: vrfChallenge.vrfPublicKey,
          encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
          contractVerified: contractVerified,
          error: `VRF session unlock failed: ${unlockError.message}`
        }
      };
    }

  } catch (error: any) {
    console.error('Registration failed:', error.message, error.stack);
    const errorMessage = `Registration failed: ${error.message}`;
    onError?.(error);

    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: errorMessage,
      error: errorMessage
    } as RegistrationSSEEvent);

    hooks?.afterCall?.(false, error);
    return {
      success: false,
      error: errorMessage
    };
  }
}

/**
 * Wait for access key to be available with retry logic
 * Account creation via faucet may have propagation delays
 */
async function waitForAccessKey(
  nearRpcProvider: Provider,
  nearAccountId: string,
  nearPublicKey: string,
  maxRetries: number = 10,
  delayMs: number = 1000
): Promise<AccessKeyView> {
  console.log(`Waiting for access key to be available for ${nearAccountId}...`);
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const accessKeyInfo = await nearRpcProvider.viewAccessKey(
        nearAccountId,
        nearPublicKey,
      ) as AccessKeyView;

      console.log(`Access key found on attempt ${attempt}`);
      return accessKeyInfo;
    } catch (error: any) {
      console.log(`Access key not available yet (attempt ${attempt}/${maxRetries}):`, error.message);

      if (attempt === maxRetries) {
        console.error(`Access key still not available after ${maxRetries} attempts`);
        throw new Error(`Access key not available after ${maxRetries * delayMs}ms. Account creation may have failed.`);
      }

      // Wait before next attempt with exponential backoff
      const delay = delayMs * Math.pow(1.5, attempt - 1);
      console.debug(`   Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('Unexpected error in waitForAccessKey');
}

/**
 * Broadcast signed transaction to NEAR network
 */
async function broadcastSignedTransaction(
  signedTransactionBorsh: number[]
): Promise<{ transactionId: string; result: any }> {
  // Convert the signed transaction to base64
  const signedTransactionBase64 = Buffer.from(signedTransactionBorsh).toString('base64');

  // Broadcast using RPC
  const response = await fetch(RPC_NODE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: crypto.randomUUID(),
      method: 'send_tx',
      params: {
        signed_tx_base64: signedTransactionBase64,
        wait_until: 'EXECUTED_OPTIMISTIC'
      }
    })
  });

  const result = await response.json();

  if (result.error) {
    const errorMessage = result.error.data?.message || result.error.message || 'Transaction broadcast failed';
    throw new Error(`Transaction broadcast failed: ${errorMessage}`);
  }

  const transactionId = result.result?.transaction_outcome?.id;
  console.log(`✅ Registration transaction broadcast successful: ${transactionId}`);

  return {
    transactionId,
    result: result.result
  };
}
