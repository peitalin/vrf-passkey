import { bufferEncode, base64UrlDecode, base64UrlEncode } from '../../../utils/encoders';
import { validateNearAccountId } from '../../utils/validation';
import type { PasskeyManager } from '../../PasskeyManager';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  OperationHooks,
} from '../../types/passkeyManager';
import { createAccountRelayServer } from './createAccountRelayServer';
import { createAccountTestnetFaucet } from './createAccountTestnetFaucet';
import { WebAuthnManager } from '../../WebAuthnManager';
import { VRFChallenge } from '@/core/WebAuthnManager/vrfManager';


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
  sessionId: string
): Promise<VRFChallenge> {
  console.log('Generating VRF keypair for registration');
  // Generate VRF keypair and persist in worker memory
  const vrfResult = await webAuthnManager.generateVrfKeypair(
    true, // saveInMemory: true - this VRF keypair is persisted in worker memory until PRF encryption
    {
      userId: nearAccountId,
      rpId: window.location.hostname,
      sessionId: sessionId,
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
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  options: RegistrationOptions
): Promise<RegistrationResult> {

  const { onEvent, onError, hooks } = options;
  // Generate a temporary sessionId for client-side events before SSE stream starts
  const tempSessionId = `client_${Date.now()}_${Math.random().toString(36).substring(2)}`;

  // Emit started event
  onEvent?.({
    step: 1,
    sessionId: tempSessionId,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: `Starting registration for ${nearAccountId}`
  } as RegistrationSSEEvent);

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validate registration inputs
    validateRegistrationInputs(nearAccountId, tempSessionId, onEvent, onError, hooks);

    console.log('⚡ Registration: Optimized VRF registration with single WebAuthn ceremony');
    return await handleRegistration(
      passkeyManager,
      nearAccountId,
      tempSessionId,
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
      sessionId: tempSessionId,
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
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
) => {

  onEvent?.({
    step: 1,
    sessionId: tempSessionId,
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
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
): Promise<RegistrationResult> {
  try {

    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const nearRpcProvider = passkeyManager.getNearRpcProvider();
    const config = passkeyManager.getConfig();
    const vrfManager = passkeyManager.getVRFManager();
    await vrfManager.initialize();

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Generating VRF credentials...'
    });

    // Step 2: Get latest NEAR block for VRF input construction
    console.log('VRF Registration Step 2: Get NEAR block data');

    const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
    const blockHeight = blockInfo.header.height;
    const blockHashBytes = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

    console.log(`Using NEAR block ${blockHeight} for VRF input construction`);

    // Step 3: Generate bootstrap VRF keypair + challenge for registration
    console.log('VRF Registration Step 3: Generating VRF keypair + challenge for registration ceremony');

    const vrfChallenge = await generateBootstrapVrfChallenge(
      webAuthnManager,
      nearAccountId,
      blockHeight,
      blockHashBytes,
      tempSessionId
    );

    // Step 4: Use VRF output as WebAuthn challenge
    console.log('VRF Registration Step 4: Use VRF output as WebAuthn challenge');

    // Decode VRF output and use first 32 bytes as WebAuthn challenge
    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    // Step 5: WebAuthn registration ceremony with PRF (using VRF challenge)
    console.log('VRF Registration Step 5: WebAuthn registration ceremony with VRF challenge');

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Performing WebAuthn registration with VRF challenge...'
    });

    const {
      credential,
      prfOutput
    } = await webAuthnManager.touchIdPrompt.generateRegistrationCredentialsAndPrf({
      nearAccountId,
      challenge: vrfChallengeBytes,
    });

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'WebAuthn ceremony successful, PRF output obtained'
    });

    // Step 6: Encrypt the existing VRF keypair with real PRF for storage and future authentication
    console.log('VRF Registration Step 6: Encrypting existing VRF keypair with real PRF for storage');
    // Encrypt the SAME VRF keypair that generated the WebAuthn challenge using dedicated method
    // This ensures perfect consistency between WebAuthn ceremony and contract verification
    const encryptedVrfResult = await webAuthnManager.encryptVrfKeypairWithPrf(
      vrfChallenge.vrfPublicKey,
      prfOutput
    );
    console.log('✅ VRF keypair encrypted with real PRF using dedicated method');

    // Step 7: Generate NEAR keypair using PRF (for traditional NEAR transactions)
    console.log('VRF Registration Step 7: Generating NEAR keypair with PRF');
    const keyGenResult = await webAuthnManager.deriveNearKeypairAndEncrypt(
      nearAccountId,
      prfOutput,
      { nearAccountId },
      credential.response as AuthenticatorAttestationResponse
    );
    if (!keyGenResult.success || !keyGenResult.publicKey) {
      throw new Error('Failed to generate NEAR keypair with PRF');
    }

    // Step 8: Encrypt VRF keypair with real PRF
    console.log('VRF Registration Step 8: Encrypt VRF keypair with real PRF');

    onEvent?.({
      step: 2,
      sessionId: tempSessionId,
      phase: 'user-ready',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF registration completed with challenge consistency!',
      verified: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey: undefined,
      mode: 'VRF'
    });

    // Step 9: Create account using testnet faucet service (before storing data)
    console.log('VRF Registration Step 9: Creating NEAR account via faucet service');

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating NEAR account...'
    });

    const accountCreationResult = await createAccountTestnetFaucet(
      nearAccountId,
      keyGenResult.publicKey,
      tempSessionId,
      onEvent
    );

    // Brief delay to allow account creation to propagate
    await new Promise(resolve => setTimeout(resolve, 600));

    if (!accountCreationResult.success) {
      console.error('❌ Account creation failed, initiating complete rollback');
      const error = new Error(`Account creation failed: ${accountCreationResult.error || 'Unknown error'}`);
      onError?.(error);
      hooks?.afterCall?.(false, error);
      throw error;
    }

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: 'NEAR account created successfully'
    });

    onEvent?.({
      step: 4,
      sessionId: tempSessionId,
      phase: 'account-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account creation verified successfully'
    });

    // Step 10: Contract verification (before data storage)
    console.log('VRF Registration Step 10: Contract verification');

    let contractVerified = false;
    let contractTransactionId: string | null = null;

    onEvent?.({
      step: 6,
      sessionId: tempSessionId,
      phase: 'contract-registration',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying VRF registration with contract...'
    });

    onEvent?.({
      step: 6,
      sessionId: tempSessionId,
      phase: 'contract-registration',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Calling verify_registration_response on contract...'
    });

    try {
      // verify registration and save authenticator credentials on-chain
      const contractVerificationResult = await webAuthnManager.verifyVrfAndRegisterUserOnContract(
        nearRpcProvider,
        config.contractId,
        vrfChallenge,
        credential,
        nearAccountId,
        {
          nearPublicKey: keyGenResult.publicKey,
          prfOutput: prfOutput
        }
      );

      contractVerified = contractVerificationResult.success && !!contractVerificationResult.verified;
      contractTransactionId = contractVerificationResult.transactionId || null;

      if (contractVerified) {
        onEvent?.({
          step: 6,
          sessionId: tempSessionId,
          phase: 'contract-registration',
          status: 'success',
          timestamp: Date.now(),
          message: `VRF registration successful, transaction ID: ${contractTransactionId}`
        });
      } else {
        console.warn(`️Contract verification failed: ${ contractVerificationResult.error}`);
        throw new Error(contractVerificationResult.error);
      }

    } catch (contractError: any) {
      console.warn(`️Contract verification failed: ${contractError.message}`);
      throw new Error(contractError.message);
    }

    // Step 11: Store user data with VRF credentials atomically
    console.log('VRF Registration Step 11: Storing VRF registration data atomically');
    onEvent?.({
      step: 5,
      sessionId: tempSessionId,
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
          vrfCredentials: encryptedVrfResult.encryptedVrfKeypair
        });

        console.log('✅ registration data stored atomically');
        return true;
      });

      onEvent?.({
        step: 5,
        sessionId: tempSessionId,
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

    // Step 13: Unlock VRF keypair in memory for immediate login state
    console.log('VRF Registration Step 13: Unlocking VRF keypair for immediate login');

    try {
      const unlockResult = await vrfManager.unlockVRFKeypair(
        nearAccountId,
        encryptedVrfResult.encryptedVrfKeypair,
        prfOutput
      );

      if (unlockResult.success) {
        console.log('✅ VRF keypair unlocked in memory - user is now logged in');
      } else {
        console.warn('️Failed to unlock VRF keypair after registration:', unlockResult.error);
      }
    } catch (unlockError: any) {
      console.warn('️VRF unlock failed after registration:', unlockError.message);
    }

    // Complete registration
    onEvent?.({
      step: 7,
      sessionId: tempSessionId,
      phase: 'registration-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF registration completed successfully!'
    });

    console.log(`✅ VRF registration completed for ${nearAccountId}`);
    console.log(`VRF credentials available for stateless authentication`);
    console.log(`Contract verification implemented with verify_registration_response`);

    const result: RegistrationResult = {
      success: true,
      clientNearPublicKey: keyGenResult.publicKey,
      nearAccountId: nearAccountId,
      transactionId: contractTransactionId,
      vrfRegistration: {
        success: true,
        vrfPublicKey: vrfChallenge.vrfPublicKey,
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
        contractVerified
      }
    };

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    /////////////////////////////////////////
    /// Catch all errors, and rollback all state
    /////////////////////////////////////////
    console.error('VRF registration error:', error);
    // Rollback VRF Service Worker state
    try {
      const vrfManager = passkeyManager.getVRFManager();
      await vrfManager.forceCleanup();
      console.log('✅ VRF Service Worker cleaned up');
    } catch (vrfError: any) {
      console.warn('️VRF cleanup partial failure:', vrfError.message);
    }
    // Rollback any stored registration data
    try {
      const webAuthnManager = passkeyManager.getWebAuthnManager();
      await webAuthnManager.rollbackUserRegistration(nearAccountId);
      console.log('✅ Registration data rolled back');
    } catch (rollbackError: any) {
      console.warn('️Rollback partial failure:', rollbackError.message);
    }

    // TODO: If passkey was created, we should also try to delete it
    // This is not currently possible with WebAuthn API, but we can at least
    // clean up our local data and warn the user
    console.warn('️WebAuthn credential may remain on device - manual deletion required');
    // TODO: delete account from testnet faucet service,
    // or alternatively:
    // first verify the registration, then save the authenticator onchain.
    // but this requires two contract calls
    console.warn('Testnet account needs to be deleted');

    onEvent?.({
      step: 0,
      sessionId: tempSessionId,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: 'VRF registration failed',
      error: error.message
    });

    onError?.(error);
    hooks?.afterCall?.(false, error);

    return {
      success: false,
      error: error.message
    };
  }
}
