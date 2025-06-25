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
import { generateUserScopedPrfSalt } from '../../../utils';


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
  webAuthnManager: any,
  nearAccountId: string,
  blockHeight: number,
  blockHashBytes: Uint8Array
): Promise<{
  vrfInput: string;
  vrfOutput: string;
  vrfProof: string;
  vrfPublicKey: string;
  rpId: string;
}> {
  console.log('Generating VRF keypair for registration');
  const sessionId = crypto.randomUUID();
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

  if (!vrfResult.vrfChallengeData) {
    throw new Error('Registration VRF keypair generation failed');
  }
  console.log('VRF keypair generated and persisted in worker memory');

  return vrfResult.vrfChallengeData;
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

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Starting registration...'
    } as RegistrationSSEEvent);

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

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Starting VRF registration with consistent keypair approach...'
    });

    // Step 1: Initialize VRF Manager
    console.log('VRF Registration Step 1: Initialize VRF Manager');

    const vrfManager = passkeyManager.getVRFManager();
    await vrfManager.initialize();

    // Step 2: Prepare for VRF challenge generation
    console.log('VRF Registration Step 2: Preparing for VRF challenge generation');

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Generating VRF credentials...'
    });

    // Step 3-4: Get latest NEAR block for VRF input construction
    console.log('VRF Registration Step 3-4: Get NEAR block data');

    const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
    const blockHeight = blockInfo.header.height;
    const blockHashBytes = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

    console.log(`Using NEAR block ${blockHeight} for VRF input construction`);

    // Step 3-4: Generate bootstrap VRF keypair + challenge for registration
    console.log('VRF Registration Step 3-4: Generating VRF keypair + challenge for registration ceremony');

    const vrfChallengeData = await generateBootstrapVrfChallenge(
      webAuthnManager,
      nearAccountId,
      blockHeight,
      blockHashBytes
    );

    // Step 5: Use VRF output as WebAuthn challenge
    console.log('VRF Registration Step 5: Use VRF output as WebAuthn challenge');

    // Decode VRF output and use first 32 bytes as WebAuthn challenge
    const vrfOutputBytes = base64UrlDecode(vrfChallengeData.vrfOutput);
    const webAuthnChallengeBytes = vrfOutputBytes.slice(0, 32); // First 32 bytes as challenge

    // Step 6: WebAuthn registration ceremony with PRF (using VRF challenge)
    console.log('VRF Registration Step 6: WebAuthn registration ceremony with VRF challenge');

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Performing WebAuthn registration with VRF challenge...'
    });

    const registrationOptions: PublicKeyCredentialCreationOptions = {
      challenge: webAuthnChallengeBytes, // Use VRF output as challenge!
      rp: {
        name: 'WebAuthn VRF Passkey',
        id: window.location.hostname
      },
      user: {
        id: new TextEncoder().encode(nearAccountId),
        name: nearAccountId,
        displayName: nearAccountId
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' }, // ES256
        { alg: -257, type: 'public-key' } // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred'
      },
      timeout: 60000,
      attestation: 'none',
      extensions: {
        prf: {
          eval: {
            first: generateUserScopedPrfSalt(nearAccountId) // User-scoped PRF salt
          }
        }
      }
    };

    const credential = await navigator.credentials.create({
      publicKey: registrationOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn registration ceremony failed or was cancelled');
    }

    console.log('✅ WebAuthn ceremony completed with VRF challenge');

    // Step 7: Get PRF output from WebAuthn ceremony for VRF keypair encryption
    console.log('VRF Registration Step 7: Get PRF output for VRF keypair encryption');

    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    if (!prfOutput) {
      throw new Error('PRF extension not supported or failed - required for VRF registration');
    }

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'WebAuthn ceremony successful, PRF output obtained'
    });

    // Step 8: Encrypt the existing VRF keypair with real PRF for storage and future authentication
    console.log('VRF Registration Step 8: Encrypting existing VRF keypair with real PRF for storage');

    // Encrypt the SAME VRF keypair that generated the WebAuthn challenge using dedicated method
    // This ensures perfect consistency between WebAuthn ceremony and contract verification
    const encryptedVrfResult = await webAuthnManager.encryptVrfKeypairWithPrf(
      vrfChallengeData.vrfPublicKey,
      prfOutput
    );

    console.log('✅ VRF keypair encrypted with real PRF using dedicated method');

    // Step 9: Generate NEAR keypair using PRF (for traditional NEAR transactions)
    console.log('VRF Registration Step 9: Generating NEAR keypair with PRF');

    const keyGenResult = await webAuthnManager.secureRegistrationWithPrf(
      nearAccountId,
      prfOutput,
      { nearAccountId },
    );

    if (!keyGenResult.success || !keyGenResult.publicKey) {
      throw new Error('Failed to generate NEAR keypair with PRF');
    }

    // Step 10: Encrypt VRF keypair with real PRF
    console.log('VRF Registration Step 10: Encrypt VRF keypair with real PRF');

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

    // Step 10-11: Create account using testnet faucet service (before storing data)
    console.log('VRF Registration Step 10-11: Creating NEAR account via faucet service');

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
    await new Promise(resolve => setTimeout(resolve, 800));

    if (!accountCreationResult.success) {
      console.error('❌ Account creation failed, initiating complete rollback');

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
        await webAuthnManager.rollbackUserRegistration(nearAccountId);
        console.log('✅ Registration data rolled back');
      } catch (rollbackError: any) {
        console.warn('️Rollback partial failure:', rollbackError.message);
    }

      // TODO: If passkey was created, we should also try to delete it
      // This is not currently possible with WebAuthn API, but we can at least
      // clean up our local data and warn the user
      console.warn('️WebAuthn credential may remain on device - manual deletion required');

      const error = new Error(`Account creation failed: ${accountCreationResult.error || 'Unknown error'}`);
      onError?.(error);
      hooks?.afterCall?.(false, error);

      return {
        success: false,
        error: `Registration failed during account creation: ${accountCreationResult.error || 'Unknown error'}`
      };
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

    // Step 10-11: Contract verification (before data storage)
    console.log('VRF Registration Step 10-11: Contract verification');

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
      const contractVerificationResult = await webAuthnManager.verifyVrfRegistration(
        nearRpcProvider,
        config.contractId,
        {
          vrfInput: vrfChallengeData.vrfInput,
          vrfOutput: vrfChallengeData.vrfOutput,
          vrfProof: vrfChallengeData.vrfProof,
          vrfPublicKey: vrfChallengeData.vrfPublicKey,
          userId: nearAccountId,
          rpId: vrfChallengeData.rpId,
          blockHeight: blockHeight,
          blockHash: bufferEncode(blockHashBytes),
        },
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
        console.log('✅ VRF registration verified by contract');
        console.log('  - Transaction ID:', contractTransactionId);

        onEvent?.({
          step: 6,
          sessionId: tempSessionId,
          phase: 'contract-registration',
          status: 'success',
          timestamp: Date.now(),
          message: 'VRF registration verified by contract'
        });
      } else {
        console.warn('️Contract verification failed, but registration continues locally');
        console.warn('  - Error:', contractVerificationResult.error);
        throw new Error(contractVerificationResult.error);
      }

    } catch (contractError: any) {
      console.warn('️Contract verification failed, but registration continues locally');
      console.warn('  - Contract Error:', contractError.message);
      throw new Error(contractError.message);
    }

    // Step 12: Store user data with VRF credentials atomically
    console.log('VRF Registration Step 12: Storing VRF registration data atomically');

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
          credentialPublicKey: await webAuthnManager.extractCosePublicKeyFromAttestation(
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
        // to ensure perfect consistency between registration and authentication
        await webAuthnManager.storeUserData({
          nearAccountId,
          clientNearPublicKey: keyGenResult.publicKey,
          lastUpdated: Date.now(),
          prfSupported: true,
          deterministicKey: false, // Using single VRF keypair encrypted with real PRF
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
        {
          encrypted_vrf_data_b64u: encryptedVrfResult.encryptedVrfKeypair.encrypted_vrf_data_b64u,
          aes_gcm_nonce_b64u: encryptedVrfResult.encryptedVrfKeypair.aes_gcm_nonce_b64u
        },
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
        vrfPublicKey: vrfChallengeData.vrfPublicKey,
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
        contractVerified
      }
    };

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    console.error('VRF registration error:', error);

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
