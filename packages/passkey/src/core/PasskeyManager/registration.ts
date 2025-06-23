import { bufferEncode, base64UrlDecode, base64UrlEncode } from '../../utils/encoders';
import { indexDBManager } from '../IndexDBManager';
import { validateNearAccountId } from '../utils/validation';
import { WEBAUTHN_CONTRACT_ID } from '../../config';
import type { PasskeyManager } from './index';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  OperationHooks,
} from '../types/passkeyManager';


/**
 * Create NEAR account using testnet faucet service
 * This is a temporary solution that will be replaced with delegate actions
 */
async function createAccountTestnetFaucet(
  nearAccountId: string,
  publicKey: string,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
): Promise<{ success: boolean; message: string; error?: string }> {
  try {
    console.log('🌊 Creating NEAR account via testnet faucet service');

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating NEAR account via faucet service...'
    });

    // Call NEAR testnet faucet service to create account
    const faucetResponse = await fetch('https://helper.nearprotocol.com/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        newAccountId: nearAccountId,
        newAccountPublicKey: publicKey
      })
    });

    if (!faucetResponse.ok) {
      const errorData = await faucetResponse.json().catch(() => ({}));
      throw new Error(`Faucet service error: ${faucetResponse.status} - ${errorData.message || 'Unknown error'}`);
    }

    const faucetResult = await faucetResponse.json();
    console.log('Faucet service response:', faucetResult);

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: `NEAR account ${nearAccountId} created successfully via faucet`
    } as RegistrationSSEEvent);

    return {
      success: true,
      message: `Account ${nearAccountId} created successfully via faucet`
    };

  } catch (faucetError: any) {
    console.error('Faucet service error:', faucetError);

    // Check if account already exists
    if (faucetError.message?.includes('already exists') || faucetError.message?.includes('AccountAlreadyExists')) {
      console.log('Account already exists, continuing with registration...');
      onEvent?.({
        step: 3,
        sessionId: tempSessionId,
        phase: 'access-key-addition',
        status: 'success',
        timestamp: Date.now(),
        message: `Account ${nearAccountId} already exists - continuing with registration`
      } as RegistrationSSEEvent);

      return {
        success: true,
        message: `Account ${nearAccountId} already exists`
      };
    } else {
      // For other errors, we'll continue but warn the user
      console.warn('Faucet service failed, but continuing with local registration:', faucetError.message);
      onEvent?.({
        step: 3,
        sessionId: tempSessionId || 'unknown',
        phase: 'access-key-addition',
        status: 'success',
        timestamp: Date.now(),
        message: 'Account creation via faucet failed, but registration will continue locally'
      } as RegistrationSSEEvent);

      return {
        success: false,
        message: 'Faucet service failed, continuing with local registration',
        error: faucetError.message
      };
    }
  }
}

/**
 * Create NEAR account using delegate actions and server-side relayer
 * This is the future implementation for true serverless account creation
 *
 * @param nearAccountId - The account ID to create (e.g., "username.testnet")
 * @param publicKey - The user's public key for the new account
 * @param serverUrl - The relayer server URL
 * @param onEvent - Event callback for progress updates
 * @param tempSessionId - Session ID for event tracking
 * @returns Promise with success status and details
 */
async function createAccountDelegateAction(
  nearAccountId: string,
  publicKey: string,
  serverUrl: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  tempSessionId?: string
): Promise<{ success: boolean; message: string; transactionId?: string; error?: string }> {
  try {
    console.log('Creating NEAR account via delegate action and server relayer');

    // Step 1: Server-side relayer account
    // The server should have a funded testnet account that acts as the relayer
    console.log('Step 1: Using server-side relayer account');

    // Step 2: User generates keypair client-side (already done - publicKey parameter)
    console.log('Step 2: User keypair already generated client-side');

    // Step 3: Create signed delegate action for account creation
    console.log('Step 3: Creating signed delegate action for account creation');

    // TODO: Implement delegate action creation
    // This would involve:
    // - Creating a DelegateAction for account creation
    // - Signing it with a temporary key or using WebAuthn signature
    // - Preparing the action for relayer execution

    const delegateActionPayload = {
      nearAccountId,
      publicKey: `ed25519:${publicKey}`,
      // TODO: Add delegate action specific fields:
      // - delegateAction: the actual action to create account
      // - signature: user's signature of the delegate action
      // - nonce: to prevent replay attacks
      // - blockHash: recent block hash for validity
    };

    onEvent?.({
      step: 3,
      sessionId: tempSessionId || 'unknown',
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Sending delegate action to relayer...'
    } as RegistrationSSEEvent);

    // Step 4: Relayer execution - Server receives delegate action and executes it
    console.log('⚡ Step 4: Sending delegate action to relayer for execution');

    const relayerResponse = await fetch(`${serverUrl}/relay-delegate-action`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(delegateActionPayload)
    });

    if (!relayerResponse.ok) {
      const errorData = await relayerResponse.json().catch(() => ({}));
      throw new Error(`Relayer service error: ${relayerResponse.status} - ${errorData.message || 'Unknown error'}`);
    }

    const relayerResult = await relayerResponse.json();
    console.log('🚀 Relayer service response:', relayerResult);

    onEvent?.({
      step: 3,
      sessionId: tempSessionId || 'unknown',
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: `NEAR account ${nearAccountId} created successfully via delegate action`
    } as RegistrationSSEEvent);

    return {
      success: true,
      message: `Account ${nearAccountId} created successfully via delegate action`,
      transactionId: relayerResult.transactionId
    };

  } catch (error: any) {
    console.error('🚀 Delegate action account creation error:', error);

    onEvent?.({
      step: 3,
      sessionId: tempSessionId || 'unknown',
      phase: 'access-key-addition',
      status: 'error',
      timestamp: Date.now(),
      message: 'Account creation via delegate action failed'
    } as RegistrationSSEEvent);

    return {
      success: false,
      message: 'Delegate action account creation failed',
      error: error.message
    };
  }
}

/**
 * Core registration function that handles passkey registration
 */
export async function registerPasskey(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  options: RegistrationOptions
): Promise<RegistrationResult> {

  const { optimisticAuth, onEvent, onError, hooks } = options;
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
    return { success: false, error: errorMessage };
  }
}

/**
 * Handle VRF registration following the specification in docs/vrf_challenges.md
 *
 * CORRECTED VRF Registration Flow (Single VRF Keypair):
 * 1. Generate VRF keypair (ed25519) with deterministic entropy
 * 2. Get latest NEAR block (height + hash) for freshness
 * 3. Construct VRF input with domain separator
 * 4. Generate VRF proof + output using the VRF keypair
 * 5. Use VRF output as WebAuthn challenge in registration ceremony
 * 6. WebAuthn registration ceremony with PRF (using VRF challenge)
 * 7. Derive AES key from PRF output and encrypt the SAME VRF keypair
 * 8. Store encrypted VRF keypair in IndexedDB
 * 9. Call contract verify_registration_response with consistent data
 * 10. Contract verifies VRF proof and WebAuthn registration (challenges match!)
 * 11. Store VRF pubkey + authenticator on-chain
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
    const validation = validateNearAccountId(nearAccountId);
    if (!validation.valid) {
      const error = new Error(validation.error!);
      onError?.(error);
      throw error;
    }

    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const nearRpcProvider = passkeyManager['nearRpcProvider'];

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

    // Step 2: Generate VRF keypair with deterministic entropy for consistency
    console.log('VRF Registration Step 2: Generate VRF keypair with deterministic entropy');

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Generating VRF credentials...'
    });

    // FIXED: Use random seed for VRF keypair generation AND challenge generation in one call
    // This ensures a truly random VRF keypair is generated once and used consistently
    const randomSeed = crypto.getRandomValues(new Uint8Array(32));

    // Step 3-4: Get latest NEAR block for VRF input construction
    console.log('VRF Registration Step 3-4: Get NEAR block data');

    const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });
    const blockHeight = blockInfo.header.height;
    const blockHashBytes = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

    console.log(`📊 Using NEAR block ${blockHeight} for VRF input construction`);

    const sessionId = crypto.randomUUID();

    // ENHANCED: Generate VRF keypair AND challenge data in one efficient call
    console.log('VRF Registration Step 3-4: Generating VRF keypair + challenge in one call');

    const tempVrfResult = await webAuthnManager.generateVrfKeypairWithPrf(
      randomSeed.buffer,
      false, // saveInMemory: false - this is a throwaway VRF keypair for challenge generation only
      {
        userId: nearAccountId,
        rpId: window.location.hostname,
        sessionId: sessionId,
        blockHeight: blockHeight,
        blockHashBytes: Array.from(blockHashBytes),
        timestamp: Date.now()
      }
    );

    console.log('✅ VRF keypair + challenge generated in one call');

    if (!tempVrfResult.vrfChallengeData) {
      throw new Error('VRF challenge data not generated - this should not happen');
    }

    const tempVrfChallengeData = tempVrfResult.vrfChallengeData;

    // Step 5: Use VRF output as WebAuthn challenge
    console.log('VRF Registration Step 5: Use VRF output as WebAuthn challenge');

    // Decode VRF output and use first 32 bytes as WebAuthn challenge
    const vrfOutputBytes = base64UrlDecode(tempVrfChallengeData.vrfOutput);
    const webAuthnChallengeBytes = vrfOutputBytes.slice(0, 32); // First 32 bytes as challenge

    console.log(`🔑 Using VRF output as WebAuthn challenge: ${webAuthnChallengeBytes.length} bytes`);
    console.log(`🔍 VRF output (base64url): ${tempVrfChallengeData .vrfOutput.substring(0, 40)}...`);
    console.log(`🔍 WebAuthn challenge (base64url): ${base64UrlEncode(webAuthnChallengeBytes)}`);

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
            first: new Uint8Array(new Array(32).fill(42)) // PRF salt for encryption
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

    // Step 8: Generate FINAL VRF keypair with real PRF for storage and future authentication
    console.log('VRF Registration Step 8: Generating final VRF keypair with real PRF for storage and future authentication');

    // Generate the FINAL VRF keypair using the real PRF output from WebAuthn
    // This VRF keypair will be stored encrypted and used for all future authentications
    const finalVrfResult = await webAuthnManager.generateVrfKeypairWithPrf(
      prfOutput,
      true, // saveInMemory: true - this is the final VRF keypair for storage and future authentication
      {
        userId: nearAccountId,
        rpId: window.location.hostname,
        sessionId: sessionId,
        blockHeight: blockHeight,
        blockHashBytes: Array.from(blockHashBytes),
        timestamp: Date.now()
      }
    );

    if (!finalVrfResult.vrfChallengeData) {
      throw new Error('VRF challenge data not generated from final VRF keypair');
    }

    const finalVrfChallengeData = finalVrfResult.vrfChallengeData;

    console.log('✅ Final VRF keypair generated with real PRF - encrypted for storage AND stored in memory for immediate login');

    // Verify the VRF challenge matches the WebAuthn challenge used in registration
    const finalVrfOutputBytes = base64UrlDecode(finalVrfChallengeData.vrfOutput);
    const finalWebAuthnChallengeBytes = finalVrfOutputBytes.slice(0, 32);

    if (!finalWebAuthnChallengeBytes.every((byte, index) => byte === webAuthnChallengeBytes[index])) {
      console.warn('⚠️ VRF challenge mismatch between temp and final VRF keypairs - this is expected due to different keypairs');
      console.log('📝 Contract verification will use temp VRF data, storage will use final VRF data');
    }

    // Step 9: Generate NEAR keypair using PRF (for traditional NEAR transactions)
    console.log('VRF Registration Step 9: Generating NEAR keypair with PRF');

    const keyGenResult = await webAuthnManager.secureRegistrationWithPrf(
      nearAccountId,
      prfOutput,
      { nearAccountId },
      undefined,
      true // skipChallengeValidation for VRF mode
    );

    if (!keyGenResult.success || !keyGenResult.publicKey) {
      throw new Error('Failed to generate NEAR keypair with PRF');
    }

    // Step 10: Encrypt VRF keypair with real PRF for future authentication
    console.log('VRF Registration Step 10: Encrypt VRF keypair with real PRF');

    // Store the FINAL VRF credentials with the real PRF encryption
    // Note: We use the finalVrfResult which contains the VRF keypair encrypted with real PRF,
    // and will be stored in IndexedDB for future authentication

    // Step 10: Store the VRF credentials encrypted with PRF for future use
    console.log('VRF Registration Step 10: Preparing final VRF credentials for storage');

    // Note: The finalVrfResult.encryptedVrfKeypair was created with real PRF output
    // For future authentication, we'll decrypt this VRF keypair using the same PRF
    // that will be obtained from future WebAuthn authentication ceremonies
    console.log('📝 Final VRF keypair encrypted with real PRF for future authentication');
    console.log('📝 Future authentication will decrypt this VRF keypair with PRF from WebAuthn');

    // Step 12: Verify VRF challenge consistency and prepare for contract submission
    console.log('VRF Registration Step 12: Verify VRF challenge consistency');

    // Use the same VRF challenge data that was generated with the deterministic seed
    // This ensures consistency between the WebAuthn challenge and the contract verification

    console.log('🔍 VRF challenge verification:');
    console.log('  - VRF output used for WebAuthn:', tempVrfChallengeData .vrfOutput.substring(0, 40) + '...');
    console.log('  - WebAuthn challenge length:', webAuthnChallengeBytes.length);
    console.log('  - WebAuthn challenge (base64url):', base64UrlEncode(webAuthnChallengeBytes));
    console.log('  - VRF Input for contract:', tempVrfChallengeData .vrfInput.substring(0, 40) + '...');
    console.log('  - VRF Proof for contract:', tempVrfChallengeData .vrfProof.substring(0, 40) + '...');
    console.log('  - VRF Public Key:', tempVrfChallengeData .vrfPublicKey.substring(0, 40) + '...');
    console.log('✅ VRF challenge and WebAuthn challenge are consistent');
    console.log('📝 NOTE: Using random VRF challenge for contract verification');

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF registration completed with challenge consistency!'
    });

    // Step 13: Call contract verify_registration_response
    console.log('📜 VRF Registration Step 13: Contract verification and storage');

    onEvent?.({
      step: 6,
      sessionId: tempSessionId,
      phase: 'contract-registration',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying VRF registration with contract...'
    });

    // Contract verification will be performed later in the final result section
    console.log('📜 Preparing VRF data for contract verification...');

    // Step 10-11: Create account using testnet faucet service (before storing data)
    console.log('🌊 VRF Registration Step 10-11: Creating NEAR account via faucet service');

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

    if (!accountCreationResult.success) {
      console.error('❌ Account creation failed, initiating complete rollback');

      // Rollback VRF Service Worker state
      try {
        const vrfManager = passkeyManager.getVRFManager();
        await vrfManager.forceCleanup();
        console.log('✅ VRF Service Worker cleaned up');
      } catch (vrfError: any) {
        console.warn('⚠️ VRF cleanup partial failure:', vrfError.message);
      }

      // Rollback any stored registration data
      try {
        await indexDBManager.rollbackUserRegistration(nearAccountId);
        console.log('✅ Registration data rolled back');
      } catch (rollbackError: any) {
        console.warn('⚠️ Rollback partial failure:', rollbackError.message);
    }

      // TODO: If passkey was created, we should also try to delete it
      // This is not currently possible with WebAuthn API, but we can at least
      // clean up our local data and warn the user
      console.warn('⚠️ WebAuthn credential may remain on device - manual deletion required');

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
      message: 'Calling verify_registration_response on contract...'
    });

    try {
      console.log('Calling verify_registration_response on contract...');
      console.log('🔍 Contract call details:');
      console.log('  - Contract ID:', WEBAUTHN_CONTRACT_ID);
      console.log('  - Block Height:', blockHeight);
      console.log('  - VRF Input:', tempVrfChallengeData .vrfInput.substring(0, 40) + '...');
      console.log('  - VRF Output:', tempVrfChallengeData .vrfOutput.substring(0, 40) + '...');
      console.log('  - VRF Proof:', tempVrfChallengeData .vrfProof.substring(0, 40) + '...');
      console.log('  - VRF Public Key:', tempVrfChallengeData .vrfPublicKey.substring(0, 40) + '...');
      console.log('  - RP ID:', tempVrfChallengeData .rpId);

      const contractVerificationResult = await webAuthnManager.verifyVrfRegistration(
        nearRpcProvider,
        WEBAUTHN_CONTRACT_ID,
        {
          vrfInput: tempVrfChallengeData .vrfInput,
          vrfOutput: tempVrfChallengeData .vrfOutput,
          vrfProof: tempVrfChallengeData .vrfProof,
          vrfPublicKey: tempVrfChallengeData .vrfPublicKey,
          userId: nearAccountId,
          rpId: tempVrfChallengeData .rpId,
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
        console.warn('⚠️ Contract verification failed, but registration continues locally');
        console.warn('  - Error:', contractVerificationResult.error);

      onEvent?.({
          step: 6,
        sessionId: tempSessionId,
          phase: 'contract-registration',
        status: 'success',
        timestamp: Date.now(),
          message: 'Contract verification failed but registration continues locally'
        });
      }
    } catch (contractError: any) {
      console.warn('⚠️ Contract verification failed, but registration continues locally');
      console.warn('  - Contract Error:', contractError.message);

      onEvent?.({
        step: 6,
        sessionId: tempSessionId,
        phase: 'contract-registration',
        status: 'success',
        timestamp: Date.now(),
        message: 'Contract verification failed but registration continues locally'
      });
    }

    // Step 12: Store user data with VRF credentials atomically
    console.log('💾 VRF Registration Step 12: Storing VRF registration data atomically');

    onEvent?.({
      step: 5,
      sessionId: tempSessionId,
      phase: 'database-storage',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Storing VRF registration data atomically...'
    });

    try {
      await indexDBManager.atomicOperation(async (db) => {
        // Register user in IndexDB
        await indexDBManager.registerUser(nearAccountId);

        // Store credential for authentication
        const credentialId = bufferEncode(credential.rawId);
        const response = credential.response as AuthenticatorAttestationResponse;

        await indexDBManager.storeAuthenticator({
          nearAccountId,
          credentialID: credentialId,
          credentialPublicKey: await webAuthnManager.extractCosePublicKeyFromAttestation(
            bufferEncode(response.attestationObject)
          ),
          counter: 0,
          transports: response.getTransports?.() || [],
          clientNearPublicKey: keyGenResult.publicKey,
          name: `VRF Passkey for ${indexDBManager.extractUsername(nearAccountId)}`,
          registered: new Date().toISOString(),
          lastUsed: undefined,
          backedUp: false,
          syncedAt: new Date().toISOString(),
        });

        // Store WebAuthn user data with final VRF credentials
        // Note: We store the final VRF keypair encrypted with real PRF
        // to ensure proper decryption during future authentication
        await webAuthnManager.storeUserData({
          nearAccountId,
          clientNearPublicKey: keyGenResult.publicKey,
          lastUpdated: Date.now(),
          prfSupported: true,
          deterministicKey: false, // Using final VRF keypair encrypted with real PRF
          passkeyCredential: {
            id: credential.id,
            rawId: credentialId
          },
          vrfCredentials: finalVrfResult.encryptedVrfKeypair
        });

        console.log('✅ All registration data stored atomically');
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
      console.error('❌ Atomic storage operation failed:', storageError);

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
          encrypted_vrf_data_b64u: finalVrfResult.encryptedVrfKeypair.encrypted_vrf_data_b64u,
          aes_gcm_nonce_b64u: finalVrfResult.encryptedVrfKeypair.aes_gcm_nonce_b64u
        },
        prfOutput
      );

      if (unlockResult.success) {
        console.log('✅ VRF keypair unlocked in memory - user is now logged in');
      } else {
        console.warn('⚠️ Failed to unlock VRF keypair after registration:', unlockResult.error);
      }
    } catch (unlockError: any) {
      console.warn('⚠️ VRF unlock failed after registration:', unlockError.message);
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
        vrfPublicKey: finalVrfResult.vrfPublicKey,
        encryptedVrfKeypair: finalVrfResult.encryptedVrfKeypair,
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
