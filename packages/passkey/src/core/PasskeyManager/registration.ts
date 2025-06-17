import { WEBAUTHN_CONTRACT_ID } from '../../config';
import { bufferEncode, publicKeyCredentialToJSON } from '../../utils/encoders';
import { indexDBManager } from '../IndexDBManager';
import { determineOperationMode, validateModeRequirements, getModeDescription } from '../utils/routing';
import { validateNearAccountId, validateServerRegistrationAccountId } from '../utils/validation';
import type { PasskeyManager } from './index';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  OperationHooks,
} from '../types/passkeyManager';

/**
 * Extract COSE public key from WebAuthn credential and create authenticator data
 * This function handles the complex COSE key extraction logic consistently across both
 * server and serverless registration flows
 */
async function extractAndStoreAuthenticatorData(
  webAuthnManager: any,
  credential: PublicKeyCredential,
  nearAccountId: string,
  clientNearPublicKey: string | undefined
): Promise<void> {
  const credentialIdBase64url = bufferEncode(credential.rawId);
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports = response.getTransports?.() || [];

  console.log('🔧 [COSE Key] Extracting proper COSE public key from attestation object');

  const attestationObjectBase64url = bufferEncode(response.attestationObject);

  try {
    // Extract COSE public key using WebAuthnManager (async operation)
    const credentialPublicKeyForDB = await webAuthnManager.extractCosePublicKeyFromAttestation(attestationObjectBase64url);
    console.log('🔧 [COSE Key] Successfully extracted COSE public key:', credentialPublicKeyForDB.length, 'bytes');

    const authenticatorData = {
      nearAccountId,
      credentialID: credentialIdBase64url,
      credentialPublicKey: credentialPublicKeyForDB, // Now stores proper COSE key
      counter: 0, // Initial counter value
      transports,
      clientNearPublicKey,
      name: `Passkey for ${indexDBManager.extractUsername(nearAccountId)}`,
      registered: new Date().toISOString(),
      lastUsed: undefined,
      backedUp: false, // Default value, will be updated by server if available
      syncedAt: new Date().toISOString(),
    };

    // Store the authenticator in IndexedDB cache for future serverless use
    await indexDBManager.storeAuthenticator(authenticatorData);
    console.log(`✅ Stored authenticator data in IndexedDB: ${credentialIdBase64url}`);

  } catch (coseError: any) {
    console.error('🔧 [COSE Key] Failed to extract COSE public key:', coseError.message);
    // Fallback to the full attestation object (this will likely fail in contract verification)
    const credentialPublicKeyForDB = new Uint8Array(response.attestationObject);
    console.warn('🔧 [COSE Key] Using fallback attestation object - this may cause contract verification failures');

    const authenticatorData = {
      nearAccountId,
      credentialID: credentialIdBase64url,
      credentialPublicKey: credentialPublicKeyForDB, // Fallback to attestation object
      counter: 0, // Initial counter value
      transports,
      clientNearPublicKey,
      name: `Passkey for ${indexDBManager.extractUsername(nearAccountId)}`,
      registered: new Date().toISOString(),
      lastUsed: undefined,
      backedUp: false, // Default value, will be updated by server if available
      syncedAt: new Date().toISOString(),
    };

    // Store the authenticator in IndexedDB cache for future serverless use
    await indexDBManager.storeAuthenticator(authenticatorData);
    console.log(`✅ Stored authenticator data in IndexedDB (with fallback): ${credentialIdBase64url}`);
  }
}

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
    console.log('🌊 Faucet service response:', faucetResult);

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
    console.error('🌊 Faucet service error:', faucetError);

    // Check if account already exists
    if (faucetError.message?.includes('already exists') || faucetError.message?.includes('AccountAlreadyExists')) {
      console.log('🌊 Account already exists, continuing with registration...');
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
      console.warn('🌊 Faucet service failed, but continuing with local registration:', faucetError.message);
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
    console.log('🚀 Creating NEAR account via delegate action and server relayer');

    // Step 1: Server-side relayer account
    // The server should have a funded testnet account that acts as the relayer
    console.log('🔗 Step 1: Using server-side relayer account');

    // Step 2: User generates keypair client-side (already done - publicKey parameter)
    console.log('🔑 Step 2: User keypair already generated client-side');

    // Step 3: Create signed delegate action for account creation
    console.log('📝 Step 3: Creating signed delegate action for account creation');

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
 * Core registration function that handles passkey registration without React dependencies
 */
export async function registerPasskey(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  options: RegistrationOptions
): Promise<RegistrationResult> {

  const { optimisticAuth, onEvent, onError, hooks } = options;
  const config = passkeyManager.getConfig();
  const nearRpcProvider = passkeyManager['nearRpcProvider']; // Access private property

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

    // Client-side routing logic using routing utilities
    const routing = determineOperationMode({
      optimisticAuth,
      config,
      operation: 'registration'
    });

    // Log the determined mode
    console.log(`Registration: ${getModeDescription(routing)}`);

    // Validate mode requirements
    const validation2 = validateModeRequirements(routing, nearRpcProvider);
    if (!validation2.valid) {
      const error = new Error(validation2.error);
      onError?.(error);
      throw error;
    }

    // Handle serverless mode with direct contract calls
    if (routing.mode === 'serverless') {
      console.log('⚡ Registration: Implementing serverless mode with direct contract calls');
      return await handleRegistrationWithRelayer(
        passkeyManager,
        nearAccountId,
        tempSessionId,
        onEvent,
        onError,
        hooks,
      );
    } else {
      return await handleRegistrationWithServer(
        routing.serverUrl!,
        passkeyManager,
        nearAccountId,
        tempSessionId,
        onEvent,
        onError,
        hooks,
      );
    }

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
 * Handle registration via server webauthn for direct contract calls
 */
async function handleRegistrationWithServer(
  serverUrl: string,
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
): Promise<RegistrationResult> {

  // Validate nearAccountId format - must be <username>.<relayerAccountId>, <username>.testnet, or <username>.near
  const validation = validateServerRegistrationAccountId(nearAccountId);
  if (!validation.valid) {
    const error = new Error(validation.error!);
    onError?.(error);
    throw error;
  }

  // For server modes, use the serverUrl from routing
  const baseUrl = serverUrl;
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const existingUserData = await webAuthnManager.getUserData(nearAccountId);
  if (existingUserData?.passkeyCredential) {
    console.warn(`⚠️ User '${nearAccountId}' already has credential data. Attempting re-registration...`);
  }

  webAuthnManager.clearAllChallenges();

  // Step 1: WebAuthn credential creation & PRF
  onEvent?.({
    step: 1,
    sessionId: tempSessionId,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Creating passkey...'
  } as RegistrationSSEEvent);

  const { credential, prfEnabled, commitmentId } = await webAuthnManager.registerWithPrfAndUrl(
    baseUrl,
    nearAccountId
  );
  const attestationForServer = publicKeyCredentialToJSON(credential);

  // Step 2: Client-side key generation/management using PRF output
  onEvent?.({
    step: 1,
    sessionId: tempSessionId,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Securing your account...'
  } as RegistrationSSEEvent);

  let clientManagedPublicKey: string | null = null;

  if (prfEnabled) {
    const extensionResults = credential.getClientExtensionResults();
    const registrationPrfOutput = (extensionResults as any).prf?.results?.first;
    if (registrationPrfOutput) {
      const prfRegistrationResult = await webAuthnManager.secureRegistrationWithPrf(
        nearAccountId,
        registrationPrfOutput,
        { nearAccountId: nearAccountId },
        undefined,
        true // Skip challenge validation as WebAuthn ceremony just completed
      );
      if (prfRegistrationResult.success) {
        clientManagedPublicKey = prfRegistrationResult.publicKey;
      } else {
        const error = new Error('Client-side key generation/encryption with PRF failed.');
        onError?.(error);
        throw error;
      }
    } else {
      const error = new Error("PRF output not available from registration, cannot derive client key this way.");
      onError?.(error);
      throw error;
    }
  } else {
    const error = new Error("PRF is required for this registration flow but not enabled/supported by authenticator.");
    onError?.(error);
    throw error;
  }

  if (!clientManagedPublicKey) {
    const error = new Error("Failed to obtain client-managed public key.");
    onError?.(error);
    throw error;
  }

  // Step 3: Call server via SSE for verification and background processing
  onEvent?.({
    step: 1,
    sessionId: tempSessionId,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Verifying with server...'
  } as RegistrationSSEEvent);

  return new Promise((resolve, reject) => {
    const verifyPayload = {
      accountId: nearAccountId,
      attestationResponse: attestationForServer,
      commitmentId: commitmentId,
      clientNearPublicKey: clientManagedPublicKey,
    };

    fetch(`${baseUrl}/verify-registration`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache',
      },
      body: JSON.stringify(verifyPayload),
    }).then(response => {
      if (!response.ok) {
        const error = new Error(`Server error: ${response.status}`);
        onError?.(error);
        throw error;
      }
      const reader = response.body?.getReader();
      if (!reader) {
        const error = new Error('Unable to read response stream');
        onError?.(error);
        throw error;
      }

      let buffer = '';
      let userRegistered = false;
      let finalResult: RegistrationResult = {
        success: false,
        clientNearPublicKey: clientManagedPublicKey,
        nearAccountId: nearAccountId,
        transactionId: null
      };

      const processStream = () => {
        reader.read().then(({ value, done }) => {
          if (done) {
            if (userRegistered) {
              // Run afterCall hook with success
              hooks?.afterCall?.(true, finalResult);
              resolve(finalResult);
            } else {
              const error = new Error('Registration completed but user not registered');
              onError?.(error);
              hooks?.afterCall?.(false, error);
              reject(error);
            }
            return;
          }

          if (value) {
            buffer += new TextDecoder().decode(value);
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.substring(6));

                  // Forward the SSE event directly to the client
                  onEvent?.(data as RegistrationSSEEvent);

                  // Handle specific server events for internal state management
                  if (data.phase === 'user-ready' && data.status === 'success') {
                    // Store user data
                    webAuthnManager.storeUserData({
                      nearAccountId: nearAccountId,
                      clientNearPublicKey: clientManagedPublicKey,
                      passkeyCredential: { id: credential.id, rawId: bufferEncode(credential.rawId) },
                      prfSupported: prfEnabled,
                      lastUpdated: Date.now(),
                    }).catch(error => {
                      console.warn('Failed to store user data:', error);
                    });

                    // Store authenticator data in IndexedDB for serverless fallback
                    // Extract authenticator data from the credential we just created
                    extractAndStoreAuthenticatorData(
                        webAuthnManager,
                        credential,
                        nearAccountId,
                        clientManagedPublicKey
                    ).catch(error => {
                      console.warn('Failed to store authenticator data:', error);
                    });

                    indexDBManager.registerUser(nearAccountId, {
                      preferences: { optimisticAuth: true },
                    });

                    userRegistered = true;
                    finalResult.success = true;
                  }

                  if (data.phase === 'registration-complete' && data.status === 'success') {
                    // Final completion event - could emit additional success event here if needed
                  }

                  if (data.phase === 'registration-error') {
                    const error = new Error(data.error || 'Registration failed');
                    onError?.(error);
                    hooks?.afterCall?.(false, error);
                    reject(error);
                    return;
                  }
                } catch (parseError) {
                  console.warn('Failed to parse SSE message:', line);
                }
              }
            }
          }

          processStream();
        }).catch(error => {
          onError?.(error);
          hooks?.afterCall?.(false, error);
          reject(error);
        });
      };

      processStream();
    }).catch(error => {
      onError?.(error);
      hooks?.afterCall?.(false, error);
      reject(error);
    });
  });
}

/**
 * Handle onchain registration using NEAR testnet faucet service
 * This approach uses the NEAR testnet faucet to create accounts without requiring
 * the user to send transactions
 */
async function handleRegistrationWithRelayer(
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

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Starting registration with faucet-sponsored account creation...'
    });
    // TODO: not truly serverless, but it's the best we can do for now
    // TODO: lookup delegationActions: relayers finish the transaction

    // Step 1: Perform WebAuthn registration ceremony with PRF
    console.log('🔒 Serverless (not truly serverless) registration: Starting WebAuthn ceremony with PRF');

    // For serverless mode, we need to generate our own registration options
    // since we can't call the contract for options (it requires authentication)
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    // Build registration options for WebAuthn ceremony
    const registrationOptions: PublicKeyCredentialCreationOptions = {
      challenge,
      rp: {
        name: 'WebAuthn Passkey',
        id: window.location.hostname
      },
      user: {
        id: new TextEncoder().encode(nearAccountId),
        name: nearAccountId, // use full account ID for WebAuthn user entity
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
            first: new Uint8Array(new Array(32).fill(42)) // PRF salt for NEAR key encryption
          }
        }
      }
    };

    const credential = await navigator.credentials.create({
      publicKey: registrationOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('Passkey creation cancelled or failed');
    }

    // Get PRF output from the credential
    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;
    const prfEnabled = !!prfOutput;

    if (!prfEnabled || !prfOutput) {
      throw new Error('PRF extension not supported or failed - required for serverless mode');
    }

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'WebAuthn registration successful with PRF support'
    });

    // Step 2: Generate NEAR keypair using PRF output
    console.log('🔑 Serverless registration: Generating NEAR keypair with PRF');

    const finalNearAccountId = nearAccountId; // Use the provided account ID directly

    const keyGenResult = await webAuthnManager.secureRegistrationWithPrf(
      nearAccountId,
      prfOutput,
      { nearAccountId: finalNearAccountId },
      undefined, // challengeId
      true // skipChallengeValidation for serverless mode
    );

    if (!keyGenResult.success || !keyGenResult.publicKey) {
      throw new Error('Failed to generate NEAR keypair with PRF');
    }

    // Step 3: Create NEAR account using testnet faucet service
    console.log('🌊 Serverless registration: Creating NEAR account via faucet service');

    onEvent?.({
      step: 3,
      sessionId: tempSessionId,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating NEAR account via faucet service...'
    });

    // Send user ready event early so user can start using the app
    onEvent?.({
      step: 2,
      sessionId: tempSessionId,
      phase: 'user-ready',
      status: 'success',
      timestamp: Date.now(),
      message: 'User ready - creating NEAR account...',
      verified: true,
      nearAccountId: finalNearAccountId,
      clientNearPublicKey: keyGenResult.publicKey,
      mode: 'serverless'
    });

    // ========================================================================
    // TODO: REPLACE WITH METATRANSACTIONS / DELEGATE ACTIONS
    //
    // Current implementation uses NEAR testnet faucet service for account creation.
    // This should be replaced with a proper serverless solution using:
    //
    // 1. Server-side relayer account - Funded testnet account on server as relayer
    // 2. User generates keypair - User generates keypair client-side for new account
    // 3. Signed delegate action - User creates signed delegate action for account creation
    // 4. Relayer execution - Server receives delegate action and executes it
    //
    // This would provide true serverless account creation without relying on external services.
    // ========================================================================

    // Use testnet faucet service for now (will be replaced with delegate actions)
    const accountCreationResult = await createAccountTestnetFaucet(
      finalNearAccountId,
      keyGenResult.publicKey,
      tempSessionId,
      onEvent
    );

    if (!accountCreationResult.success && accountCreationResult.error) {
      console.warn('Account creation failed but continuing with registration:', accountCreationResult.error);
    }

    // ========================================================================
    // END TODO: REPLACE WITH METATRANSACTIONS / DELEGATE ACTIONS
    // ========================================================================

    // Step 4: Wait for account to be available before proceeding
    console.log('⏳ Serverless registration: Waiting for account to be available...');

    onEvent?.({
      step: 4,
      sessionId: tempSessionId,
      phase: 'account-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Waiting for account to be available on network...'
    });

    // Only wait for account verification if account creation was successful
    if (accountCreationResult.success) {
      // Check account balance to verify successful creation
      console.log('⏳ Verifying account creation by checking balance...');

      const maxRetries = 10;
      const retryDelay = 2000; // 2 seconds
      let accountVerified = false;

      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          // Query account state to check if it exists and has balance
          const nearRpcProvider = passkeyManager['nearRpcProvider'];
          const accountState = await nearRpcProvider.query({
            request_type: 'view_account',
            finality: 'final',
            account_id: finalNearAccountId,
          }) as any; // Cast to any since the NEAR RPC types are complex

          // Check if account has a balance (indicating successful creation)
          const balance = accountState?.amount || '0';
          const balanceNum = BigInt(balance);

          if (balanceNum > 0n) {
            console.log(`✅ Account ${finalNearAccountId} verified with balance: ${balance} yoctoNEAR`);
            accountVerified = true;
            break;
          } else {
            console.log(`⏳ Account ${finalNearAccountId} exists but has no balance yet, attempt ${attempt}/${maxRetries}`);
          }
        } catch (error: any) {
          if (error.type === 'AccountDoesNotExist' ||
              (error.cause && error.cause.name === 'UNKNOWN_ACCOUNT')) {
            console.log(`⏳ Account ${finalNearAccountId} not yet created, attempt ${attempt}/${maxRetries}`);
          } else {
            console.warn(`Unexpected error checking account ${finalNearAccountId}:`, error);
            // For unexpected errors, assume account exists and continue
            accountVerified = true;
            break;
          }
        }

        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, retryDelay));
        }
      }

      if (!accountVerified) {
        console.warn(`⚠️ Account ${finalNearAccountId} verification failed after ${maxRetries} attempts, continuing anyway...`);
      }

      onEvent?.({
        step: 4,
        sessionId: tempSessionId,
        phase: 'account-verification',
        status: 'success',
        timestamp: Date.now(),
        message: accountVerified
          ? 'Account verified with balance - ready for use'
          : 'Proceeding despite account verification timeout'
      });
    } else {
      onEvent?.({
        step: 4,
        sessionId: tempSessionId,
        phase: 'account-verification',
        status: 'success',
        timestamp: Date.now(),
        message: 'Skipping account verification (creation failed but continuing)'
      });
    }

    // Step 5: Store authenticator data locally
    console.log('💾 Serverless registration: Storing authenticator data');

    onEvent?.({
      step: 5,
      sessionId: tempSessionId,
      phase: 'database-storage',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Storing authenticator data...'
    });

    // Extract credential data for storage
    const credentialId = bufferEncode(credential.rawId);
    const response = credential.response as AuthenticatorAttestationResponse;
    const transports = response.getTransports?.() || [];

    // Store in IndexDBManager
    await indexDBManager.registerUser(finalNearAccountId);

    // Store WebAuthn user data
    await webAuthnManager.storeUserData({
      nearAccountId: finalNearAccountId,
      clientNearPublicKey: keyGenResult.publicKey,
      lastUpdated: Date.now(),
      prfSupported: true,
      deterministicKey: true,
      passkeyCredential: {
        id: credential.id,
        rawId: credentialId
      }
    });

    // Extract and store COSE public key from attestation object
    await extractAndStoreAuthenticatorData(
      webAuthnManager,
      credential,
      finalNearAccountId,
      keyGenResult.publicKey
    );

    onEvent?.({
      step: 5,
      sessionId: tempSessionId,
      phase: 'database-storage',
      status: 'success',
      timestamp: Date.now(),
      message: 'Authenticator data stored successfully'
    });

    // Step 6: Contract registration - Skip for serverless mode
    console.log('📜 Serverless registration: Skipping contract storage (local-only mode)');

    onEvent?.({
      step: 6,
      sessionId: tempSessionId,
      phase: 'contract-registration',
      status: 'success',
      timestamp: Date.now(),
      message: 'Serverless mode: Authenticator stored locally only - no contract storage needed'
    });

    // Step 7: Complete registration
    onEvent?.({
      step: 7,
      sessionId: tempSessionId,
      phase: 'registration-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'Serverless registration completed successfully!'
    });

    console.log(`✅ Serverless registration completed for ${nearAccountId} with account ${finalNearAccountId}`);

    const result: RegistrationResult = {
      success: true,
      clientNearPublicKey: keyGenResult.publicKey,
      nearAccountId: finalNearAccountId,
      transactionId: null // No transaction in serverless registration
    };

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    console.error('Serverless registration error:', error);

    onEvent?.({
      step: 0,
      sessionId: tempSessionId,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: 'Serverless registration failed',
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