import { bufferEncode, publicKeyCredentialToJSON, bufferDecode } from '../../utils/encoders';
import { RELAYER_ACCOUNT_ID, WEBAUTHN_CONTRACT_ID, RPC_NODE_URL } from '../../config';
import { indexDBManager } from '../IndexDBManager';
import { ContractService } from '../ContractService';
import { JsonRpcProvider } from '@near-js/providers';
import { determineOperationMode, validateModeRequirements, getModeDescription } from '../utils/routing';
import type { PasskeyManager } from './index';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  PasskeyManagerConfig,
  OperationHooks,
  UserReadySSEEvent,
  RegistrationCompleteSSEEvent
} from './types';

/**
 * Core registration function that handles passkey registration without React dependencies
 */
export async function registerPasskey(
  passkeyManager: PasskeyManager,
  username: string,
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
    message: `Starting registration for ${username}`
  } as RegistrationSSEEvent);

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validation
    if (!username) {
      const error = new Error('Username is required for registration.');
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
    const validation = validateModeRequirements(routing, nearRpcProvider);
    if (!validation.valid) {
      const error = new Error(validation.error);
      onError?.(error);
      throw error;
    }

    // Handle serverless mode with direct contract calls
    if (routing.mode === 'serverless') {
      console.log('⚡ Registration: Implementing serverless mode with direct contract calls');
      return await handleRegistrationOnchain(
        passkeyManager,
        username,
        tempSessionId,
        onEvent,
        onError,
        hooks,
      );
    } else {
      return await handleRegistrationWithServer(
        routing.serverUrl!,
        passkeyManager,
        username,
        tempSessionId,
        onEvent,
        onError,
        hooks,
        optimisticAuth
      );
    }

  } catch (err: any) {
    console.error('Registration error:', err.message, err.stack);
    const errorMessage = err.message?.includes('one of the credentials already registered')
      ? `A passkey for '${username}' already exists. Please try logging in instead.`
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
  username: string,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
  optimisticAuth?: boolean
): Promise<RegistrationResult> {

  // For server modes, use the serverUrl from routing
  const baseUrl = serverUrl;
  const webAuthnManager = passkeyManager.getWebAuthnManager();
  const existingUserData = await webAuthnManager.getUserData(username);
  if (existingUserData?.passkeyCredential) {
    console.warn(`⚠️ User '${username}' already has credential data. Attempting re-registration...`);
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
    username
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
  const userNearAccountIdToUse = indexDBManager.generateNearAccountId(username, RELAYER_ACCOUNT_ID);

  if (prfEnabled) {
    const extensionResults = credential.getClientExtensionResults();
    const registrationPrfOutput = (extensionResults as any).prf?.results?.first;
    if (registrationPrfOutput) {
      const prfRegistrationResult = await webAuthnManager.secureRegistrationWithPrf(
        username,
        registrationPrfOutput,
        { nearAccountId: userNearAccountIdToUse },
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
      username: username,
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
        nearAccountId: userNearAccountIdToUse,
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
                      username: username,
                      nearAccountId: userNearAccountIdToUse,
                      clientNearPublicKey: clientManagedPublicKey,
                      passkeyCredential: { id: credential.id, rawId: bufferEncode(credential.rawId) },
                      prfSupported: prfEnabled,
                      lastUpdated: Date.now(),
                    }).catch(error => {
                      console.warn('Failed to store user data:', error);
                    });

                    // Store authenticator data in IndexedDB for serverless fallback
                    // Extract authenticator data from the credential we just created
                    const credentialIdBase64url = bufferEncode(credential.rawId);
                    const response = credential.response as AuthenticatorAttestationResponse;

                    // CRITICAL FIX: Extract proper COSE public key from attestation object
                    // This matches the server-side fix to ensure consistent COSE key storage
                    console.log('🔧 [Client COSE Key] Extracting proper COSE public key from attestation object');

                    const attestationObjectBase64url = bufferEncode(response.attestationObject);

                    // Extract COSE public key using WebAuthnManager (async operation)
                    webAuthnManager.extractCosePublicKeyFromAttestation(attestationObjectBase64url)
                      .then((credentialPublicKeyForDB) => {
                        console.log('🔧 [Client COSE Key] Successfully extracted COSE public key:', credentialPublicKeyForDB.length, 'bytes');

                        const authenticatorData = {
                          nearAccountId: userNearAccountIdToUse,
                          credentialID: credentialIdBase64url,
                          credentialPublicKey: credentialPublicKeyForDB, // Now stores proper COSE key
                          counter: 0, // Initial counter value
                          transports: response.getTransports?.() || [],
                          clientNearPublicKey: clientManagedPublicKey,
                          name: `Passkey for ${username}`,
                          registered: new Date().toISOString(),
                          lastUsed: undefined,
                          backedUp: false, // Default value, will be updated by server if available
                          syncedAt: new Date().toISOString(),
                        };

                        // Store the authenticator in IndexedDB cache for future serverless use
                        indexDBManager.storeAuthenticator(authenticatorData).then(() => {
                          console.log(`✅ Stored authenticator data in IndexedDB for serverless fallback: ${credentialIdBase64url}`);
                        }).catch((error) => {
                          console.warn(`⚠️ Failed to store authenticator data in IndexedDB:`, error);
                        });
                      })
                      .catch((coseError: any) => {
                        console.error('🔧 [Client COSE Key] Failed to extract COSE public key:', coseError.message);
                        // Fallback to the full attestation object (this will likely fail in contract verification)
                        const credentialPublicKeyForDB = new Uint8Array(response.attestationObject);
                        console.warn('🔧 [Client COSE Key] Using fallback attestation object - this may cause contract verification failures');

                        const authenticatorData = {
                          nearAccountId: userNearAccountIdToUse,
                          credentialID: credentialIdBase64url,
                          credentialPublicKey: credentialPublicKeyForDB, // Fallback to attestation object
                          counter: 0, // Initial counter value
                          transports: response.getTransports?.() || [],
                          clientNearPublicKey: clientManagedPublicKey,
                          name: `Passkey for ${username}`,
                          registered: new Date().toISOString(),
                          lastUsed: undefined,
                          backedUp: false, // Default value, will be updated by server if available
                          syncedAt: new Date().toISOString(),
                        };

                        // Store the authenticator in IndexedDB cache for future serverless use
                        indexDBManager.storeAuthenticator(authenticatorData).then(() => {
                          console.log(`✅ Stored authenticator data in IndexedDB for serverless fallback: ${credentialIdBase64url}`);
                        }).catch((error) => {
                          console.warn(`⚠️ Failed to store authenticator data in IndexedDB:`, error);
                        });
                      });

                    indexDBManager.registerUser(username, RELAYER_ACCOUNT_ID, {
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
 * Handle onchain (serverless) registration using direct contract calls
 */
async function handleRegistrationOnchain(
  passkeyManager: PasskeyManager,
  username: string,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
): Promise<RegistrationResult> {
  try {
    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const nearRpcProvider = passkeyManager['nearRpcProvider']; // Access private property

    // Initialize ContractService
    const contractService = new ContractService(
      nearRpcProvider,
      WEBAUTHN_CONTRACT_ID,
      'WebAuthn Passkey',
      window.location.hostname,
      RELAYER_ACCOUNT_ID
    );

    const userNearAccountIdToUse = indexDBManager.generateNearAccountId(username, RELAYER_ACCOUNT_ID);

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Getting registration options from contract...'
    } as RegistrationSSEEvent);

    // Step 1: Get existing authenticators from cache for exclusion
    const existingAuthenticators = await indexDBManager.getAuthenticatorsByUser(userNearAccountIdToUse);

    // Step 2: Generate client-side challenge and build contract arguments
    const userId = contractService.generateUserId();
    // SECURITY NOTE: Generate a random challenge to trigger the contract call
    // and dispatch a generate_authentication_options() transaction which returns
    // the real contract-generated challenge in Step 3.
    // The real WebAuthn ceremony will use the challenge returned by the contract.
    const clientChallenge = crypto.getRandomValues(new Uint8Array(32));
    const clientChallengeBase64url = bufferEncode(clientChallenge);

    const { contractArgs } = contractService.buildRegistrationOptionsArgs(
      username,
      userId,
      existingAuthenticators
    );

    // Add the client-generated challenge to bootstrap the contract call
    const contractArgsWithChallenge = {
      ...contractArgs,
      challenge: clientChallengeBase64url
    };

    console.log('🔄 Calling contract generate_registration_options with client challenge for serverless registration');

    // Call contract to get registration options using PasskeyManager.callFunction
    const optionsResult = await passkeyManager.callFunction2(
      WEBAUTHN_CONTRACT_ID,
      'generate_registration_options',
      contractArgsWithChallenge,
      '30000000000000', // 30 TGas
      '0',
      username
    );

    const parsedOptions = contractService.parseContractResponse(optionsResult, 'generate_registration_options');

    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating passkey...'
    } as RegistrationSSEEvent);

    // Step 3: Perform WebAuthn registration ceremony
    // IMPORTANT: This uses the REAL challenge from the contract (parsedOptions.options.challenge),
    // NOT the client-generated bootstrap challenge. The contract has replaced our bootstrap
    // challenge with a legitimate, cryptographically secure challenge.
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array(bufferDecode(parsedOptions.options.challenge)), // Real contract challenge
        rp: parsedOptions.options.rp,
        user: {
          id: new Uint8Array(bufferDecode(parsedOptions.options.user.id)),
          name: parsedOptions.options.user.name,
          displayName: parsedOptions.options.user.displayName
        },
        pubKeyCredParams: parsedOptions.options.pubKeyCredParams,
        timeout: parsedOptions.options.timeout,
        attestation: parsedOptions.options.attestation as AttestationConveyancePreference,
                 excludeCredentials: parsedOptions.options.excludeCredentials?.map((cred: any) => ({
           id: new Uint8Array(bufferDecode(cred.id)),
           type: cred.type as PublicKeyCredentialType,
           transports: cred.transports as AuthenticatorTransport[]
         })),
        authenticatorSelection: parsedOptions.options.authenticatorSelection,
        extensions: {
          prf: {
            eval: {
              first: new Uint8Array(new Array(32).fill(42)) // PRF salt for key derivation
            }
          }
        }
      }
    }) as PublicKeyCredential | null;

    if (!credential) {
      const error = new Error('Passkey registration cancelled or failed.');
      onError?.(error);
      throw error;
    }

    // Step 4: Handle PRF for client-side key generation
    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Securing your account...'
    } as RegistrationSSEEvent);

    const extensionResults = credential.getClientExtensionResults();
    const registrationPrfOutput = (extensionResults as any).prf?.results?.first;

    if (!registrationPrfOutput) {
      const error = new Error("PRF is required for this registration flow but not available from authenticator.");
      onError?.(error);
      throw error;
    }

    // Generate client-managed key using PRF
    const prfRegistrationResult = await webAuthnManager.secureRegistrationWithPrf(
      username,
      registrationPrfOutput,
      { nearAccountId: userNearAccountIdToUse },
      undefined,
      true // Skip challenge validation as WebAuthn ceremony just completed
    );

    if (!prfRegistrationResult.success) {
      const error = new Error('Client-side key generation/encryption with PRF failed.');
      onError?.(error);
      throw error;
    }

    const clientManagedPublicKey = prfRegistrationResult.publicKey;

    // Step 5: Verify registration with contract
    onEvent?.({
      step: 1,
      sessionId: tempSessionId,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying registration with contract...'
    } as RegistrationSSEEvent);

    const attestationForContract = publicKeyCredentialToJSON(credential);
    const verificationArgs = contractService.buildRegistrationVerificationArgs(
      attestationForContract,
      parsedOptions.commitmentId || ''
    );

    // Call contract to verify registration using PasskeyManager.callFunction
    console.log('🔄 Calling contract verify_registration_response for serverless registration');

    const verificationResult = await passkeyManager.callFunction2(
      WEBAUTHN_CONTRACT_ID,
      'verify_registration_response',
      verificationArgs,
      '30000000000000', // 30 TGas
      '0',
      username
    );

    const parsedVerification = contractService.parseContractResponse(verificationResult, 'verify_registration_response');

    if (!parsedVerification.verified) {
      const error = new Error('Registration verification failed by contract.');
      onError?.(error);
      throw error;
    }

    // Step 6: Store user data locally
    onEvent?.({
      step: 2,
      sessionId: tempSessionId,
      phase: 'user-ready',
      status: 'success',
      timestamp: Date.now(),
      message: 'Registration successful!',
      verified: true,
      username: username,
      nearAccountId: userNearAccountIdToUse,
      clientNearPublicKey: clientManagedPublicKey,
      mode: 'serverless'
    } as UserReadySSEEvent);

    // Store user data
    await webAuthnManager.storeUserData({
      username: username,
      nearAccountId: userNearAccountIdToUse,
      clientNearPublicKey: clientManagedPublicKey,
      passkeyCredential: { id: credential.id, rawId: bufferEncode(credential.rawId) },
      prfSupported: true,
      lastUpdated: Date.now(),
    });

    // CRITICAL FIX: Store authenticator data with proper COSE public key for serverless mode
    console.log('🔧 [Serverless COSE Key] Extracting and storing proper COSE public key from attestation object');

    const credentialIdBase64url = bufferEncode(credential.rawId);
    const response = credential.response as AuthenticatorAttestationResponse;

    let credentialPublicKeyForDB: Uint8Array;
    try {
      // Extract COSE public key using WebAuthnManager
      const attestationObjectBase64url = bufferEncode(response.attestationObject);
      credentialPublicKeyForDB = await webAuthnManager.extractCosePublicKeyFromAttestation(attestationObjectBase64url);
      console.log('🔧 [Serverless COSE Key] Successfully extracted COSE public key:', credentialPublicKeyForDB.length, 'bytes');
    } catch (coseError: any) {
      console.error('🔧 [Serverless COSE Key] Failed to extract COSE public key:', coseError.message);
      // Fallback to the full attestation object (this will likely fail in contract verification)
      credentialPublicKeyForDB = new Uint8Array(response.attestationObject);
      console.warn('🔧 [Serverless COSE Key] Using fallback attestation object - this may cause contract verification failures');
    }

    const authenticatorData = {
      nearAccountId: userNearAccountIdToUse,
      credentialID: credentialIdBase64url,
      credentialPublicKey: credentialPublicKeyForDB, // Now stores proper COSE key
      counter: 0, // Initial counter value
      transports: response.getTransports?.() || [],
      clientNearPublicKey: clientManagedPublicKey,
      name: `Passkey for ${username}`,
      registered: new Date().toISOString(),
      lastUsed: undefined,
      backedUp: false, // Default value
      syncedAt: new Date().toISOString(),
    };

    // Store the authenticator in IndexedDB for future serverless use
    await indexDBManager.storeAuthenticator(authenticatorData);
    console.log(`✅ Stored authenticator data in IndexedDB for serverless mode: ${credentialIdBase64url}`);

    await indexDBManager.registerUser(username, RELAYER_ACCOUNT_ID, {
      preferences: { optimisticAuth: false },
    });

    const finalResult: RegistrationResult = {
      success: true,
      clientNearPublicKey: clientManagedPublicKey,
      nearAccountId: userNearAccountIdToUse,
      transactionId: null // No transaction ID in serverless registration
    };

    onEvent?.({
      step: 6,
      sessionId: tempSessionId,
      phase: 'registration-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'Registration completed successfully!'
    } as RegistrationCompleteSSEEvent);

    hooks?.afterCall?.(true, finalResult);
    return finalResult;

  } catch (error: any) {
    console.error('Serverless registration error:', error);
    onError?.(error);

    onEvent?.({
      step: 0,
      sessionId: tempSessionId,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: error.message,
      error: error.message
    } as RegistrationSSEEvent);

    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}