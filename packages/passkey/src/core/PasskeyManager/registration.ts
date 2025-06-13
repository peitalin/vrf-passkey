import { bufferEncode, publicKeyCredentialToJSON } from '../../utils/encoders';
import { RELAYER_ACCOUNT_ID, WEBAUTHN_CONTRACT_ID, RPC_NODE_URL } from '../../config';
import { indexDBManager } from '../IndexDBManager';
import { ContractService } from '../ContractService';
import { JsonRpcProvider } from '@near-js/providers';
import { determineOperationMode, validateModeRequirements, getModeDescription } from '../utils/routing';
import type { WebAuthnManager } from '../WebAuthnManager';
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
  webAuthnManager: WebAuthnManager,
  username: string,
  options: RegistrationOptions,
  config: PasskeyManagerConfig,
  nearRpcProvider?: any
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

    // Validate mode requirements
    const validation = validateModeRequirements(routing, nearRpcProvider);
    if (!validation.valid) {
      const error = new Error(validation.error);
      onError?.(error);
      throw error;
    }

    // Log the determined mode
    console.log(`Registration: ${getModeDescription(routing)}`);

    // Handle serverless mode with direct contract calls
    if (routing.mode === 'serverless') {
      console.log('⚡ Registration: Implementing serverless mode with direct contract calls');
      return await handleServerlessRegistration(
        webAuthnManager,
        username,
        nearRpcProvider,
        tempSessionId,
        onEvent,
        onError,
        hooks,
        optimisticAuth
      );
    }

    // For server modes, use the serverUrl from routing
    const baseUrl = routing.serverUrl!;

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
      username,
      optimisticAuth
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
        useOptimistic: optimisticAuth,
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

                      // For now, we'll store basic authenticator info that can be used for serverless fallback
                      // The actual public key will be extracted from the attestation object by the server
                      // but we store enough info to enable serverless authentication later
                      const authenticatorData = {
                        nearAccountId: userNearAccountIdToUse,
                        credentialID: credentialIdBase64url,
                        credentialPublicKey: new Uint8Array(response.attestationObject), // Store full attestation object for now
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

                      indexDBManager.registerUser(username, RELAYER_ACCOUNT_ID, {
                        preferences: { optimisticAuth: optimisticAuth },
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
 * Handle serverless registration using direct contract calls
 */
async function handleServerlessRegistration(
  webAuthnManager: WebAuthnManager,
  username: string,
  nearRpcProvider: any,
  tempSessionId: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
  hooks?: OperationHooks,
  optimisticAuth?: boolean
): Promise<RegistrationResult> {
  try {
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

    // Step 2: Build contract arguments and get registration options
    const userId = contractService.generateUserId();
    const { contractArgs } = contractService.buildRegistrationOptionsArgs(
      username,
      userId,
      existingAuthenticators
    );

    // Call contract to get registration options
    const optionsResult = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'generate_registration_options',
      args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
      finality: 'optimistic'
    });

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
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array(Buffer.from(parsedOptions.options.challenge, 'base64url')),
        rp: parsedOptions.options.rp,
        user: {
          id: new Uint8Array(Buffer.from(parsedOptions.options.user.id, 'base64url')),
          name: parsedOptions.options.user.name,
          displayName: parsedOptions.options.user.displayName
        },
        pubKeyCredParams: parsedOptions.options.pubKeyCredParams,
        timeout: parsedOptions.options.timeout,
        attestation: parsedOptions.options.attestation as AttestationConveyancePreference,
                 excludeCredentials: parsedOptions.options.excludeCredentials?.map((cred: any) => ({
           id: new Uint8Array(Buffer.from(cred.id, 'base64url')),
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

    // Call contract to verify registration
    const verificationResult = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'verify_registration_response',
      args_base64: Buffer.from(JSON.stringify(verificationArgs)).toString('base64'),
      finality: 'optimistic'
    });

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

    await indexDBManager.registerUser(username, RELAYER_ACCOUNT_ID, {
      preferences: { optimisticAuth: optimisticAuth || false },
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