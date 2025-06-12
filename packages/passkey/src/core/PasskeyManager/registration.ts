import { bufferEncode, publicKeyCredentialToJSON } from '../../utils/encoders';
import { SERVER_URL, RELAYER_ACCOUNT_ID, MUTED_GREEN, MUTED_BLUE } from '../../config';
import { indexDBManager } from '../IndexDBManager';
import type { WebAuthnManager } from '../WebAuthnManager';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent
} from './types';

/**
 * Core registration function that handles passkey registration without React dependencies
 */
export async function registerPasskey(
  webAuthnManager: WebAuthnManager,
  username: string,
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

    const { credential, prfEnabled, commitmentId } = await webAuthnManager.registerWithPrf(username, optimisticAuth);
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
        clientManagedNearPublicKey: clientManagedPublicKey,
      };

      fetch(`${SERVER_URL}/verify-registration`, {
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