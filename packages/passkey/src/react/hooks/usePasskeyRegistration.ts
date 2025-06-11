import { useCallback } from 'react';
import { bufferEncode, publicKeyCredentialToJSON } from '../../utils/encoders';
import {
  SERVER_URL,
  RELAYER_ACCOUNT_ID,
  MUTED_GREEN,
  MUTED_BLUE
} from '../../config';
import { indexDBManager } from '../../core/IndexDBManager';
import type { RegistrationResult } from '../types';
import type { AuthEventEmitter } from '../../core/AuthEventEmitter';
import type { WebAuthnManager } from '../../core/WebAuthnManager';

interface PasskeyRegistrationHook {
  registerPasskey: (currentUsername: string) => Promise<RegistrationResult>;
}

export const usePasskeyRegistration = (
  isProcessing: boolean,
  setIsProcessing: (isProcessing: boolean) => void,
  setIsLoggedIn: (isLoggedIn: boolean) => void,
  setUsername: (username: string | null) => void,
  setNearAccountId: (nearAccountId: string | null) => void,
  setNearPublicKey: (nearPublicKey: string | null) => void,
  optimisticAuth: boolean,
  authEventEmitter: AuthEventEmitter,
  webAuthnManager: WebAuthnManager
): PasskeyRegistrationHook => {
  const registerPasskey = useCallback(async (currentUsername: string): Promise<RegistrationResult> => {
    let toastId = '';

    try {
      if (!currentUsername) {
        throw new Error('Username is required for registration.');
      }
      if (!window.isSecureContext) {
        throw new Error('Passkey operations require a secure context (HTTPS or localhost).');
      }

      if (isProcessing) {
        console.warn('🚫 Registration already in progress, rejecting additional call');
        throw new Error('Registration already in progress. Please wait.');
      }

      toastId = authEventEmitter.loading('Starting registration...');

      const existingUserData = await webAuthnManager.getUserData(currentUsername);
      if (existingUserData?.passkeyCredential) {
        console.warn(`⚠️ User '${currentUsername}' already has credential data. Attempting re-registration...`);
      }

      setIsProcessing(true);
      webAuthnManager.clearAllChallenges();

      // Step 1: WebAuthn credential creation & PRF
      authEventEmitter.success('Step 1: Creating passkey...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
      const { credential, prfEnabled, commitmentId } = await webAuthnManager.registerWithPrf(currentUsername, optimisticAuth);
      const attestationForServer = publicKeyCredentialToJSON(credential);

      // Step 2: Client-side key generation/management using PRF output
      authEventEmitter.success('Step 2: Securing your account...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
      let clientManagedPublicKey: string | null = null;
      const userNearAccountIdToUse = indexDBManager.generateNearAccountId(currentUsername, RELAYER_ACCOUNT_ID);

      if (prfEnabled) {
        const extensionResults = credential.getClientExtensionResults();
        const registrationPrfOutput = (extensionResults as any).prf?.results?.first;
        if (registrationPrfOutput) {
          const prfRegistrationResult = await webAuthnManager.secureRegistrationWithPrf(
            currentUsername,
            registrationPrfOutput,
            { nearAccountId: userNearAccountIdToUse },
            undefined,
            true // Skip challenge validation as WebAuthn ceremony just completed
          );
          if (prfRegistrationResult.success) {
            clientManagedPublicKey = prfRegistrationResult.publicKey;
          } else {
            throw new Error('Client-side key generation/encryption with PRF failed.');
          }
        } else {
          throw new Error("PRF output not available from registration, cannot derive client key this way.");
        }
      } else {
        throw new Error("PRF is required for this registration flow but not enabled/supported by authenticator.");
      }

      if (!clientManagedPublicKey) {
        throw new Error("Failed to obtain client-managed public key.");
      }

      // Step 3: Call server via SSE for verification and background processing
      authEventEmitter.success('Step 3: Verifying with server...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
      return new Promise((resolve, reject) => {
        const verifyPayload = {
          username: currentUsername,
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
          if (!response.ok) { throw new Error(`Server error: ${response.status}`); }
          const reader = response.body?.getReader();
          if (!reader) { throw new Error('Unable to read response stream'); }

          let buffer = '';
          let userLoggedIn = false;
          let finalResult: RegistrationResult = {
            success: false,
            clientNearPublicKey: clientManagedPublicKey,
            nearAccountId: userNearAccountIdToUse,
            transactionId: null
          };

          const processStream = () => {
            reader.read().then(({ value, done }) => {
              if (done) {
                if (userLoggedIn) {
                  resolve(finalResult);
                } else {
                  reject(new Error('Registration completed but user not logged in'));
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

                      // Handle different steps in the registration process
                      switch (data.step) {
                        case 'webauthn-verification':
                          if(data.status === 'progress') authEventEmitter.success('Step 4: Verifying passkey...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
                          break;
                        case 'user-ready':
                          if (data.status === 'success') {
                            authEventEmitter.success('Step 5: User ready!', { id: toastId, style: { background: MUTED_GREEN, color: 'white' } });
                            setIsLoggedIn(true);
                            setUsername(currentUsername);
                            setNearAccountId(userNearAccountIdToUse);
                            setNearPublicKey(clientManagedPublicKey);
                            setIsProcessing(false);
                            webAuthnManager.storeUserData({
                              username: currentUsername,
                              nearAccountId: userNearAccountIdToUse,
                              clientNearPublicKey: clientManagedPublicKey,
                              passkeyCredential: { id: credential.id, rawId: bufferEncode(credential.rawId) },
                              prfSupported: prfEnabled,
                              lastUpdated: Date.now(),
                            });
                            indexDBManager.registerUser(currentUsername, RELAYER_ACCOUNT_ID, {
                              preferences: { optimisticAuth: optimisticAuth },
                            });
                            userLoggedIn = true;
                            finalResult.success = true;
                          }
                          break;
                        case 'access-key-addition':
                          if(data.status === 'progress') authEventEmitter.success('Step 6: Adding access key...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
                          break;
                        case 'database-storage':
                          if(data.status === 'progress') authEventEmitter.success('Step 7: Storing authenticator...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
                          break;
                        case 'contract-registration':
                           if(data.status === 'progress') authEventEmitter.success('Step 8: Registering with contract...', { id: toastId, style: { background: MUTED_BLUE, color: 'white' } });
                          break;
                        case 'registration-complete':
                          if (data.status === 'success') {
                            authEventEmitter.success(`🎉 Welcome ${currentUsername}! All setup complete!`, { id: toastId, duration: 5000, style: { background: MUTED_GREEN, color: 'white' } });
                          }
                          break;
                        case 'registration-error':
                          reject(new Error(data.error || 'Registration failed'));
                          return;
                      }
                    } catch (parseError) {
                      console.warn('Failed to parse SSE message:', line);
                    }
                  }
                }
              }

              processStream();
            }).catch(reject);
          };

          processStream();
        }).catch(reject);
      });

    } catch (err: any) {
      console.error('Registration error in PasskeyContext:', err.message, err.stack);
      let errorMessage = err.message;
      if (err.message?.includes('one of the credentials already registered')) {
        errorMessage = `A passkey for '${currentUsername}' already exists. Please try logging in instead.`;
      }
      if(toastId) authEventEmitter.error(errorMessage, { id: toastId });
      setIsProcessing(false);
      return { success: false, error: errorMessage };
    }
  }, [
    isProcessing,
    setIsProcessing,
    setIsLoggedIn,
    setUsername,
    setNearAccountId,
    setNearPublicKey,
    optimisticAuth,
    authEventEmitter,
    webAuthnManager,
  ]);

  return { registerPasskey };
};