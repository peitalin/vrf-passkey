import { useCallback } from 'react';
import { bufferEncode, publicKeyCredentialToJSON } from '../../../utils';
import { webAuthnManager } from '../../../security/WebAuthnManager';
import {
  SERVER_URL,
  RELAYER_ACCOUNT_ID,
  MUTED_GREEN,
  MUTED_BLUE
} from '../../../config';
import { indexDBManager } from '../../../services/IndexDBManager';
import { useToastManager } from './useToastManager';
import type { RegistrationResult, ManagedToast } from '../types';

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
  optimisticAuth: boolean
): PasskeyRegistrationHook => {
  const managedToast: ManagedToast = useToastManager();

  const registerPasskey = useCallback(async (currentUsername: string): Promise<RegistrationResult> => {
    console.log('🎯 registerPasskey CALLED for username:', currentUsername, 'at', new Date().toISOString());
    console.log('🎯 Current state:', { isProcessing, username: currentUsername });

    if (!currentUsername) {
      return { success: false, error: 'Username is required for registration.' };
    }
    if (!window.isSecureContext) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost).' };
    }

    // Prevent multiple concurrent registrations
    if (isProcessing) {
      console.warn('🚫 Registration already in progress, rejecting additional call');
      return { success: false, error: 'Registration already in progress. Please wait.' };
    }

    // Check if user already has credentials - warn but allow re-registration
    const existingUserData = await webAuthnManager.getUserData(currentUsername);
    if (existingUserData?.passkeyCredential) {
      console.warn(`⚠️ User '${currentUsername}' already has credential data. Attempting re-registration...`);
    }

    setIsProcessing(true);

    // Clear any existing challenges to prevent conflicts
    webAuthnManager.clearAllChallenges();

    try {
      console.log('🔄 Step 1: Starting WebAuthn credential creation & PRF...');

      // Show initial toast for Step 1
      const step1Toast = managedToast.loading('🔐 Step 1: Creating passkey with PRF...', {
        style: { background: MUTED_BLUE, color: 'white' },
        duration: 5000
      });

      // Step 1: WebAuthn credential creation & PRF
      const { credential, prfEnabled, commitmentId } = await webAuthnManager.registerWithPrf(currentUsername, optimisticAuth);
      const attestationForServer = publicKeyCredentialToJSON(credential);

      console.log('✅ Step 1 complete: WebAuthn credential created, PRF enabled:', prfEnabled);
      managedToast.success('✅ Step 1: Passkey created successfully', {
        id: step1Toast,
        style: { background: MUTED_GREEN, color: 'white' },
        duration: 5000
      });

      // Step 2: Client-side key generation/management using PRF output
      console.log('🔄 Step 2: Starting client-side key generation...');
      managedToast.dismiss(step1Toast);
      const processingToast = managedToast.loading('🔐 Securing your account...', {
        style: { background: MUTED_BLUE, color: 'white' }
      });

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
            console.log('✅ Step 2 complete: Client-managed public key obtained/generated:', clientManagedPublicKey);
          } else {
            throw new Error('Client-side key generation/encryption with PRF failed.');
          }
        } else {
          console.warn("PRF was enabled, but no PRF output directly from registration. Key derivation might need separate authN.");
          throw new Error("PRF output not available from registration, cannot derive client key this way.");
        }
      } else {
        throw new Error("PRF is required for this registration flow but not enabled/supported by authenticator.");
      }

      if (!clientManagedPublicKey) {
        throw new Error("Failed to obtain client-managed public key.");
      }

      // Step 3: Call server via SSE for verification and background processing
      console.log('🔄 Step 3: Starting SSE registration verification...');

      return new Promise((resolve, reject) => {
        const verifyPayload = {
          username: currentUsername,
          attestationResponse: attestationForServer,
          commitmentId: commitmentId,
          useOptimistic: optimisticAuth,
          clientManagedNearPublicKey: clientManagedPublicKey,
        };

        // Use fetch but stream the response
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
            throw new Error(`Server error: ${response.status}`);
          }

          const reader = response.body?.getReader();
          if (!reader) {
            throw new Error('Unable to read response stream');
          }

          let buffer = '';
          let userLoggedIn = false;
          let finalResult = {
            success: false,
            clientNearPublicKey: clientManagedPublicKey,
            nearAccountId: userNearAccountIdToUse,
            transactionId: null as string | null
          };

          const processStream = () => {
            reader.read().then(({ value, done }) => {
              if (done) {
                console.log('🎉 SSE stream completed');
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
                      console.log('📡 SSE Message:', data);

                      // Handle different steps in the registration process
                      if (data.step === 'webauthn-verification' && data.status === 'progress') {
                        managedToast.loading('🔐 Verifying credentials...', {
                          id: processingToast,
                          style: { background: MUTED_BLUE, color: 'white' }
                        });
                      }

                      if (data.step === 'user-ready' && data.status === 'success') {
                        console.log('✅ Step 5: Registration verified - updating UI state...');

                        // Update React state immediately for user login
                        setIsLoggedIn(true);
                        setUsername(currentUsername);
                        setNearAccountId(userNearAccountIdToUse);
                        setNearPublicKey(clientManagedPublicKey);
                        setIsProcessing(false);

                        // Store user data locally
                        webAuthnManager.storeUserData({
                          username: currentUsername,
                          nearAccountId: userNearAccountIdToUse,
                          clientNearPublicKey: clientManagedPublicKey,
                          passkeyCredential: {
                            id: credential.id,
                            rawId: bufferEncode(credential.rawId)
                          },
                          prfSupported: prfEnabled,
                          lastUpdated: Date.now(),
                        });

                        // Register user in IndexDBManager
                        indexDBManager.registerUser(currentUsername, RELAYER_ACCOUNT_ID, {
                          preferences: {
                            optimisticAuth: optimisticAuth,
                          },
                        });

                        userLoggedIn = true;
                        finalResult.success = true;
                      }

                      // Handle other steps (database-storage, access-key-addition, etc.)
                      if (data.step === 'database-storage' && data.status === 'success') {
                        console.log('✅ Step 6a: Authenticator stored successfully');
                        managedToast.success('✅ Account registered, authenticator stored!', {
                          id: processingToast,
                          style: { background: MUTED_GREEN, color: 'white' },
                          duration: 5000
                        });
                      }

                      if (data.step === 'registration-complete' && data.status === 'success') {
                        console.log('🎉 Step 7: Registration completed successfully!');
                        managedToast.success(`🎉 Welcome ${currentUsername}! All setup complete!`, {
                          duration: 5000,
                          style: { background: MUTED_GREEN, color: 'white' }
                        });
                      }

                      if (data.step === 'registration-error') {
                        console.error('❌ Registration error:', data.error);
                        reject(new Error(data.error || 'Registration failed'));
                        return;
                      }
                    } catch (parseError) {
                      console.warn('Failed to parse SSE message:', line);
                    }
                  }
                }
              }

              processStream(); // Continue reading
            }).catch(reject);
          };

          processStream();
        }).catch(reject);
      });

    } catch (err: any) {
      console.error('Registration error in PasskeyContext:', err.message, err.stack);

      // Handle specific WebAuthn errors
      let errorMessage = err.message;
      if (err.message?.includes('one of the credentials already registered')) {
        errorMessage = `A passkey for '${currentUsername}' already exists. Please try logging in instead, or clear your browser data to re-register.`;
      }

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
    managedToast
  ]);

  return { registerPasskey };
};