import { useCallback } from 'react';
import { bufferDecode, publicKeyCredentialToJSON } from '../../utils/encoders';
import { webAuthnManager } from '../../core/WebAuthnManager';
import { SERVER_URL, RELAYER_ACCOUNT_ID } from '../../config';
import { indexDBManager } from '../../core/IndexDBManager';
import type { ServerAuthenticationOptions } from '../../types';
import type { LoginResult } from '../types';

interface PasskeyLoginHook {
  loginPasskey: (currentUsername?: string) => Promise<LoginResult>;
}

interface ServerAuthOptions extends ServerAuthenticationOptions {
  nearAccountId?: string;
  commitmentId?: string;
}

interface ServerVerificationResponse {
  verified: boolean;
  username?: string;
  nearAccountId?: string;
  error?: string;
}

export const usePasskeyLogin = (
  username: string | null,
  optimisticAuth: boolean,
  setIsProcessing: (isProcessing: boolean) => void,
  setIsLoggedIn: (isLoggedIn: boolean) => void,
  setUsername: (username: string | null) => void,
  setNearAccountId: (nearAccountId: string | null) => void,
  setNearPublicKey: (nearPublicKey: string | null) => void,
): PasskeyLoginHook => {
  const loginPasskey = useCallback(async (currentUsername?: string): Promise<LoginResult> => {
    const userToLogin = currentUsername || username;
    if (!userToLogin) {
      return { success: false, error: 'Username is required for login.' };
    }
    if (!window.isSecureContext) {
      return {
        success: false,
        error: 'Passkey operations require a secure context (HTTPS or localhost).'
      };
    }
    setIsProcessing(true);

    try {
      // Step 1: Get authentication options from server
      const requestBody = userToLogin
        ? { username: userToLogin, useOptimistic: optimisticAuth }
        : { useOptimistic: optimisticAuth };

      const authOptionsResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });

      if (!authOptionsResponse.ok) {
        const errorData = await authOptionsResponse.json().catch(() => ({
          error: 'Failed to fetch auth options'
        }));
        throw new Error(errorData.error || `Server error ${authOptionsResponse.status}`);
      }

      const options: ServerAuthOptions = await authOptionsResponse.json();
      const commitmentId = options.commitmentId;
      console.log('PasskeyContext: Received authentication options with commitmentId:', commitmentId);

      // Step 2: Perform WebAuthn assertion ceremony
      const pkRequestOpts: PublicKeyCredentialRequestOptions = {
        challenge: bufferDecode(options.challenge),
        rpId: options.rpId,
        allowCredentials: options.allowCredentials?.map(c => ({
          ...c,
          id: bufferDecode(c.id)
        })),
        userVerification: options.userVerification || "preferred",
        timeout: options.timeout || 60000,
      };

      const assertion = await navigator.credentials.get({
        publicKey: pkRequestOpts
      }) as PublicKeyCredential | null;

      if (!assertion) {
        throw new Error('Passkey login cancelled or no assertion.');
      }

      // Step 3: Prepare verification payload
      const assertionJSON = publicKeyCredentialToJSON(assertion);
      const verificationPayload = {
        ...assertionJSON,
        commitmentId,
        useOptimistic: optimisticAuth,
      };

      // Step 4: Send assertion to server for verification
      const verifyResponse = await fetch(`${SERVER_URL}/verify-authentication`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(verificationPayload),
      });

      const serverVerifyData: ServerVerificationResponse = await verifyResponse.json();

      if (verifyResponse.ok && serverVerifyData.verified) {
        const loggedInUsername = serverVerifyData.username;
        if (!loggedInUsername) {
          throw new Error("Login successful but server didn't return username.");
        }

        // Fetch comprehensive user data from local storage
        const localUserData = await webAuthnManager.getUserData(loggedInUsername);
        const finalNearAccountId = serverVerifyData.nearAccountId || localUserData?.nearAccountId;

        setIsLoggedIn(true);
        setUsername(loggedInUsername);
        setNearAccountId(finalNearAccountId || null);

        // Update IndexDBManager with login
        if (finalNearAccountId) {
          let clientUser = await indexDBManager.getUser(finalNearAccountId);
          if (!clientUser) {
            console.log(`Creating IndexDBManager entry for existing user: ${loggedInUsername}`);
            clientUser = await indexDBManager.registerUser(loggedInUsername, RELAYER_ACCOUNT_ID);
          } else {
            await indexDBManager.updateLastLogin(finalNearAccountId);
          }
        }

        // Set the UI-driving public key state from locally stored clientNearPublicKey
        if (localUserData?.clientNearPublicKey) {
          setNearPublicKey(localUserData.clientNearPublicKey);
          console.log(`Login successful for ${loggedInUsername}. Client-managed PK set from local store: ${localUserData.clientNearPublicKey}`);
        } else {
          setNearPublicKey(null);
          console.warn(`User ${loggedInUsername} logged in, but no clientNearPublicKey found in local storage. Greeting functionality may be limited.`);
        }

        setIsProcessing(false);
        return {
          success: true,
          loggedInUsername,
          clientNearPublicKey: localUserData?.clientNearPublicKey || null,
          nearAccountId: finalNearAccountId
        };
      } else {
        throw new Error(serverVerifyData.error || 'Passkey authentication failed by server.');
      }
    } catch (err: any) {
      console.error('Login error in PasskeyContext:', err.message, err.stack);
      setIsProcessing(false);
      return { success: false, error: err.message };
    }
  }, [
    username,
    optimisticAuth,
    setIsProcessing,
    setIsLoggedIn,
    setUsername,
    setNearAccountId,
    setNearPublicKey,
  ]);

  return { loginPasskey };
};