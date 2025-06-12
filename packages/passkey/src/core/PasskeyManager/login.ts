import { bufferDecode, publicKeyCredentialToJSON } from '../../utils/encoders';
import { SERVER_URL, RELAYER_ACCOUNT_ID } from '../../config';
import { indexDBManager } from '../IndexDBManager';
import type { WebAuthnManager } from '../WebAuthnManager';
import type { ServerAuthenticationOptions } from '../../types';
import type {
  LoginOptions,
  LoginResult,
  LoginEvent
} from './types';

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

/**
 * Core login function that handles passkey authentication without React dependencies
 */
export async function loginPasskey(
  webAuthnManager: WebAuthnManager,
  username?: string,
  options?: LoginOptions
): Promise<LoginResult> {
  const { optimisticAuth, onEvent, onError, hooks } = options || { optimisticAuth: true };

  // Emit started event
  onEvent?.({ type: 'loginStarted', data: { username } });

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validation
    if (!window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 1: Get authentication options from server
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'getting-options',
        message: 'Getting authentication options...'
      }
    });

    const requestBody = username
      ? { username: username, useOptimistic: optimisticAuth }
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
      const errorMessage = errorData.error || `Server error ${authOptionsResponse.status}`;
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    const options: ServerAuthOptions = await authOptionsResponse.json();
    const commitmentId = options.commitmentId;
    console.log('PasskeyLogin: Received authentication options with commitmentId:', commitmentId);

    // Step 2: Perform WebAuthn assertion ceremony
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'webauthn-assertion',
        message: 'Authenticating with passkey...'
      }
    });

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
      const errorMessage = 'Passkey login cancelled or no assertion.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 3: Prepare verification payload
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'verifying-server',
        message: 'Verifying with server...'
      }
    });

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
        const errorMessage = "Login successful but server didn't return username.";
        const error = new Error(errorMessage);
        onError?.(error);
        onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username } });
        hooks?.afterCall?.(false, error);
        return { success: false, error: errorMessage };
      }

      // Fetch comprehensive user data from local storage
      const localUserData = await webAuthnManager.getUserData(loggedInUsername);
      const finalNearAccountId = serverVerifyData.nearAccountId || localUserData?.nearAccountId;

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

      const result: LoginResult = {
        success: true,
        loggedInUsername,
        clientNearPublicKey: localUserData?.clientNearPublicKey || null,
        nearAccountId: finalNearAccountId
      };

      if (localUserData?.clientNearPublicKey) {
        console.log(`Login successful for ${loggedInUsername}. Client-managed PK set from local store: ${localUserData.clientNearPublicKey}`);
      } else {
        console.warn(`User ${loggedInUsername} logged in, but no clientNearPublicKey found in local storage. Greeting functionality may be limited.`);
      }

      onEvent?.({
        type: 'loginCompleted',
        data: {
          username: loggedInUsername,
          nearAccountId: finalNearAccountId,
          publicKey: localUserData?.clientNearPublicKey
        }
      });

      hooks?.afterCall?.(true, result);
      return result;
    } else {
      const errorMessage = serverVerifyData.error || 'Passkey authentication failed by server.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }
  } catch (err: any) {
    console.error('Login error:', err.message, err.stack);
    onError?.(err);
    onEvent?.({ type: 'loginFailed', data: { error: err.message, username } });
    hooks?.afterCall?.(false, err);
    return { success: false, error: err.message };
  }
}