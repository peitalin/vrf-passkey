import { bufferDecode, publicKeyCredentialToJSON } from '../../utils/encoders';
import { RELAYER_ACCOUNT_ID, WEBAUTHN_CONTRACT_ID } from '../../config';
import { indexDBManager } from '../IndexDBManager';
import { ContractService } from '../ContractService';
import { determineOperationMode, validateModeRequirements, getModeDescription } from '../utils/routing';
import type { WebAuthnManager } from '../WebAuthnManager';
import type { ServerAuthenticationOptions } from '../../types';
import type {
  LoginOptions,
  LoginResult,
  LoginEvent,
  PasskeyManagerConfig
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
  options?: LoginOptions,
  config?: PasskeyManagerConfig,
  nearRpcProvider?: any
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

    // Client-side routing logic using routing utilities
    const routing = determineOperationMode({
      optimisticAuth,
      config,
      operation: 'login'
    });

    // Validate mode requirements
    const validation = validateModeRequirements(routing, nearRpcProvider);
    if (!validation.valid) {
      const error = new Error(validation.error!);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: validation.error!, username } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: validation.error! };
    }

    // Log the determined mode
    console.log(`Login: ${getModeDescription(routing)}`);

    // Handle serverless mode with direct contract calls
    if (routing.mode === 'serverless') {
      console.log('⚡ Login: Implementing serverless mode with direct contract calls');
      return await handleServerlessLogin(
        webAuthnManager,
        username,
        nearRpcProvider,
        onEvent,
        onError,
        hooks,
        optimisticAuth
      );
    }

    // For server modes, use the serverUrl from routing
    const baseUrl = routing.serverUrl!;

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

    const authOptionsResponse = await fetch(`${baseUrl}/generate-authentication-options`, {
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
    const verifyResponse = await fetch(`${baseUrl}/verify-authentication`, {
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

/**
 * Handle serverless login using direct contract calls
 */
async function handleServerlessLogin(
  webAuthnManager: WebAuthnManager,
  username?: string,
  nearRpcProvider?: any,
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  hooks?: { beforeCall?: () => void | Promise<void>; afterCall?: (success: boolean, result?: any) => void | Promise<void> },
  optimisticAuth?: boolean
): Promise<LoginResult> {
  try {
    // Initialize ContractService
    const contractService = new ContractService(
      nearRpcProvider,
      WEBAUTHN_CONTRACT_ID,
      'WebAuthn Passkey',
      window.location.hostname,
      RELAYER_ACCOUNT_ID
    );

    // Step 1: Determine which user to authenticate
    let targetUsername = username;
    let targetNearAccountId: string;

    if (!targetUsername) {
      // No username provided - try to get the last used username
      targetUsername = await webAuthnManager.getLastUsedUsername() || undefined;
      if (!targetUsername) {
        const errorMessage = 'No username provided and no previous user found. Please provide a username for serverless login.';
        const error = new Error(errorMessage);
        onError?.(error);
        onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username } });
        hooks?.afterCall?.(false, error);
        return { success: false, error: errorMessage };
      }
    }

    targetNearAccountId = indexDBManager.generateNearAccountId(targetUsername, RELAYER_ACCOUNT_ID);

    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'getting-options',
        message: 'Getting authentication options from contract...'
      }
    });

    // Step 2: Get authenticator data from local cache
    const authenticators = await indexDBManager.getAuthenticatorsByUser(targetNearAccountId);
    if (authenticators.length === 0) {
      const errorMessage = `No authenticators found for user ${targetUsername}. Please register first.`;
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username: targetUsername } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Use the first (most recent) authenticator for authentication
    const primaryAuthenticator = authenticators[0];

    // Step 3: Build contract arguments and get authentication options
    const allowCredentials = authenticators.map(auth => ({
      id: auth.credentialID,
      type: 'public-key' as const,
      transports: auth.transports || undefined,
    }));

    const contractArgs = contractService.buildAuthenticationOptionsArgs(
      primaryAuthenticator,
      allowCredentials,
      'preferred'
    );

    // Call contract to get authentication options
    const optionsResult = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'generate_authentication_options',
      args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
      finality: 'optimistic'
    });

    const parsedOptions = contractService.parseContractResponse(optionsResult, 'generate_authentication_options');

    // Step 4: Perform WebAuthn assertion ceremony
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'webauthn-assertion',
        message: 'Authenticating with passkey...'
      }
    });

    const pkRequestOpts: PublicKeyCredentialRequestOptions = {
      challenge: new Uint8Array(Buffer.from(parsedOptions.options.challenge, 'base64url')),
      rpId: parsedOptions.options.rpId,
      allowCredentials: parsedOptions.options.allowCredentials?.map((cred: any) => ({
        id: new Uint8Array(Buffer.from(cred.id, 'base64url')),
        type: cred.type as PublicKeyCredentialType,
        transports: cred.transports as AuthenticatorTransport[]
      })),
      userVerification: parsedOptions.options.userVerification || "preferred",
      timeout: parsedOptions.options.timeout || 60000,
    };

    const assertion = await navigator.credentials.get({
      publicKey: pkRequestOpts
    }) as PublicKeyCredential | null;

    if (!assertion) {
      const errorMessage = 'Passkey login cancelled or no assertion.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username: targetUsername } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 5: Verify authentication with contract
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'verifying-server',
        message: 'Verifying authentication with contract...'
      }
    });

    const assertionJSON = publicKeyCredentialToJSON(assertion);
    const verificationArgs = contractService.buildAuthenticationVerificationArgs(
      assertionJSON,
      parsedOptions.commitmentId || ''
    );

    // Call contract to verify authentication
    const verificationResult = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'verify_authentication_response',
      args_base64: Buffer.from(JSON.stringify(verificationArgs)).toString('base64'),
      finality: 'optimistic'
    });

    const parsedVerification = contractService.parseContractResponse(verificationResult, 'verify_authentication_response');

    if (!parsedVerification.verified) {
      const errorMessage = 'Authentication verification failed by contract.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, username: targetUsername } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 6: Update local data and return success
    const localUserData = await webAuthnManager.getUserData(targetUsername);

    // Update IndexDBManager with login
    let clientUser = await indexDBManager.getUser(targetNearAccountId);
    if (!clientUser) {
      console.log(`Creating IndexDBManager entry for existing user: ${targetUsername}`);
      clientUser = await indexDBManager.registerUser(targetUsername, RELAYER_ACCOUNT_ID);
    } else {
      await indexDBManager.updateLastLogin(targetNearAccountId);
    }

    const result: LoginResult = {
      success: true,
      loggedInUsername: targetUsername,
      clientNearPublicKey: localUserData?.clientNearPublicKey || null,
      nearAccountId: targetNearAccountId
    };

    if (localUserData?.clientNearPublicKey) {
      console.log(`Serverless login successful for ${targetUsername}. Client-managed PK: ${localUserData.clientNearPublicKey}`);
    } else {
      console.warn(`User ${targetUsername} logged in via serverless mode, but no clientNearPublicKey found in local storage.`);
    }

    onEvent?.({
      type: 'loginCompleted',
      data: {
        username: targetUsername,
        nearAccountId: targetNearAccountId,
        publicKey: localUserData?.clientNearPublicKey
      }
    });

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    console.error('Serverless login error:', error);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: error.message, username } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}