import { bufferDecode, publicKeyCredentialToJSON, bufferEncode } from '../../utils/encoders';
import { RELAYER_ACCOUNT_ID, WEBAUTHN_CONTRACT_ID } from '../../config';
import { indexDBManager } from '../IndexDBManager';
import { ContractService } from '../ContractService';
import { determineOperationMode, validateModeRequirements, getModeDescription } from '../utils/routing';
import type { PasskeyManager } from '../PasskeyManager';
import type { ServerAuthenticationOptions } from '../../types';
import type {
  LoginOptions,
  LoginResult,
  LoginEvent,
} from './types';
import {
  VERIFY_AUTHENTICATION_RESPONSE_GAS_STRING,
  GENERATE_AUTHENTICATION_OPTIONS_GAS_STRING
} from '../../config';
import { FinalExecutionOutcome } from '@near-js/types';


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
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  options?: LoginOptions
): Promise<LoginResult> {

  const { optimisticAuth, onEvent, onError, hooks } = options || { optimisticAuth: false };
  const config = passkeyManager.getConfig();
  const nearRpcProvider = passkeyManager['nearRpcProvider']; // Access private property

  // Emit started event
  onEvent?.({ type: 'loginStarted', data: { nearAccountId } });

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validation
    if (!window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
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
    const validation = validateModeRequirements(routing, nearRpcProvider, 'login');
    if (!validation.valid) {
      const error = new Error(validation.error!);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: validation.error!, nearAccountId } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: validation.error! };
    }

    // Log the determined mode
    console.log(`Login: ${getModeDescription(routing)}`);

    // Handle serverless mode with direct contract calls via WASM worker
    if (routing.mode === 'serverless') {
      console.log('⚡ Login: Implementing serverless mode with WASM worker contract calls');

      return await handleLoginOnchain(
        passkeyManager,
        nearAccountId,
        onEvent,
        onError,
        hooks
      );
    } else {

      return await handleLoginWithServer(
        routing.serverUrl!,
        passkeyManager,
        nearAccountId,
        onEvent,
        onError,
        hooks
      );
    }
  } catch (err: any) {
    console.error('Login error:', err.message, err.stack);
    onError?.(err);
    onEvent?.({ type: 'loginFailed', data: { error: err.message, nearAccountId } });
    hooks?.afterCall?.(false, err);
    return { success: false, error: err.message };
  }
}

/**
 * Handle login via server webauthn authentication to sign contract calls
 */
async function handleLoginWithServer(
  serverUrl: string,
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  hooks?: { beforeCall?: () => void | Promise<void>; afterCall?: (success: boolean, result?: any) => void | Promise<void> }
): Promise<LoginResult> {
  // For server modes, use the serverUrl from routing
  const baseUrl = serverUrl;

  // Step 1: Get authentication options from server
  onEvent?.({
    type: 'loginProgress',
    data: {
      step: 'getting-options',
      message: 'Getting authentication options...'
    }
  });

  const authOptionsResponse = await fetch(`${baseUrl}/generate-authentication-options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      accountId: nearAccountId
    }),
  });

  if (!authOptionsResponse.ok) {
    const errorData = await authOptionsResponse.json().catch(() => ({
      error: 'Failed to fetch auth options'
    }));
    const errorMessage = errorData.error || `Server error ${authOptionsResponse.status}`;
    const error = new Error(errorMessage);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: errorMessage };
  }

  const options: ServerAuthOptions = await authOptionsResponse.json();
  const commitmentId = options.commitmentId;
  console.log('PasskeyLogin: Received authentication options with commitmentId:', commitmentId);

  // Step 2: Perform WebAuthn assertion ceremony with PRF extension
  onEvent?.({
    type: 'loginProgress',
    data: {
      step: 'webauthn-assertion',
      message: 'Authenticating with passkey...'
    }
  });

  // Add PRF extension to the request options
  const pkRequestOpts: PublicKeyCredentialRequestOptions = {
    challenge: bufferDecode(options.challenge),
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map(c => ({
      id: bufferDecode(c.id),
      type: 'public-key' as const,
      transports: c.transports as AuthenticatorTransport[]
    })),
    userVerification: (options.userVerification || "preferred") as UserVerificationRequirement,
    timeout: options.timeout || 60000,
    extensions: {
      prf: {
        eval: {
          first: new Uint8Array(new Array(32).fill(42)) // PRF salt for NEAR key encryption
        }
      }
    }
  };

  const assertion = await navigator.credentials.get({
    publicKey: pkRequestOpts
  }) as PublicKeyCredential | null;

  if (!assertion) {
    const errorMessage = 'Passkey login cancelled or no assertion.';
    const error = new Error(errorMessage);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: errorMessage };
  }

  // Get PRF output from the assertion
  const extensionResults = assertion.getClientExtensionResults();
  const prfOutput = (extensionResults as any).prf?.results?.first;

  if (!prfOutput) {
    const errorMessage = 'PRF output not available - required for serverless verification.';
    const error = new Error(errorMessage);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
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
  };

  // Step 4: Send assertion to server for verification
  const verifyResponse = await fetch(`${baseUrl}/verify-authentication`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(verificationPayload),
  });

  const serverVerifyData: ServerVerificationResponse = await verifyResponse.json();

  if (verifyResponse.ok && serverVerifyData.verified) {
    const loggedInNearAccountId = serverVerifyData.nearAccountId;
    if (!loggedInNearAccountId) {
      const errorMessage = "Login successful but server didn't return NEAR account ID.";
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Fetch comprehensive user data from local storage
    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const localUserData = await webAuthnManager.getUserData(loggedInNearAccountId);
    const finalNearAccountId = serverVerifyData.nearAccountId || localUserData?.nearAccountId;

    // Update IndexDBManager with login
    if (finalNearAccountId) {
      let clientUser = await indexDBManager.getUser(finalNearAccountId);
      if (!clientUser) {
        console.log(`Creating IndexDBManager entry for existing user: ${loggedInNearAccountId}`);
        clientUser = await indexDBManager.registerUser(finalNearAccountId);
      } else {
        await indexDBManager.updateLastLogin(finalNearAccountId);
      }
    }

    const result: LoginResult = {
      success: true,
      loggedInNearAccountId,
      clientNearPublicKey: localUserData?.clientNearPublicKey || null,
      nearAccountId: finalNearAccountId
    };

    if (localUserData?.clientNearPublicKey) {
      console.log(`Login successful for ${loggedInNearAccountId}. Client-managed PK set from IndexDBManager: ${localUserData.clientNearPublicKey}`);
    } else {
      console.warn(`User ${loggedInNearAccountId} logged in, but no clientNearPublicKey found in local storage. Greeting functionality may be limited.`);
    }

    onEvent?.({
      type: 'loginCompleted',
      data: {
        nearAccountId: loggedInNearAccountId,
        publicKey: localUserData?.clientNearPublicKey || ''
      }
    });

    hooks?.afterCall?.(true, result);
    return result;
  } else {
    const errorMessage = serverVerifyData.error || 'Passkey authentication failed by server.';
    const error = new Error(errorMessage);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: errorMessage };
  }
}

/**
 * Handle onchain (serverless) login using WASM worker to sign contract calls
 *
 * OPTIMIZATION: This flow uses only TWO TouchID prompts instead of three by:
 * 1. First TouchID: callContract() for generate_authentication_options (gets contract challenge)
 * 2. Second TouchID: WebAuthn assertion ceremony with contract's challenge (gets PRF output)
 * 3. NO TouchID: callContract() with prfOutput for verify_authentication_response (reuses PRF from step 2)
 */
async function handleLoginOnchain(
  passkeyManager: PasskeyManager,
  nearAccountId?: string,
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  hooks?: { beforeCall?: () => void | Promise<void>; afterCall?: (success: boolean, result?: any) => void | Promise<void> }
): Promise<LoginResult> {
  try {
    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const nearRpcProvider = passkeyManager['nearRpcProvider'];

    // Step 1: Determine which user to authenticate
    let targetNearAccountId = nearAccountId;

    if (!targetNearAccountId) {
      // No nearAccountId provided - try to get the last used account
      targetNearAccountId = await webAuthnManager.getLastUsedNearAccountId() || undefined;
      if (!targetNearAccountId) {
        const errorMessage = 'No NEAR account ID provided and no previous user found. Please provide a NEAR account ID for serverless login.';
        const error = new Error(errorMessage);
        onError?.(error);
        onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId } });
        hooks?.afterCall?.(false, error);
        return { success: false, error: errorMessage };
      }
    }

    // Step 2: Get authenticator data from local cache
    const authenticators = await indexDBManager.getAuthenticatorsByUser(targetNearAccountId);
    if (authenticators.length === 0) {
      const errorMessage = `No authenticators found for account ${targetNearAccountId}. Please register first.`;
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId: targetNearAccountId } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 3: Get authentication options from contract using callContract (FIRST TOUCHID)
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'getting-options',
        message: 'Getting authentication options from contract...'
      }
    });

    // Initialize ContractService to build arguments
    const contractService = new ContractService(
      nearRpcProvider,
      WEBAUTHN_CONTRACT_ID,
      'WebAuthn Passkey',
      window.location.hostname,
      RELAYER_ACCOUNT_ID
    );

    // Use the first (most recent) authenticator for authentication
    const primaryAuthenticator = authenticators[0];

    // Build contract arguments for generate_authentication_options
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

    // Use callContract to get authentication options (this will do its own TouchID)
    const authOptionsResult: FinalExecutionOutcome = await passkeyManager.callContract({
      contractId: WEBAUTHN_CONTRACT_ID,
      methodName: 'generate_authentication_options',
      args: contractArgs,
      gas: GENERATE_AUTHENTICATION_OPTIONS_GAS_STRING,
      attachedDeposit: '0',
      nearAccountId: targetNearAccountId,
      requiresAuth: true,
      optimisticAuth: false
    });
    console.log("Auth options result:", authOptionsResult);

    // Parse the authentication options from the result
    const parsedOptions = contractService.parseContractResponse(authOptionsResult, 'generate_authentication_options');

    // Step 4: Perform WebAuthn assertion ceremony with CONTRACT'S challenge (SECOND TOUCHID)
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'webauthn-assertion',
        message: 'Authenticating with passkey using contract challenge...'
      }
    });

    // Add PRF extension to the request options using the CONTRACT'S challenge
    const pkRequestOpts: PublicKeyCredentialRequestOptions = {
      challenge: bufferDecode(parsedOptions.options.challenge), // Use contract's challenge
      rpId: parsedOptions.options.rpId,
      allowCredentials: parsedOptions.options.allowCredentials?.map((c: any) => ({
        id: bufferDecode(c.id),
        type: 'public-key' as const,
        transports: c.transports as AuthenticatorTransport[]
      })),
      userVerification: (parsedOptions.options.userVerification || "preferred") as UserVerificationRequirement,
      timeout: parsedOptions.options.timeout || 60000,
      extensions: {
        prf: {
          eval: {
            first: new Uint8Array(new Array(32).fill(42)) // PRF salt for NEAR key encryption
          }
        }
      }
    };

    const assertion = await navigator.credentials.get({
      publicKey: pkRequestOpts
    }) as PublicKeyCredential | null;

    if (!assertion) {
      const errorMessage = 'Passkey login cancelled or no assertion.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId: targetNearAccountId } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Get PRF output from the assertion
    const extensionResults = assertion.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    if (!prfOutput) {
      const errorMessage = 'PRF output not available - required for serverless verification.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId: targetNearAccountId } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 5: Verify authentication with contract using PRF from verification ceremony (NO ADDITIONAL TOUCHID)
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'verifying-server',
        message: 'Verifying authentication with contract (reusing PRF)...'
      }
    });

    const assertionJSON = publicKeyCredentialToJSON(assertion);
    const verificationArgs = contractService.buildAuthenticationVerificationArgs(
      assertionJSON,
      parsedOptions.commitmentId || ''
    );

    // Use callContract to verify authentication (reusing PRF from verification)
    const verificationResult: FinalExecutionOutcome = await passkeyManager.callContract({
      contractId: WEBAUTHN_CONTRACT_ID,
      methodName: 'verify_authentication_response',
      args: verificationArgs,
      gas: VERIFY_AUTHENTICATION_RESPONSE_GAS_STRING,
      attachedDeposit: '0',
      nearAccountId: targetNearAccountId,
      prfOutput,
      optimisticAuth: false
    });

    const parsedVerification = contractService.parseContractResponse(
      verificationResult,
      'verify_authentication_response'
    );

    if (!parsedVerification.verified) {
      const errorMessage = 'Authentication verification failed by contract.';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({ type: 'loginFailed', data: { error: errorMessage, nearAccountId: targetNearAccountId } });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Step 6: Update local data and return success
    const localUserData = await webAuthnManager.getUserData(targetNearAccountId);

    // Update IndexDBManager with login
    let clientUser = await indexDBManager.getUser(targetNearAccountId);
    if (!clientUser) {
      console.log(`Creating IndexDBManager entry for existing user: ${targetNearAccountId}`);
      clientUser = await indexDBManager.registerUser(targetNearAccountId);
    } else {
      await indexDBManager.updateLastLogin(targetNearAccountId);
    }

    const result: LoginResult = {
      success: true,
      loggedInNearAccountId: targetNearAccountId,
      clientNearPublicKey: localUserData?.clientNearPublicKey || null,
      nearAccountId: targetNearAccountId
    };

    if (localUserData?.clientNearPublicKey) {
      console.log(`Serverless login successful for ${targetNearAccountId}. Client-managed PK: ${localUserData.clientNearPublicKey}`);
    } else {
      console.warn(`User ${targetNearAccountId} logged in via serverless mode, but no clientNearPublicKey found in local storage.`);
    }

    onEvent?.({
      type: 'loginCompleted',
      data: {
        nearAccountId: targetNearAccountId,
        publicKey: localUserData?.clientNearPublicKey || ''
      }
    });

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    console.error('Serverless login error:', error);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: error.message, nearAccountId } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}
