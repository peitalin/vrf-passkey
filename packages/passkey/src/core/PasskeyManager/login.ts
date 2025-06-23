import { indexDBManager } from '../IndexDBManager';
import type { PasskeyManager } from '../PasskeyManager';
import type {
  LoginOptions,
  LoginResult,
  LoginEvent,
} from '../types/passkeyManager';
import { base64UrlDecode } from '../../utils/encoders';


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

    // Handle serverless mode with direct contract calls via WASM worker
    console.log('⚡ Login: VRF login with WASM worker contract calls');

      return await handleLoginOnchain(
        passkeyManager,
        nearAccountId,
        onEvent,
        onError,
        hooks
      );

  } catch (err: any) {
    console.error('Login error:', err.message, err.stack);
    onError?.(err);
    onEvent?.({ type: 'loginFailed', data: { error: err.message, nearAccountId } });
    hooks?.afterCall?.(false, err);
    return { success: false, error: err.message };
  }
}

/**
 * Handle onchain (serverless) login using VRF flow per docs/vrf_challenges.md
 *
 * VRF AUTHENTICATION FLOW (Per Specification):
 * 1. Check if user has VRF credentials stored locally
 * 2. Get NEAR block data for freshness (height + hash)
 * 3. Decrypt VRF keypair using PRF from initial WebAuthn ceremony
 * 4. Generate VRF challenge using stored VRF keypair + NEAR block data
 * 5. Use VRF output as WebAuthn challenge for final authentication
 * 6. Verify VRF proof and WebAuthn response on contract
 *
 *
 * BENEFITS OF VRF FLOW:
 * - Provides cryptographically verifiable, stateless authentication
 * - Uses NEAR block data for freshness guarantees
 * - Follows RFC-compliant VRF challenge construction
 * - Eliminates server-side session state
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

    // Step 2: Check for VRF credentials and determine authentication method
    const userData = await webAuthnManager.getUserData(targetNearAccountId);
    const hasVrfCredentials = userData?.vrfCredentials?.encrypted_vrf_data_b64u && userData?.vrfCredentials?.aes_gcm_nonce_b64u;

    if (hasVrfCredentials) {
      console.log('🔐 VRF credentials found - using VRF authentication flow');
      return await handleVrfLogin(
        passkeyManager,
        targetNearAccountId,
        userData.vrfCredentials!, // Non-null assertion since we've verified it exists
        onEvent,
        onError,
        hooks
      );
    } else {
      console.log('⚡ No VRF credentials - traditional contract authentication flow not implemented');
      throw new Error('No VRF credentials found. Please register with VRF support first.');
    }

  } catch (error: any) {
    console.error('Serverless login error:', error);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: error.message, nearAccountId } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}

/**
 * Handle VRF-based login using Service Worker for persistent VRF keypair management
 *
 * New Architecture:
 * 1. Single WebAuthn authentication to get PRF output
 * 2. Unlock VRF keypair in Service Worker memory using PRF
 * 3. VRF keypair persists in Service Worker until logout
 * 4. Subsequent authentications can generate VRF challenges without additional TouchID
 */
async function handleVrfLogin(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  vrfCredentials: { encrypted_vrf_data_b64u: string; aes_gcm_nonce_b64u: string },
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  hooks?: { beforeCall?: () => void | Promise<void>; afterCall?: (success: boolean, result?: any) => void | Promise<void> }
): Promise<LoginResult> {
  try {
    console.log(`Starting VRF login for ${nearAccountId} (Service Worker architecture)`);

    // Step 1: Check if VRF Service Worker is ready
    const vrfManager = passkeyManager.getVRFManager();
    const isVRFReady = await vrfManager.isReady();

    if (!isVRFReady) {
      console.warn('VRF Service Worker not ready yet - VRF initialization may still be in progress');
    }

    // Step 2: Get authenticator data for WebAuthn authentication
    const authenticators = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    // Step 3: Perform single WebAuthn authentication to get PRF output for VRF decryption
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'webauthn-assertion',
        message: 'Authenticating to unlock VRF keypair (TouchID #1)...'
      }
    });

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge,
      rpId: window.location.hostname,
      allowCredentials: authenticators.map(auth => ({
        id: new Uint8Array(Buffer.from(auth.credentialID, 'base64')),
        type: 'public-key' as const,
        transports: auth.transports as AuthenticatorTransport[]
      })),
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: new Uint8Array(new Array(32).fill(42)) // Consistent PRF salt
          }
        }
      }
    };

    const credential = await navigator.credentials.get({
      publicKey: authOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn authentication failed or was cancelled');
    }

    // Get PRF output for VRF decryption
    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    if (!prfOutput) {
      throw new Error('PRF output not available - required for VRF keypair decryption');
    }

    console.log('✅ WebAuthn authentication successful, PRF output obtained');

    // Step 4: Unlock VRF keypair in Service Worker memory
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'verifying-server',
        message: 'Unlocking VRF keypair in secure memory...'
      }
    });

    console.log('Unlocking VRF keypair in Service Worker memory');

    const unlockResult = await vrfManager.unlockVRFKeypair(
      nearAccountId,
      vrfCredentials,
      prfOutput
    );

    if (!unlockResult.success) {
      throw new Error(`Failed to unlock VRF keypair: ${unlockResult.error}`);
    }

    console.log('✅ VRF keypair unlocked in Service Worker memory');
    console.log('VRF session active - challenge generation available without additional TouchID');

    // Step 5: Update local data and return success
    const localUserData = await passkeyManager.getWebAuthnManager().getUserData(nearAccountId);

    // Update IndexDBManager with login
    let clientUser = await indexDBManager.getUser(nearAccountId);
    if (!clientUser) {
      console.log(`Creating IndexDBManager entry for existing user: ${nearAccountId}`);
      clientUser = await indexDBManager.registerUser(nearAccountId);
    } else {
      await indexDBManager.updateLastLogin(nearAccountId);
    }

    const result: LoginResult = {
      success: true,
      loggedInNearAccountId: nearAccountId,
      clientNearPublicKey: localUserData?.clientNearPublicKey || null,
      nearAccountId: nearAccountId
    };

    if (localUserData?.clientNearPublicKey) {
      console.log(`VRF login successful for ${nearAccountId}. Client-managed PK: ${localUserData.clientNearPublicKey}`);
    } else {
      console.warn(`User ${nearAccountId} logged in via VRF mode, but no clientNearPublicKey found in local storage.`);
    }

    onEvent?.({
      type: 'loginCompleted',
      data: {
        nearAccountId: nearAccountId,
        publicKey: localUserData?.clientNearPublicKey || ''
      }
    });
    await indexDBManager.updateLastLogin(nearAccountId);

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    console.error('VRF login error:', error);
    onError?.(error);
    onEvent?.({ type: 'loginFailed', data: { error: error.message, nearAccountId } });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}
