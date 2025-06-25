import type { PasskeyManager } from '../PasskeyManager';
import type {
  LoginOptions,
  LoginResult,
  LoginEvent,
} from '../types/passkeyManager';

/**
 * Core login function that handles passkey authentication without React dependencies
 */
export async function loginPasskey(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  options?: LoginOptions
): Promise<LoginResult> {

  const { onEvent, onError, hooks } = options || {};

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

    console.log('⚡ Login: VRF login with WASM worker contract calls');
    // Handle login and unlock VRF keypair in VRF WASM worker for WebAuthn challenge generation
    return await handleLoginUnlockVRF(
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
 * VRF AUTHENTICATION FLOW:
 * 1. Unlock VRF keypair in Service Worker memory using PRF
 *      - Check if user has VRF credentials stored locally
 *      - Decrypt VRF keypair using PRF from WebAuthn ceremony
 * 2. Generate VRF challenge using stored VRF keypair + NEAR block data (no TouchID needed)
 * 3. Use VRF output as WebAuthn challenge for authentication
 * 4. Verify VRF proof and WebAuthn response on contract simultaneously
 *      - VRF proof assures WebAuthn challenge is fresh and valid (replay protection)
 *      - WebAuthn verification for origin + biometric credentials + device authenticity
 *
 * BENEFITS OF VRF FLOW:
 * - Single WebAuthn authentication to unlock VRF keys to generate WebAuthn challenges
 *   - VRF keypair persists in-memory in VRF Worker until logout
 *   - Subsequent authentications can generate VRF challenges without additional TouchID
 * - Provides cryptographically verifiable, stateless authentication
 * - Uses NEAR block data for freshness guarantees
 * - Follows RFC-compliant VRF challenge construction
 * - Eliminates server-side session state
 */
async function handleLoginUnlockVRF(
  passkeyManager: PasskeyManager,
  nearAccountId: string,
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  hooks?: { beforeCall?: () => void | Promise<void>; afterCall?: (success: boolean, result?: any) => void | Promise<void> }
): Promise<LoginResult> {
  try {

    const webAuthnManager = passkeyManager.getWebAuthnManager();
    const vrfManager = passkeyManager.getVRFManager();

    // Step 1: Get VRF credentials and authenticators, and validate them
    const { userData, authenticators } = await Promise.all([
      // fetch user data
      webAuthnManager.getUser(nearAccountId),
      // fetch authenticators
      webAuthnManager.getAuthenticatorsByUser(nearAccountId),
      // check if VRF manager is ready
      vrfManager.isReady(),
    ]).then(([userData, authenticators, isVRFReady]) => {
      // Validate user data and authenticators
      if (!userData) {
        throw new Error(`User data not found for ${nearAccountId} in IndexedDB. Please register an account first.`);
      }
      if (!userData.clientNearPublicKey) {
        throw new Error(`No NEAR public key found for ${nearAccountId}. Please register an account first.`);
      }
      if (
        !userData.vrfCredentials?.encrypted_vrf_data_b64u ||
        !userData.vrfCredentials?.aes_gcm_nonce_b64u
      ) {
        throw new Error('No VRF credentials found. Please register an account first.');
      }
      if (authenticators.length === 0) {
        throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
      }
      if (!isVRFReady) {
        console.warn('VRF Worker not ready yet - VRF initialization may still be in progress');
      }
      return { userData, authenticators };
    });

    // Step 2: Perform initial WebAuthn authentication to get PRF output for VRF decryption
    onEvent?.({
      type: 'loginProgress',
      data: {
        step: 'webauthn-assertion',
        message: 'Authenticating to unlock VRF keypair...'
      }
    });

    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const {
      credential: _credential,
      prfOutput
    } = await webAuthnManager.touchIdPrompt.getCredentialsAndPrf({
      nearAccountId,
      challenge,
      authenticators,
    });

    // Step 3: Unlock VRF keypair in VRF Worker memory
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
      userData.vrfCredentials!, // non-null assertion; validated above
      prfOutput
    );

    if (!unlockResult.success) {
      throw new Error(`Failed to unlock VRF keypair: ${unlockResult.error}`);
    }
    console.log('✅ VRF session active - VRF keypair unlocked in VRF Worker memory');
    // Step 4: Update local data and return success
    await webAuthnManager.updateLastLogin(nearAccountId);

    const result: LoginResult = {
      success: true,
      loggedInNearAccountId: nearAccountId,
      clientNearPublicKey: userData?.clientNearPublicKey!, // non-null, validated above
      nearAccountId: nearAccountId
    };

    onEvent?.({
      type: 'loginCompleted',
      data: {
        nearAccountId: nearAccountId,
        publicKey: userData?.clientNearPublicKey || ''
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
