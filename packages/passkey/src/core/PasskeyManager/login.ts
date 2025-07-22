import type {
  LoginOptions,
  LoginResult,
  LoginState,
  LoginEvent,
} from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import type { AccountId, AccountIdDeviceSpecific } from '../types/accountIds';
import { toDeviceSpecificAccountId } from '../types/accountIds';

/**
 * Core login function that handles passkey authentication without React dependencies
 */
export async function loginPasskey(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options?: LoginOptions
): Promise<LoginResult> {

  const { onEvent, onError, hooks } = options || {};
  // Emit started event
  onEvent?.({
    step: 1,
    phase: 'preparation',
    status: 'progress',
    timestamp: Date.now(),
    message: `Starting login for ${nearAccountId}`
  });

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validation
    if (!window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      const error = new Error(errorMessage);
      onError?.(error);
      onEvent?.({
        step: 0,
        phase: 'login-error',
        status: 'error',
        timestamp: Date.now(),
        message: errorMessage,
        error: errorMessage
      });
      hooks?.afterCall?.(false, error);
      return { success: false, error: errorMessage };
    }

    // Handle login and unlock VRF keypair in VRF WASM worker for WebAuthn challenge generation
    return await handleLoginUnlockVRF(
      context,
      nearAccountId,
      onEvent,
      onError,
      hooks
    );

  } catch (err: any) {
    onError?.(err);
    onEvent?.({
      step: 0,
      phase: 'login-error',
      status: 'error',
      timestamp: Date.now(),
      message: err.message,
      error: err.message
    });
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
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  onEvent?: (event: LoginEvent) => void,
  onError?: (error: Error) => void,
  hooks?: { beforeCall?: () => void | Promise<void>; afterCall?: (success: boolean, result?: any) => void | Promise<void> }
): Promise<LoginResult> {

  const { webAuthnManager, nearClient, configs } = context;

  try {

    // Step 1: Get VRF credentials and authenticators, and validate them
    const {
      userData,
      authenticators
    } = await Promise.all([
      webAuthnManager.getUser(nearAccountId),
      webAuthnManager.getAuthenticatorsByUser(nearAccountId),
    ]).then(([userData, authenticators]) => {
      // Validate user data and authenticators
      if (!userData) {
        throw new Error(`User data not found for ${nearAccountId} in IndexedDB. Please register an account.`);
      }
      if (!userData.clientNearPublicKey) {
        throw new Error(`No NEAR public key found for ${nearAccountId}. Please register an account.`);
      }
      if (
        !userData.encryptedVrfKeypair?.encrypted_vrf_data_b64u ||
        !userData.encryptedVrfKeypair?.aes_gcm_nonce_b64u
      ) {
        throw new Error('No VRF credentials found. Please register an account.');
      }
      if (authenticators.length === 0) {
        throw new Error(`No authenticators found for account ${nearAccountId}. Please register.`);
      }
      return { userData, authenticators };
    });

    // Step 2: Perform initial WebAuthn authentication to get PRF output for VRF decryption
    onEvent?.({
      step: 2,
      phase: 'webauthn-assertion',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Authenticating to unlock VRF keypair...'
    });

    // Get credential for VRF unlock
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = await webAuthnManager.touchIdPrompt.getCredentials({
      nearAccountId,
      challenge,
      authenticators,
    });

    const unlockResult = await webAuthnManager.unlockVRFKeypair({
      nearAccountId: nearAccountId,
      encryptedVrfKeypair: userData.encryptedVrfKeypair!, // non-null assertion; validated above
      credential: credential, // Use the credential instead of authenticators
    });

    if (!unlockResult.success) {
      throw new Error(`Failed to unlock VRF keypair: ${unlockResult.error}`);
    }

    onEvent?.({
      step: 3,
      phase: 'vrf-unlock',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF keypair unlocked successfully'
    });

    // Step 3: Update local data and return success
    await webAuthnManager.updateLastLogin(nearAccountId);

    const result: LoginResult = {
      success: true,
      loggedInNearAccountId: nearAccountId,
      clientNearPublicKey: userData?.clientNearPublicKey!, // non-null, validated above
      nearAccountId: nearAccountId
    };

    onEvent?.({
      step: 4,
      phase: 'login-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'Login completed successfully',
      nearAccountId: nearAccountId,
      clientNearPublicKey: userData?.clientNearPublicKey || ''
    });

    hooks?.afterCall?.(true, result);
    return result;

  } catch (error: any) {
    onError?.(error);
    onEvent?.({
      step: 0,
      phase: 'login-error',
      status: 'error',
      timestamp: Date.now(),
      message: error.message,
      error: error.message
    });
    hooks?.afterCall?.(false, error);
    return { success: false, error: error.message };
  }
}

export async function getLoginState(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId
): Promise<LoginState> {
  const { webAuthnManager } = context;
  try {
    // Determine target account ID
    let targetAccountId = nearAccountId;
    if (!targetAccountId) {
      const lastUsedAccountId = await webAuthnManager.getLastUsedNearAccountId() || undefined;
      targetAccountId = lastUsedAccountId?.nearAccountId || undefined;
    }
    if (!targetAccountId) {
      return {
        isLoggedIn: false,
        nearAccountId: null,
        publicKey: null,
        vrfActive: false,
        userData: null
      };
    }

    // Get comprehensive user data from IndexedDB (single call instead of two)
    const userData = await webAuthnManager.getUser(targetAccountId);
    const publicKey = userData?.clientNearPublicKey || null;

    // Check actual VRF worker status
    const vrfStatus = await webAuthnManager.checkVrfStatus();
    const vrfActive = vrfStatus.active && vrfStatus.nearAccountId === targetAccountId;

    // Determine if user is considered "logged in"
    // User is logged in if they have user data and VRF is active
    const isLoggedIn = !!(userData && userData.clientNearPublicKey && vrfActive);

    return {
      isLoggedIn,
      nearAccountId: targetAccountId,
      publicKey,
      vrfActive,
      userData,
      vrfSessionDuration: vrfStatus.sessionDuration || 0
    };

  } catch (error: any) {
    console.warn('Error getting login state:', error);
    return {
      isLoggedIn: false,
      nearAccountId: nearAccountId || null,
      publicKey: null,
      vrfActive: false,
      userData: null
    };
  }
}

export async function getRecentLogins(
  context: PasskeyManagerContext
): Promise<{
  accountIds: string[],
  lastUsedAccountId: {
    nearAccountId: AccountId,
    deviceNumber: number,
    accountIdDeviceSpecific: AccountIdDeviceSpecific
  } | null
}> {
  const { webAuthnManager } = context;
  // Get all user accounts from IndexDB
  const allUsersData = await webAuthnManager.getAllUserData();
  const accountIds = allUsersData.map(user => user.nearAccountId);
  // Get last used account for initial state
  const lastUsedAccountId = await webAuthnManager.getLastUsedNearAccountId();

  return {
    accountIds,
    lastUsedAccountId,
  }
}

export async function logoutAndClearVrfSession(context: PasskeyManagerContext): Promise<void> {
  const { webAuthnManager } = context;
  await webAuthnManager.clearVrfSession();
}