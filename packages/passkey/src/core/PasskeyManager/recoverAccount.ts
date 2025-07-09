import type { NearClient } from '../NearClient';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import type { VRFChallenge } from '../types';
import type { EncryptedVRFKeypair } from '../types/vrf-worker';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';
import { base58Decode } from '../../utils/encoders';
import { base64UrlEncode } from '../../utils/encoders';

/**
 * Use case:
 * Suppose a user accidentally clears their browser's indexedDB, and deletes their:
 * - encrypted NEAR keypair
 * - encrypted VRF keypair
 * - webauthn authenticator
 * Provide a way for the user to recover their account from onchain authenticator information with their Passkey.
 */

export interface RecoveryResult {
  success: boolean;
  accountId: string;
  publicKey: string;
  message: string;
  error?: string;
  loginState?: {
    isLoggedIn: boolean;
    vrfActive: boolean;
    vrfSessionDuration?: number;
  };
}

export interface AccountLookupResult {
  accountId: string;
  publicKey: string;
  hasAccess: boolean;
}

export interface PasskeyOption {
  credentialId: string;
  accountId: string | null;
  publicKey: string;
  displayName: string;
  credential: PublicKeyCredential | null;
}

// Public-facing passkey option without sensitive credential data
export interface PasskeyOptionWithoutCredential {
  credentialId: string;
  accountId: string | null;
  publicKey: string;
  displayName: string;
}

// Internal selection identifier for secure credential lookup
export interface PasskeySelection {
  credentialId: string;
  accountId: string;
}

/**
 * Account recovery flow with credential encapsulation
 *
 * Usage:
 * ```typescript
 * const flow = new AccountRecoveryFlow(context);
 * const options = await flow.discover(); // Get safe display options
 * // ... user selects account in UI ...
 * const result = await flow.recover({ credentialId, accountId }); // Execute recovery
 * ```
 */
export class AccountRecoveryFlow {
  private context: PasskeyManagerContext;
  private options?: ActionOptions;
  private availableAccounts?: PasskeyOption[]; // Full options with credentials (private)
  private phase: 'idle' | 'discovering' | 'ready' | 'recovering' | 'complete' | 'error' = 'idle';
  private error?: Error;

  constructor(context: PasskeyManagerContext, options?: ActionOptions) {
    this.context = context;
    this.options = options;
  }

  /**
   * Phase 1: Discover available accounts
   * Returns safe display data without exposing credentials to UI
   */
  async discover(accountId: string): Promise<PasskeyOptionWithoutCredential[]> {
    try {
      this.phase = 'discovering';
      console.log('AccountRecoveryFlow: Discovering available accounts...');

      // Get full options with credentials, requires TouchID prompt
      this.availableAccounts = await getRecoverableAccounts(this.context, accountId);

      if (this.availableAccounts.length === 0) {
        // throw new Error('No recoverable accounts found for this passkey');
        console.warn('No recoverable accounts found for this passkey');
        console.warn(`Continuing with account recovery for ${accountId}`);
      } else {
        console.log(`AccountRecoveryFlow: Found ${this.availableAccounts.length} recoverable accounts`);
      }

      this.phase = 'ready';

      // Return safe options without credentials for UI display
      return this.availableAccounts.map(option => ({
        credentialId: option.credentialId,
        accountId: option.accountId,
        publicKey: option.publicKey,
        displayName: option.displayName
      }));

    } catch (error: any) {
      this.phase = 'error';
      this.error = error;
      console.error('AccountRecoveryFlow: Discovery failed:', error);
      throw error;
    }
  }

  /**
   * Phase 2: Execute recovery with user selection
   * Securely looks up credential based on selection
   */
  async recover(selection: PasskeySelection): Promise<RecoveryResult> {
    if (this.phase !== 'ready') {
      throw new Error(`Cannot recover - flow is in ${this.phase} phase. Call discover() first.`);
    }

    if (!this.availableAccounts) {
      throw new Error('No available accounts found. Call discover() first.');
    }

    try {
      this.phase = 'recovering';
      console.log(`AccountRecoveryFlow: Recovering account: ${selection.accountId}`);

      // Securely lookup the full option with credential
      const selectedOption = this.availableAccounts.find(
        option => option.credentialId === selection.credentialId &&
                 option.accountId === selection.accountId
      );

      if (!selectedOption) {
        throw new Error('Invalid selection - account not found in available options');
      }

      if (!selectedOption.accountId) {
        throw new Error('Invalid account selection - no account ID provided');
      }

      const recoveryResult = await recoverAccount(
        this.context,
        selectedOption.accountId,
        this.options,
        selectedOption.credential || undefined
      );

      this.phase = 'complete';
      console.log('AccountRecoveryFlow: Recovery completed successfully');
      return recoveryResult;

    } catch (error: any) {
      this.phase = 'error';
      this.error = error;
      console.error('AccountRecoveryFlow: Recovery failed:', error);
      throw error;
    }
  }

  /**
   * Get current flow state (safe display data only)
   */
  getState() {
    // Convert internal accounts to safe display format
    const safeAccounts = this.availableAccounts?.map(option => ({
      credentialId: option.credentialId,
      accountId: option.accountId,
      publicKey: option.publicKey,
      displayName: option.displayName
    }));

    return {
      phase: this.phase,
      availableAccounts: safeAccounts,
      error: this.error,
      isReady: this.phase === 'ready',
      isComplete: this.phase === 'complete',
      hasError: this.phase === 'error'
    };
  }

  /**
   * Reset flow to initial state
   */
  reset() {
    this.phase = 'idle';
    this.availableAccounts = undefined;
    this.error = undefined;
  }
}

/**
 * Public API: Get available passkeys for account recovery UI
 * Returns a list of passkeys/accounts that can be recovered
 */
async function getRecoverableAccounts(
  context: PasskeyManagerContext,
  accountId: string
): Promise<PasskeyOption[]> {
  try {
    const vrfChallenge = await generateBootstrapVrfChallenge(context, accountId);

    const availablePasskeys = await getAvailablePasskeysForDomain(context, vrfChallenge, accountId);
    // Filter to only return passkeys with known account IDs for recovery
    return availablePasskeys.filter(passkey => passkey.accountId !== null);
  } catch (error: any) {
    console.error('Error getting recoverable accounts:', error);
    return [];
  }
}

/**
 * Get available passkeys for the current domain and their associated accounts
 * Uses efficient contract-based discovery with single authentication ceremony
 */
async function getAvailablePasskeysForDomain(
  context: PasskeyManagerContext,
  vrfChallenge: VRFChallenge,
  accountId: string
): Promise<PasskeyOption[]> {
  const { webAuthnManager, nearClient, configs } = context;
  console.log('Discovering recoverable accounts for:', accountId);

  try {
    // Step 1: Get credential IDs for this account from contract
    console.log('Querying contract for credential IDs...');
    const credentialIds = await nearClient.view({
      account: configs.contractId,
      method: 'get_credential_ids_by_account',
      args: { account_id: accountId }
    });

    if (credentialIds.length === 0) {
      console.log('No credential IDs found for account:', accountId);
      return [{
        credentialId: 'manual-input',
        accountId: null,
        publicKey: '',
        displayName: 'No credentials found - manual account entry required',
        credential: null,
      }];
    }

    console.log(`Found ${credentialIds.length} credential IDs for ${accountId}:`, credentialIds);

    // Step 2: Single WebAuthn authentication ceremony with all credential IDs
    console.log('Starting WebAuthn authentication with available credentials...');
    const credential = await webAuthnManager.touchIdPrompt.getCredentialsForRecovery({
      nearAccountId: accountId,
      challenge: vrfChallenge.outputAs32Bytes(),
      credentialIds: credentialIds,
    });

    // Step 3: Determine which credential ID was used
    const usedCredentialId = credential.id;
    console.log(`✅ Authentication successful with credential: ${usedCredentialId}`);

    // Return the successful credential option
    return [{
      credentialId: usedCredentialId,
      accountId: accountId,
      publicKey: '', // Will be derived during actual recovery
      displayName: `${accountId} (Authenticated with this passkey)`,
      credential: credential // Store the successful credential for reuse
    }];

  } catch (error: any) {
    console.error('Error discovering passkey accounts:', error);

    // If WebAuthn authentication was cancelled or failed, still provide manual option
    if (error.message?.includes('cancelled') || error.message?.includes('NotAllowedError')) {
      console.log('WebAuthn authentication cancelled by user');
      return [{
        credentialId: 'manual-input',
        accountId: null,
        publicKey: '',
        displayName: 'Authentication cancelled - enter account ID manually',
        credential: null,
      }];
    }

    // For other errors, provide fallback
    return [{
      credentialId: 'manual-input',
      accountId: null,
      publicKey: '',
      displayName: 'Discovery failed - enter account ID manually',
      credential: null,
    }];
  }
}

/**
 * Main entry point for account recovery
 *
 * Recommended Flow:
 * 1. Frontend calls getRecoverableAccounts() to display available passkeys/accounts
 * 2. User selects an account from the UI
 * 3. Frontend calls this function with the selected accountId and optional reusable credential
 */
export async function recoverAccount(
  context: PasskeyManagerContext,
  accountId: string,
  options?: ActionOptions,
  reuseCredential?: PublicKeyCredential
): Promise<RecoveryResult> {

  const { onEvent, onError, hooks } = options || {};
  const { webAuthnManager, nearClient } = context;

  await hooks?.beforeCall?.();

  onEvent?.({
    step: 1,
    phase: 'preparation',
    status: 'progress',
    timestamp: Date.now(),
    message: `Starting account recovery for ${accountId}`
  });

  try {
    // Validate account ID
    const validation = validateNearAccountId(accountId);
    if (!validation.valid) {
      throw new Error(`Invalid NEAR account ID: ${validation.error}`);
    }

    // Step 1: Use simple random challenge for initial WebAuthn authentication (recovery approach)
    console.log('Recovery Step 1: Using random challenge for initial WebAuthn authentication');
    const randomChallenge = crypto.getRandomValues(new Uint8Array(32));

    if (reuseCredential) {
      console.log('Reusing credential from passkey discovery (no additional TouchID prompt)');
    }
    // Use random challenge for initial authentication to get PRF outputs
    const credential = await webAuthnManager.touchIdPrompt.getCredentialsForRecovery({
      nearAccountId: accountId,
      challenge: randomChallenge,
      credentialIds: [reuseCredential?.id || '']
    });

    // Note: Any registration credential from the same passkey will work
    // The PRF-based derivation produces the same Ed25519 keypair from the same PRF outputs
    const recoveredKeypair = await webAuthnManager.recoverKeypairFromPasskey(
      randomChallenge,
      credential,
      accountId
    );
    console.log('keypair derived from current passkey with encrypted private key for storage');

    // 2. Verify account ownership
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying account ownership...'
    });

    const hasAccess = await nearClient.viewAccessKey(accountId, recoveredKeypair.publicKey);
    if (!hasAccess) {
      throw new Error(`Account ${accountId} was not created with this passkey`);
    }

    console.log('Recovery Steps 2-4: Deriving deterministic VRF keypair with challenge and generating NEAR keypair with PRF');

    // Step 2: Get real NEAR block data for VRF challenge generation
    console.log('Fetching real NEAR block data for VRF challenge...');
    const blockInfo = await nearClient.viewBlock({ finality: 'final' });
    const blockHashBytes: number[] = Array.from(base58Decode(blockInfo.header.hash));

    const vrfInputParams = {
      userId: accountId,
      rpId: window.location.hostname,
      blockHeight: blockInfo.header.height,
      blockHashBytes: blockHashBytes,
      timestamp: Date.now()
    };

    // Step 3: Derive deterministic VRF keypair AND generate VRF challenge in one call
    const deterministicVrfResult = await webAuthnManager.deriveVrfKeypairFromPrf({
      credential,
      nearAccountId: accountId,
      vrfInputParams
    });

    if (!deterministicVrfResult.success || !deterministicVrfResult.vrfPublicKey || !deterministicVrfResult.vrfChallenge) {
      throw new Error('Failed to derive deterministic VRF keypair and generate challenge from PRF');
    }
    if (!deterministicVrfResult.encryptedVrfKeypair) {
      throw new Error('Failed to derive encrypted VRF keypair from PRF');
    }
    console.log('Deterministic VRF keypair and challenge generated successfully');
    // Use the encrypted VRF keypair returned from the VRF derivation
    const encryptedVrfResult = {
      vrfPublicKey: deterministicVrfResult.vrfPublicKey,
      encryptedVrfKeypair: deterministicVrfResult.encryptedVrfKeypair
    };
    const vrfChallenge = deterministicVrfResult.vrfChallenge;

    // Step 4: Generate NEAR keypair with PRF
    const keyGenResult = await webAuthnManager.deriveNearKeypairAndEncrypt({
      credential,
      nearAccountId: accountId
    });

    if (!keyGenResult.success || !keyGenResult.publicKey) {
      throw new Error('Failed to generate NEAR keypair with PRF');
    }
    console.log('NEAR keypair generated and encrypted successfully');

    // 3. Perform recovery
    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Restoring account data...'
    });

    const recoveryResult = await performAccountRecovery({
      context,
      accountId,
      publicKey: recoveredKeypair.publicKey,
      encryptedKeypair: {
        encryptedPrivateKey: recoveredKeypair.encryptedPrivateKey,
        iv: recoveredKeypair.iv,
      },
      vrfChallenge,
      credential,
      encryptedVrfResult,
    });

    onEvent?.({
      step: 6,
      phase: 'action-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account recovery completed successfully'
    });

    hooks?.afterCall?.(true, recoveryResult);
    return recoveryResult;

  } catch (error: any) {
    console.error('[recoverByAccountId] Error:', error);
    onError?.(error);

    onEvent?.({
      step: 0,
      phase: 'action-error',
      status: 'error',
      timestamp: Date.now(),
      message: `Account recovery failed: ${error.message}`,
      error: error.message
    });

    const errorResult: RecoveryResult = {
      success: false,
      accountId: accountId,
      publicKey: '',
      message: `Recovery failed: ${error.message}`,
      error: error.message
    };

    hooks?.afterCall?.(false, error);
    return errorResult;
  }
}

/**
 * Perform the actual recovery process
 * Syncs on-chain data and restores local IndexedDB data
 */
async function performAccountRecovery({
  context,
  accountId,
  publicKey,
  encryptedKeypair,
  vrfChallenge,
  credential,
  encryptedVrfResult,
}: {
  context: PasskeyManagerContext,
  accountId: string,
  publicKey: string,
  encryptedKeypair: {
    encryptedPrivateKey: string,
    iv: string
  },
  vrfChallenge: VRFChallenge,
  credential: PublicKeyCredential,
  encryptedVrfResult: { encryptedVrfKeypair: EncryptedVRFKeypair; vrfPublicKey: string },
}): Promise<RecoveryResult> {

  const { webAuthnManager, nearClient, configs } = context;

  try {
    console.log(`Performing recovery for account: ${accountId}`);

    // 1. Sync on-chain authenticator data
    const contractAuthenticators = await syncContractAuthenticators(nearClient, configs.contractId, accountId);

    // 2. Restore user data to IndexedDB
    await restoreUserData(webAuthnManager, accountId, publicKey, encryptedVrfResult.encryptedVrfKeypair);

    // 3. Restore authenticator data to IndexedDB
    await restoreAuthenticators(webAuthnManager, accountId, contractAuthenticators, vrfChallenge.vrfPublicKey);

    // 4. Unlock VRF keypair in memory for immediate login
    const vrfUnlockSuccess = await unlockVrfKeypair(webAuthnManager, accountId, encryptedVrfResult.encryptedVrfKeypair, credential);

    // 5. Update last login timestamp and get final login state
    await webAuthnManager.updateLastLogin(accountId);
    const loginState = await getRecoveryLoginState(webAuthnManager, accountId);

    console.log(`Account recovery completed for ${accountId}`, {
      vrfActive: loginState.vrfActive,
      isLoggedIn: loginState.isLoggedIn
    });

    return {
      success: true,
      accountId,
      publicKey,
      message: 'Account successfully recovered',
      loginState
    };

  } catch (error: any) {
    console.error('[performAccountRecovery] Error:', error);
    throw new Error(`Recovery process failed: ${error.message}`);
  }
}

// Helper functions for cleaner code organization

async function syncContractAuthenticators(nearClient: any, contractId: string, accountId: string) {
  try {
    const authenticatorsResult = await nearClient.view({
      account: contractId,
      method: 'get_authenticators_by_user',
      args: { user_id: accountId }
    });

    if (authenticatorsResult && Array.isArray(authenticatorsResult)) {
      return authenticatorsResult.map(([credentialId, authenticator]: [string, any]) => ({
        credentialId,
        authenticator
      }));
    }
    return [];
  } catch (error: any) {
    console.warn('Failed to fetch authenticators from contract:', error.message);
    return [];
  }
}

async function restoreUserData(webAuthnManager: any, accountId: string, publicKey: string, encryptedVrfKeypair: EncryptedVRFKeypair) {
  const existingUser = await webAuthnManager.getUser(accountId);

  if (!existingUser) {
    await webAuthnManager.registerUser(accountId, {
      clientNearPublicKey: publicKey,
      prfSupported: true,
      lastUpdated: Date.now(),
      encryptedVrfKeypair,
    });
  } else {
    await webAuthnManager.storeUserData({
      nearAccountId: accountId,
      clientNearPublicKey: publicKey,
      lastUpdated: Date.now(),
      prfSupported: existingUser.prfSupported ?? true,
      deterministicKey: true,
      passkeyCredential: existingUser.passkeyCredential,
      encryptedVrfKeypair
    });
  }
}

async function restoreAuthenticators(webAuthnManager: any, accountId: string, contractAuthenticators: any[], vrfPublicKey: string) {
  for (const { credentialId, authenticator } of contractAuthenticators) {
    const credentialPublicKey = new Uint8Array(authenticator.credential_public_key);
    const transports = authenticator.transports?.map((t: any) => t.transport) || [];

    await webAuthnManager.storeAuthenticator({
      nearAccountId: accountId,
      credentialId: credentialId,
      credentialPublicKey,
      transports,
      name: `Recovered Authenticator`,
      registered: authenticator.registered,
      syncedAt: new Date().toISOString(),
      vrfPublicKey
    });
  }
}

async function unlockVrfKeypair(webAuthnManager: any, accountId: string, encryptedVrfKeypair: EncryptedVRFKeypair, credential: PublicKeyCredential): Promise<boolean> {
  try {
    const unlockResult = await webAuthnManager.unlockVRFKeypair({
      nearAccountId: accountId,
      encryptedVrfKeypair,
      credential,
    });

    if (unlockResult.success) {
      console.log('✅ VRF keypair unlocked successfully during recovery');
      return true;
    }
    return false;
  } catch (error: any) {
    console.warn('VRF keypair unlock failed during recovery:', error.message);
    return false;
  }
}

async function getRecoveryLoginState(webAuthnManager: any, accountId: string) {
  const loginState = await webAuthnManager.checkVrfStatus();
  const isVrfActive = loginState.active && loginState.nearAccountId === accountId;

  return {
    isLoggedIn: isVrfActive,
    vrfActive: isVrfActive,
    vrfSessionDuration: loginState.sessionDuration
  };
}

