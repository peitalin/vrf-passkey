import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import type { VRFChallenge } from '../types';
import type { EncryptedVRFKeypair } from '../types/vrf-worker';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';
import { base58Decode } from '../../utils/encoders';
import { NearClient } from '../NearClient';

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
      console.debug('AccountRecoveryFlow: Discovering available accounts...');

      // Get full options with credentials, requires TouchID prompt
      this.availableAccounts = await getRecoverableAccounts(this.context, accountId);

      if (this.availableAccounts.length === 0) {
        // throw new Error('No recoverable accounts found for this passkey');
        console.warn('No recoverable accounts found for this passkey');
        console.warn(`Continuing with account recovery for ${accountId}`);
      } else {
        console.debug(`AccountRecoveryFlow: Found ${this.availableAccounts.length} recoverable accounts`);
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
      console.debug(`AccountRecoveryFlow: Recovering account: ${selection.accountId}`);

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
      console.debug('AccountRecoveryFlow: Recovery completed successfully');
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
 * Get available passkeys for account recovery
 */
async function getRecoverableAccounts(
  context: PasskeyManagerContext,
  accountId: string
): Promise<PasskeyOption[]> {
  const vrfChallenge = await generateBootstrapVrfChallenge(context, accountId);
  const availablePasskeys = await getAvailablePasskeysForDomain(context, vrfChallenge, accountId);
  return availablePasskeys.filter(passkey => passkey.accountId !== null);
}

/**
 * Discover passkeys for domain using contract-based lookup
 */
async function getAvailablePasskeysForDomain(
  context: PasskeyManagerContext,
  vrfChallenge: VRFChallenge,
  accountId: string
): Promise<PasskeyOption[]> {
  const { webAuthnManager, nearClient, configs } = context;

  const credentialIds = await getCredentialIdsFromContract(nearClient, configs.contractId, accountId);

  // Always try to authenticate with the provided account ID, even if no credentials found in contract
  try {
  const credential = await webAuthnManager.touchIdPrompt.getCredentialsForRecovery({
    nearAccountId: accountId,
    challenge: vrfChallenge.outputAs32Bytes(),
      credentialIds: credentialIds.length > 0 ? credentialIds : [], // Empty array if no contract credentials
    });

    if (credential) {
  return [{
    credentialId: credential.id,
    accountId: accountId,
    publicKey: '',
    displayName: `${accountId} (Authenticated with this passkey)`,
    credential: credential
      }];
    }
  } catch (error) {
    console.warn('Failed to authenticate with passkey:', error);
  }

  // If authentication failed, still return the account option but without credential
  return [{
    credentialId: 'manual-input',
    accountId: accountId, // Use the provided accountId instead of null
    publicKey: '',
    displayName: `${accountId} (Authentication failed - please try again)`,
    credential: null,
  }];
}

/**
 * Get credential IDs from contract
 */
async function getCredentialIdsFromContract(nearClient: NearClient, contractId: string, accountId: string): Promise<string[]> {
  try {
    const credentialIds = await nearClient.callFunction<string[]>(
      contractId,
      'get_credential_ids_by_account',
      { account_id: accountId }
    );
    return credentialIds || [];
  } catch (error: any) {
    console.warn('Failed to fetch credential IDs from contract:', error.message);
    return [];
  }
}

/**
 * Main account recovery function
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
    const validation = validateNearAccountId(accountId);
    if (!validation.valid) {
      return handleRecoveryError(accountId, `Invalid NEAR account ID: ${validation.error}`, onError, hooks);
    }

    const credential = await getOrCreateCredential(webAuthnManager, accountId, reuseCredential);
    const recoveredKeypair = await deriveKeypairFromCredential(webAuthnManager, credential, accountId);

    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying account ownership...'
    });

    const { hasAccess, blockHeight, blockHashBytes } = await Promise.all([
      nearClient.viewAccessKey(accountId, recoveredKeypair.publicKey),
      nearClient.viewBlock({ finality: 'final' })
    ]).then(([hasAccess, blockInfo]) => {
      return {
        hasAccess,
        blockHeight: blockInfo.header.height,
        blockHashBytes: Array.from(base58Decode(blockInfo.header.hash)),
      };
    });

    if (!hasAccess) {
      return handleRecoveryError(accountId, `Account ${accountId} was not created with this passkey`, onError, hooks);
    }
    const vrfInputParams = {
      userId: accountId,
      rpId: window.location.hostname,
      blockHeight,
      blockHashBytes,
      timestamp: Date.now()
    };
    const { encryptedVrfResult, vrfChallenge } = await deriveVrfKeypair(
      webAuthnManager,
      credential,
      accountId,
      vrfInputParams
    );

    await generateNearKeypair(webAuthnManager, credential, accountId);

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
    return handleRecoveryError(accountId, error.message, onError, hooks);
  }
}

/**
 * Get credential (reuse existing or create new)
 */
async function getOrCreateCredential(
  webAuthnManager: any,
  accountId: string,
  reuseCredential?: PublicKeyCredential
): Promise<PublicKeyCredential> {
  if (reuseCredential) {
    const prfResults = reuseCredential.getClientExtensionResults()?.prf?.results;
    if (!prfResults?.first || !prfResults?.second) {
      throw new Error('Reused credential missing PRF outputs - cannot proceed with recovery');
    }
    return reuseCredential;
  }

  const randomChallenge = crypto.getRandomValues(new Uint8Array(32));
  return await webAuthnManager.touchIdPrompt.getCredentialsForRecovery({
    nearAccountId: accountId,
    challenge: randomChallenge,
    credentialIds: []
  });
}

/**
 * Derive keypair from credential
 */
async function deriveKeypairFromCredential(webAuthnManager: any, credential: PublicKeyCredential, accountId: string) {
  return await webAuthnManager.recoverKeypairFromPasskey(
    crypto.getRandomValues(new Uint8Array(32)),
    credential,
    accountId
  );
}

/**
 * Derive VRF keypair and generate challenge
 */
async function deriveVrfKeypair(webAuthnManager: any, credential: PublicKeyCredential, accountId: string, vrfInputParams: any) {
  const deterministicVrfResult = await webAuthnManager.deriveVrfKeypairFromPrf({
    credential,
    nearAccountId: accountId,
    vrfInputParams
  });

  if (
    !deterministicVrfResult.success ||
    !deterministicVrfResult.vrfPublicKey ||
    !deterministicVrfResult.vrfChallenge ||
    !deterministicVrfResult.encryptedVrfKeypair
  ) {
    throw new Error('Failed to derive deterministic VRF keypair and generate challenge from PRF');
  }

  return {
    encryptedVrfResult: {
      vrfPublicKey: deterministicVrfResult.vrfPublicKey,
      encryptedVrfKeypair: deterministicVrfResult.encryptedVrfKeypair
    },
    vrfChallenge: deterministicVrfResult.vrfChallenge
  };
}

/**
 * Generate and encrypt NEAR keypair
 */
async function generateNearKeypair(webAuthnManager: any, credential: PublicKeyCredential, accountId: string) {
  const keyGenResult = await webAuthnManager.deriveNearKeypairAndEncrypt({
    credential,
    nearAccountId: accountId
  });

  if (!keyGenResult.success || !keyGenResult.publicKey) {
    throw new Error('Failed to generate NEAR keypair with PRF');
  }

  return keyGenResult;
}

/**
 * Handle recovery error
 */
function handleRecoveryError(accountId: string, errorMessage: string, onError: any, hooks: any): RecoveryResult {
  console.error('[recoverAccount] Error:', errorMessage);
  onError?.(new Error(errorMessage));

  const errorResult: RecoveryResult = {
    success: false,
    accountId,
    publicKey: '',
    message: `Recovery failed: ${errorMessage}`,
    error: errorMessage
  };

  hooks?.afterCall?.(false, new Error(errorMessage));
  return errorResult;
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
    console.debug(`Performing recovery for account: ${accountId}`);

    // 1. Sync on-chain authenticator data
    const contractAuthenticators = await syncContractAuthenticators(nearClient, configs.contractId, accountId);

    // 2. Restore user data to IndexedDB
    await restoreUserData(webAuthnManager, accountId, publicKey, encryptedVrfResult.encryptedVrfKeypair);

    // 3. Restore authenticator data to IndexedDB
    await restoreAuthenticators(webAuthnManager, accountId, contractAuthenticators, vrfChallenge.vrfPublicKey);

    // 4. Unlock VRF keypair in memory for immediate login
    const vrfUnlockResult = await webAuthnManager.unlockVRFKeypair({
      nearAccountId: accountId,
      encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
      credential,
    });

    if (!vrfUnlockResult.success) {
      console.warn('VRF keypair unlock failed during recovery');
    }

    // 5. Update last login timestamp and get final login state
    await webAuthnManager.updateLastLogin(accountId);
    const loginState = await getRecoveryLoginState(webAuthnManager, accountId);

    console.debug(`Account recovery completed for ${accountId}`, {
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

    // Fix transport processing: filter out undefined values and provide fallback
    const rawTransports = authenticator.transports?.map((t: any) => t.transport) || [];
    const validTransports = rawTransports.filter((transport: any) =>
      transport !== undefined && transport !== null && typeof transport === 'string'
    );

    // If no valid transports, default to 'internal' for platform authenticators
    const transports = validTransports.length > 0 ? validTransports : ['internal'];

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

async function getRecoveryLoginState(webAuthnManager: any, accountId: string) {
  const loginState = await webAuthnManager.checkVrfStatus();
  const isVrfActive = loginState.active && loginState.nearAccountId === accountId;
  return {
    isLoggedIn: isVrfActive,
    vrfActive: isVrfActive,
    vrfSessionDuration: loginState.sessionDuration
  };
}

