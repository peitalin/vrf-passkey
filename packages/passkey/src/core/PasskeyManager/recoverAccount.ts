import type { NearClient } from '../NearClient';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import type { VRFChallenge } from '../types';
import type { EncryptedVRFKeypair } from '../types/vrf-worker';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';

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

    // Step 1: Generate bootstrap VRF keypair + challenge for registration
    console.log('Registration Step 1: Generating VRF keypair + challenge for registration');
    const vrfChallenge = await generateBootstrapVrfChallenge(context, accountId);

    // Step 2: Use VRF output as WebAuthn challenge
    console.log('Registration Step 3: Use VRF output as WebAuthn challenge');
    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    if (reuseCredential) {
      console.log('Reusing credential from passkey discovery (no additional TouchID prompt)');
    }
    // Reuse credential if provided (from passkey selection)
    const credential = await webAuthnManager.touchIdPrompt.getCredentialsForRecovery({
      nearAccountId: accountId,
      challenge: vrfChallengeBytes,
      credentialIds: [reuseCredential?.id || '']
    });

    // Note: Any registration credential from the same passkey will work
    // The PRF-based derivation produces the same Ed25519 keypair from the same PRF outputs
    const recoveredKeypair = await webAuthnManager.recoverKeypairFromPasskey(
      vrfChallengeBytes,
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

    console.log('Registration Steps 5-7: Encrypting VRF keypair, generating NEAR keypair with PRF, and checking registration');
    const { encryptedVrfResult, keyGenResult, canRegisterUserResult } = await Promise.all([
      webAuthnManager.encryptVrfKeypairWithCredentials({
        credential,
        vrfPublicKey: vrfChallenge.vrfPublicKey
      }),
      webAuthnManager.deriveNearKeypairAndEncrypt({
        credential,
        nearAccountId: accountId
      }),
      webAuthnManager.checkCanRegisterUser({
        contractId: webAuthnManager.configs.contractId,
        credential: credential,
        vrfChallenge: vrfChallenge,
        onEvent: (progress) => {
          console.debug(`Registration progress: ${progress.step} - ${progress.message}`);
          onEvent?.({
            step: 3,
            phase: 'contract-verification',
            status: 'progress',
            timestamp: Date.now(),
            message: `Checking registration: ${progress.message}`
          });
        },
      })
    ]).then(([encryptedVrfResult, keyGenResult, canRegisterUserResult]) => {
      if (!encryptedVrfResult.encryptedVrfKeypair || !encryptedVrfResult.vrfPublicKey) {
        throw new Error('Failed to encrypt VRF keypair');
      }
      if (!keyGenResult.success || !keyGenResult.publicKey) {
        throw new Error('Failed to generate NEAR keypair with PRF');
      }
      if (!canRegisterUserResult.verified) {
        throw new Error(`Web3Authn contract registration check failed: ${canRegisterUserResult.error}`);
      }
      return { encryptedVrfResult, keyGenResult, canRegisterUserResult };
    });

    console.log(`Account ownership verified for ${accountId}`);

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

    // 1. Sync on-chain authenticator data from web3authn contract
    console.log('Syncing on-chain authenticator data...');

    let contractAuthenticators: Array<{
      credentialId: string;
      authenticator: {
        credential_public_key: number[];
        transports?: { transport: string }[];
        registered: string;
        vrf_public_keys: number[][];
      };
    }> = [];

    try {
      // Query web3authn contract for stored authenticator data
      const authenticatorsResult = await nearClient.view({
        account: configs.contractId,
        method: 'get_authenticators_by_user',
        args: { user_id: accountId }
      });

      if (authenticatorsResult && Array.isArray(authenticatorsResult)) {
        contractAuthenticators = authenticatorsResult.map(([credentialId, authenticator]: [string, any]) => ({
          credentialId,
          authenticator
        }));
        console.log(`Found ${contractAuthenticators.length} authenticators on-chain for ${accountId}`);
      }
    } catch (contractError: any) {
      console.warn('Failed to fetch authenticators from contract:', contractError.message);
      // Continue with recovery even if contract query fails
    }

    // 2. Restore local IndexedDB user data
    console.log('Restoring user data to IndexedDB...');

    const existingUser = await webAuthnManager.getUser(accountId);
    if (!existingUser) {
      // Register user if they don't exist locally
      await webAuthnManager.registerUser(accountId, {
        clientNearPublicKey: publicKey,
        prfSupported: true,
        lastUpdated: Date.now(),
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair, // Store the encrypted VRF keypair
      });
      console.log(`Registered user ${accountId} in IndexedDB with encrypted VRF keypair`);
    } else {
      // Update existing user data
      await webAuthnManager.storeUserData({
        nearAccountId: accountId,
        clientNearPublicKey: publicKey,
        lastUpdated: Date.now(),
        prfSupported: existingUser.prfSupported ?? true,
        deterministicKey: true,
        passkeyCredential: existingUser.passkeyCredential,
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair // Store the encrypted VRF keypair
      });
      console.log(`Updated user ${accountId} in IndexedDB with encrypted VRF keypair`);
    }

    // TODO: save recovered encrypted keypair to IndexedDB: in packages/passkey/src/core/IndexedDBManager/passkeyNearKeysDB.ts

    // 3. Restore authenticator data to IndexedDB
    console.log('Restoring authenticator data to IndexedDB...');

    for (const { credentialId, authenticator } of contractAuthenticators) {
      const credentialPublicKey = new Uint8Array(authenticator.credential_public_key);
      const transports = authenticator.transports?.map(t => t.transport) || [];

      await webAuthnManager.storeAuthenticator({
        nearAccountId: accountId,
        credentialId: credentialId,
        credentialPublicKey,
        transports,
        name: `Recovered Authenticator`,
        registered: authenticator.registered,
        syncedAt: new Date().toISOString(),
        vrfPublicKey: vrfChallenge.vrfPublicKey
      });

      console.log(`Restored authenticator ${credentialId} for ${accountId}`);
    }

    // 4. Add VRF public key to authenticator (FIFO queue)
    console.log('Adding VRF public key from encrypted keypair to authenticator...');

    if (contractAuthenticators.length > 0) {
      // Use the VRF public key from the encrypted result (same one that was generated during steps 5-7)
      const vrfPublicKeyToAdd = encryptedVrfResult.vrfPublicKey;

      // Add the VRF public key to the first authenticator on-chain
      // (FIFO queue with max 5 keys, oldest will be removed if needed)
      const firstAuthenticator = contractAuthenticators[0];

      try {
        console.log(`Adding VRF public key to authenticator: ${firstAuthenticator.credentialId}`);

        // Get transaction metadata
        const [accessKeyInfo, transactionBlockInfo] = await Promise.all([
          nearClient.viewAccessKey(accountId, publicKey),
          nearClient.viewBlock({ finality: 'final' })
        ]);

        if (!accessKeyInfo || accessKeyInfo.nonce === undefined) {
          throw new Error(`Access key not found for account ${accountId} with public key ${publicKey}`);
        }

        const nonce = BigInt(accessKeyInfo.nonce) + BigInt(1);
        const blockHashString = transactionBlockInfo.header.hash;
        const transactionBlockHashBytes = Array.from(Buffer.from(blockHashString, 'base64'));

        // Convert VRF public key from base64 string to Uint8Array
        const vrfPublicKeyBytes = Buffer.from(vrfPublicKeyToAdd, 'base64');

        // Add VRF key to contract
        const contractResult = await webAuthnManager.addVrfKeyToAuthenticator({
          nearAccountId: accountId,
          contractId: configs.contractId,
          credentialId: firstAuthenticator.credentialId,
          vrfPublicKey: vrfPublicKeyBytes,
          nonce: nonce.toString(),
          blockHashBytes: transactionBlockHashBytes,
          vrfChallenge: vrfChallenge,
          credential: credential,
          nearRpcUrl: configs.nearRpcUrl,
          onEvent: (progress) => {
            console.debug(`VRF key addition progress: ${progress.message}`);
          }
        });

        console.log(`VRF public key added successfully to ${firstAuthenticator.credentialId}`);
        console.log(`Transaction ID: ${contractResult.signedTransaction.base64Encode()}`);

      } catch (contractError: any) {
        console.warn(`Failed to add VRF key to contract: ${contractError.message}`);
        // Continue with recovery even if VRF key addition fails
        // The encrypted VRF keypair is still stored locally and can be used
      }

      console.log(`Added VRF public key from encrypted keypair: ${vrfPublicKeyToAdd.substring(0, 20)}...`);
    }

    // 5. Update last login timestamp
    await webAuthnManager.updateLastLogin(accountId);

    console.log(`Account recovery completed for ${accountId}`);

    return {
      success: true,
      accountId,
      publicKey,
      message: 'Account successfully recovered'
    };

  } catch (error: any) {
    console.error('[performAccountRecovery] Error:', error);
    throw new Error(`Recovery process failed: ${error.message}`);
  }
}

