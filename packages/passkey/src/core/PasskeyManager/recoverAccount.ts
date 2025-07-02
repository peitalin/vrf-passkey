import type { NearClient } from '../NearClient';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';

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

export async function recoverAccount(
  context: PasskeyManagerContext,
  accountId: string,
  method: 'accountId' | 'passkeySelection' = 'accountId',
  options?: ActionOptions
): Promise<RecoveryResult> {
  if (method === 'accountId') {
    return recoverAccountWithAccountId(context, accountId, options);
  } else if (method === 'passkeySelection') {
    return recoverAccountWithPasskeySelection(context, options);
  } else {
    throw new Error(`Invalid recovery method, must be either "accountId" or "passkeySelection", received ${method}`);
  }
}

/**
 * Recover account by providing the NEAR account ID
 * Derives DD-keypair from current passkey and verifies account ownership
 */
export async function recoverAccountWithAccountId(
  context: PasskeyManagerContext,
  accountId: string,
  options?: ActionOptions
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

    // Step 1: Get latest NEAR block for VRF input construction
    console.log('Registration Step 1: Get NEAR block data');
    const {
      blockHeight,
      blockHashBytes,
    } = await nearClient.viewBlock({ finality: 'final' }).then(blockInfo => {
      return {
        blockHeight: blockInfo.header.height,
        blockHashBytes: new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'))
      };
    });

    // Step 2: Generate bootstrap VRF keypair + challenge for registration
    console.log('Registration Step 2: Generating VRF keypair + challenge for registration');
    const vrfChallenge = await generateBootstrapVrfChallenge(
      webAuthnManager,
      accountId,
      blockHeight,
      blockHashBytes,
    );

    // Step 3: Use VRF output as WebAuthn challenge
    console.log('Registration Step 3: Use VRF output as WebAuthn challenge');
    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    const credential = await webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
      nearAccountId: accountId,
      challenge: vrfChallengeBytes,
    });

    // Note: Any registration credential from the same passkey will work
    // The deterministic derivation extracts the same COSE P-256 coordinates regardless of challenge
    const ddKeypair = await webAuthnManager.recoverKeypairFromPasskey(
      vrfChallengeBytes,
      credential
    );
    console.log('DD-keypair derived from current passkey');

    // 2. Verify account ownership
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying account ownership...'
    });

    const hasAccess = await nearClient.viewAccessKey(accountId, ddKeypair.publicKey);
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

    const recoveryResult = await performAccountRecovery(
      context,
      accountId,
      ddKeypair.publicKey,
      vrfChallenge.vrfPublicKey
    );

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
 * Recover account by selecting from available passkeys
 * Enumerates passkeys and finds accounts controlled by each
 */
export async function recoverAccountWithPasskeySelection(
  context: PasskeyManagerContext,
  options?: ActionOptions
): Promise<RecoveryResult> {

  const { onEvent, onError, hooks } = options || {};
  const { webAuthnManager, nearClient } = context;

  // Run beforeCall hook
  await hooks?.beforeCall?.();

  // Emit started event
  onEvent?.({
    step: 1,
    phase: 'preparation',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Starting passkey-based account recovery'
  });

  try {
    // 1. Enumerate available passkeys
    onEvent?.({
      step: 2,
      phase: 'authentication',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Enumerating available passkeys...'
    });

    // This would require WebAuthn credential enumeration
    // For now, use placeholder implementation
    console.log('Passkey enumeration not yet implemented');

    // Placeholder: In practice, this would iterate through credentials
    const accountOptions: AccountLookupResult[] = [];

    if (accountOptions.length === 0) {
      throw new Error('No recoverable accounts found for available passkeys');
    }

    // 3. Present account selection UI (would be handled by the caller)
    // For now, select the first available account
    const selectedAccount = accountOptions[0];
    const accountId = selectedAccount.accountId;

    // 4. Perform recovery for selected account
    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      timestamp: Date.now(),
      message: `Recovering account: ${selectedAccount.accountId}...`
    });


    // Step 1: Get latest NEAR block for VRF input construction
    console.log('Registration Step 1: Get NEAR block data');
    const {
      blockHeight,
      blockHashBytes,
    } = await nearClient.viewBlock({ finality: 'final' }).then(blockInfo => {
      return {
        blockHeight: blockInfo.header.height,
        blockHashBytes: new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'))
      };
    });

    // Step 2: Generate bootstrap VRF keypair + challenge for registration
    console.log('Registration Step 2: Generating VRF keypair + challenge for registration');
    const vrfChallenge = await generateBootstrapVrfChallenge(
      webAuthnManager,
      accountId,
      blockHeight,
      blockHashBytes,
    );

    // Step 3: Use VRF output as WebAuthn challenge
    console.log('Registration Step 3: Use VRF output as WebAuthn challenge');
    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    const credential = await webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
      nearAccountId: accountId,
      challenge: vrfChallengeBytes,
    });

    // Note: Any registration credential from the same passkey will work
    // The deterministic derivation extracts the same COSE P-256 coordinates regardless of challenge
    const ddKeypair = await webAuthnManager.recoverKeypairFromPasskey(
      vrfChallengeBytes,
      credential
    );
    console.log('DD-keypair derived from current passkey');


    // 2. For each credential, derive keypair and lookup account
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Looking up accounts for available passkeys...'
    });

    const recoveryResult = await performAccountRecovery(
      context,
      selectedAccount.accountId,
      selectedAccount.publicKey,
      selectedAccount.publicKey, // TODO: Get VRF public key from contract
    );

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
    console.error('[recoverByPasskeySelection] Error:', error);
    onError?.(error);

    onEvent?.({
      step: 0,
      phase: 'action-error',
      status: 'error',
      timestamp: Date.now(),
      message: `Passkey recovery failed: ${error.message}`,
      error: error.message
    });

    const errorResult: RecoveryResult = {
      success: false,
      accountId: '',
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
async function performAccountRecovery(
  context: PasskeyManagerContext,
  accountId: string,
  publicKey: string,
  vrfPublicKey: string
): Promise<RecoveryResult> {

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
      });
      console.log(`Registered user ${accountId} in IndexedDB`);
    } else {
      // Update existing user data
      await webAuthnManager.storeUserData({
        nearAccountId: accountId,
        clientNearPublicKey: publicKey,
        lastUpdated: Date.now(),
        prfSupported: existingUser.prfSupported ?? true,
        deterministicKey: true,
        passkeyCredential: existingUser.passkeyCredential,
        encryptedVrfKeypair: existingUser.encryptedVrfKeypair
      });
      console.log(`Updated user ${accountId} in IndexedDB`);
    }

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
        clientNearPublicKey: publicKey,
        name: `Recovered Authenticator`,
        registered: authenticator.registered,
        syncedAt: new Date().toISOString()
      });

      console.log(`Restored authenticator ${credentialId} for ${accountId}`);
    }

    // 4. Generate new VRF keypair and add to authenticator (FIFO queue)
    console.log('Generating new VRF keypair for recovery...');

    if (contractAuthenticators.length > 0) {
                  // Generate a new VRF keypair for this recovery session
      const { blockHeight, blockHashBytes } = await nearClient.viewBlock({ finality: 'final' }).then(blockInfo => {
        return {
          blockHeight: blockInfo.header.height,
          blockHashBytes: Array.from(Buffer.from(blockInfo.header.hash, 'base64'))
        };
      });

      const vrfKeypair = await webAuthnManager.generateVrfKeypair(false, {
        userId: accountId,
        rpId: configs.contractId.split('.')[configs.contractId.split('.').length - 1], // Extract domain from contract ID
        blockHeight,
        blockHashBytes,
        timestamp: Date.now()
      });

      // Add the new VRF public key to the first authenticator on-chain
      // (FIFO queue with max 5 keys, oldest will be removed if needed)
      const firstAuthenticator = contractAuthenticators[0];

      // TODO: Add VRF public key to authenticator on-chain using contract call
      // This requires implementing the contract mutation call method in NearClient
      // For now, VRF keypair is generated and can be used locally
      console.log(`Generated new VRF public key for recovery: ${vrfKeypair.vrfPublicKey.substring(0, 20)}...`);

      // TODO: Implement contract call when NearClient supports mutations:
      // await nearClient.callContract({
      //   contractId: configs.contractId,
      //   method: 'add_vrf_key_to_authenticator',
      //   args: {
      //     user_id: accountId,
      //     credential_id: firstAuthenticator.credentialId,
      //     new_vrf_key: Array.from(Buffer.from(vrfKeypair.vrfPublicKey, 'base64'))
      //   }
      // });
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
