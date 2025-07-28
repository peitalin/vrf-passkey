import type { AccessKeyView } from '@near-js/types';
import type { NearClient, SignedTransaction } from '../NearClient';
import { MinimalNearClient } from '../NearClient';
import { validateNearAccountId } from '../../utils/validation';
import type {
  RegistrationOptions,
  RegistrationResult,
  RegistrationSSEEvent,
  OperationHooks,
} from '../types/passkeyManager';
import { createAccountAndRegisterWithRelayServer } from './faucets/createAccountRelayServer';
import { createAccountAndRegisterWithTestnetFaucet } from './faucets/createAccountTestnetFaucet';
import { WebAuthnManager } from '../WebAuthnManager';
import { VRFChallenge } from '../types/webauthn';
import type { PasskeyManagerContext } from './index';
import type { AccountId } from '../types/accountIds';
import { base64UrlEncode, base64Decode } from '../../utils/encoders';

/**
 * Core registration function that handles passkey registration
 *
 * VRF Registration Flow (Single VRF Keypair):
 * 1. Generate VRF keypair (ed25519) using crypto.randomUUID() + persist in worker memory
 * 2. Generate VRF proof + output using the VRF keypair
 *    - VRF input with domain separator + NEAR block height + hash
 * 3. Use VRF output as WebAuthn challenge in registration ceremony
 * 4. Derive AES key from WebAuthn PRF output and encrypt the SAME VRF keypair
 * 5. Store encrypted VRF keypair in IndexedDB
 * 6. Call contract verify_registration_response with VRF proof + WebAuthn registration payload
 * 7. Contract verifies VRF proof and WebAuthn registration (challenges match!)
 * 8. Contract stores VRF pubkey + authenticator credentials on-chain for
 *    future stateless authentication
 */
export async function registerPasskey(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options: RegistrationOptions
): Promise<RegistrationResult> {

  const { onEvent, onError, hooks, useRelayer } = options;
  const { webAuthnManager, configs } = context;

  // Track registration progress for rollback
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
    preSignedDeleteTransaction: null as SignedTransaction | null,
  };

  console.log('⚡ Registration: Passkey registration with VRF WebAuthn ceremony');
  // Emit started event
  onEvent?.({
    step: 1,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: `Starting registration for ${nearAccountId}`
  } as RegistrationSSEEvent);

  try {
    // Run beforeCall hook
    await hooks?.beforeCall?.();

    // Validate registration inputs
    await validateRegistrationInputs(context, nearAccountId, onEvent, onError);

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Account available - generating VRF credentials...'
    });

    // Step 1: Generate bootstrap VRF keypair + challenge for registration
    console.log('Registration Step 1: Generating VRF keypair + challenge for registration');
    const { vrfChallenge } = await Promise.all([
      validateRegistrationInputs(context, nearAccountId, onEvent, onError),
      generateBootstrapVrfChallenge(context, nearAccountId),
    ]).then(([_, vrfChallenge]) => ({ vrfChallenge }));

    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    // Step 2: WebAuthn registration ceremony with PRF (TouchID)
    console.log('Registration Step 2: WebAuthn registration ceremony with VRF challenge');

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Performing WebAuthn registration with VRF challenge...'
    });

    const credential = await webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
      nearAccountId: nearAccountId,
      challenge: vrfChallengeBytes,
    });

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'WebAuthn ceremony successful, PRF output obtained'
    });

    // Steps 3-4: Encrypt VRF keypair, derive NEAR keypair, and check registration in parallel
    console.log('Registration Steps 3-4: Encrypt VRF keypair, derive NEAR keypair, and check registration');
    const {
      encryptedVrfResult,
      deterministicVrfKeyResult,
      nearKeyResult,
      canRegisterUserResult,
    } = await Promise.all([
      webAuthnManager.encryptVrfKeypairWithCredentials({
        credential,
        vrfPublicKey: vrfChallenge.vrfPublicKey
      }),
      // Generate deterministic VRF keypair from PRF output for recovery
      webAuthnManager.deriveVrfKeypairFromPrf({
        credential,
        nearAccountId
      }),
      webAuthnManager.deriveNearKeypairAndEncrypt({
        credential,
        nearAccountId
      }),
      webAuthnManager.checkCanRegisterUser({
        contractId: webAuthnManager.configs.contractId,
        credential: credential,
        vrfChallenge: vrfChallenge,
        onEvent: (progress) => {
          console.debug(`Registration progress: ${progress.step} - ${progress.message}`);
          onEvent?.({
            step: 4,
            phase: 'account-verification',
            status: 'progress',
            timestamp: Date.now(),
            message: `Checking registration: ${progress.message}`
          });
        },
      }),
    ]).then(([encryptedVrfResult, deterministicVrfKeyResult, nearKeyResult, canRegisterUserResult]) => {
      if (!encryptedVrfResult.encryptedVrfKeypair || !encryptedVrfResult.vrfPublicKey) {
        throw new Error('Failed to encrypt VRF keypair');
      }
      if (!deterministicVrfKeyResult.success || !deterministicVrfKeyResult.vrfPublicKey) {
        throw new Error('Failed to derive deterministic VRF keypair from PRF');
      }
      if (!nearKeyResult.success || !nearKeyResult.publicKey) {
        throw new Error('Failed to generate NEAR keypair with PRF');
      }
      if (!canRegisterUserResult.verified) {
        console.error(canRegisterUserResult);
        const errorMessage = canRegisterUserResult.error || 'User verification failed - account may already exist or contract is unreachable';
        throw new Error(`Web3Authn contract registration check failed: ${errorMessage}`);
      }
      return {
        encryptedVrfResult,
        deterministicVrfKeyResult,
        nearKeyResult,
        canRegisterUserResult
      };
    });

    console.debug('Dual VRF registration strategy:');
    console.debug(`  Bootstrap VRF key: ${vrfChallenge.vrfPublicKey.substring(0, 20)}... (WebAuthn-bound)`);
    console.debug(`  Deterministic VRF key: ${deterministicVrfKeyResult.vrfPublicKey.substring(0, 20)}... (recovery-compatible)`);
    console.debug('Both keys will be stored on the contract for comprehensive VRF support');

    // Step 5: Create account and register with contract using appropriate flow
    console.log('Registration Step 5: Account creation and contract registration');
    onEvent?.({
      step: 2,
      phase: 'user-ready',
      status: 'success',
      timestamp: Date.now(),
      message: 'Registration completed with challenge consistency!',
      verified: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey: nearKeyResult.publicKey,
    });

    let accountAndRegistrationResult;
    if (useRelayer) {
      console.debug('Using relay-server registration flow');
      accountAndRegistrationResult = await createAccountAndRegisterWithRelayServer(
        context,
        nearAccountId,
        nearKeyResult.publicKey,
        credential,
        vrfChallenge,
        deterministicVrfKeyResult.vrfPublicKey,
        onEvent
      );
    } else {
      console.debug('Using testnet faucet registration flow');
      accountAndRegistrationResult = await createAccountAndRegisterWithTestnetFaucet(
        context,
        nearAccountId,
        nearKeyResult.publicKey,
        credential,
        vrfChallenge,
        deterministicVrfKeyResult.vrfPublicKey,
        onEvent
      );
    }

    if (!accountAndRegistrationResult.success) {
      throw new Error(accountAndRegistrationResult.error || 'Account creation and registration failed');
    }

    // Update registration state based on results
    registrationState.accountCreated = true;
    registrationState.contractRegistered = true;
    registrationState.contractTransactionId = accountAndRegistrationResult.transactionId || null;

    // Handle preSignedDeleteTransaction based on flow type
    if (useRelayer) {
      // For atomic transactions, no delete transaction is needed (rollback is automatic)
      registrationState.preSignedDeleteTransaction = null;
      console.debug('registration completed - no delete transaction needed');
    } else {
      // For sequential flow, store the delete transaction for rollback
      registrationState.preSignedDeleteTransaction = accountAndRegistrationResult.preSignedDeleteTransaction;
      console.debug('Pre-signed delete transaction captured for rollback');

      // Generate hash for verification/testing
      if (registrationState.preSignedDeleteTransaction) {
        const preSignedDeleteTransactionHash = generateTransactionHash(registrationState.preSignedDeleteTransaction);
        onEvent?.({
          step: 5,
          phase: 'contract-registration',
          status: 'progress',
          timestamp: Date.now(),
          message: `Presigned delete transaction created for rollback (hash: ${preSignedDeleteTransactionHash})`
        });
      }
    }

    // Step 6: Store user data with VRF credentials atomically
    console.log('Registration Step 6: Storing VRF registration data');
    onEvent?.({
      step: 6,
      phase: 'database-storage',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Storing VRF registration data'
    });

    await webAuthnManager.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      publicKey: nearKeyResult.publicKey,
      encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
      vrfPublicKey: encryptedVrfResult.vrfPublicKey,
      onEvent
    });

    // Mark database as stored for rollback tracking
    registrationState.databaseStored = true;

    onEvent?.({
      step: 6,
      phase: 'database-storage',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF registration data stored successfully'
    });

    // Step 7: Unlock VRF keypair in memory for login
    console.log('Registration Step 7: Unlocking VRF keypair for login');

    const unlockResult = await webAuthnManager.unlockVRFKeypair({
      nearAccountId: nearAccountId,
      encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
      credential: credential,
    }).catch((unlockError: any) => {
      console.warn('VRF keypair unlock failed:', unlockError);
      return { success: false, error: unlockError.message };
    });

    if (!unlockResult.success) {
      console.warn('VRF keypair unlock failed:', unlockResult.error);
      throw new Error(unlockResult.error);
    }

    onEvent?.({
      step: 7,
      phase: 'registration-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'Registration completed successfully'
    });

    const successResult = {
      success: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey: nearKeyResult.publicKey,
      transactionId: registrationState.contractTransactionId,
      vrfRegistration: {
        success: true,
        vrfPublicKey: vrfChallenge.vrfPublicKey,
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
        contractVerified: accountAndRegistrationResult.success,
      }
    };

    hooks?.afterCall?.(true, successResult);
    return successResult;

  } catch (error: any) {
    console.error('Registration failed:', error.message, error.stack);

    // Perform rollback based on registration state
    await performRegistrationRollback(
      registrationState,
      nearAccountId,
      webAuthnManager,
      configs.nearRpcUrl,
      onEvent
    );

    const errorMessage = error.message?.includes('one of the credentials already registered')
      ? `A passkey for '${nearAccountId}' already exists. Please try logging in instead.`
      : `Registration failed: ${error.message}`;

    const errorObject = new Error(errorMessage);
    onError?.(errorObject);

    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: errorMessage,
      error: errorMessage
    } as RegistrationSSEEvent);

    hooks?.afterCall?.(false, error);
    return {
      success: false,
      error: errorMessage
    };
  }
}

//////////////////////////////////////
// HELPER FUNCTIONS
//////////////////////////////////////

/**
 * Generate a VRF keypair + challenge in VRF wasm worker for WebAuthn registration ceremony bootstrapping
 *
 * ARCHITECTURE: This function solves the chicken-and-egg problem with a single VRF keypair:
 * 1. Generate VRF keypair + challenge (no PRF needed)
 * 2. Persist VRF keypair in worker memory (NOT encrypted yet)
 * 3. Use VRF challenge for WebAuthn ceremony → get PRF output
 * 4. Encrypt the SAME VRF keypair (still in memory) with PRF
 *
 * @param webAuthnManager - WebAuthn manager instance
 * @param nearAccountId - NEAR account ID for VRF input
 * @param blockHeight - Current NEAR block height for freshness
 * @param blockHashBytes - Current NEAR block hash bytes for entropy
 * @returns VRF challenge data (VRF keypair persisted in worker memory)
 */
export async function generateBootstrapVrfChallenge(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
): Promise<VRFChallenge> {

  const { webAuthnManager, nearClient } = context;

  const blockInfo = await nearClient.viewBlock({ finality: 'final' });

  console.log('Generating VRF keypair for registration');
  // Generate VRF keypair and persist in worker memory
  const vrfResult = await webAuthnManager.generateVrfKeypair(
    true, // saveInMemory: true - this VRF keypair is persisted in worker memory until PRF encryption
    {
      userId: nearAccountId,
      rpId: window.location.hostname,
      blockHeight: blockInfo.header.height,
      blockHash: blockInfo.header.hash,
      timestamp: Date.now()
    }
  );

  if (!vrfResult.vrfChallenge) {
    throw new Error('Registration VRF keypair generation failed');
  }
  console.log('VRF keypair generated and persisted in worker memory');
  return vrfResult.vrfChallenge;
}

/**
 * Validates registration inputs and throws errors if invalid
 * @param nearAccountId - NEAR account ID to validate
 * @param onEvent - Optional callback for registration progress events
 * @param onError - Optional callback for error handling
 */
const validateRegistrationInputs = async (
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
) => {

  onEvent?.({
    step: 1,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: 'Validating registration inputs...'
  } as RegistrationSSEEvent);

  // Validation
  if (!nearAccountId) {
    const error = new Error('NEAR account ID is required for registration.');
    onError?.(error);
    throw error;
  }
  // Validate the account ID format
  const validation = validateNearAccountId(nearAccountId);
  if (!validation.valid) {
    const error = new Error(`Invalid NEAR account ID: ${validation.error}`);
    onError?.(error);
    throw error;
  }
  if (!window.isSecureContext) {
    const error = new Error('Passkey operations require a secure context (HTTPS or localhost).');
    onError?.(error);
    throw error;
  }

  // Check if account already exists on-chain
  onEvent?.({
    step: 1,
    phase: 'webauthn-verification',
    status: 'progress',
    timestamp: Date.now(),
    message: `Checking if account ${nearAccountId} is available...`
  } as RegistrationSSEEvent);

  try {
    const accountInfo = await context.nearClient.viewAccount(nearAccountId);
    // If we get here without an error, the account already exists
    const error = new Error(`Account ${nearAccountId} already exists. Please choose a different account ID.`);
    onError?.(error);
    throw error;
  } catch (viewError: any) {
    // If viewAccount throws any error, assume the account doesn't exist
    // This is more reliable than parsing specific error formats that vary between RPC servers
    console.log(`✅ Account ${nearAccountId} is available for registration (viewAccount failed: ${viewError.message})`);
    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: `Account ${nearAccountId} is available for registration`
    } as RegistrationSSEEvent);
    return; // Continue with registration
  }
}

/**
 * Rollback registration data in case of errors
 */
async function performRegistrationRollback(
  registrationState: {
    accountCreated: boolean;
    contractRegistered: boolean;
    databaseStored: boolean;
    contractTransactionId: string | null;
    preSignedDeleteTransaction: SignedTransaction | null;
  },
  nearAccountId: AccountId,
  webAuthnManager: WebAuthnManager,
  rpcNodeUrl: string,
  onEvent?: (event: RegistrationSSEEvent) => void
): Promise<void> {
  console.debug('Starting registration rollback...', registrationState);

  // Rollback in reverse order
  try {
    // 3. Rollback database storage
    if (registrationState.databaseStored) {
      console.debug('Rolling back database storage...');
      onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: 'Rolling back database storage...',
        error: 'Registration failed - rolling back database storage'
      } as RegistrationSSEEvent);

      await webAuthnManager.rollbackUserRegistration(nearAccountId);
      console.debug('Database rollback completed');
    }

     // 2. Rollback NEAR account (if created)
    if (registrationState.accountCreated) {
      console.debug('Rolling back NEAR account...');
      onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: `Rolling back NEAR account ${nearAccountId}...`,
        error: 'Registration failed - attempting account deletion'
      } as RegistrationSSEEvent);

      if (registrationState.preSignedDeleteTransaction) {
        console.debug('Broadcasting pre-signed delete transaction for account rollback...');
        try {
          // Note: We need to create a new NearClient here since we only have rpcNodeUrl
          const tempNearClient = new MinimalNearClient(rpcNodeUrl);
          const deletionResult = await tempNearClient.sendTransaction(registrationState.preSignedDeleteTransaction);
          const deleteTransactionId = deletionResult?.transaction_outcome?.id;
          console.debug(`NEAR account ${nearAccountId} deleted successfully via pre-signed transaction`);
          console.debug(`   Delete transaction ID: ${deleteTransactionId}`);

          onEvent?.({
            step: 0,
            phase: 'registration-error',
            status: 'error',
            timestamp: Date.now(),
            message: `NEAR account ${nearAccountId} deleted successfully (rollback completed)`,
            error: 'Registration failed but account rollback completed'
          } as RegistrationSSEEvent);
        } catch (deleteError: any) {
          console.error(`NEAR account deletion failed:`, deleteError);
          onEvent?.({
            step: 0,
            phase: 'registration-error',
            status: 'error',
            timestamp: Date.now(),
            message: `️NEAR account ${nearAccountId} could not be deleted: ${deleteError.message}. Account will remain on testnet.`,
            error: 'Registration failed - account deletion failed'
          } as RegistrationSSEEvent);
        }
      } else {
        console.debug(`No pre-signed delete transaction available for ${nearAccountId}. Account will remain on testnet.`);
        onEvent?.({
          step: 0,
          phase: 'registration-error',
          status: 'error',
          timestamp: Date.now(),
          message: `️NEAR account ${nearAccountId} could not be deleted: No pre-signed transaction available. Account will remain on testnet.`,
          error: 'Registration failed - no rollback transaction available'
        } as RegistrationSSEEvent);
      }
    }

    // 1. Contract rollback on the Web3Authn contract is not possible at the moment. No authenticator deletion functions exposed yet.
    // However if a user retries with the same accountID, they can overwrite the old authenticator entry linked to the accountID
    if (registrationState.contractRegistered) {
      console.debug('Contract registration cannot be rolled back (immutable blockchain state)');
      onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: `Contract registration (tx: ${registrationState.contractTransactionId}) cannot be rolled back`,
        error: 'Registration failed - contract state is immutable'
      } as RegistrationSSEEvent);
    }

    console.debug('Registration rollback completed');

  } catch (rollbackError: any) {
    console.error('Rollback failed:', rollbackError);
    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: `Rollback failed: ${rollbackError.message}`,
      error: 'Both registration and rollback failed'
    } as RegistrationSSEEvent);
  }
}

/**
 * Generate a hash of a signed transaction for verification purposes
 * Uses the borsh bytes of the transaction to create a consistent hash
 */
function generateTransactionHash(signedTransaction: SignedTransaction): string {
  try {
    // Use the borsh_bytes which contain the serialized transaction data
    const transactionBytes = new Uint8Array(signedTransaction.borsh_bytes);

    // Create a simple hash using crypto.subtle (available in secure contexts)
    // For testing purposes, we'll use a truncated hash of the borsh bytes
    const hashInput = Array.from(transactionBytes).join(',');

    // Create a deterministic hash by taking first 16 chars of base64 encoding
    const hash = base64UrlEncode(new TextEncoder().encode(hashInput)).substring(0, 16);

    return hash;
  } catch (error) {
    console.warn('Failed to generate transaction hash:', error);
    return 'hash-generation-failed';
  }
}