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
import { createAccountRelayServer } from './faucets/createAccountRelayServer';
import { createAccountTestnetFaucet } from './faucets/createAccountTestnetFaucet';
import { WebAuthnManager } from '../WebAuthnManager';
import { VRFChallenge } from '../types/webauthn';
import type { PasskeyManagerContext } from './index';

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
  nearAccountId: string,
  options: RegistrationOptions
): Promise<RegistrationResult> {

  const { onEvent, onError, hooks, useRelayer } = options;
  const { webAuthnManager, nearClient, configs } = context;

  // Track registration progress for rollback
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
    preSignedDeleteTransaction: null as SignedTransaction | null,
  };

  console.log('⚡ Registration: Optimized VRF registration with single WebAuthn ceremony');
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

    // Step 2: Use VRF output as WebAuthn challenge
    console.log('Registration Step 2: Use VRF output as WebAuthn challenge');
    const vrfChallengeBytes = vrfChallenge.outputAs32Bytes();

    // Step 3: WebAuthn registration ceremony with PRF (TouchID)
    console.log('Registration Step 3: WebAuthn registration ceremony with VRF challenge');

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Performing WebAuthn registration with VRF challenge...'
    });

    const credential = await webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
      nearAccountId,
      challenge: vrfChallengeBytes,
    });

    onEvent?.({
      step: 1,
      phase: 'webauthn-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'WebAuthn ceremony successful, PRF output obtained'
    });

    // Steps 4-6: Encrypt VRF keypair, generate NEAR keypair, and check registration in parallel
    console.log('Registration Steps 4-6: Encrypting VRF keypair, generating NEAR keypair with PRF, and checking registration');
    const {
      encryptedVrfResult,
      keyGenResult,
      canRegisterUserResult,
      deterministicVrfResult
    } = await Promise.all([
      webAuthnManager.encryptVrfKeypairWithCredentials({
        credential,
        vrfPublicKey: vrfChallenge.vrfPublicKey
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
      // Generate deterministic VRF keypair from PRF output for recovery
      webAuthnManager.deriveVrfKeypairFromPrf({
        credential,
        nearAccountId
      })
    ]).then(([encryptedVrfResult, keyGenResult, canRegisterUserResult, deterministicVrfResult]) => {
      if (!encryptedVrfResult.encryptedVrfKeypair || !encryptedVrfResult.vrfPublicKey) {
        throw new Error('Failed to encrypt VRF keypair');
      }
      if (!keyGenResult.success || !keyGenResult.publicKey) {
        throw new Error('Failed to generate NEAR keypair with PRF');
      }
      if (!canRegisterUserResult.verified) {
        throw new Error(`Web3Authn contract registration check failed: ${canRegisterUserResult.error}`);
      }
      if (!deterministicVrfResult.success || !deterministicVrfResult.vrfPublicKey) {
        throw new Error('Failed to derive deterministic VRF keypair from PRF');
      }
      return { encryptedVrfResult, keyGenResult, canRegisterUserResult, deterministicVrfResult };
    });

    console.log('✅ Dual VRF registration strategy:');
    console.log(`  Bootstrap VRF key: ${vrfChallenge.vrfPublicKey.substring(0, 20)}... (WebAuthn-bound)`);
    console.log(`  Deterministic VRF key: ${deterministicVrfResult.vrfPublicKey.substring(0, 20)}... (recovery-compatible)`);
    console.log('Both keys will be stored on the contract for comprehensive VRF support');

    onEvent?.({
      step: 2,
      phase: 'user-ready',
      status: 'success',
      timestamp: Date.now(),
      message: 'Registration completed with challenge consistency!',
      verified: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey: keyGenResult.publicKey,
    });

    // Step 7: Create account using faucet service (before storing data)
    console.log('Registration Step 7: Creating NEAR account via faucet service');
    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating NEAR account...'
    });

    if (useRelayer) {
      if (!configs.relayServerUrl) {
        throw new Error('Relay server URL is required when useRelayer is true');
      }
      // Create account using relay server
      await createAccountRelayServer(
        nearAccountId,
        keyGenResult.publicKey,
        configs.relayServerUrl,
        onEvent
      ).then((accountCreationResult) => {
        console.log(`DEBUG: Relay server used public key: ${keyGenResult.publicKey}`);
        if (!accountCreationResult.success) {
          throw new Error(`Account creation failed: ${accountCreationResult.error || 'Unknown error'}`);
        }
        // Mark account as created for rollback tracking
        registrationState.accountCreated = true;
      });
    } else {
      // Create account using faucet service
      await createAccountTestnetFaucet(
        nearAccountId,
        keyGenResult.publicKey,
        onEvent
      ).then((accountCreationResult) => {
        console.log(`DEBUG: Testnet Faucet used public key: ${keyGenResult.publicKey}`);
        if (!accountCreationResult.success) {
          throw new Error(`Account creation failed: ${accountCreationResult.error || 'Unknown error'}`);
        }
        // Mark account as created for rollback tracking
        registrationState.accountCreated = true;
      });
    }

    console.log('DEBUG: Faucet public key:', keyGenResult.publicKey);
    console.log('DEBUG: About to check access key for:', nearAccountId);

    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: 'NEAR account created successfully'
    });

    // Check for access key to be available
    const accessKeyInfo = await waitForAccessKey(
      nearClient,
      nearAccountId,
      keyGenResult.publicKey,
      10, // max retries
      1000 // 1 second delay
    );

    onEvent?.({
      step: 4,
      phase: 'account-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account creation verified successfully'
    });

    // Step 8: Contract verification and registration transaction
    console.log('Registration Step 8: Contract verification and registration transaction');

    const contractRegistrationResult = await webAuthnManager.signVerifyAndRegisterUser({
      contractId: webAuthnManager.configs.contractId,
      credential: credential,
      vrfChallenge: vrfChallenge,
      deterministicVrfPublicKey: deterministicVrfResult.vrfPublicKey,
      signerAccountId: nearAccountId,
      nearAccountId: nearAccountId,
      publicKeyStr: keyGenResult.publicKey,
      nearClient: nearClient,
      onEvent: (progress) => {
        console.debug(`Registration progress: ${progress.step} - ${progress.message}`);
        onEvent?.({
          step: 6,
          phase: 'contract-registration',
          status: 'progress',
          timestamp: Date.now(),
          message: `VRF registration: ${progress.message}`
        });
      },
    });

    const contractVerified = contractRegistrationResult.verified;
    const signedTransaction = contractRegistrationResult.signedTransaction;
    const preSignedDeleteTransaction = contractRegistrationResult.preSignedDeleteTransaction;
    console.log('>>>>>> contractRegistrationResult', contractRegistrationResult);

    // Store pre-signed delete transaction for rollback (always present when WASM worker succeeds)
    registrationState.preSignedDeleteTransaction = preSignedDeleteTransaction;
    console.log('✅ Pre-signed delete transaction captured for rollback');

    if (contractVerified && signedTransaction) {
      // Broadcast the signed transaction
      console.log('Broadcasting registration transaction...');

      onEvent?.({
        step: 6,
        phase: 'contract-registration',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Broadcasting registration transaction...'
      });

      const transactionResult = await nearClient.sendTransaction(signedTransaction!);
      const transactionId = transactionResult?.transaction_outcome?.id;
      registrationState.contractTransactionId = transactionId;
      registrationState.contractRegistered = true;

      onEvent?.({
        step: 6,
        phase: 'contract-registration',
        status: 'success',
        timestamp: Date.now(),
        message: `VRF registration successful, transaction ID: ${registrationState.contractTransactionId}`
      });
    } else {
      console.warn('Contract verification failed: Registration transaction not verified');
      throw new Error('Registration verification failed');
    }

    // Step 9: Store user data with VRF credentials atomically
    console.log('Registration Step 9: Storing VRF registration data atomically');
    onEvent?.({
      step: 5,
      phase: 'database-storage',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Storing VRF registration data atomically...'
    });

    await webAuthnManager.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      publicKey: keyGenResult.publicKey,
      encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
      vrfPublicKey: encryptedVrfResult.vrfPublicKey,
      onEvent
    });

    // Mark database as stored for rollback tracking
    registrationState.databaseStored = true;

    onEvent?.({
      step: 5,
      phase: 'database-storage',
      status: 'success',
      timestamp: Date.now(),
      message: 'VRF registration data stored successfully'
    });

    // Step 10: Unlock VRF keypair in memory for immediate login state (non-fatal)
    console.log('Registration Step 10: Unlocking VRF keypair for immediate login');

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
      clientNearPublicKey: keyGenResult.publicKey,
      transactionId: registrationState.contractTransactionId,
      vrfRegistration: {
        success: true,
        vrfPublicKey: vrfChallenge.vrfPublicKey,
        encryptedVrfKeypair: encryptedVrfResult.encryptedVrfKeypair,
        contractVerified: contractVerified,
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
  nearAccountId: string,
): Promise<VRFChallenge> {

  const { webAuthnManager, nearClient } = context;

  const {
    blockHeight,
    blockHashBytes,
  } = await nearClient.viewBlock({ finality: 'final' }).then(blockInfo => {
    return {
      blockHeight: blockInfo.header.height,
      blockHashBytes: new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'))
    };
  });

  console.log('Generating VRF keypair for registration');
  // Generate VRF keypair and persist in worker memory
  const vrfResult = await webAuthnManager.generateVrfKeypair(
    true, // saveInMemory: true - this VRF keypair is persisted in worker memory until PRF encryption
    {
      userId: nearAccountId,
      rpId: window.location.hostname,
      blockHeight: blockHeight,
      blockHashBytes: Array.from(blockHashBytes),
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
  nearAccountId: string,
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

}

/**
 * Wait for access key to be available with retry logic
 * Account creation via faucet may have propagation delays
 */
async function waitForAccessKey(
  nearClient: NearClient,
  nearAccountId: string,
  nearPublicKey: string,
  maxRetries: number = 10,
  delayMs: number = 1000
): Promise<AccessKeyView> {
  console.log(`Waiting for access key to be available for ${nearAccountId}...`);
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const accessKeyInfo = await nearClient.viewAccessKey(
        nearAccountId,
        nearPublicKey,
      ) as AccessKeyView;

      console.log(`Access key found on attempt ${attempt}`);
      console.log(`DEBUG: Access key response:`, JSON.stringify(accessKeyInfo, null, 2));
      return accessKeyInfo;
    } catch (error: any) {
      console.log(`Access key not available yet (attempt ${attempt}/${maxRetries}):`, error.message);

      if (attempt === maxRetries) {
        console.error(`Access key still not available after ${maxRetries} attempts`);
        throw new Error(`Access key not available after ${maxRetries * delayMs}ms. Account creation may have failed.`);
      }

      // Wait before next attempt with exponential backoff
      const delay = delayMs * Math.pow(1.5, attempt - 1);
      console.debug(`   Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('Unexpected error in waitForAccessKey');
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
  nearAccountId: string,
  webAuthnManager: WebAuthnManager,
  rpcNodeUrl: string,
  onEvent?: (event: RegistrationSSEEvent) => void
): Promise<void> {
  console.log('Starting registration rollback...', registrationState);

  // Rollback in reverse order
  try {
    // 3. Rollback database storage
    if (registrationState.databaseStored) {
      console.log('Rolling back database storage...');
      onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: 'Rolling back database storage...',
        error: 'Registration failed - rolling back database storage'
      } as RegistrationSSEEvent);

      await webAuthnManager.rollbackUserRegistration(nearAccountId);
      console.log('Database rollback completed');
    }

     // 2. Rollback NEAR account (if created)
    if (registrationState.accountCreated) {
      console.log('Rolling back NEAR account...');
      onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: `Rolling back NEAR account ${nearAccountId}...`,
        error: 'Registration failed - attempting account deletion'
      } as RegistrationSSEEvent);

      if (registrationState.preSignedDeleteTransaction) {
        console.log('Broadcasting pre-signed delete transaction for account rollback...');
        try {
          // Note: We need to create a new NearClient here since we only have rpcNodeUrl
          const tempNearClient = new MinimalNearClient(rpcNodeUrl);
          const deletionResult = await tempNearClient.sendTransaction(registrationState.preSignedDeleteTransaction);
          const deleteTransactionId = deletionResult?.transaction_outcome?.id;
          console.log(`NEAR account ${nearAccountId} deleted successfully via pre-signed transaction`);
          console.log(`   Delete transaction ID: ${deleteTransactionId}`);

          onEvent?.({
            step: 0,
            phase: 'registration-error',
            status: 'error',
            timestamp: Date.now(),
            message: `NEAR account ${nearAccountId} deleted successfully (rollback completed)`,
            error: 'Registration failed but account rollback completed'
          } as RegistrationSSEEvent);
        } catch (deleteError: any) {
          console.error(`❌ NEAR account deletion failed:`, deleteError);
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
        console.log(`️No pre-signed delete transaction available for ${nearAccountId}. Account will remain on testnet.`);
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
      console.log('Contract registration cannot be rolled back (immutable blockchain state)');
      onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: `Contract registration (tx: ${registrationState.contractTransactionId}) cannot be rolled back`,
        error: 'Registration failed - contract state is immutable'
      } as RegistrationSSEEvent);
    }

    console.log('Registration rollback completed');

  } catch (rollbackError: any) {
    console.error('❌ Rollback failed:', rollbackError);
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
