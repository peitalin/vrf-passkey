import type { NearClient } from '../NearClient';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import { ActionType } from '../types/actions';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';
import { KeyPair } from '@near-js/crypto';
import { broadcastTransaction } from './actions';

// Type definitions for key management
export interface AddKeysOptions extends ActionOptions {
  /** Optional gas amount for the AddKey transaction */
  gas?: string;
  /** Optional access key permissions (defaults to FullAccess) */
  accessKeyPermission?: 'FullAccess' | {
    receiver_id: string;
    method_names: string[];
    allowance?: string;
  };
}

export interface AddKeysResult {
  success: boolean;
  accountId: string;
  newDevicePublicKey: string;
  totalKeys: number;
  transactionId?: string;
  error?: string;
}

export interface DeviceKeysView {
  accountId: string;
  keys: Array<{
    publicKey: string;
    isCurrentDevice: boolean;
    deviceType: 'passkey' | 'traditional';
    canDelete: boolean;
  }>;
}

/**
 * Add a new device to an existing NEAR account
 *
 * This function creates a new passkey-derived access key for the specified account.
 * It requires both the private key (for signing the AddKey transaction) and the account ID.
 *
 * The UX flow is similar to `registerPasskey` but adds a key to an existing account instead.
 *
 * @param context - PasskeyManager context with WebAuthn and NEAR client
 * @param privateKey - Private key of the existing account (for signing AddKey transaction)
 * @param accountId - Account ID to add the device to
 * @param options - Optional configuration for the operation
 */
export async function addDeviceToAccount({
  context,
  accountId,
  privateKey,
  options
}: {
  context: PasskeyManagerContext,
  accountId: string,
  privateKey: string,
  options?: AddKeysOptions
}): Promise<AddKeysResult> {

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
    message: 'Starting add keys operation...'
  });

    try {
    onEvent?.({
      step: 1,
      phase: 'preparation',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Validating account and preparing new device key...'
    });

    validateAddDeviceInputs({
      context,
      accountId,
      privateKey,
      nearClient
    });

    onEvent?.({
      step: 2,
      phase: 'authentication',
      status: 'progress',
      timestamp: Date.now(),
      message: `Creating new passkey for account ${accountId}...`
    });

    let vrfChallenge = await generateBootstrapVrfChallenge(context, accountId);

    // Generate new WebAuthn credentials for this device
    const credential = await webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
      nearAccountId: accountId,
      challenge: vrfChallenge.outputAs32Bytes(),
    });

    // Derive NEAR keypair from the new credential
    const newKeypairResult = await webAuthnManager.deriveNearKeypairAndEncrypt({
      credential,
      nearAccountId: accountId
    });

    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Verifying account exists and getting current keys...'
    });

    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Adding new device key to account...'
    });

    // 4. Create and sign AddKey transaction using the imported private key
    // This adds the device's new keypair as an access key to the imported account:
    // The new keypair's accountId = imported account's AccountID
    const signedTransaction = await webAuthnManager.signAddKeyToDevice({
      context,
      accountId,
      importedPrivateKey: privateKey,
      newDevicePublicKey: newKeypairResult.publicKey,
      accessKeyPermission: options?.accessKeyPermission || 'FullAccess',
    });

    onEvent?.({
      step: 5,
      phase: 'broadcasting',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Storing new authenticator onchain...'
    });

    const addKeyResult = await broadcastTransaction(context, signedTransaction, options);

    // 5. Store the new authenticator in the contract
    await webAuthnManager.storeAuthenticator({
      credentialId: credential.id,
      credentialPublicKey: new Uint8Array(credential.rawId), // Use rawId instead of response.publicKey
      transports: ['internal'],
      name: `Device added ${new Date().toISOString()}`,
      nearAccountId: accountId,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      vrfPublicKey: newKeypairResult.publicKey // Use publicKey as fallback for vrfPublicKey
    });

    // 6. Get updated key count
    const updatedKeys = await getDeviceKeys(context, accountId);

    onEvent?.({
      step: 6,
      phase: 'action-complete',
      status: 'success',
      timestamp: Date.now(),
      message: 'Device key generated and AddKey transaction prepared'
    });

    hooks?.afterCall?.(true);

    return {
      success: true,
      accountId,
      newDevicePublicKey: newKeypairResult.publicKey,
      totalKeys: updatedKeys.keys.length,
      transactionId: addKeyResult.transactionId
    };

  } catch (error: any) {
    console.error('[addKeysToAccount] Error:', error);
    onError?.(error);

    onEvent?.({
      step: 0,
      phase: 'action-error',
      status: 'error',
      timestamp: Date.now(),
      message: `Add keys failed: ${error.message}`,
      error: error.message
    });

    const errorResult: AddKeysResult = {
      success: false,
      accountId: '',
      newDevicePublicKey: '',
      totalKeys: 0,
      error: error.message
    };

    hooks?.afterCall?.(false, error);
    return errorResult;
  }
}

/**
 * Validates inputs for adding a new device to an account
 *
 * Checks that:
 * - Account ID is valid format
 * - Private key matches account
 * - Account exists and has access keys
 */
async function validateAddDeviceInputs({
  context,
  accountId,
  privateKey,
  nearClient,
}: {
  context: PasskeyManagerContext
  accountId: string,
  privateKey: string,
  nearClient: NearClient,
}) {

  // Validate the provided account ID
  const validation = validateNearAccountId(accountId);
  if (!validation.valid) {
    throw new Error(`Invalid NEAR account ID: ${validation.error}`);
  }

  // Validate that the private key and account ID are properly associated
  await validatePrivateKeyAndAccount(nearClient, privateKey, accountId);

  // Verify the account exists and get current access keys
  const currentKeys = await getDeviceKeys(context, accountId);
  if (currentKeys.keys.length === 0) {
    throw new Error(`Account ${accountId} does not exist or has no access keys`);
  }
}

/**
 * Get device keys for an account
 * Shows all access keys with metadata about device types and management options
 *
 * @example
 * ```typescript
 * const keysView = await passkeyManager.getDeviceKeys('alice.near');
 * console.log(`Account has ${keysView.keys.length} access keys`);
 * keysView.keys.forEach(key => {
 *   console.log(`${key.publicKey} - ${key.deviceType} - Current: ${key.isCurrentDevice}`);
 * });
 * ```
 */
export async function getDeviceKeys(
  context: PasskeyManagerContext,
  accountId: string
): Promise<DeviceKeysView> {

  const { webAuthnManager, nearClient } = context;
  // Validate account ID
  const validation = validateNearAccountId(accountId);
  if (!validation.valid) {
    throw new Error(`Invalid NEAR account ID: ${validation.error}`);
  }

  try {
    // Fetch access keys from NEAR network
    const accessKeyList = await nearClient.viewAccessKeyList(accountId);
    console.log('Access keys for', accountId, ':', accessKeyList);

    // Get current device's public key for comparison
    const currentDeviceKey = await getCurrentDevicePublicKey(webAuthnManager);

    // Map access keys to our DeviceKeysView format
    const keys = accessKeyList.keys.map((accessKey: any) => ({
      publicKey: accessKey.public_key as string,
      isCurrentDevice: accessKey.public_key === currentDeviceKey,
      deviceType: (isPasskeyDerived(accessKey.public_key) ? 'passkey' : 'traditional') as 'passkey' | 'traditional',
      canDelete: accessKeyList.keys.length > 1 // Always keep at least one key
    }));

    return {
      accountId,
      keys
    };

  } catch (error: any) {
    console.error(`Failed to fetch access keys for account ${accountId}:`, error);
    // If the account doesn't exist or we can't fetch keys, return empty result
    if (error.message?.includes('does not exist') || error.message?.includes('AccountDoesNotExist')) {
      return {
        accountId,
        keys: []
      };
    }
    // For other errors, re-throw with more context
    throw new Error(`Failed to fetch device keys for ${accountId}: ${error.message}`);
  }
}

// === HELPER FUNCTIONS ===

/**
 * Check if a public key was derived from a passkey (heuristic)
 */
function isPasskeyDerived(publicKey: string): boolean {
  // This is a heuristic - in practice we'd store metadata about key origins
  // For now, assume all ed25519 keys could be passkey-derived
  return publicKey.startsWith('ed25519:');
}

/**
 * Get current device's public key by deriving from passkey
 */
export async function getCurrentDevicePublicKey(webAuthnManager: any): Promise<string> {
  try {
    // This requires the original registration credential
    // In a real implementation, this would be retrieved from storage
    const keypair = await webAuthnManager.deriveDeterministicKeypairFromPasskey();
    return keypair.publicKey;
  } catch (error) {
    console.warn('Could not get current device public key:', error);
    return '';
  }
}

/**
 * Validate that a private key is associated with the given account ID
 * @param nearClient - NEAR RPC client
 * @param privateKey - Base58 encoded private key (with or without ed25519: prefix)
 * @param accountId - NEAR account ID to validate against
 * @throws Error if validation fails
 */
async function validatePrivateKeyAndAccount(
  nearClient: NearClient,
  privateKey: string,
  accountId: string
): Promise<void> {
  try {
    // 1. Derive public key from private key using NEAR crypto
    const publicKey = derivePublicKeyFromPrivateKey(privateKey);
    const publicKeyString = publicKey.toString();

    // 2. Check if the account has this public key as an access key
    try {
      const accessKeyInfo = await nearClient.viewAccessKey(accountId, publicKey);

      if (!accessKeyInfo) {
        throw new Error(`Account ${accountId} does not have access key ${publicKeyString}`);
      }

    } catch (error: any) {
      if (error.message?.includes('does not exist') || error.message?.includes('AccessKeyNotFound')) {
        throw new Error(
          `Private key validation failed: Account ${accountId} does not have the access key derived from the provided private key (${publicKeyString}). ` +
          `Please ensure you're using the correct private key and account ID.`
        );
      }
      throw error;
    }

  } catch (error: any) {
    console.error('validatePrivateKeyAndAccount: Validation failed:', error);
    throw error;
  }
}

/**
 * Derive NEAR public key from private key
 * @param privateKeyB58 - Base58 encoded private key
 * @returns PublicKey object
 */
function derivePublicKeyFromPrivateKey(privateKeyB58: string) {
  try {
    console.log('derivePublicKeyFromPrivateKey: Deriving public key from private key');

    // Ensure the private key has the proper format
    let formattedPrivateKey = privateKeyB58;
    if (!formattedPrivateKey.startsWith('ed25519:')) {
      formattedPrivateKey = `ed25519:${privateKeyB58}`;
    }

    // Use NEAR crypto library to create KeyPair from private key
    const keyPair = KeyPair.fromString(formattedPrivateKey as any);

    // Extract the public key
    const publicKey = keyPair.getPublicKey();

    console.log('derivePublicKeyFromPrivateKey: Successfully derived public key');
    return publicKey;

  } catch (error: any) {
    console.error('derivePublicKeyFromPrivateKey: Failed to derive public key:', error);
    throw new Error(`Failed to derive public key from private key: ${error.message}`);
  }
}

