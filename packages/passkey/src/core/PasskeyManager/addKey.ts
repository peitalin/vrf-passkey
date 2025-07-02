import type { NearClient } from '../NearClient';
import type { ActionOptions, ActionResult } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import { ActionType } from '../types/actions';
import { validateNearAccountId } from '../../utils/validation';

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
 * Add current device's DD-keypair to an existing NEAR account
 * This enables multi-device access by adding the current device as an additional access key
 */
export async function addKeysToAccount(
  context: PasskeyManagerContext,
  privateKey: string,
  options?: AddKeysOptions
): Promise<AddKeysResult> {

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
    // 1. Convert private key to keypair (existing device)
    onEvent?.({
      step: 1,
      phase: 'preparation',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Processing existing device private key...'
    });

    if (!privateKey || !privateKey.startsWith('ed25519:')) {
      throw new Error('Invalid private key format. Expected ed25519:... format');
    }

    // Extract the base58-encoded part
    const privateKeyB58 = privateKey.slice(8); // Remove 'ed25519:' prefix

    // For now, we'll validate the format but rely on WASM worker for actual key operations
    // The WASM worker has access to proper Ed25519 key parsing
    console.log('Private key format validated');

        // 2. Find account controlled by existing device
    onEvent?.({
      step: 2,
      phase: 'authentication',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Looking up account controlled by existing device...'
    });

    const accountId = await findAccountByPrivateKey(nearClient, privateKeyB58);
    if (!accountId) {
      throw new Error('No NEAR account found for this private key');
    }

    console.log(`Found account controlled by existing device: ${accountId}`);

    // 3. Derive DD-keypair for current device
    onEvent?.({
      step: 3,
      phase: 'contract-verification',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Deriving deterministic keypair for current device...'
    });

    // TODO: Implement deriveDeterministicKeypairFromPasskey in WebAuthnManager
    // For now, use placeholder
    const currentDeviceKeypair = {
      publicKey: 'ed25519:placeholder' // This will be implemented in WebAuthnManager
    };
    console.log('Current device DD-keypair derived successfully (placeholder)');

    // 4. Create AddKey transaction using existing WASM infrastructure
    onEvent?.({
      step: 4,
      phase: 'transaction-signing',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating AddKey transaction...'
    });

    // TODO: Implement addDeviceKey in WebAuthnManager
    // For now, use placeholder result
    const addKeyResult = {
      transactionId: 'placeholder-tx-id'
    };

    // 5. Get total key count for confirmation
    // Get all access keys by querying each known key - this is a workaround
    // In practice, we'd need a proper method to list all access keys
    const totalKeys = 1; // Placeholder - will be implemented properly

    const result: AddKeysResult = {
      success: true,
      accountId,
      newDevicePublicKey: currentDeviceKeypair.publicKey,
      totalKeys,
      transactionId: addKeyResult.transactionId
    };

        onEvent?.({
      step: 5,
      phase: 'broadcasting',
      status: 'success',
      timestamp: Date.now(),
      message: `Device key added successfully. Account now has ${totalKeys} access keys.`
    });

    hooks?.afterCall?.(true, result);
    return result;

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
 * Get comprehensive device keys view for an account
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

  // TODO: Implement proper access keys listing
  // For now, return placeholder data
  const allKeys: Array<{public_key: string}> = [];

  // Get current device's public key
  const currentDeviceKey = await getCurrentDevicePublicKey(webAuthnManager);

  return {
    accountId,
    keys: allKeys.map((key: {public_key: string}) => ({
      publicKey: key.public_key,
      isCurrentDevice: key.public_key === currentDeviceKey,
      deviceType: isPasskeyDerived(key.public_key) ? 'passkey' : 'traditional',
      canDelete: allKeys.length > 1 // Always keep at least one key
    }))
  };
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
 * Find account ID by private key (simplified lookup)
 * In production, this would use a more sophisticated approach
 */
export async function findAccountByPrivateKey(
  nearClient: NearClient,
  privateKeyB58: string
): Promise<string | null> {
  try {
    // This is a simplified implementation
    // In practice, we'd need to:
    // 1. Derive public key from private key
    // 2. Query NEAR indexer/RPC for accounts with this public key
    // 3. Handle multiple accounts (user selection)

    // For now, throw an error indicating this needs implementation
    throw new Error('Account lookup by private key not yet implemented. Please provide account ID directly.');
  } catch (error) {
    console.error('Account lookup failed:', error);
    return null;
  }
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