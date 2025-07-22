
/**
 * Type-safe account ID system for handling base account IDs vs device-specific account IDs
 *
 * USAGE PATTERNS:
 * - AccountId: Use for on-chain operations, PRF salt derivation, VRF operations, transaction signing
 * - AccountIdDeviceSpecific: Use for IndexedDB storage, passkey storage, local identification
 *
 * EXAMPLES:
 * - Base: "serp126.web3-authn-v2.testnet"
 * - Device-specific: "serp126.3.web3-authn-v2.testnet" (device 3)
 */

// Branded string types for compile-time type safety
export type AccountId = string & { readonly __brand: 'AccountId' };
export type AccountIdDeviceSpecific = string & { readonly __brand: 'AccountIdDeviceSpecific' };

/**
 * Type guard to check if an account ID is device-specific
 * Detects format: username.deviceNumber.contract.testnet
 */
export function isDeviceSpecificAccountId(accountId: string): accountId is AccountIdDeviceSpecific {
  const parts = accountId.split('.');

  // Need at least 3 parts to potentially have a device number
  if (parts.length >= 3) {
    const potentialDeviceNumber = parts[1];
    // Check if second part is a number (device number)
    return /^\d+$/.test(potentialDeviceNumber);
  }

  return false;
}

/**
 * Type guard to check if an account ID is a base account ID
 */
export function isBaseAccountId(accountId: string): accountId is AccountId {
  return !isDeviceSpecificAccountId(accountId);
}

/**
 * Extract base account ID from any account ID (base or device-specific)
 * Safe for both input types - idempotent for base account IDs
 *
 * Base account ID:
 * For PRF salt derivation, we need consistent base account IDs across devices
 *
 * Device-specific account ID:
 * We need this for when Linking Devices, so that passkey sync doesn't overwrite existing passkeys
 * on older devices
 *
 * Examples:
 * - "serp126.3.web3-authn-v2.testnet" -> "serp126.web3-authn-v2.testnet"
 * - "serp126.web3-authn-v2.testnet" -> "serp126.web3-authn-v2.testnet" (unchanged)
 * - "simple.testnet" -> "simple.testnet" (unchanged)
 * - "user.1.contract.near" -> "user.contract.near"
 *
 * @param accountId - Any account ID (base or device-specific)
 * @returns Base account ID for consistent operations
 */
export function extractBaseAccountId(accountId: string): AccountId {
  const parts = accountId.split('.');

  // Need at least 3 parts to potentially have a device number
  if (parts.length >= 3) {
    const potentialDeviceNumber = parts[1];
    // Check if second part is a number (device number)
    if (/^\d+$/.test(potentialDeviceNumber)) {
      // Remove the device number part
      const baseParts = [parts[0], ...parts.slice(2)];
      return baseParts.join('.') as AccountId;
    }
  }

  // If not device-specific format, return as base account ID
  return accountId as AccountId;
}

/**
 * Extract device number from device-specific account ID
 * Returns undefined for base account IDs
 */
export function extractDeviceNumber(accountId: string): number | undefined {
  const parts = accountId.split('.');

  if (parts.length >= 3) {
    const potentialDeviceNumber = parts[1];
    if (/^\d+$/.test(potentialDeviceNumber)) {
      return parseInt(potentialDeviceNumber, 10);
    }
  }

  return undefined; // Base account ID (device 0)
}

/**
 * Validate and cast string to AccountId
 * Throws if the account ID appears to be device-specific
 */
export function validateBaseAccountId(accountId: string): AccountId {
  if (isDeviceSpecificAccountId(accountId)) {
    throw new Error(`Expected base account ID, got device-specific: ${accountId}. Use extractBaseAccountId() to convert.`);
  }
  return accountId as AccountId;
}

/**
 * Validate and cast string to AccountIdDeviceSpecific
 * Accepts both base and device-specific account IDs (base IDs are treated as device 0)
 */
export function validateDeviceSpecificAccountId(accountId: string): AccountIdDeviceSpecific {
  // Both base and device-specific account IDs are valid for storage
  return accountId as AccountIdDeviceSpecific;
}

/**
 * Convert any account ID to AccountId (safe conversion)
 * Alias for extractBaseAccountId with clearer intent
 */
export function toBaseAccountId(accountId: string): AccountId {
  return extractBaseAccountId(accountId);
}

/**
 * Convert base account ID to device-specific account ID
 */
export function toDeviceSpecificAccountId(
  baseAccountId: AccountId,
  deviceNumber?: number
): AccountIdDeviceSpecific {
  // Device 0 or undefined = first device, use base account ID
  if (deviceNumber === undefined || deviceNumber === 0) {
    return baseAccountId as unknown as AccountIdDeviceSpecific;
  }

  // Add device number to account ID
  if (baseAccountId.includes('.')) {
    const parts = baseAccountId.split('.');
    // Insert device number after the first part
    // "serp124.web3-authn-v2.testnet" → "serp124.1.web3-authn-v2.testnet"
    parts.splice(1, 0, deviceNumber.toString());
    return parts.join('.') as AccountIdDeviceSpecific;
  } else {
    // Fallback for accounts without dots
    return `${baseAccountId}.${deviceNumber}` as AccountIdDeviceSpecific;
  }
}

/**
 * Account ID type utilities for runtime type checking
 */
export const AccountId = {
  isBase: isBaseAccountId,
  isDeviceSpecific: isDeviceSpecificAccountId,
  extractBase: extractBaseAccountId,
  extractDeviceNumber,
  validateBase: validateBaseAccountId,
  validateDeviceSpecific: validateDeviceSpecificAccountId,
  toBase: toBaseAccountId,
  toDeviceSpecific: toDeviceSpecificAccountId,
} as const;
