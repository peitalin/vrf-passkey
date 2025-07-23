
/**
 * Type-safe account ID system for NEAR account operations
 *
 * USAGE:
 * - AccountId: Use for all operations - on-chain, PRF salt derivation, VRF operations, storage, WebAuthn
 *
 * EXAMPLES:
 * - "serp126.web3-authn-v2.testnet"
 * - "alice.near"
 * - "simple.testnet"
 */

// Branded string type for compile-time type safety
export type AccountId = string & { readonly __brand: 'AccountId' };

/**
 * Validate and cast string to AccountId
 * Simple validation for standard NEAR account IDs
 */
export function validateAccountId(accountId: string): AccountId {
  if (!accountId || typeof accountId !== 'string') {
    throw new Error(`Invalid account ID: must be a non-empty string`);
  }
  if (!accountId.includes('.')) {
    throw new Error(`Invalid NEAR account ID format: must contain at least one dot (e.g., "alice.near")`);
  }
  return accountId as AccountId;
}

/**
 * Convert and validate string to AccountId
 * Validates proper NEAR account format (must contain at least one dot)
 */
export function toAccountId(accountId: string): AccountId {
  return validateAccountId(accountId);
}

/**
 * Account ID utilities
 */
export const AccountId = {
  validate: validateAccountId,
  to: toAccountId,
} as const;
