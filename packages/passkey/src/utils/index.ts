import { sha256 } from 'js-sha256';

export * from './encoders';

// === HELPER FUNCTIONS ===

export const shortenString = (str: string | null | undefined, headChars = 6, tailChars = 4) => {
  if (!str) return '';
  if (str.length <= headChars + tailChars + 2) return str; // If already short or has a prefix like "ed25519:"
  const prefixIndex = str.indexOf(':');
  if (prefixIndex > -1 && prefixIndex < headChars) { // Handle prefixes like ed25519:
    return `${str.substring(0, prefixIndex + 1 + headChars)}...${str.substring(str.length - tailChars)}`;
  }
  return `${str.substring(0, headChars)}...${str.substring(str.length - tailChars)}`;
};


/**
 * Generate a unique session ID for client-side events
 */
export const generateSessionId = () => {
  return `session_${Date.now()}_${Math.random().toString(36).substring(2)}`;
}

/**
 * Generate user-scoped PRF salt to prevent collision risks
 * @param accountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt unique to the user
 */
export function generateUserScopedPrfSalt(accountId: string): Uint8Array {
  const saltInput = `prf-salt:${accountId}`;
  const hashArray = sha256.array(saltInput);
  return new Uint8Array(hashArray);
}