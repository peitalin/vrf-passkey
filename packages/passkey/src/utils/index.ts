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
 * Generate user-scoped PRF salt to prevent collision risks
 * @param accountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt unique to the user
 */
export function generateUserScopedPrfSalt(accountId: string): Uint8Array {
  const saltInput = `prf-salt:${accountId}`;
  const hashArray = sha256.array(saltInput);
  return new Uint8Array(hashArray);
}

/**
 * SECURITY UTILITY: Extract calling function name for context-restricted operations
 * Used to validate that only legitimate functions can trigger sensitive operations like DeleteAccount
 *
 * @returns The name of the calling function or 'unknown' if not determinable
 */
export function getCallerFunctionName(): string {
  try {
    const stack = new Error().stack;
    if (!stack) return 'unknown';

    // Parse stack trace to find the actual calling function
    // Stack format: "at functionName (file:line:col)" or "at file:line:col"
    const lines = stack.split('\n');

    // Skip the first few lines which are internal calls
    // Look for the first line that contains a recognizable function name
    for (let i = 2; i < Math.min(lines.length, 8); i++) {
      const line = lines[i];
      if (line && line.includes('at ')) {
        // Extract function name from various patterns:
        // "at functionName ("
        // "at ClassName.functionName ("
        // "at async functionName ("
        const patterns = [
          /at\s+async\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/,        // async functions
          /at\s+[a-zA-Z_$][a-zA-Z0-9_$]*\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/, // class methods
          /at\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/                  // regular functions
        ];

        for (const pattern of patterns) {
          const match = line.match(pattern);
          if (match && match[1] &&
              !match[1].startsWith('get') && // Skip getters
              !match[1].startsWith('execute') && // Skip generic execution functions
              !match[1].includes('Worker') && // Skip worker-related functions
              !match[1].includes('Handler') && // Skip handlers
              match[1] !== 'unknown') {
            return match[1];
          }
        }
      }
    }
    return 'unknown';
  } catch (error) {
    console.warn('[security]: Failed to extract caller function name:', error);
    return 'unknown';
  }
}

/**
 * SECURITY UTILITY: Validate that caller function is authorized for DeleteAccount operations
 * This provides an additional client-side check before sending to WASM worker
 *
 * @param callerFunction - Name of the calling function
 * @returns true if caller is authorized, false otherwise
 */
export function isAuthorizedForDeleteAccount(callerFunction: string): boolean {
  const authorizedCallers = [
    'handleRegistration',           // Main registration function
    'registerUser',                 // Alternative registration function name
    'signVerifyAndRegisterUser',    // WebAuthn registration function
    'performRegistrationRollback',  // Explicit rollback function
    'registration_cleanup',         // Registration cleanup function
  ];

  return authorizedCallers.includes(callerFunction);
}