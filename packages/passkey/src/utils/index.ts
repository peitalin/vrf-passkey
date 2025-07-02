export * from './encoders';
export * from './validation';

/**
 * Shortens a string by keeping a fixed number of characters at the start and end,
 * with an ellipsis in the middle. Handles special cases like ed25519: prefixes.
 *
 * @param str - String to shorten, can be null/undefined
 * @param headChars - Number of characters to keep at start (default: 6)
 * @param tailChars - Number of characters to keep at end (default: 4)
 * @returns Shortened string with ellipsis, or empty string if input is null/undefined
 */
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
 * Formats a multi-line message into a single line by removing extra whitespace
 * and newlines. Useful for displaying error messages or logs in a more compact format.
 *
 * @param message - Multi-line string to format
 * @returns Single line string with normalized whitespace
 */
export const formatLongMessage = (message: string) => {
  return message.split('\n').map(line => line.trim()).join(' ').trim();
};

/**
 * SECURITY UTILITY: Extract calling function name for context-restricted operations
 * Used to validate that only legitimate functions can trigger sensitive operations
 * like exportKeyPair, etc.
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

