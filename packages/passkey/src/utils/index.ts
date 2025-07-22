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

export function jsonTryParse<T>(obj: string | undefined): T {
  return JSON.parse(obj || '{}') as T;
}


