import type { PasskeyErrorDetails } from './errors';

/**
 * Generic Result type for better error handling throughout the SDK
 * Replaces boolean success flags with discriminated unions for type safety
 */
export type Result<T, E = PasskeyErrorDetails> =
  | { success: true; data: T }
  | { success: false; error: E };
