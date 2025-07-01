export * from './encoders';
export declare const shortenString: (str: string | null | undefined, headChars?: number, tailChars?: number) => string;
/**
 * Generate user-scoped PRF salt to prevent collision risks
 * @param accountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt unique to the user
 */
export declare function generateUserScopedPrfSalt(accountId: string): Uint8Array;
/**
 * SECURITY UTILITY: Extract calling function name for context-restricted operations
 * Used to validate that only legitimate functions can trigger sensitive operations like DeleteAccount
 *
 * @returns The name of the calling function or 'unknown' if not determinable
 */
export declare function getCallerFunctionName(): string;
/**
 * SECURITY UTILITY: Validate that caller function is authorized for DeleteAccount operations
 * This provides an additional client-side check before sending to WASM worker
 *
 * @param callerFunction - Name of the calling function
 * @returns true if caller is authorized, false otherwise
 */
export declare function isAuthorizedForDeleteAccount(callerFunction: string): boolean;
//# sourceMappingURL=index.d.ts.map