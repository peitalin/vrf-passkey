export interface ValidationResult {
    valid: boolean;
    error?: string;
}
export interface NearAccountValidationOptions {
    /** Restrict to specific suffixes (e.g., ['testnet', 'near']) */
    allowedSuffixes?: string[];
    /** Require Top-level domains with exactly 2 parts (username.suffix) instead of allowing subdomains */
    requireTopLevelDomain?: boolean;
}
/**
 * Validate NEAR account ID format with optional suffix restrictions
 * @param nearAccountId - The account ID to validate
 * @param options - Optional validation constraints
 */
export declare function validateNearAccountId(nearAccountId: string, options?: NearAccountValidationOptions): ValidationResult;
/**
 * Validate NEAR account ID with specific suffix requirements for server registration
 * Must be <username>.<relayerAccountId>, <username>.testnet, or <username>.near
 */
export declare function validateServerRegistrationAccountId(nearAccountId: string): ValidationResult;
//# sourceMappingURL=validation.d.ts.map