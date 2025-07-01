import { sha256 } from 'js-sha256';

/**
 * Generate user-scoped PRF salt to prevent collision risks
 * @param accountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt unique to the user
 */
function generateUserScopedPrfSalt(accountId) {
    const saltInput = `prf-salt:${accountId}`;
    const hashArray = sha256.array(saltInput);
    return new Uint8Array(hashArray);
}

export { generateUserScopedPrfSalt };
//# sourceMappingURL=index.js.map
