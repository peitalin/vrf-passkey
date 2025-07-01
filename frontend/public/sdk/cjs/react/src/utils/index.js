'use strict';

var jsSha256 = require('js-sha256');

/**
 * Generate user-scoped PRF salt to prevent collision risks
 * @param accountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt unique to the user
 */
function generateUserScopedPrfSalt(accountId) {
    const saltInput = `prf-salt:${accountId}`;
    const hashArray = jsSha256.sha256.array(saltInput);
    return new Uint8Array(hashArray);
}

exports.generateUserScopedPrfSalt = generateUserScopedPrfSalt;
//# sourceMappingURL=index.js.map
