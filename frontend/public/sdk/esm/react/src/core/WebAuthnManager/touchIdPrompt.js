import { generateUserScopedPrfSalt } from '../../utils/index.js';

/**
 * TouchIdPrompt prompts for touchID,
 * creates credentials,
 * manages WebAuthn touchID prompts,
 * and generates credentials, and PRF Outputs
 */
class TouchIdPrompt {
    constructor() { }
    /**
     * Prompts for TouchID/biometric authentication and generates WebAuthn credentials with PRF output
     * @param nearAccountId - NEAR account ID to authenticate
     * @param challenge - VRF challenge bytes to use for WebAuthn authentication
     * @param authenticators - List of stored authenticator data for the user
     * @returns Object with WebAuthn credential and PRF output for VRF keypair decryption:
     * ```ts
     * { credential: PublicKeyCredential, prfOutput: ArrayBuffer }
     * ```
     * @example
     * ```ts
     * const { credential, prfOutput } = await touchIdPrompt.getCredentialsAndPrf({
     *   nearAccountId,
     *   challenge,
     *   authenticators,
     * });
     * ```
     */
    async getCredentialsAndPrf({ nearAccountId, challenge, authenticators }) {
        const credential = await navigator.credentials.get({
            publicKey: {
                challenge,
                rpId: window.location.hostname,
                allowCredentials: authenticators.map(auth => ({
                    id: new Uint8Array(Buffer.from(auth.credentialID, 'base64')),
                    type: 'public-key',
                    transports: auth.transports
                })),
                userVerification: 'preferred',
                timeout: 60000,
                extensions: {
                    prf: {
                        eval: {
                            first: generateUserScopedPrfSalt(nearAccountId) // User-scoped PRF salt
                        }
                    }
                }
            }
        });
        if (!credential) {
            throw new Error('WebAuthn authentication failed or was cancelled');
        }
        // Get PRF output for VRF decryption
        const extensionResults = credential.getClientExtensionResults();
        const prfOutput = extensionResults?.prf?.results?.first;
        if (!prfOutput) {
            throw new Error('PRF output not available - required for VRF keypair decryption');
        }
        console.log('✅ WebAuthn authentication successful, PRF output obtained');
        return {
            credential,
            prfOutput
        };
    }
    /**
     * Generate WebAuthn registration credentials and PRF output for a new passkey
     * @param nearAccountId - NEAR account ID to register the passkey for
     * @param challenge - Random challenge bytes for the registration ceremony
     * @returns Credential and PRF output for VRF keypair generation
     */
    async generateRegistrationCredentialsAndPrf({ nearAccountId, challenge, }) {
        const credential = await navigator.credentials.create({
            publicKey: {
                challenge,
                rp: {
                    name: 'WebAuthn VRF Passkey',
                    id: window.location.hostname
                },
                user: {
                    id: new TextEncoder().encode(nearAccountId),
                    name: nearAccountId,
                    displayName: nearAccountId
                },
                pubKeyCredParams: [
                    { alg: -7, type: 'public-key' }, // ES256
                    { alg: -257, type: 'public-key' } // RS256
                ],
                authenticatorSelection: {
                    residentKey: 'required',
                    userVerification: 'preferred'
                },
                timeout: 60000,
                attestation: 'none',
                extensions: {
                    prf: {
                        eval: {
                            first: generateUserScopedPrfSalt(nearAccountId) // User-scoped PRF salt
                        }
                    }
                }
            }
        });
        return {
            credential,
            prfOutput: credential.getClientExtensionResults()?.prf?.results?.first
        };
    }
}

export { TouchIdPrompt };
//# sourceMappingURL=touchIdPrompt.js.map
