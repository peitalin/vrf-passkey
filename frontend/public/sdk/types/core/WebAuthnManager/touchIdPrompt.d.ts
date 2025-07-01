import { ClientAuthenticatorData } from '../IndexedDBManager';
export interface RegisterCredentialsArgs {
    nearAccountId: string;
    challenge: Uint8Array<ArrayBuffer>;
}
export interface AuthenticateCredentialsArgs {
    nearAccountId: string;
    challenge: Uint8Array<ArrayBuffer>;
    authenticators: ClientAuthenticatorData[];
}
export interface TouchIdCredentialsResult {
    credential: PublicKeyCredential;
    prfOutput: ArrayBuffer;
}
/**
 * TouchIdPrompt prompts for touchID,
 * creates credentials,
 * manages WebAuthn touchID prompts,
 * and generates credentials, and PRF Outputs
 */
export declare class TouchIdPrompt {
    constructor();
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
    getCredentialsAndPrf({ nearAccountId, challenge, authenticators }: AuthenticateCredentialsArgs): Promise<TouchIdCredentialsResult>;
    /**
     * Generate WebAuthn registration credentials and PRF output for a new passkey
     * @param nearAccountId - NEAR account ID to register the passkey for
     * @param challenge - Random challenge bytes for the registration ceremony
     * @returns Credential and PRF output for VRF keypair generation
     */
    generateRegistrationCredentialsAndPrf({ nearAccountId, challenge, }: RegisterCredentialsArgs): Promise<TouchIdCredentialsResult>;
}
//# sourceMappingURL=touchIdPrompt.d.ts.map