import { generateUserScopedPrfSalt } from '@/utils';
import { ClientAuthenticatorData } from '../IndexedDBManager';

export interface TouchIdAndGenerateCredentialsArgs {
  nearAccountId: string,
  challenge: Uint8Array<ArrayBuffer>,
  authenticators: ClientAuthenticatorData[],
}
export interface TouchIdAndGenerateCredentialsResult {
  credential: PublicKeyCredential,
  prfOutput: ArrayBuffer
}

/**
 * TouchIdPrompt prompts for touchID,
 * creates credentials,
 * manages WebAuthn touchID prompts,
 * and generates credentials, and PRF Outputs
 */
export class TouchIdPrompt {

  constructor() {}

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
  async getCredentialsAndPrf({
    nearAccountId,
    challenge,
    authenticators,
  }: TouchIdAndGenerateCredentialsArgs): Promise<TouchIdAndGenerateCredentialsResult> {

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: window.location.hostname,
        allowCredentials: authenticators.map(auth => ({
          id: new Uint8Array(Buffer.from(auth.credentialID, 'base64')),
          type: 'public-key' as const,
          transports: auth.transports as AuthenticatorTransport[]
        })),
        userVerification: 'preferred' as UserVerificationRequirement,
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: generateUserScopedPrfSalt(nearAccountId) // User-scoped PRF salt
            }
          }
        }
      } as PublicKeyCredentialRequestOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn authentication failed or was cancelled');
    }
    // Get PRF output for VRF decryption
    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = extensionResults?.prf?.results?.first as ArrayBuffer;
    if (!prfOutput) {
      throw new Error('PRF output not available - required for VRF keypair decryption');
    }
    console.log('✅ WebAuthn authentication successful, PRF output obtained');
    return {
      credential,
      prfOutput
    }
  }
}