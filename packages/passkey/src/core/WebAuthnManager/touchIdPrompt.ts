import { generateUserScopedPrfSalt } from '@/utils';
import { ClientAuthenticatorData } from '../IndexedDBManager';

export interface RegisterCredentialsArgs {
  nearAccountId: string,
  challenge: Uint8Array<ArrayBuffer>,
}

export interface AuthenticateCredentialsArgs {
  nearAccountId: string,
  challenge: Uint8Array<ArrayBuffer>,
  authenticators: ClientAuthenticatorData[],
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
  async getCredentials({
    nearAccountId,
    challenge,
    authenticators
  }: AuthenticateCredentialsArgs): Promise<PublicKeyCredential> {

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
    return credential;
  }

  /**
   * Generate WebAuthn registration credentials and PRF output for a new passkey
   * @param nearAccountId - NEAR account ID to register the passkey for
   * @param challenge - Random challenge bytes for the registration ceremony
   * @returns Credential and PRF output for VRF keypair generation
   */
  async generateRegistrationCredentials({
    nearAccountId,
    challenge,
  }: RegisterCredentialsArgs): Promise<PublicKeyCredential> {
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
      } as PublicKeyCredentialCreationOptions
    }) as PublicKeyCredential;

    return credential;
  }
}