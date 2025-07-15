import { ClientAuthenticatorData } from '../IndexedDBManager';
import { base64Decode } from '../../utils/encoders';

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
 * Generate AES-GCM salt using account-specific HKDF for encryption key derivation
 * @param nearAccountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt for AES-GCM key derivation
 */
export function generateAesGcmSalt(nearAccountId: string): Uint8Array {
  const saltString = `aes-gcm-salt:${nearAccountId}`;
  const salt = new Uint8Array(32);
  const saltBytes = new TextEncoder().encode(saltString);
  salt.set(saltBytes.slice(0, 32));
  return salt;
}

/**
 * Generate Ed25519 salt using account-specific HKDF for signing key derivation
 * @param nearAccountId - NEAR account ID to scope the salt to
 * @returns 32-byte Uint8Array salt for Ed25519 key derivation
 */
export function generateEd25519Salt(nearAccountId: string): Uint8Array {
  const saltString = `ed25519-salt:${nearAccountId}`;
  const salt = new Uint8Array(32);
  const saltBytes = new TextEncoder().encode(saltString);
  salt.set(saltBytes.slice(0, 32));
  return salt;
}

/**
 * Generate account-specific PRF salt for WebAuthn (legacy single PRF)
 * @deprecated Use generateAesGcmSalt and generateEd25519Salt for dual PRF
 * @param nearAccountId - NEAR account ID to include in the salt
 * @returns 32-byte Uint8Array account-specific salt
 */
export function generateAccountSpecificPrfSalt(nearAccountId: string): Uint8Array {
  // Create account-specific salt for WebAuthn PRF
  // WASM worker will do additional HKDF domain separation for AES vs. Ed25519
  const saltString = `webauthn-prf-salt-v1:${nearAccountId}`;
  const salt = new Uint8Array(32);
  const saltBytes = new TextEncoder().encode(saltString);

  // Copy up to 32 bytes, padding with zeros if needed
  salt.set(saltBytes.slice(0, 32));
  return salt;
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
   * @returns WebAuthn credential with PRF output (HKDF derivation done in WASM worker)
   * ```ts
   * const credential = await touchIdPrompt.getCredentials({
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
          id: base64Decode(auth.credentialId),
          type: 'public-key' as const,
          transports: auth.transports as AuthenticatorTransport[]
        })),
        userVerification: 'preferred' as UserVerificationRequirement,
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: generateAesGcmSalt(nearAccountId),    // AES-GCM encryption keys
              second: generateEd25519Salt(nearAccountId)   // Ed25519 signing keys
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
   * Simplified authentication for account recovery
   * Uses credential IDs from contract without needing full authenticator data
   * @param nearAccountId - NEAR account ID to authenticate
   * @param challenge - VRF challenge bytes
   * @param credentialIds - Array of credential IDs from contract lookup
   * @returns WebAuthn credential with PRF output
   */
  async getCredentialsForRecovery({
    nearAccountId,
    challenge,
    credentialIds
  }: {
    nearAccountId: string,
    challenge: Uint8Array<ArrayBuffer>,
    credentialIds: string[]
  }): Promise<PublicKeyCredential> {

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: window.location.hostname,
        allowCredentials: credentialIds.map(credentialId => ({
          id: base64Decode(credentialId),
          type: 'public-key' as const,
          transports: ['internal', 'hybrid', 'usb', 'ble'] as AuthenticatorTransport[]
          // Include all common transports
        })),
        userVerification: 'preferred' as UserVerificationRequirement,
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: generateAesGcmSalt(nearAccountId),    // AES-GCM encryption keys
              second: generateEd25519Salt(nearAccountId)   // Ed25519 signing keys
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
   * Generate WebAuthn registration credentials with PRF output for a new passkey
   * @param nearAccountId - NEAR account ID to register
   * @param challenge - Random challenge bytes for the registration ceremony
   * @returns Credential with PRF output
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
              first: generateAesGcmSalt(nearAccountId),    // AES-GCM encryption keys
              second: generateEd25519Salt(nearAccountId)   // Ed25519 signing keys
            }
          }
        }
      } as PublicKeyCredentialCreationOptions
    }) as PublicKeyCredential;

    return credential;
  }
}