import { ClientAuthenticatorData } from '../IndexedDBManager';
import { base64Decode, base64UrlDecode } from '../../utils/encoders';

export interface RegisterCredentialsArgs {
  nearAccountId: string,
  challenge: Uint8Array<ArrayBuffer>,
  deviceNumber?: number, // Optional device number for device-specific user ID (0, 1, 2, etc.)
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
          id: base64UrlDecode(auth.credentialId),
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
          id: base64UrlDecode(credentialId),
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
   * @param deviceNumber - Device number for device-specific user ID.
   * e.g. bob.1.testnet, where 1 is the device number.
   * For registration leave it blank if you want bob.testnet for the userID (device 0)
   * This is mostly for device linking purposes: giving the 2nd device a unique passkey userId
   * so that chrome passkey sync doesn't overwrite the old passkey
   * @returns Credential with PRF output
   */
  async generateRegistrationCredentials({
    nearAccountId,
    challenge,
    deviceNumber // Only provide during device linking, not during registration
  }: RegisterCredentialsArgs): Promise<PublicKeyCredential> {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          name: 'WebAuthn VRF Passkey',
          id: window.location.hostname
        },
        user: {
          id: new TextEncoder().encode(generateDeviceSpecificUserId(nearAccountId, deviceNumber)),
          name: generateDeviceSpecificUserId(nearAccountId, deviceNumber),
          displayName: generateDeviceSpecificUserId(nearAccountId, deviceNumber)
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

/**
 * Generate device-specific user ID to prevent Chrome sync conflicts
 * Uses device number for device identification
 *
 * @param nearAccountId - The NEAR account ID (e.g., "serp120.web3-authn.testnet")
 * @param deviceNumber - The device number (optional, 0 for device 1, 1 for device 2, etc.)
 * @returns Device-specific user ID:
 *   - Device 0 (first device): "serp120.web3-authn.testnet" (original account ID)
 *   - Device 1 (second device): "serp120.1.web3-authn.testnet"
 *   - Device 2 (third device): "serp120.2.web3-authn.testnet"
 */
function generateDeviceSpecificUserId(nearAccountId: string, deviceNumber?: number): string {
  // If no device number provided or device number is 0, this is the first device (registration)
  if (deviceNumber === undefined || deviceNumber === 0) {
    return nearAccountId;
  }

  // Add device number to account ID
  if (nearAccountId.includes('.')) {
    const parts = nearAccountId.split('.');
    // Insert device number after the first part
    // "serp120.web3-authn.testnet" -> "serp120.1.web3-authn.testnet"
    parts.splice(1, 0, deviceNumber.toString());
    return parts.join('.');
  } else {
    // Fallback for accounts without dots
    return `${nearAccountId}.${deviceNumber}`;
  }
}