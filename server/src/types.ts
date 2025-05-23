import type { AuthenticatorTransport } from '@simplewebauthn/types';

/**
 * Represents a user in the system.
 */
export interface User {
  id: string; // A unique identifier for the user (e.g., the username itself or a UUID)
  username: string;
  currentChallenge?: string; // To store the challenge for the current WebAuthn operation
}

/**
 * Represents an authenticator registered by a user, structured for storage
 * and for use with @simplewebauthn/server verification functions.
 */
export interface StoredAuthenticator {
  credentialID: string; // Stored as Base64URL string from the original Uint8Array
  credentialPublicKey: Uint8Array; // Stored as Uint8Array (or convert from PEM/other format if necessary)
  counter: number;
  transports?: AuthenticatorTransport[];

  // Application-specific fields:
  userId: string; // Link back to the user this authenticator belongs to
  name?: string; // A user-friendly name for the authenticator
  registered: Date;
  lastUsed?: Date;
  // BackedUp is an important property for passkeys to indicate if they are synced across devices.
  // simplewebauthn's verifyRegistrationResponse can provide this as `credentialBackedUp`.
  backedUp: boolean;
}