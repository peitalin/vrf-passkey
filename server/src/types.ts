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
  derivedNearPublicKey?: string | null; // The NEAR public key derived from this passkey
}

// Types for PasskeyController Smart Contract interaction

export enum ActionType {
  CreateAccount = "CreateAccount",
  DeployContract = "DeployContract",
  FunctionCall = "FunctionCall",
  Transfer = "Transfer",
  Stake = "Stake",
  AddKey = "AddKey",
  DeleteKey = "DeleteKey",
  DeleteAccount = "DeleteAccount",
}

// Interface for the arguments expected by the contract's execute_actions method
export interface SerializableActionArgs {
  action_type: ActionType;
  receiver_id?: string;
  method_name?: string;
  args?: string; // Base64 encoded string of JSON args
  deposit?: string; // yoctoNEAR as string (e.g., "1000000000000000000000000")
  gas?: string; // Gas as string (e.g., "30000000000000")
  amount?: string; // yoctoNEAR as string, for Transfer
  public_key?: string; // For AddKey, DeleteKey, Stake
  allowance?: string; // yoctoNEAR as string, for AddKey (FunctionCallAccessKey)
  method_names?: string[]; // For AddKey (FunctionCallAccessKey)
  code?: string; // Base64 encoded string of contract code, for DeployContract
  stake?: string; // yoctoNEAR as string, for Stake
  beneficiary_id?: string; // For DeleteAccount
}