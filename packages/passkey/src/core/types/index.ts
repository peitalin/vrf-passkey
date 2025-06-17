
// === RESULT TYPES FOR PASSKEY SDK ===

import type { PasskeyErrorDetails } from './errors';

/**
 * Generic Result type for better error handling throughout the SDK
 * Replaces boolean success flags with discriminated unions for type safety
 */
export type Result<T, E = PasskeyErrorDetails> =
  | { success: true; data: T }
  | { success: false; error: E };

/**
 * ActionType is the type of action to be performed
 * Copied from server/src/types.ts for frontend use
 */
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

/**
 * Arguments for serializable NEAR actions that can be passed between contexts
 * All numeric values are represented as strings to maintain precision
 */
export interface SerializableActionArgs {
  /** Type of NEAR action to perform */
  action_type: ActionType;
  /** Account ID of the receiver for the action */
  receiver_id?: string;
  /** Name of the contract method to call */
  method_name?: string;
  /** Base64 encoded string of JSON arguments for contract calls */
  args?: string;
  /** Amount of yoctoNEAR to attach to the call */
  deposit?: string;
  /** Maximum amount of gas to use for the call */
  gas?: string;
  /** Amount of yoctoNEAR to transfer (for Transfer action) */
  amount?: string;
  /** Public key for key management actions (AddKey, DeleteKey, Stake) */
  public_key?: string;
  /** Maximum amount of yoctoNEAR allowed for function call access key */
  allowance?: string;
  /** List of method names allowed for function call access key */
  method_names?: string[];
  /** Base64 encoded contract code for deployment */
  code?: string;
  /** Amount of yoctoNEAR to stake (for Stake action) */
  stake?: string;
  /** Account ID that will receive the balance (for DeleteAccount) */
  beneficiary_id?: string;
}