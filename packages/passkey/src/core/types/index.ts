
// === RESULT TYPES FOR PASSKEY SDK ===

import type { PasskeyErrorDetails } from './errors';
import { TxExecutionStatus } from '@near-js/types';
import { CallFunctionRequest, RpcQueryRequest } from '@near-js/types';
import { ActionType } from './worker';

export interface NearRpcCallParams {
  jsonrpc: string;
  id: string;
  method: string;
  params: {
    signed_tx_base64: string;
    wait_until: TxExecutionStatus;
  }
}

/**
 * Generic Result type for better error handling throughout the SDK
 * Replaces boolean success flags with discriminated unions for type safety
 */
export type Result<T, E = PasskeyErrorDetails> =
  | { success: true; data: T }
  | { success: false; error: E };

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