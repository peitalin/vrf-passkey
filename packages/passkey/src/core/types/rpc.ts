import { AccessKeyView, TxExecutionStatus } from "@near-js/types";
import { ClientUserData } from "../IndexedDBManager";

export const DEFAULT_WAIT_STATUS = {
  executeAction: "EXECUTED_OPTIMISTIC" as TxExecutionStatus,
  // See default finality settings:
  // https://github.com/near/near-api-js/blob/99f34864317725467a097dc3c7a3cc5f7a5b43d4/packages/accounts/src/account.ts#L68
}

export interface NearRpcCallParams {
  jsonrpc: string;
  id: string;
  method: string;
  params: {
    signed_tx_base64: string;
    wait_until: TxExecutionStatus;
  }
}

export interface TransactionContext {
  userData: ClientUserData;
  publicKeyStr: string;
  accessKeyInfo: AccessKeyView;
  transactionBlockInfo: BlockInfo;
  nonce: bigint;
  transactionBlockHashBytes: number[];
}

export interface BlockInfo {
  header: {
    hash: string;
    height: number;
  };
}
export interface RpcErrorData {
  message?: string;
}

export interface RpcError {
  data?: RpcErrorData;
  message?: string;
}

export interface RpcResponse {
  error?: RpcError;
  result?: any;
}
