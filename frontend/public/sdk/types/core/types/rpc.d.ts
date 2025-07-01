import { AccessKeyView, TxExecutionStatus } from "@near-js/types";
import { ClientUserData } from "../IndexedDBManager";
export declare const DEFAULT_WAIT_STATUS: {
    executeAction: TxExecutionStatus;
};
export interface NearRpcCallParams {
    jsonrpc: string;
    id: string;
    method: string;
    params: {
        signed_tx_base64: string;
        wait_until: TxExecutionStatus;
    };
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
//# sourceMappingURL=rpc.d.ts.map