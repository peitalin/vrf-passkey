/**
 * Minimal NEAR RPC client that replaces @near-js/providers
 * Only includes the methods actually used by PasskeyManager
 *
 * If needed, we can just wrap @near-js if we require more complex
 * functionality and type definitions
 */

import {
  FinalExecutionOutcome,
  QueryResponseKind,
  TxExecutionStatus,
  AccessKeyView,
  AccessKeyList,
  AccountView,
  BlockResult,
  BlockReference,
  RpcQueryRequest,
  FinalityReference,
} from "@near-js/types";
import { Signature, Transaction } from "@near-js/transactions";
import { PublicKey } from "@near-js/crypto";
import { base64Encode } from "../utils";
import { DEFAULT_WAIT_STATUS } from "./types/rpc";
import { Provider } from "@near-js/providers";

interface ContractResult<T> extends QueryResponseKind {
  result?: T | string | number | any;
  logs: string[];
}

export enum RpcCallType {
  Query = "query",
  View = "view",
  Send = "send_tx",
  Block = "block",
  Call = "call_function",
}

export class SignedTransaction {
    transaction: Transaction;
    signature: Signature;
    borsh_bytes: number[];

    constructor({ transaction, signature, borsh_bytes }: {
      transaction: Transaction;
      signature: Signature;
      borsh_bytes: number[];
    }) {
      this.transaction = transaction;
      this.signature = signature;
      this.borsh_bytes = borsh_bytes;
    }

    encode(): Uint8Array {
        // If borsh_bytes are already available, use them
        return new Uint8Array(this.borsh_bytes);
    }

    base64Encode(): string {
        return base64Encode(this.encode());
    }

    static decode(bytes: Uint8Array): SignedTransaction {
        // This would need borsh deserialization
        throw new Error('SignedTransaction.decode(): borsh deserialization not implemented');
    }
}

/**
 * MinimalNearClient provides a simplified interface for NEAR protocol interactions
 */
export interface NearClient {
  viewAccessKey(accountId: string, publicKey: PublicKey | string, finalityQuery?: FinalityReference): Promise<AccessKeyView>;
  viewAccessKeyList(accountId: string, finalityQuery?: FinalityReference): Promise<AccessKeyList>;
  viewAccount(accountId: string): Promise<AccountView>;
  viewBlock(params: BlockReference): Promise<BlockResult>;
  sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil?: TxExecutionStatus
  ): Promise<FinalExecutionOutcome>;
  query<T extends QueryResponseKind>(params: RpcQueryRequest): Promise<T>;
  callFunction<T>(
    contractId: string,
    method: string,
    args: Record<string, unknown>,
    blockQuery?: BlockReference
  ): Promise<T>;
  view<T>(params: { account: string; method: string; args: any }): Promise<T>;
}

export class MinimalNearClient implements NearClient {
  private readonly rpcUrl: string;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
  }

  // ===========================
  // PRIVATE HELPER FUNCTIONS
  // ===========================

  /**
   * Execute RPC call with proper error handling and result extraction
   */
  private async makeRpcCall<T>(
    method: string,
    params: any,
    operationName: string
  ): Promise<T> {

    const body = {
      jsonrpc: '2.0',
      id: crypto.randomUUID(),
      method,
      params
    };

    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    const responseText = await response.text();
    if (!responseText?.trim()) {
      throw new Error('Empty response from RPC server');
    }

    const result = JSON.parse(responseText);
    if (result.error) {
      throw result.error;
    }

    // Check for query-specific errors in result.result
    if (result.result?.error) {
      throw new Error(`${operationName} Error: ${result.result.error}`);
    }

    return result.result;
  }

  // ===========================
  // PUBLIC API METHODS
  // ===========================

  async query<T extends QueryResponseKind>(params: RpcQueryRequest): Promise<T> {
    return this.makeRpcCall<T>(RpcCallType.Query, params, 'Query');
  }

  async viewAccessKey(accountId: string, publicKey: PublicKey | string, finalityQuery?: FinalityReference): Promise<AccessKeyView> {
    const publicKeyStr = typeof publicKey === 'string' ? publicKey : publicKey.toString();
    const finality = finalityQuery?.finality || 'final';

    const params = {
      request_type: 'view_access_key',
      finality: finality,
      account_id: accountId,
      public_key: publicKeyStr
    };

    return this.makeRpcCall<AccessKeyView>(RpcCallType.Query, params, 'View Access Key');
  }

  async viewAccessKeyList(accountId: string, finalityQuery?: FinalityReference): Promise<AccessKeyList> {
    const finality = finalityQuery?.finality || 'final';

    const params = {
      request_type: 'view_access_key_list',
      finality: finality,
      account_id: accountId
    };

    return this.makeRpcCall<AccessKeyList>(RpcCallType.Query, params, 'View Access Key List');
  }

  async viewAccount(accountId: string): Promise<AccountView> {
    const params = {
      request_type: 'view_account',
      finality: 'final',
      account_id: accountId
    };

    return this.makeRpcCall<AccountView>(RpcCallType.Query, params, 'View Account');
  }

  async viewBlock(params: BlockReference): Promise<BlockResult> {
    return this.makeRpcCall<BlockResult>(RpcCallType.Block, params, 'View Block');
  }

  async sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil: TxExecutionStatus = DEFAULT_WAIT_STATUS.executeAction
  ): Promise<FinalExecutionOutcome> {
    return await this.makeRpcCall<FinalExecutionOutcome>(
      RpcCallType.Send,
      {
        signed_tx_base64: signedTransaction.base64Encode(),
        wait_until: waitUntil
      },
      'Send Transaction'
    );
  }

  async callFunction<T>(
    contractId: string,
    method: string,
    args: Record<string, unknown>,
    blockQuery?: BlockReference
  ): Promise<T> {
    const rpcParams = {
      request_type: 'call_function',
      finality: 'final',
      account_id: contractId,
      method_name: method,
      args_base64: base64Encode(new TextEncoder().encode(JSON.stringify(args)))
    };

    const result = await this.makeRpcCall<ContractResult<T>>(
      RpcCallType.Query,
      rpcParams,
      'View Function'
    );

    // Parse result bytes to string/JSON
    const resultBytes = result.result;
    if (!Array.isArray(resultBytes)) {
      // If result is not bytes array, it might already be parsed
      return result as unknown as T;
    }

    const resultString = String.fromCharCode(...resultBytes);
    if (!resultString.trim()) {
      return null as T;
    }

    try {
      const parsed = JSON.parse(resultString);
      return parsed as T;
    } catch {
      // Return the string value if it's not valid JSON
      const cleanString = resultString.replace(/^"|"$/g, ''); // Remove quotes
      return cleanString as T;
    }
  }

  async view<T>(params: { account: string; method: string; args: any }): Promise<T> {
    return this.callFunction<T>(params.account, params.method, params.args);
  }
}