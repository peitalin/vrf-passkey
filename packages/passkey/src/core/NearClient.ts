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
 * A minimal NEAR RPC client that only includes the methods actually used by PasskeyManager
 * If needed, we can just wrap @near-js if we require more complex functionality and type definitions
 */
export interface NearClient {
  viewAccessKey(accountId: string, publicKey: PublicKey | string, finalityQuery?: FinalityReference): Promise<AccessKeyView>;
  viewAccessKeyList(accountId: string, finalityQuery?: FinalityReference): Promise<AccessKeyList>;
  viewAccount(accountId: string): Promise<any>;
  viewBlock(params: BlockReference): Promise<BlockResult>;
  sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil?: TxExecutionStatus
  ): Promise<FinalExecutionOutcome>;
  query<T extends QueryResponseKind>(path: string, data: string): Promise<T>;
  view(params: { account: string; method: string; args: any }): Promise<any>;
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
   * Execute single RPC call to specific endpoint
   */
  private async makeRpcCall(url: string, requestBody: object): Promise<any> {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
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
      throw new Error(`RPC Error: ${result.error.message}`);
    }

    return result;
  }

  /**
   * Make a single RPC call
   */
  private async makeDirectRpcCall<T>(
    method: string,
    params: any,
    operationName: string
  ): Promise<T> {
    const request = {
      jsonrpc: '2.0',
      id: crypto.randomUUID(),
      method,
      params
    };

    const result = await this.makeRpcCall(this.rpcUrl, request);

    // Check for query-specific errors in result.result
    if (result.result?.error) {
      throw new Error(`${operationName} Error: ${result.result.error}`);
    }

    return result.result;
  }

  // ===========================
  // PUBLIC API METHODS
  // ===========================

  async query<T extends QueryResponseKind>(params: RpcQueryRequest): Promise<T>;
  async query<T extends QueryResponseKind>(path: string, data: string): Promise<T>;
  async query<T extends QueryResponseKind>(pathOrParams: string | RpcQueryRequest, data?: string): Promise<T> {
    const params = typeof pathOrParams === 'string'
      ? { request_type: pathOrParams, ...JSON.parse(data!) }
      : pathOrParams;

    const finalParams = { ...params, finality: params.finality || 'final' };
    return this.makeDirectRpcCall<T>('query', finalParams, 'Query');
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

    return this.makeDirectRpcCall<AccessKeyView>('query', params, 'View Access Key');
  }

  async viewAccessKeyList(accountId: string, finalityQuery?: FinalityReference): Promise<AccessKeyList> {
    const finality = finalityQuery?.finality || 'final';

    const params = {
      request_type: 'view_access_key_list',
      finality: finality,
      account_id: accountId
    };

    return this.makeDirectRpcCall<AccessKeyList>('query', params, 'View Access Key List');
  }

  async viewAccount(accountId: string): Promise<any> {
    const params = {
      request_type: 'view_account',
      finality: 'final',
      account_id: accountId
    };

    return this.makeDirectRpcCall('query', params, 'View Account');
  }

  async viewBlock(params: BlockReference): Promise<BlockResult> {
    return this.makeDirectRpcCall<BlockResult>('block', params, 'View Block');
  }

  async sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil: TxExecutionStatus = DEFAULT_WAIT_STATUS.executeAction
  ): Promise<FinalExecutionOutcome> {

    const result = await this.makeRpcCall(this.rpcUrl, {
      jsonrpc: '2.0',
      id: crypto.randomUUID(),
      method: 'send_tx',
      params: {
        signed_tx_base64: signedTransaction.base64Encode(),
        wait_until: waitUntil
      }
    });

    if (result.error) {
      const errorMessage = result.error.data?.message || result.error.message || 'Transaction failed';
      throw new Error(`Transaction Error: ${errorMessage}`);
    }

    return result.result;
  }

  async view(params: { account: string; method: string; args: any }): Promise<any> {
    const rpcParams = {
      request_type: 'call_function',
      finality: 'final',
      account_id: params.account,
      method_name: params.method,
      args_base64: base64Encode(new TextEncoder().encode(JSON.stringify(params.args)))
    };

    const result = await this.makeDirectRpcCall<{ result: number[] }>('query', rpcParams, 'View Function');

    // Parse result bytes to string/JSON
    const resultBytes = result.result;
    if (!Array.isArray(resultBytes)) return result;

    const resultString = String.fromCharCode(...resultBytes);
    try {
      return JSON.parse(resultString);
    } catch {
      return resultString.replace(/^"|"$/g, ''); // Remove quotes
    }
  }
}