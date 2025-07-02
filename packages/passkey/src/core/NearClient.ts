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
  BlockResult,
  BlockReference,
  RpcQueryRequest,
} from "@near-js/types";
import { Signature, Transaction } from "@near-js/transactions";
import { base64Encode } from "../utils";
import { DEFAULT_WAIT_STATUS } from "./types/rpc";
import { Provider } from "@near-js/providers";

export class SignedTransaction {
    transaction: any;
    signature: any;
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

export interface NearClient {
  viewAccessKey(accountId: string, publicKey: string): Promise<AccessKeyView>;
  viewBlock(params: BlockReference): Promise<BlockResult>;
  sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil?: TxExecutionStatus
  ): Promise<FinalExecutionOutcome>;
  query<T extends QueryResponseKind>(path: string, data: string): Promise<T>;
  view(params: { account: string; method: string; args: any }): Promise<any>;
}

export class MinimalNearClient implements NearClient {
  constructor(private rpcUrl: string) {}

  async query<T extends QueryResponseKind>(params: RpcQueryRequest): Promise<T>;
  async query<T extends QueryResponseKind>(path: string, data: string): Promise<T>;
  async query<T extends QueryResponseKind>(pathOrParams: string | RpcQueryRequest, data?: string): Promise<T> {
    let params;
    if (typeof pathOrParams === 'string') {
      params = {
        request_type: pathOrParams,
        ...JSON.parse(data!)
      };
    } else {
      params = pathOrParams;
    }

    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method: 'query',
        params
      })
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    const responseText = await response.text();
    if (!responseText || responseText.trim() === '') {
      throw new Error('Empty response from RPC server');
    }

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      throw new Error(`Invalid JSON response from RPC server: ${responseText.substring(0, 100)}...`);
    }

    if (result.error) {
      throw new Error(`RPC Error: ${result.error.message}`);
    }
    return result.result;
  }

  async viewAccessKey(accountId: string, publicKey: string): Promise<any> {
    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method: 'query',
        params: {
          request_type: 'view_access_key',
          finality: 'final',
          account_id: accountId,
          public_key: publicKey
        }
      })
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    const responseText = await response.text();
    if (!responseText || responseText.trim() === '') {
      throw new Error('Empty response from RPC server');
    }

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      throw new Error(`Invalid JSON response from RPC server: ${responseText.substring(0, 100)}...`);
    }

    if (result.error) {
      throw new Error(`RPC Error: ${result.error.message}`);
    }
    return result.result;
  }

  async viewBlock(params: BlockReference): Promise<BlockResult> {
    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method: 'block',
        params
      })
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    const responseText = await response.text();
    if (!responseText || responseText.trim() === '') {
      throw new Error('Empty response from RPC server');
    }

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      throw new Error(`Invalid JSON response from RPC server: ${responseText.substring(0, 100)}...`);
    }

    if (result.error) {
      throw new Error(`RPC Error: ${result.error.message}`);
    }
    return result.result;
  }

  async sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil: TxExecutionStatus = DEFAULT_WAIT_STATUS.executeAction
  ): Promise<FinalExecutionOutcome> {
    // Convert signed transaction to base64 using the encode method
    const signedTransactionBase64 = signedTransaction.base64Encode();

    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method: 'send_tx',
        params: {
          signed_tx_base64: signedTransactionBase64,
          wait_until: waitUntil
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Transaction broadcast failed: ${response.status} ${response.statusText}`);
    }

    const responseText = await response.text();
    if (!responseText || responseText.trim() === '') {
      throw new Error('Empty response from RPC server');
    }

    let result;
    try {
      result = JSON.parse(responseText);
    } catch (parseError) {
      throw new Error(`Invalid JSON response from RPC server: ${responseText.substring(0, 100)}...`);
    }

    if (result.error) {
      const errorMessage = result.error.data?.message || result.error.message || 'Transaction broadcast failed';
      throw new Error(`Transaction broadcast failed: ${errorMessage}`);
    }

    return result.result;
  }

  async view(params: { account: string; method: string; args: any }): Promise<any> {
    // Use the generic query function for the RPC call
    const queryData = JSON.stringify({
      finality: 'final',
      account_id: params.account,
      method_name: params.method,
      args_base64: Buffer.from(JSON.stringify(params.args)).toString('base64')
    });

    const result = await this.query<{ result: number[] } & QueryResponseKind>(
      'call_function',
      queryData
    );

    // Parse the result bytes as a string (typical for view functions that return strings)
    const resultBytes = result.result;
    if (Array.isArray(resultBytes)) {
      const resultString = String.fromCharCode(...resultBytes);
      try {
        // Try to parse as JSON first (for complex return types)
        return JSON.parse(resultString);
      } catch {
        // If not JSON, return as string (for simple string returns)
        return resultString.replace(/^"|"$/g, ''); // Remove surrounding quotes if present
      }
    }

    return result;
  }
}