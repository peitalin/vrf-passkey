/**
 * Minimal NEAR RPC client that replaces @near-js/providers
 * Only includes the methods actually used by PasskeyManager
 *
 * If needed, we can just wrap @near-js if we require more complex
 * functionality and type definitions
 */

import { FinalExecutionOutcome, QueryResponseKind } from "@near-js/types";
import { Signature, Transaction } from "@near-js/transactions";
// import { Provider } from "@near-js/providers";

export declare class SignedTransaction {
    transaction: any;
    signature: any;
    borsh_bytes?: number[] | undefined;

    constructor({ transaction, signature }: {
        transaction: Transaction;
        signature: Signature;
    });

    encode(): Uint8Array;

    static decode(bytes: Uint8Array): SignedTransaction;
}

export interface NearClient {
  viewAccessKey(accountId: string, publicKey: string): Promise<any>;
  viewBlock(params: { finality: string }): Promise<any>;
  // sendTransaction(signedTransaction: SignedTransaction): Promise<FinalExecutionOutcome>;
  sendTransaction(signedTransaction: Uint8Array | number[]): Promise<FinalExecutionOutcome>;
  query<T extends QueryResponseKind>(path: string, data: string): Promise<T>;
  view(params: { account: string; method: string; args: any }): Promise<any>;
}

export class MinimalNearClient implements NearClient {
  constructor(private rpcUrl: string) {}

  async query<T>(path: string, data: string): Promise<T> {
    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method: 'query',
        params: {
          request_type: path,
          ...JSON.parse(data)
        }
      })
    });

    // Check if response is ok (not rate limited, server error, etc.)
    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    // Get response text first to handle non-JSON responses
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

  async viewBlock(params: { finality: string }): Promise<any> {
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

  async sendTransaction(signedTransaction: Uint8Array | number[]): Promise<FinalExecutionOutcome> {
    // Convert to base64 - handle both Uint8Array and number[]
    const txBytes = signedTransaction instanceof Uint8Array
      ? signedTransaction
      : new Uint8Array(signedTransaction);
    const signedTransactionBase64 = Buffer.from(txBytes).toString('base64');

    const response = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: crypto.randomUUID(),
        method: 'send_tx',
        params: {
          signed_tx_base64: signedTransactionBase64,
          wait_until: 'EXECUTED_OPTIMISTIC'
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

    const result = await this.query<{ result: number[] }>('call_function', queryData);

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