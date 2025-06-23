import type { Provider } from '@near-js/providers';
import type { PublicKeyCredentialRequestOptionsJSON } from '../types/webauthn';
import { publicKeyCredentialToJSON } from '../../utils/encoders';
import { WebAuthnWorkers } from './webauthn-workers';
import type { NetworkAuthenticationOptions } from '../types/worker';

/**
 * WebAuthnNetworkCalls handles server/contract communication
 */
export class WebAuthnNetworkCalls {
  private readonly webauthnWorkers: WebAuthnWorkers;

  constructor(webauthnWorkers: WebAuthnWorkers) {
    this.webauthnWorkers = webauthnWorkers;
  }

  /**
   * Get current network information for transaction building
   */
  async getNetworkInfo(nearRpcProvider: Provider): Promise<{
    blockHash: Uint8Array;
    nonce: string;
  }> {
    console.log('WebAuthnManager: Getting network info for transaction building');

    try {
      // Get latest block for hash and nonce
      const blockInfo = await nearRpcProvider.block({ finality: 'final' });
      const blockHash = new Uint8Array(Buffer.from(blockInfo.header.hash, 'base64'));

      // For demo purposes, use current timestamp as nonce
      // In production, this should be retrieved from the account's current nonce
      const nonce = Date.now().toString();

      console.log('WebAuthnManager: Network info retrieved successfully');

      return { blockHash, nonce };
    } catch (error: any) {
      console.error('WebAuthnManager: Failed to get network info:', error);
      throw new Error(`Failed to get network information: ${error.message}`);
    }
  }

  /**
   * Estimate gas for contract call
   */
  async estimateGas(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: Record<string, any>
  ): Promise<string> {
    console.log(`WebAuthnManager: Estimating gas for ${methodName} on ${contractId}`);

    // For now, use static gas estimates based on method type
    // TODO: Implement actual gas estimation via RPC
    const baseGas = methodName.includes('register') ? '300000000000000' : '100000000000000';

    console.log(`WebAuthnManager: Estimated gas: ${baseGas}`);
    return baseGas;
  }

  /**
   * Check account access key permissions
   */
  async checkAccountPermissions(
    nearRpcProvider: Provider,
    accountId: string,
    publicKey: string
  ): Promise<{ hasPermission: boolean; allowedReceivers?: string[]; allowedMethods?: string[] }> {
    console.log(`WebAuthnManager: Checking permissions for account ${accountId} with key ${publicKey}`);

    try {
      const response = await nearRpcProvider.viewAccessKey(accountId, publicKey);

      if (response && response.permission) {
        if (response.permission === 'FullAccess') {
          console.log('WebAuthnManager: Account has full access permissions');
          return { hasPermission: true };
        } else if (response.permission.FunctionCall) {
          const funcCall = response.permission.FunctionCall;
          console.log('WebAuthnManager: Account has function call permissions:', funcCall);
          return {
            hasPermission: true,
            allowedReceivers: funcCall.receiver_id ? [funcCall.receiver_id] : undefined,
            allowedMethods: funcCall.method_names || undefined
          };
        }
      }

      console.log('WebAuthnManager: No valid permissions found');
      return { hasPermission: false };

    } catch (error: any) {
      console.warn('WebAuthnManager: Could not check account permissions:', error.message);
      // Assume permission exists if we can't check (account might not exist yet)
      return { hasPermission: true };
    }
  }
}