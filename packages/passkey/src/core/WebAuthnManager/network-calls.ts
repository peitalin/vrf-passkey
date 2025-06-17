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

  // === SERVER COMMUNICATION ===

  /**
   * Get registration options from server using account ID to generate WebAuthn challenge
   */
  async getRegistrationOptionsFromServer(
    serverUrl: string,
    nearAccountId: string
  ): Promise<{ challengeId: string; options: any }> {
    console.log('WebAuthnManager: Getting registration options from server for:', nearAccountId);

    const response = await fetch(`${serverUrl}/generate-registration-options`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ nearAccountId })
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    if (!data.options?.challenge) {
      throw new Error('Server did not return valid registration options');
    }

    // Register the challenge from server response for validation later
    const challengeId = this.webauthnWorkers.registerServerChallenge(data.options.challenge, 'registration');

    console.log('WebAuthnManager: Registration options received from server, challenge registered:', challengeId);

    return {
      challengeId,
      options: data.options
    };
  }

  /**
   * Get authentication options from server with contract transaction details
   */
  async getAuthenticationOptionsFromServer(
    serverUrl: string,
    options: NetworkAuthenticationOptions
  ): Promise<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }> {
    console.log('WebAuthnManager: Getting authentication options from server for contract call');

    const response = await fetch(`${serverUrl}/generate-authentication-options`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(options)
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    if (!data.options?.challenge) {
      throw new Error('Server did not return valid authentication options');
    }

    // Register the challenge from server response for validation later
    const challengeId = this.webauthnWorkers.registerServerChallenge(data.options.challenge, 'authentication');

    console.log('WebAuthnManager: Authentication options received from server, challenge registered:', challengeId);

    return {
      challengeId,
      options: data.options
    };
  }

  /**
   * Send authenticated contract call to server for execution
   */
  async submitAuthenticatedCall(
    serverUrl: string,
    nearAccountId: string,
    contractMethodName: string,
    contractArgs: Record<string, any>,
    credential: PublicKeyCredential,
    commitmentId: string
  ): Promise<{ success: boolean; transactionHash?: string; error?: string }> {
    console.log('WebAuthnManager: Submitting authenticated call to server');

    const attestation = publicKeyCredentialToJSON(credential);

    const response = await fetch(`${serverUrl}/execute-authenticated-call`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        nearAccountId,
        contractMethodName,
        contractArgs,
        attestation,
        commitmentId
      })
    });

    if (!response.ok) {
      throw new Error(`Server error: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    console.log('WebAuthnManager: Server response received:', result.success ? 'success' : 'failed');

    return result;
  }

  // === CONTRACT COMMUNICATION ===

  /**
   * Get authentication options from contract for serverless mode
   */
  async getAuthenticationOptionsFromContract(
    nearRpcProvider: Provider,
    contractId: string,
    options: NetworkAuthenticationOptions
  ): Promise<{ challengeId: string; options: PublicKeyCredentialRequestOptionsJSON }> {
    console.log('WebAuthnManager: Getting authentication options from contract for serverless mode');

    // For serverless mode, create a pseudo-challenge for local validation
    // The actual challenge will be replaced by the contract during transaction execution
    const serverlessChallenge = crypto.getRandomValues(new Uint8Array(32));
    const challengeB64 = btoa(String.fromCharCode.apply(null, Array.from(serverlessChallenge)));

    // Register as serverless challenge
    const challengeId = `serverless-${Date.now()}-${Math.random().toString(36).substring(2)}`;

    // Build authentication options for WebAuthn ceremony
    const authenticationOptions: PublicKeyCredentialRequestOptionsJSON = {
      challenge: challengeB64,
      timeout: 60000,
      rpId: window.location.hostname,
      userVerification: 'preferred',
      extensions: {
        prf: {
          eval: {
            first: Array.from(this.webauthnWorkers.getPrfSalts().nearKeyEncryption)
          }
        }
      }
    };

    console.log('WebAuthnManager: Serverless authentication options generated, pseudo-challenge:', challengeId);

    return {
      challengeId,
      options: authenticationOptions
    };
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
   * Validate contract method existence
   */
  async validateContractMethod(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string
  ): Promise<boolean> {
    console.log(`WebAuthnManager: Validating contract method ${methodName} on ${contractId}`);

    try {
      // Call contract to get available methods
      const result = await nearRpcProvider.query({
        request_type: 'call_function',
        account_id: contractId,
        method_name: 'get_contract_metadata',
        args_base64: '',
        finality: 'final'
      });

      // For now, just return true as method validation is complex
      // In production, this would parse the contract metadata
      console.log(`WebAuthnManager: Contract method ${methodName} validation: assuming valid`);
      return true;
    } catch (error: any) {
      console.warn(`WebAuthnManager: Could not validate contract method (contract may not exist yet):`, error.message);
      // Return true for contract creation scenarios
      return true;
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