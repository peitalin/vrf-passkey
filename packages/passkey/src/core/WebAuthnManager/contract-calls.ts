import type { Provider } from '@near-js/providers';
import type { FinalExecutionOutcome } from '@near-js/types';
import { SignedTransaction } from '@near-js/transactions';
import { WebAuthnWorkers } from './webauthn-workers';
import { WebAuthnNetworkCalls } from './network-calls';
import { indexDBManager } from '../IndexDBManager';
import { bufferDecode } from '../../utils/encoders';
import bs58 from 'bs58';
import type {
  ContractCallOptions,
  AccessKeyView
} from '../types/worker';

/**
 * WebAuthnContractCalls handles blockchain contract interactions
 */
export class WebAuthnContractCalls {
  private readonly webauthnWorkers: WebAuthnWorkers;
  private readonly networkCalls: WebAuthnNetworkCalls;

  constructor(webauthnWorkers: WebAuthnWorkers, networkCalls: WebAuthnNetworkCalls) {
    this.webauthnWorkers = webauthnWorkers;
    this.networkCalls = networkCalls;
  }

  /**
   * Unified contract call function that intelligently handles all scenarios:
   * - View functions (no auth required)
   * - State-changing functions (with auth)
   * - Batch operations (with PRF reuse)
   */
  async callContract(
    nearRpcProvider: Provider,
    options: ContractCallOptions
  ): Promise<any> {
    const {
      contractId,
      methodName,
      args,
      gas = '50000000000000',
      attachedDeposit = '0',
      nearAccountId,
      prfOutput,
      viewOnly = false,
      requiresAuth = false
    } = options;

    // 1. Handle explicit view-only calls
    if (viewOnly) {
      return this.executeViewCall(nearRpcProvider, contractId, methodName, args);
    }

    // 2. Handle state-changing calls
    console.log(`Executing state-changing call: ${methodName}`);

    // 2a. Use pre-obtained PRF if available (batch mode)
    if (prfOutput && nearAccountId) {
      return this.executeAuthenticatedCallWithPrf(
        nearRpcProvider,
        contractId,
        methodName,
        args,
        gas,
        attachedDeposit,
        nearAccountId,
        prfOutput
      );
    }

    // 2b. Regular authenticated call requires nearAccountId
    if (!nearAccountId) {
      throw new Error('NEAR account ID required for authenticated contract calls');
    }

    return this.executeAuthenticatedCall(
      nearRpcProvider,
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit,
      nearAccountId
    );
  }

  /**
   * Execute a view call (read-only, no authentication)
   */
  async executeViewCall(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: any
  ): Promise<any> {
    console.log(`Calling contract view function: ${methodName}`);

    const result = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: contractId,
      method_name: methodName,
      args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
      finality: 'optimistic'
    });

    return result;
  }

  /**
   * Execute an authenticated call (requires PRF authentication)
   */
  async executeAuthenticatedCall(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string,
    nearAccountId: string
  ): Promise<FinalExecutionOutcome> {
    // For contract calls, we need to authenticate via PRF
    // Since we don't have direct access to the main WebAuthn flow here,
    // we'll need to get it through the network calls and workers

    // For serverless mode, use local authentication
    const challengeId = 'serverless-contract-call-' + crypto.randomUUID();

    // Create a simple challenge for serverless authentication
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    // Get user data to build allowCredentials
    const userData = await this.getUserDataForTransaction(nearAccountId);
    if (!userData?.clientNearPublicKey) {
      throw new Error(`No user data found for account ${nearAccountId}`);
    }

    // Get stored authenticator data for this user
    const authenticators = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register first.`);
    }

    // Build authentication options using stored credential
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge,
      rpId: window.location.hostname,
      allowCredentials: authenticators.map(auth => {
        return {
          id: bufferDecode(auth.credentialID),
          type: 'public-key' as const,
          transports: auth.transports as AuthenticatorTransport[]
        };
      }),
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: this.webauthnWorkers.getPrfSalts().nearKeyEncryption
          }
        }
      }
    };

    const credential = await navigator.credentials.get({
      publicKey: authOptions
    }) as PublicKeyCredential;

    if (!credential) {
      throw new Error('WebAuthn authentication failed or was cancelled');
    }

    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = (extensionResults as any).prf?.results?.first;

    if (!prfOutput) {
      throw new Error('PRF output not available - required for contract calls');
    }

    console.log('Contract call authentication successful, executing with PRF...');

    return this.executeAuthenticatedCallWithPrf(
      nearRpcProvider,
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit,
      nearAccountId,
      prfOutput
    );
  }

  /**
   * Execute an authenticated call with pre-obtained PRF (no additional TouchID)
   */
  async executeAuthenticatedCallWithPrf(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string,
    nearAccountId: string,
    prfOutput: ArrayBuffer
  ): Promise<FinalExecutionOutcome> {
    // For serverless mode with pre-obtained PRF, use a dummy challenge ID
    const challengeId = 'serverless-reused-prf-' + crypto.randomUUID();

    console.log("Contract call (with PRF): secureTransactionSigningWithPrf", challengeId);

    return this.signAndSubmitTransaction(
      nearRpcProvider,
      nearAccountId,
      prfOutput,
      challengeId,
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit
    );
  }

  /**
   * Sign and submit a transaction to the blockchain
   */
  async signAndSubmitTransaction(
    nearRpcProvider: Provider,
    nearAccountId: string,
    prfOutput: ArrayBuffer,
    challengeId: string,
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string
  ): Promise<FinalExecutionOutcome> {
    // Get user data to retrieve public key for nonce lookup
    const userData = await this.getUserDataForTransaction(nearAccountId);
    if (!userData?.clientNearPublicKey) {
      throw new Error('Client NEAR public key not found in user data');
    }

    // Get current nonce and block info concurrently
    const [accessKeyInfo, blockInfo] = await Promise.all([
      nearRpcProvider.viewAccessKey(
        nearAccountId,
        userData.clientNearPublicKey,
      ) as Promise<AccessKeyView>,
      nearRpcProvider.viewBlock({ finality: 'final' })
    ]);

    const nonce = accessKeyInfo.nonce + BigInt(1); // Proper nonce calculation

    console.log("Contract call: secureTransactionSigningWithPrf", challengeId);

    // Use WASM worker to sign the transaction
    const signedTxResult = await this.webauthnWorkers.secureTransactionSigningWithPrf(
      nearAccountId,
      prfOutput,
      {
        nearAccountId,
        receiverId: contractId,
        contractMethodName: methodName,
        contractArgs: args,
        gasAmount: gas,
        depositAmount: attachedDeposit,
        nonce: nonce.toString(),
        blockHashBytes: Array.from(bs58.decode(blockInfo.header.hash))
      },
      challengeId
    );

    // Create a SignedTransaction object from the Borsh bytes
    const signedTransaction = SignedTransaction.decode(Buffer.from(signedTxResult.signedTransactionBorsh));

    try {
      // Submit the transaction asynchronously to avoid RPC timeouts
      console.log("Submitting transaction with optimistic execution...");
      const finalResult = await nearRpcProvider.sendTransactionUntil(
        signedTransaction,
        'INCLUDED_FINAL' // Wait until included in final block
      );

      console.log("Transaction successful:", finalResult);
      return finalResult;

    } catch (error: any) {
      console.error("Transaction failed:", error);
      throw new Error(`Transaction submission failed: ${error.message}`);
    }
  }

  /**
   * Get user data for transaction - integrates with IndexDBManager
   */
  private async getUserDataForTransaction(nearAccountId: string): Promise<{ clientNearPublicKey?: string } | null> {
    try {
      const userData = await indexDBManager.getWebAuthnUserData(nearAccountId);
      return userData ? { clientNearPublicKey: userData.clientNearPublicKey } : null;
    } catch (error: any) {
      console.error('Failed to get user data for transaction:', error);
      throw new Error(`Failed to retrieve user data for ${nearAccountId}: ${error.message}`);
    }
  }

  /**
   * Estimate transaction gas costs
   */
  async estimateTransactionGas(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: any
  ): Promise<string> {
    return await this.networkCalls.estimateGas(nearRpcProvider, contractId, methodName, args);
  }

  /**
   * Validate that a contract method exists before calling
   */
  async validateContractCall(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string
  ): Promise<boolean> {
    return await this.networkCalls.validateContractMethod(nearRpcProvider, contractId, methodName);
  }

  /**
   * Check if account has permission to call contract method
   */
  async checkCallPermissions(
    nearRpcProvider: Provider,
    accountId: string,
    publicKey: string
  ): Promise<{ hasPermission: boolean; allowedReceivers?: string[]; allowedMethods?: string[] }> {
    return await this.networkCalls.checkAccountPermissions(nearRpcProvider, accountId, publicKey);
  }

  /**
   * Get blockchain network information for transaction building
   */
  async getNetworkInfo(nearRpcProvider: Provider) {
    return await this.networkCalls.getNetworkInfo(nearRpcProvider);
  }

  /**
   * Refill account balance using NEAR testnet faucet service
   */
  private async refillAccountBalance(nearAccountId: string, publicKey: string): Promise<void> {
    console.log(`🌊 Refilling account balance for ${nearAccountId} via testnet faucet`);

    try {
      // Call NEAR testnet faucet service to add more funds
      const faucetResponse = await fetch('https://helper.nearprotocol.com/account', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          newAccountId: nearAccountId,
          newAccountPublicKey: publicKey
        })
      });

      if (!faucetResponse.ok) {
        const errorData = await faucetResponse.json().catch(() => ({}));
        throw new Error(`Faucet service error: ${faucetResponse.status} - ${errorData.message || 'Unknown error'}`);
      }

      const faucetResult = await faucetResponse.json();
      console.log('🌊 Faucet refill response:', faucetResult);

      // Wait a moment for the transaction to be processed
      await new Promise(resolve => setTimeout(resolve, 2000));

    } catch (faucetError: any) {
      console.error('🌊 Faucet refill error:', faucetError);

      // Check if account already exists (which is expected)
      if (faucetError.message?.includes('already exists') || faucetError.message?.includes('AccountAlreadyExists')) {
        console.log('🌊 Account already exists, faucet may have still added funds');
        // Wait a moment for potential balance update
        await new Promise(resolve => setTimeout(resolve, 2000));
        return;
      } else {
        throw new Error(`Failed to refill account balance: ${faucetError.message}`);
      }
    }
  }
}