import type { Provider } from '@near-js/providers';
import type {
  FinalExecutionOutcome,
  QueryResponseKind,
  CallContractViewFunctionResultRaw,
} from '@near-js/types';
import { SignedTransaction } from '@near-js/transactions';
import { WebAuthnWorkers } from './webauthn-workers';
import { WebAuthnNetworkCalls } from './network-calls';
import { WebAuthnIndexedDBCalls } from './indexedDB-calls';
import { bufferDecode, base64UrlDecode, base64UrlEncode } from '../../utils/encoders';
import bs58 from 'bs58';
import type {
  ContractCallOptions,
  AccessKeyView
} from '../types/worker';
import type {
  VrfChallengeData,
  RegistrationData,
  UserDataForTransaction,
  ContractVerificationResponse,
  VrfAuthenticationResult,
  VrfRegistrationResult,
  CallPermissionsResult,
  AuthenticatorTransport,
  UserVerificationRequirement
} from '../types/webauthn';
import { generateUserScopedPrfSalt } from '../../utils';

// Type for contract verification response parsing - handles multiple NEAR RPC response formats
export type ContractResponse =
  | CallContractViewFunctionResultRaw  // View call responses
  | FinalExecutionOutcome              // Transaction responses

export const CONTRACT_FUNCTIONS = {
  VERIFY_AUTHENTICATION_RESPONSE: 'verify_authentication_response',
  VERIFY_REGISTRATION_RESPONSE: 'verify_registration_response',
}

/**
 * WebAuthnContractCalls handles blockchain contract interactions
 */
export class WebAuthnContractCalls {
  private readonly webauthnWorkers: WebAuthnWorkers;
  private readonly networkCalls: WebAuthnNetworkCalls;
  private readonly indexedDBCalls: WebAuthnIndexedDBCalls;

  constructor(
    webauthnWorkers: WebAuthnWorkers,
    networkCalls: WebAuthnNetworkCalls,
    indexedDBCalls: WebAuthnIndexedDBCalls
  ) {
    this.webauthnWorkers = webauthnWorkers;
    this.networkCalls = networkCalls;
    this.indexedDBCalls = indexedDBCalls;
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
      gas = '30000000000000',
      attachedDeposit = '0',
      nearAccountId,
      prfOutput,
      viewOnly = false,
    } = options;

    // 1. Handle explicit view-only calls
    if (viewOnly) {
      return this.executeViewCall(nearRpcProvider, contractId, methodName, args);
    }

    // 2. Handle state-changing calls
    console.debug(`Executing state-changing call: ${methodName}`);

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
  ): Promise<CallContractViewFunctionResultRaw> {
    console.debug(`Calling contract view function: ${methodName}`);

    const argsJson = JSON.stringify(args);
    const argsBase64 = Buffer.from(argsJson).toString('base64');

    console.debug('DEBUG: View call execution:');
    console.debug('  - Method:', methodName);
    console.debug('  - Args JSON length:', argsJson.length);
    console.debug('  - Args JSON sample:', argsJson.substring(0, 200) + '...');
    console.debug('  - Args Base64 length:', argsBase64.length);

    const result: CallContractViewFunctionResultRaw = await nearRpcProvider.query({
      request_type: 'call_function',
      account_id: contractId,
      method_name: methodName,
      args_base64: argsBase64,
      finality: 'optimistic'
    });

    return result;
  }

  /**
   * Execute a registration contract call with registration data
   * Special case for registration where account exists but user data not in IndexedDB yet
   */
  async executeRegistrationContractCall(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: any,
    nearAccountId: string,
    registrationData?: {
      nearPublicKey: string;
      prfOutput: ArrayBuffer;
    }
  ): Promise<any> {
    console.debug(`Calling registration contract function: ${methodName} for account: ${nearAccountId}`);

    try {
      // For registration verification, we need to call the contract to save authenticator data
      // The account exists (created by faucet) but user data isn't in IndexedDB yet
      // We'll use the registration PRF output and public key

      if (!registrationData) {
        throw new Error('Registration data required for registration contract calls');
      }

      // Use the PRF output from registration directly
      console.debug('Using registration PRF output for contract call...');
      return this.executeRegistrationCallWithData(
        nearRpcProvider,
        contractId,
        methodName,
        args,
        '300000000000000', // 300 TGas for registration
        '0', // no deposit
        nearAccountId,
        registrationData.nearPublicKey,
        registrationData.prfOutput
      );

    } catch (error: any) {
      console.error('Registration contract call failed:', error);
      throw error;
    }
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
    const authenticators = await this.indexedDBCalls.getAuthenticatorsByUser(nearAccountId);
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
            first: generateUserScopedPrfSalt(nearAccountId) // User-scoped PRF salt
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

    console.debug('Contract call authentication successful, executing with PRF...');

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
    // No challenge validation needed - VRF provides cryptographic freshness
    console.debug("Contract call (with PRF): secureTransactionSigningWithPrf");

    return this.signAndSubmitTransaction(
      nearRpcProvider,
      nearAccountId,
      prfOutput,
      contractId,
      methodName,
      args,
      gas,
      attachedDeposit
    );
  }

  /**
   * Execute a registration contract call with known registration data
   * This bypasses IndexedDB lookup since user data isn't stored yet during registration
   */
  async executeRegistrationCallWithData(
    nearRpcProvider: Provider,
    contractId: string,
    methodName: string,
    args: any,
    gas: string,
    attachedDeposit: string,
    nearAccountId: string,
    nearPublicKey: string,
    prfOutput: ArrayBuffer
  ): Promise<FinalExecutionOutcome> {
    console.debug(`Registration contract call: ${methodName} for ${nearAccountId}`);

    // Wait for account and access key to be available (with retry logic)
    const accessKeyInfo = await this.waitForAccessKey(nearRpcProvider, nearAccountId, nearPublicKey);
    const blockInfo = await nearRpcProvider.viewBlock({ finality: 'final' });

    // Debug blockInfo to understand the structure
    console.debug('📊 Block info debug:', {
      hasBlockInfo: !!blockInfo,
      hasHeader: !!blockInfo?.header,
      hasHash: !!blockInfo?.header?.hash,
      blockInfoKeys: blockInfo ? Object.keys(blockInfo) : 'undefined',
      headerKeys: blockInfo?.header ? Object.keys(blockInfo.header) : 'undefined',
      hashValue: blockInfo?.header?.hash
    });

    if (!blockInfo || !blockInfo.header || !blockInfo.header.hash) {
      console.error('❌ Invalid block info received:', blockInfo);
      throw new Error('Failed to get valid block information from NEAR RPC');
    }

    const nonce = accessKeyInfo.nonce + BigInt(1); // Proper nonce calculation

    // No challenge validation needed - VRF provides cryptographic freshness
    console.debug("Registration contract call: secureTransactionSigningWithPrf");

    let blockHashBytes: number[];
    try {
      blockHashBytes = Array.from(bs58.decode(blockInfo.header.hash));
      console.debug('✅ Block hash decoded successfully:', blockHashBytes.length, 'bytes');
    } catch (error: any) {
      console.error('❌ Failed to decode block hash:', error);
      console.error('Block hash value:', blockInfo.header.hash);
      throw new Error(`Failed to decode block hash: ${error.message}`);
    }

    // Debug the registration transaction args before signing
    console.debug('🔧 DEBUG: Registration transaction signing args:');
    console.debug('  - Method name:', methodName);
    console.debug('  - Contract args type:', typeof args);
    console.debug('  - Contract args JSON structure:');
    console.debug(JSON.stringify(args, null, 2));

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
        blockHashBytes: blockHashBytes
      }
    );

    // Create a SignedTransaction object from the Borsh bytes
    const signedTransaction = SignedTransaction.decode(Buffer.from(signedTxResult.signedTransactionBorsh));

    try {
      // Submit the transaction asynchronously to avoid RPC timeouts
      console.debug("Submitting registration transaction with optimistic execution...");
      const finalResult = await nearRpcProvider.sendTransactionUntil(
        signedTransaction,
        'INCLUDED_FINAL' // Wait until included in final block
      );

      console.debug("Registration transaction successful:", finalResult);
      return finalResult;

    } catch (error: any) {
      console.error("Registration transaction failed:", error);
      throw new Error(`Registration transaction submission failed: ${error.message}`);
    }
  }

  /**
   * Wait for access key to be available with retry logic
   * Account creation via faucet may have propagation delays
   */
  private async waitForAccessKey(
    nearRpcProvider: Provider,
    nearAccountId: string,
    nearPublicKey: string,
    maxRetries: number = 10,
    delayMs: number = 1000
  ): Promise<AccessKeyView> {
    console.debug(`Waiting for access key to be available for ${nearAccountId}...`);

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const accessKeyInfo = await nearRpcProvider.viewAccessKey(
          nearAccountId,
          nearPublicKey,
        ) as AccessKeyView;

        console.debug(`✅ Access key found on attempt ${attempt}`);
        return accessKeyInfo;
      } catch (error: any) {
        console.debug(`⏳ Access key not available yet (attempt ${attempt}/${maxRetries}):`, error.message);

        if (attempt === maxRetries) {
          console.error(`❌ Access key still not available after ${maxRetries} attempts`);
          throw new Error(`Access key not available after ${maxRetries * delayMs}ms. Account creation may have failed.`);
        }

        // Wait before next attempt with exponential backoff
        const delay = delayMs * Math.pow(1.5, attempt - 1);
        console.debug(`   Waiting ${delay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('Unexpected error in waitForAccessKey');
  }

  /**
   * Sign and submit a transaction to the blockchain
   */
  async signAndSubmitTransaction(
    nearRpcProvider: Provider,
    nearAccountId: string,
    prfOutput: ArrayBuffer,
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

    // Debug blockInfo to understand the structure
    console.debug('📊 Block info debug (signAndSubmitTransaction):', {
      hasBlockInfo: !!blockInfo,
      hasHeader: !!blockInfo?.header,
      hasHash: !!blockInfo?.header?.hash,
      blockInfoKeys: blockInfo ? Object.keys(blockInfo) : 'undefined',
      headerKeys: blockInfo?.header ? Object.keys(blockInfo.header) : 'undefined',
      hashValue: blockInfo?.header?.hash
    });

    if (!blockInfo || !blockInfo.header || !blockInfo.header.hash) {
      console.error('❌ Invalid block info received:', blockInfo);
      throw new Error('Failed to get valid block information from NEAR RPC');
    }

    const nonce = accessKeyInfo.nonce + BigInt(1); // Proper nonce calculation

    console.debug("Contract call: secureTransactionSigningWithPrf");

    let blockHashBytes: number[];
    try {
      blockHashBytes = Array.from(bs58.decode(blockInfo.header.hash));
      console.debug('✅ Block hash decoded successfully:', blockHashBytes.length, 'bytes');
    } catch (error: any) {
      console.error('❌ Failed to decode block hash:', error);
      console.error('Block hash value:', blockInfo.header.hash);
      throw new Error(`Failed to decode block hash: ${error.message}`);
    }

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
        blockHashBytes: blockHashBytes
      }
    );

    // Create a SignedTransaction object from the Borsh bytes
    const signedTransaction = SignedTransaction.decode(Buffer.from(signedTxResult.signedTransactionBorsh));

    try {
      // Submit the transaction asynchronously to avoid RPC timeouts
      console.debug("Submitting transaction with optimistic execution...");
      const finalResult = await nearRpcProvider.sendTransactionUntil(
        signedTransaction,
        'INCLUDED_FINAL' // Wait until included in final block
      );

      console.debug("Transaction successful:", finalResult);
      return finalResult;

    } catch (error: any) {
      console.error("Transaction failed:", error);
      throw new Error(`Transaction submission failed: ${error.message}`);
    }
  }

  /**
   * Get user data for transaction - integrates with IndexedDBManager
   */
  private async getUserDataForTransaction(nearAccountId: string): Promise<UserDataForTransaction | null> {
    try {
      const userData = await this.indexedDBCalls.getWebAuthnUserData(nearAccountId);
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
   * Check if account has permission to call contract method
   */
  async checkCallPermissions(
    nearRpcProvider: Provider,
    accountId: string,
    publicKey: string
  ): Promise<CallPermissionsResult> {
    return await this.networkCalls.checkAccountPermissions(nearRpcProvider, accountId, publicKey);
  }

  /**
   * Get blockchain network information for transaction building
   */
  async getNetworkInfo(nearRpcProvider: Provider): Promise<any> {
    return await this.networkCalls.getNetworkInfo(nearRpcProvider);
  }

  // === VRF CONTRACT INTEGRATION ===

  /**
   * Verify VRF authentication with the contract (gas-free view call)
   * Calls verify_authentication_response as a view function on the WebAuthn contract
   */
  async verifyVrfAuthentication(
    nearRpcProvider: Provider,
    contractId: string,
    vrfChallengeData: VrfChallengeData,
    webauthnCredential: PublicKeyCredential,
    debugMode: boolean,
  ): Promise<VrfAuthenticationResult> {
    try {
      console.debug('Verifying VRF authentication with contract...');

      // Extract WebAuthn response data
      const response = webauthnCredential.response as AuthenticatorAssertionResponse;
      const clientDataJSONBytes = new Uint8Array(response.clientDataJSON);
      const authenticatorData = new Uint8Array(response.authenticatorData);
      const signature = new Uint8Array(response.signature);

      // Construct VRF data for contract verification
      const vrfData = {
        vrf_input_data: Array.from(base64UrlDecode(vrfChallengeData.vrfInput)),
        vrf_output: Array.from(base64UrlDecode(vrfChallengeData.vrfOutput)),
        vrf_proof: Array.from(base64UrlDecode(vrfChallengeData.vrfProof)),
        public_key: Array.from(base64UrlDecode(vrfChallengeData.vrfPublicKey)),
        user_id: vrfChallengeData.userId, // NEAR account_id - cryptographically bound in VRF input
        rp_id: vrfChallengeData.rpId, // Relying Party ID - cryptographically binds VRF to specific website
        block_height: vrfChallengeData.blockHeight,
        block_hash: Array.from(base64UrlDecode(vrfChallengeData.blockHash)), // Block hash for additional entropy and blockchain state binding
      };

      // Construct WebAuthn Authentication response for contract verification
      // Note: Contract expects base64url strings and camelCase field names per serde renames
      const webauthnAuthentication = {
        id: webauthnCredential.id,
        rawId: base64UrlEncode(new Uint8Array(webauthnCredential.rawId)),
        response: {
          clientDataJSON: base64UrlEncode(clientDataJSONBytes),
          authenticatorData: base64UrlEncode(authenticatorData),
          signature: base64UrlEncode(signature),
          userHandle: response.userHandle ? base64UrlEncode(new Uint8Array(response.userHandle)) : null,
        },
        authenticatorAttachment: (webauthnCredential as any).authenticatorAttachment || null,
        type: 'public-key',
        // clientExtensionResults: webauthnCredential.getClientExtensionResults() || {},
        // Don't send PRF extension results to contract, should be kept private
      };

      // Call contract verification method
      const contractArgs = {
        vrf_data: vrfData,
        webauthn_authentication: webauthnAuthentication,
      };

      console.debug(`Calling ${CONTRACT_FUNCTIONS.VERIFY_AUTHENTICATION_RESPONSE} on contract...`);
      console.debug('Contract args structure:', JSON.stringify(contractArgs, null, 2));

      // Call contract as view function (gas-free, read-only)
      let result: ContractResponse;
      if (!debugMode) {
        result = await this.executeViewCall(
          nearRpcProvider,
          contractId,
          CONTRACT_FUNCTIONS.VERIFY_AUTHENTICATION_RESPONSE,
          contractArgs
        );
      } else {
        // NOTE: view vs non-view function calls
        // DEBUG VERSION: Uncomment below to call as authenticated function for debugging contract logs
        console.debug('DEBUG: Calling verify_authentication_response as authenticated function to see logs');
        result = await this.executeAuthenticatedCall(
          nearRpcProvider,
          contractId,
          CONTRACT_FUNCTIONS.VERIFY_AUTHENTICATION_RESPONSE,
          contractArgs,
          '100000000000000', // 100 TGas for debugging
          '0', // no deposit
          vrfChallengeData.userId // use the userId from VRF data as nearAccountId
        );
      }

      // Parse contract response
      const contractResponse = this.parseContractVerificationResponse(result);

      if (contractResponse.verified) {
        console.debug('✅ VRF authentication verified by contract');
        return {
          success: true,
          verified: true,
        };
      } else {
        console.warn('❌ VRF authentication verification failed');
        return {
          success: false,
          verified: false,
          error: contractResponse.error || 'Contract verification failed',
        };
      }

    } catch (error: any) {
      console.error('❌ VRF contract verification error:', error);
      return {
        success: false,
        error: error.message || 'VRF contract verification failed',
      };
    }
  }

  /**
   * Parse contract verification response from various NEAR RPC response formats
   */
  private parseContractVerificationResponse(
    result: ContractResponse
  ): ContractVerificationResponse {
    try {
      // Handle different response formats from NEAR RPC
      let responseData: any;

      // Check for logs if available
      if (result && typeof result === 'object' && 'logs' in result && Array.isArray(result.logs) && result.logs.length > 0) {
        console.log('logs:', result.logs);
      }

      if (result && typeof result === 'object') {
        if ('result' in result && result.result) {
          // Handle RPC query response format (view calls)
          const resultBytes = new Uint8Array(result.result);
          const resultString = new TextDecoder().decode(resultBytes);
          responseData = JSON.parse(resultString);
        } else if ('receipts_outcome' in result && result.receipts_outcome) {
          // Handle transaction response format (change calls)
          console.debug('🔍 Parsing transaction response for verification result');

          // Look for return value in the transaction outcome
          const status = result.status;
          if (typeof status === 'object' && status?.SuccessValue) {
            const returnValueBytes = new Uint8Array(
              Buffer.from(status.SuccessValue, 'base64')
            );
            const returnValueString = new TextDecoder().decode(returnValueBytes);
            responseData = JSON.parse(returnValueString);
          } else {
            // If no return value, assume success based on transaction success
            const hasSuccessValue = typeof status === 'object' && status?.SuccessValue;
            const transactionHash = result?.transaction?.hash ?? undefined;

            responseData = {
              verified: hasSuccessValue,
              transaction_id: transactionHash
            };
          }
        } else {
          // Handle direct object response
          responseData = result;
        }
      } else if (typeof result === 'string') {
        // Handle string response
        responseData = JSON.parse(result);
      } else {
        // Fallback
        responseData = result || {};
      }

      // Extract transaction hash safely
      let transactionId: string | undefined;
      if (responseData?.transaction_id) {
        transactionId = responseData.transaction_id;
      } else if (
        typeof result === 'object'
        && 'transaction' in result
        && result.transaction
        && typeof result.transaction === 'object'
        && 'hash' in result.transaction
      ) {
        transactionId = result.transaction.hash;
      }

      return {
        verified: responseData?.verified || false,
        transaction_id: transactionId,
        error: responseData?.error,
      };
    } catch (parseError: any) {
      console.error('Failed to parse contract verification response:', parseError);
      console.error('Raw result:', result);
      return {
        verified: false,
        error: `Failed to parse contract response: ${parseError.message}`,
      };
    }
  }

  /**
   * Verify VRF registration with the contract
   * Calls verify_registration_response on the WebAuthn contract
   */
  async verifyVrfRegistration(
    nearRpcProvider: Provider,
    contractId: string,
    vrfChallengeData: VrfChallengeData,
    webauthnCredential: PublicKeyCredential,
    nearAccountId: string,
    registrationData?: RegistrationData
  ): Promise<VrfRegistrationResult> {
    try {
      console.debug('🔐 Verifying VRF registration with contract...');

      // Extract WebAuthn response data
      const response = webauthnCredential.response as AuthenticatorAttestationResponse;
      const clientDataJSONBytes = new Uint8Array(response.clientDataJSON);
      const attestationObject = new Uint8Array(response.attestationObject);

      // Convert base64url data to bytes for contract
      const vrfInput = base64UrlDecode(vrfChallengeData.vrfInput);
      const vrfOutput = base64UrlDecode(vrfChallengeData.vrfOutput);
      const vrfProof = base64UrlDecode(vrfChallengeData.vrfProof);
      const vrfPublicKey = base64UrlDecode(vrfChallengeData.vrfPublicKey);
      const blockHash = base64UrlDecode(vrfChallengeData.blockHash);

      // Construct VRF data for contract verification
      const vrfData = {
        vrf_input_data: Array.from(vrfInput),
        vrf_output: Array.from(vrfOutput),
        vrf_proof: Array.from(vrfProof),
        public_key: Array.from(vrfPublicKey),
        user_id: vrfChallengeData.userId, // NEAR account_id - cryptographically bound in VRF input
        rp_id: vrfChallengeData.rpId, // Relying Party ID - cryptographically binds VRF to specific website
        block_height: vrfChallengeData.blockHeight,
        block_hash: Array.from(base64UrlDecode(vrfChallengeData.blockHash)), // Block hash for additional entropy and blockchain state binding
      };

      // Construct WebAuthn registration data for contract verification
      // Note: Contract expects base64url strings and camelCase field names per serde renames
      const webauthnRegistration = {
        id: webauthnCredential.id,
        rawId: base64UrlEncode(new Uint8Array(webauthnCredential.rawId)),
        response: {
          clientDataJSON: base64UrlEncode(clientDataJSONBytes),
          attestationObject: base64UrlEncode(attestationObject),
          transports: (response as any).getTransports?.() || [],
        },
        authenticatorAttachment: (webauthnCredential as any).authenticatorAttachment || null,
        type: 'public-key',
        clientExtensionResults: webauthnCredential.getClientExtensionResults() || {},
      };

      // Call contract verification method
      const contractArgs = {
        vrf_data: vrfData,
        webauthn_registration: webauthnRegistration,
      };

      console.debug(`DEBUG: Contract args being sent to ${CONTRACT_FUNCTIONS.VERIFY_REGISTRATION_RESPONSE}:`);
      console.debug('Full contract args JSON:');
      console.debug(JSON.stringify(contractArgs, null, 2));
      console.debug('VRF data structure:');
      console.debug(JSON.stringify(vrfData, null, 2));
      console.debug('WebAuthn data structure:');
      console.debug(JSON.stringify(webauthnRegistration, null, 2));

      // Use state-changing function for registration (saves authenticator on-chain)
      // Special case: account exists but user data not in IndexedDB yet
      const result = await this.executeRegistrationContractCall(
        nearRpcProvider,
        contractId,
        CONTRACT_FUNCTIONS.VERIFY_REGISTRATION_RESPONSE,
        contractArgs,
        nearAccountId,
        registrationData
      );

      // Parse contract response
      const contractResponse = this.parseContractVerificationResponse(result);

      if (contractResponse.verified) {
        console.debug('✅ VRF registration verified by contract');
        return {
          success: true,
          verified: true,
          transactionId: contractResponse.transaction_id,
        };
      } else {
        console.warn('❌ VRF registration verification failed');
        return {
          success: false,
          verified: false,
          error: contractResponse.error || 'Contract verification failed',
        };
      }

    } catch (error: any) {
      console.error('❌ VRF contract registration verification error:', error);
      return {
        success: false,
        error: error.message || 'VRF contract registration verification failed',
      };
    }
  }
}