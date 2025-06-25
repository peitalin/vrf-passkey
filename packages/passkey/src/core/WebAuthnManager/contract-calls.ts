import type { Provider } from '@near-js/providers';
import type {
  FinalExecutionOutcome,
  QueryResponseKind,
  CallContractViewFunctionResultRaw,
  AccessKeyView,
} from '@near-js/types';
import { SignedTransaction } from '@near-js/transactions';
import { WebAuthnWorkers } from './webauthn-workers';
import { IndexedDBManager } from '../IndexedDBManager';
import { bufferDecode, base64UrlDecode, base64UrlEncode } from '../../utils/encoders';
import bs58 from 'bs58';
import type {
  VrfChallengeData,
  RegistrationData,
  ContractVerificationResponse,
  VrfAuthenticationResult,
  VrfRegistrationResult,
} from '../types/webauthn';
import { ActionType, ActionParams } from '../types/worker';


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

  constructor(webauthnWorkers: WebAuthnWorkers) {
    this.webauthnWorkers = webauthnWorkers;
  }

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
      let result: ContractResponse = await nearRpcProvider.query({
        request_type: 'call_function',
        account_id: contractId,
        method_name: CONTRACT_FUNCTIONS.VERIFY_AUTHENTICATION_RESPONSE,
        args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
        finality: 'optimistic'
      }) as CallContractViewFunctionResultRaw;

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
   * Verify VRF registration with the contract, and save the user's authenticator, and public keys on-chain
   * Calls verify_registration_response() on the WebAuthn contract
   */
  async verifyVrfAndRegisterUserOnContract(
    nearRpcProvider: Provider,
    contractId: string,
    vrfChallengeData: VrfChallengeData,
    webauthnCredential: PublicKeyCredential,
    nearAccountId: string,
    registrationData?: RegistrationData
  ): Promise<VrfRegistrationResult> {
    try {
      console.debug('Verifying VRF registration with contract...');

      // Extract WebAuthn response data
      const response = webauthnCredential.response as AuthenticatorAttestationResponse;
      const clientDataJSONBytes = new Uint8Array(response.clientDataJSON);
      const attestationObject = new Uint8Array(response.attestationObject);

      // Convert base64url data to bytes for contract
      const vrfData = {
        vrf_input_data: Array.from(base64UrlDecode(vrfChallengeData.vrfInput)),
        vrf_output: Array.from(base64UrlDecode(vrfChallengeData.vrfOutput)),
        vrf_proof: Array.from(base64UrlDecode(vrfChallengeData.vrfProof)),
        public_key: Array.from(base64UrlDecode(vrfChallengeData.vrfPublicKey)),
        user_id: vrfChallengeData.userId,
        rp_id: vrfChallengeData.rpId,
        block_height: vrfChallengeData.blockHeight,
        block_hash: Array.from(base64UrlDecode(vrfChallengeData.blockHash)),
      };

      // Construct WebAuthn registration data for contract verification
      // Note: Contract expects base64url strings and camelCase field names per serde renames
      const webauthnRegistration = {
        id: webauthnCredential.id,
        rawId: base64UrlEncode(new Uint8Array(webauthnCredential.rawId)),
        response: {
          clientDataJSON: base64UrlEncode(clientDataJSONBytes),
          attestationObject: base64UrlEncode(attestationObject),
          transports: response.getTransports() || [],
        },
        authenticatorAttachment: webauthnCredential.authenticatorAttachment || null,
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

      const { prfOutput, nearPublicKey } = registrationData!;

      // Wait for account and access key to be available (with retry logic)
      const {
        nonce,
        blockHashBytes
      } = await Promise.all([
        // Wait for access key to be available (with retry logic)
        this.waitForAccessKey(nearRpcProvider, nearAccountId, nearPublicKey),
        // Get latest block info for nonce and block hash
        nearRpcProvider.viewBlock({ finality: 'final' }),
      ]).then(([accessKeyInfo, blockInfo]) => {
        if (!blockInfo?.header?.hash) {
          throw new Error('Failed to get valid block information from NEAR RPC');
        }
        return {
          nonce: accessKeyInfo.nonce + BigInt(1),
          blockHashBytes: Array.from(bs58.decode(blockInfo.header.hash)),
        }
      });

      // Use WASM worker to sign the transaction with modern action-based approach
      const functionCallAction = {
        actionType: ActionType.FunctionCall,
        method_name: CONTRACT_FUNCTIONS.VERIFY_REGISTRATION_RESPONSE,
        args: JSON.stringify(contractArgs),
        gas: '30000000000000', // 30 TGas for debugging
        deposit: '0' // no deposit
      };

      const signedTxResult = await this.webauthnWorkers.signTransactionWithActions(
        nearAccountId,
        prfOutput,
        {
          nearAccountId,
          receiverId: contractId,
          actions: [functionCallAction as ActionParams],
          nonce: nonce.toString(),
          blockHashBytes: blockHashBytes
        }
      );

      // Create a SignedTransaction object from the Borsh bytes
      const signedTransaction = SignedTransaction.decode(Buffer.from(signedTxResult.signedTransactionBorsh));

      // Submit the transaction asynchronously to avoid RPC timeouts
      console.debug("Submitting registration transaction with optimistic execution...");
      const finalResult = await nearRpcProvider.sendTransactionUntil(
        signedTransaction,
        'INCLUDED_FINAL' // Wait until included in final block
      );
      console.debug("Registration transaction successful:", finalResult);


      // Parse contract response
      const contractResponse = this.parseContractVerificationResponse(finalResult);

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
        console.log(`${CONTRACT_FUNCTIONS.VERIFY_REGISTRATION_RESPONSE} contract logs: ${result.logs}`);
      }

      if (result && typeof result === 'object') {
        if ('result' in result && result.result) {
          // Handle RPC query response format (view calls)
          const resultBytes = new Uint8Array(result.result);
          const resultString = new TextDecoder().decode(resultBytes);
          responseData = JSON.parse(resultString);
        } else if ('receipts_outcome' in result && result.receipts_outcome) {
          // Handle transaction response format (change calls)
          console.debug('Parsing transaction response for verification result');

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
   * Wait for access key to be available with retry logic
   * Account creation via faucet may have propagation delays
   */
  async waitForAccessKey(
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
}