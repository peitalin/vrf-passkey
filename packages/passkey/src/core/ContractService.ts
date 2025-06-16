import type { Provider } from '@near-js/providers';
import type { FinalExecutionOutcome } from '@near-js/types';
import type { ClientAuthenticatorData } from './IndexDBManager';
import { bufferDecode } from '../utils/encoders';

// Define WebAuthn types locally since we can't import from @simplewebauthn
export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  authenticatorAttachment?: string;
  type: string;
  clientExtensionResults?: any;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  type: string;
  clientExtensionResults?: any;
}

export interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ alg: number; type: string }>;
  timeout?: number;
  attestation?: string;
  excludeCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  extensions?: any;
}

// === CONTRACT ARGUMENT TYPES ===

// Registration contract arguments (extracted from server)
export interface ContractGenerateOptionsArgs {
  rp_name: string;
  rp_id: string;
  user_name: string;
  user_id: string; // Contract expects base64url encoded user_id
  challenge: string | null; // Can be null to let contract generate
  user_display_name: string | null;
  timeout: number | null;
  attestation_type: string | null;
  exclude_credentials: { id: string; type: string; transports?: string[] }[] | null;
  authenticator_selection: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  } | null;
  extensions: { cred_props?: boolean } | null;
  supported_algorithm_ids: number[] | null;
  preferred_authenticator_type: string | null;
}

export interface ContractCompleteRegistrationArgs {
  registration_response: RegistrationResponseJSON;
  commitment_id: string;
}

// Authentication contract arguments (extracted from server)
export interface ContractGenerateAuthOptionsArgs {
  rp_id: string | null;
  allow_credentials: { id: string; type: string; transports?: string[] }[] | null;
  challenge: string | null; // Let contract generate
  timeout: number | null;
  user_verification: 'discouraged' | 'preferred' | 'required' | null;
  extensions: {
    appid?: string;
    cred_props?: boolean;
    hmac_create_secret?: boolean;
    min_pin_length?: boolean
  } | null;
  authenticator: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    transports?: string[];
  };
}

export interface ContractVerifyAuthArgs {
  authentication_response: AuthenticationResponseJSON;
  commitment_id: string;
}

// === CONTRACT RESPONSE TYPES ===

export interface ContractRegistrationOptionsResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId: string | undefined;
  commitmentId: string | null;
}

export interface ContractAuthenticationOptionsResponse {
  options: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: { id: string; type: string; transports?: string[] }[];
    userVerification?: 'discouraged' | 'preferred' | 'required';
    extensions?: {
      appid?: string;
      cred_props?: boolean;
      hmac_create_secret?: boolean;
      min_pin_length?: boolean
    };
  };
  commitmentId?: string;
}

export interface ContractVerificationResult {
  verified: boolean;
  registrationInfo?: any;
  authenticationInfo?: any;
}

// === CONTRACT SERVICE CLASS ===

export class ContractService {
  private provider: Provider;
  private contractId: string;
  private rpName: string;
  private rpId: string;
  private relayerAccountId: string;

  constructor(
    provider: Provider,
    contractId: string,
    rpName: string,
    rpId: string,
    relayerAccountId: string
  ) {
    this.provider = provider;
    this.contractId = contractId;
    this.rpName = rpName;
    this.rpId = rpId;
    this.relayerAccountId = relayerAccountId;
  }

  // === REGISTRATION METHODS ===

    /**
   * Build contract arguments for registration options
   * Replicates server/src/routes/registration.ts:getRegistrationOptionsContract()
   */
  buildRegistrationOptionsArgs(
    nearAccountId: string,
    userId: string,
    existingAuthenticators: ClientAuthenticatorData[] = []
  ): { contractArgs: ContractGenerateOptionsArgs; nearAccountId: string } {
    console.log(`🔗 ContractService: Building registration options args for ${nearAccountId}`);

    // Convert existing authenticators to exclusion list
    const excludeCredentials = existingAuthenticators.length > 0
      ? existingAuthenticators.map(auth => ({
          id: auth.credentialID, // Contract expects base64url string id
          type: 'public-key' as const,
          transports: auth.transports || undefined,
        }))
      : null;

    // Build contract arguments (replicate server logic)
    const contractArgs: ContractGenerateOptionsArgs = {
      rp_name: this.rpName,
      rp_id: this.rpId,
      user_name: nearAccountId,
      user_id: userId,
      challenge: null, // Let contract generate challenge
      user_display_name: nearAccountId,
      timeout: 60000,
      attestation_type: "none",
      exclude_credentials: excludeCredentials,
      authenticator_selection: {
        residentKey: 'required',
        userVerification: 'preferred'
      },
      extensions: { cred_props: true },
      supported_algorithm_ids: [-7, -257], // ES256 and RS256
      preferred_authenticator_type: null,
    };

    console.log('🔗 ContractService: Built registration options args:', JSON.stringify(contractArgs));

    return { contractArgs, nearAccountId };
  }

  /**
   * Build contract arguments for registration verification
   * Replicates server/src/routes/registration.ts:verifyRegistrationResponseContract()
   */
  buildRegistrationVerificationArgs(
    attestationResponse: RegistrationResponseJSON,
    commitmentId: string
  ): ContractCompleteRegistrationArgs {
    console.log('🔗 ContractService: Building registration verification args with commitmentId:', commitmentId, '(serverless mode)');

    const contractArgs: ContractCompleteRegistrationArgs = {
      registration_response: attestationResponse,
      commitment_id: commitmentId,
    };

    console.log("🔗 ContractService: Built registration verification args:", JSON.stringify(contractArgs));

    return contractArgs;
  }

  // === AUTHENTICATION METHODS ===

  /**
   * Build contract arguments for authentication options
   * Replicates server/src/routes/authentication.ts:generateAuthenticationOptionsContract()
   */
  buildAuthenticationOptionsArgs(
    authenticator: ClientAuthenticatorData,
    allowCredentials?: { id: string; type: string; transports?: string[] }[],
    userVerification: 'discouraged' | 'preferred' | 'required' = 'preferred'
  ): ContractGenerateAuthOptionsArgs {
    console.log('🔗 ContractService: Building authentication options args (serverless mode)');

    // Convert authenticator to contract format
    const authenticatorForContract = {
      credential_id: Array.from(new Uint8Array(bufferDecode(authenticator.credentialID))),
      credential_public_key: Array.from(authenticator.credentialPublicKey),
      counter: authenticator.counter,
      transports: authenticator.transports?.map(t => String(t)),
    };

    const contractArgs: ContractGenerateAuthOptionsArgs = {
      rp_id: this.rpId,
      allow_credentials: allowCredentials || null,
      challenge: null, // Let contract generate challenge
      timeout: 60000,
      user_verification: userVerification,
      extensions: null,
      authenticator: authenticatorForContract,
    };

    console.log('🔗 ContractService: Built authentication options args:', JSON.stringify(contractArgs));

    return contractArgs;
  }

  /**
   * Build contract arguments for authentication verification
   * Replicates server/src/routes/authentication.ts:verifyAuthenticationResponseContract()
   */
  buildAuthenticationVerificationArgs(
    authResponse: AuthenticationResponseJSON,
    commitmentId: string
  ): ContractVerifyAuthArgs {
    console.log('🔗 ContractService: Building authentication verification args with commitmentId:', commitmentId, '(serverless mode)');

    const contractArgs: ContractVerifyAuthArgs = {
      authentication_response: authResponse,
      commitment_id: commitmentId,
    };

    console.log('🔗 ContractService: Built authentication verification args:', JSON.stringify(contractArgs));

    return contractArgs;
  }

  // === HELPER METHODS ===

  /**
   * Parse contract response with robust error handling
   * Handles both legacy query responses and FinalExecutionOutcome from transactions
   */
  parseContractResponse(rawResult: FinalExecutionOutcome | any, methodName: string): any {
    console.log(`🔗 ContractService: Parsing response for ${methodName}:`, rawResult);

    // Handle FinalExecutionOutcome from sendTransactionUntil
    if (rawResult && rawResult.status) {
      console.log(`🔗 ContractService: Processing FinalExecutionOutcome for ${methodName}`);

      // Check main transaction status first (simpler path)
      if (typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status) {
        try {
          const base64Value = rawResult.status.SuccessValue;
          const decodedString = Buffer.from(base64Value, 'base64').toString();
          console.log(`🔗 ContractService: Decoded SuccessValue for ${methodName}:`, decodedString);
          return JSON.parse(decodedString);
        } catch (parseError: any) {
          console.error(`🔗 ContractService: Failed to parse SuccessValue for ${methodName}:`, parseError);
          throw new Error(`Failed to parse contract response JSON from SuccessValue: ${parseError.message}`);
        }
      }

      // Check for transaction failures
      if (typeof rawResult.status === 'object' && 'Failure' in rawResult.status) {
        const failure = rawResult.status.Failure;
        const executionError = failure.ActionError?.kind?.FunctionCallError?.ExecutionError;
        const errorMessage = executionError || JSON.stringify(failure);
        console.error(`🔗 ContractService: Transaction failed for ${methodName}:`, errorMessage);
        throw new Error(`Transaction Error: ${errorMessage}`);
      }
    }

    // Fallback: Handle receipts_outcome if main status doesn't have SuccessValue
    if (rawResult && rawResult.receipts_outcome && Array.isArray(rawResult.receipts_outcome)) {
      console.log(`🔗 ContractService: Checking receipts_outcome for ${methodName}`);

      // Find the first receipt with a successful function call result
      for (const receipt of rawResult.receipts_outcome) {
        if (receipt?.outcome?.status && typeof receipt.outcome.status === 'object' && 'SuccessValue' in receipt.outcome.status) {
          try {
            const base64Value = receipt.outcome.status.SuccessValue;
            const decodedString = Buffer.from(base64Value, 'base64').toString();
            console.log(`🔗 ContractService: Decoded SuccessValue from receipt for ${methodName}:`, decodedString);
            return JSON.parse(decodedString);
          } catch (parseError: any) {
            console.error(`🔗 ContractService: Failed to parse SuccessValue from receipt for ${methodName}:`, parseError);
            throw new Error(`Failed to parse contract response JSON from receipt SuccessValue: ${parseError.message}`);
          }
        }

        // Check for execution failures in receipts
        if (receipt?.outcome?.status && typeof receipt.outcome.status === 'object' && 'Failure' in receipt.outcome.status) {
          const failure = receipt.outcome.status.Failure;
          const executionError = failure.ActionError?.kind?.FunctionCallError?.ExecutionError;
          const errorMessage = executionError || JSON.stringify(failure);
          console.error(`🔗 ContractService: Contract execution failed for ${methodName}:`, errorMessage);
          throw new Error(`Contract Error: ${errorMessage}`);
        }
      }
    }

    // Legacy handling for direct query responses
    // Check for transaction failures (replicate server logic)
    if (rawResult?.status && typeof rawResult.status === 'object' && 'Failure' in rawResult.status && rawResult.status.Failure) {
      const failure = rawResult.status.Failure;
      const executionError = (failure as any).ActionError?.kind?.FunctionCallError?.ExecutionError;
      const errorMessage = executionError || JSON.stringify(failure);
      console.error(`🔗 ContractService: Contract execution failed for ${methodName}:`, errorMessage);
      throw new Error(`Contract Error: ${errorMessage}`);
    }

    // Check for RPC errors
    if (rawResult && typeof (rawResult as any).error === 'object') {
      const rpcError = (rawResult as any).error;
      console.error(`🔗 ContractService: RPC error from ${methodName}:`, rpcError);
      const errorMessage = rpcError.message || rpcError.name || `RPC error during ${methodName}`;
      const errorData = rpcError.data || JSON.stringify(rpcError.cause);
      throw new Error(`Contract Call RPC Error: ${errorMessage} (Details: ${errorData})`);
    }

    // Parse response string (legacy format)
    let contractResponseString: string;
    if (rawResult?.status && typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status && typeof rawResult.status.SuccessValue === 'string') {
      contractResponseString = Buffer.from(rawResult.status.SuccessValue, 'base64').toString();
    } else if (typeof rawResult === 'string' && rawResult.startsWith('{')) {
      contractResponseString = rawResult;
    } else {
      console.warn(`🔗 ContractService: Unexpected rawResult structure from ${methodName}:`, rawResult);
      throw new Error('Failed to parse contract response: Unexpected format.');
    }

    // Parse JSON response
    try {
      return JSON.parse(contractResponseString);
    } catch (parseError: any) {
      console.error(`🔗 ContractService: Failed to parse response from ${methodName}:`, contractResponseString, parseError);
      throw new Error(`Failed to parse contract response JSON: ${parseError.message}`);
    }
  }

  /**
   * Generate a unique user ID for new users
   * Replicates server logic from registration.ts
   */
  generateUserId(): string {
    const timestamp = Date.now();
    const randomBytes = crypto.getRandomValues(new Uint8Array(8));
    const randomString = Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return `user_${timestamp}_${randomString}`;
  }
}