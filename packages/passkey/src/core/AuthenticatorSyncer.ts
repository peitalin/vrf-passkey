import type { Provider } from '@near-js/providers';
import type { FinalExecutionOutcome } from '@near-js/types';
import { view } from '@near-js/client';
import { indexDBManager, type ClientAuthenticatorData } from './IndexDBManager';
import { bufferDecode } from '../utils/encoders';
import {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransport,
  StoredAuthenticator,
  ContractAuthenticator,
  ContractGenerateOptionsArgs,
  ContractCompleteRegistrationArgs,
  ContractGenerateAuthOptionsArgs,
  ContractVerifyAuthArgs,
  ContractRegistrationOptionsResponse,
} from './types/webauthn';

// === CONTRACT SERVICE ===

/**
 * Unified Authenticator Syncing service that handles:
 * - WebAuthn argument building and response parsing
 * - Authenticator data management with caching
 * - Contract reads/writes for saving Authenticators to the contract
 */
export class AuthenticatorSyncer {
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

  // === AUTHENTICATOR MANAGEMENT METHODS ===

  /**
   * Find authenticators by user (NEAR account ID)
   * Tries cache first, falls back to contract
   */
  async findAuthenticatorsByUserId(nearAccountId: string): Promise<StoredAuthenticator[]> {
    try {
      console.log(`Finding authenticators for user: ${nearAccountId}`);

      // Try cache first
      const cached = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
      if (cached.length > 0) {
        console.log(`Found ${cached.length} authenticators in cache`);
        return cached.map(this.mapClientToStoredAuthenticator);
      }

      console.log(`Cache miss, fetching from contract`);

      // Cache miss, fetch from contract
      const result = await view({
        account: this.contractId,
        method: 'get_authenticators_by_user',
        args: { user_id: nearAccountId },
        deps: { rpcProvider: this.provider },
      }) as Array<[string, ContractAuthenticator]>;

      console.log(`Contract returned ${result.length} authenticators`);

      const authenticators = result.map(([credentialId, auth]) =>
        this.mapContractToStoredAuthenticator(auth, credentialId, nearAccountId)
      );

      // Update cache with contract data
      await this.syncCacheFromContract(nearAccountId, authenticators);

      return authenticators;
    } catch (error) {
      console.error('Error in findAuthenticatorsByUserId:', error);

      // If contract fails, try cache as backup
      const cached = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
      console.log(`Fallback to cache returned ${cached.length} authenticators`);
      return cached.map(this.mapClientToStoredAuthenticator);
    }
  }

  /**
   * Find authenticator by credential ID
   *
   * This method differs from `findAuthenticatorsByUserId()` by searching for a specific
   * authenticator using its unique credential ID rather than retrieving all authenticators
   * for a user. It implements a cache-first strategy with contract fallback.
   *
   * @param credentialId - The base64url-encoded credential ID to search for
   * @param nearAccountId - Optional NEAR account ID to optimize cache lookup and enable contract fallback
   * @returns The matching authenticator or undefined if not found
   *
   * **Behavior:**
   * - If `nearAccountId` provided: Tries IndexDB cache first, then contract on cache miss
   * - If `nearAccountId` missing: Only searches cache (cannot query contract without user ID)
   * - Updates cache with contract data when found via contract query
   * - Falls back to cache on contract errors
   */
  async findAuthenticatorByCredentialId(
    credentialId: string,
    nearAccountId?: string
  ): Promise<StoredAuthenticator | undefined> {
    try {
      // If we have nearAccountId, try cache first
      if (nearAccountId) {
        const cached = await indexDBManager.getAuthenticatorByCredentialId(nearAccountId, credentialId);
        if (cached) {
          console.log(`Found authenticator ${credentialId} in cache`);
          return this.mapClientToStoredAuthenticator(cached);
        }
      }

      // Cache miss - we need the nearAccountId to query the contract
      if (!nearAccountId) {
        console.warn(`Cache miss for credential ${credentialId} and no nearAccountId provided`);
        return undefined;
      }

      console.log(`Cache miss for credential ${credentialId}, fetching from contract`);

      const result = await view({
        account: this.contractId,
        method: 'get_authenticator',
        args: {
          user_id: nearAccountId,
          credential_id: credentialId
        },
        deps: { rpcProvider: this.provider },
      }) as ContractAuthenticator | null;

      if (!result) return undefined;

      const authenticator = this.mapContractToStoredAuthenticator(result, credentialId, nearAccountId);

      // Update cache
      await this.syncAuthenticatorToCache(authenticator, nearAccountId);

      return authenticator;
    } catch (error) {
      console.error('Error in findAuthenticatorByCredentialId:', error);

      // Try cache as backup
      if (nearAccountId) {
        const cached = await indexDBManager.getAuthenticatorByCredentialId(nearAccountId, credentialId);
        return cached ? this.mapClientToStoredAuthenticator(cached) : undefined;
      }
      return undefined;
    }
  }

  /**
   * Get latest authenticator by user - tries cache first
   *
   * **Key Differences from Other Authenticator Query Functions:**
   * - `findAuthenticatorsByUserId()`: Returns complete authenticator data for ALL user's authenticators
   * - `findAuthenticatorByCredentialId()`: Returns complete data for ONE specific authenticator
   * - `getLatestAuthenticatorByUserId()`: Returns only the credential ID of the MOST RECENTLY REGISTERED authenticator
   *
   * This method is optimized for quick lookups when you only need to know which authenticator
   * to use for authentication, without fetching full authenticator metadata. It's commonly used
   * for automatic authenticator selection in authentication flows.
   *
   * @param nearAccountId - The NEAR account ID to find the latest authenticator for
   * @returns Object with just the credential ID of the most recent authenticator, or undefined if none found
   *
   * **Behavior:**
   * - Implements cache-first strategy with contract fallback
   * - "Latest" means most recently registered (earliest in registration timestamp order)
   * - Triggers full cache refresh if data found in contract but not in cache
   * - Returns minimal data structure for performance optimization
   */
  async getLatestAuthenticatorByUserId(nearAccountId: string): Promise<{ credentialID: string } | undefined> {
    try {
      // Try cache first
      const cached = await indexDBManager.getLatestAuthenticatorByUser(nearAccountId);
      if (cached) {
        return cached;
      }

      // Cache miss, try contract
      const result = await view({
        account: this.contractId,
        method: 'get_latest_authenticator_by_user',
        args: { user_id: nearAccountId },
        deps: { rpcProvider: this.provider },
      }) as string | null;

      const fromContract = result ? { credentialID: result } : undefined;

      // If found in contract, refresh cache
      if (fromContract) {
        await this.syncCacheFromContract(nearAccountId);
      }

      return fromContract;
    } catch (error) {
      console.error('Error getting latest authenticator:', error);

      // Try cache as backup
      const cached = await indexDBManager.getLatestAuthenticatorByUser(nearAccountId);
      return cached || undefined;
    }
  }

  /**
   * Refresh cache from contract for a user
   */
  async refreshAuthenticatorCache(nearAccountId: string): Promise<void> {
    try {
      console.log(`Refreshing cache for user: ${nearAccountId}`);
      await this.syncCacheFromContract(nearAccountId);
    } catch (error) {
      console.error('Error refreshing cache:', error);
    }
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
    console.log(`AuthenticatorSyncer: Building registration options args for ${nearAccountId}`);

    // Convert existing authenticators to exclusion list
    const excludeCredentials = existingAuthenticators.length > 0
      ? existingAuthenticators.map(auth => ({
          id: auth.credentialID, // Contract expects base64url string id
          type: 'public-key' as const,
          transports: auth.transports || undefined,
        }))
      : null;

    // Extract username for contract calls - contract expects just username for proper suggestions
    const username = nearAccountId.split('.')[0];

    // Build contract arguments (replicate server logic)
    const contractArgs: ContractGenerateOptionsArgs = {
      rp_name: this.rpName,
      rp_id: this.rpId,
      user_name: username, // Use username for contract (contract expects username)
      user_id: userId,
      challenge: null, // Let contract generate challenge
      user_display_name: username, // Use username for contract display
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

    console.log('AuthenticatorSyncer: Built registration options args:', JSON.stringify(contractArgs));

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
    console.log('AuthenticatorSyncer: Building registration verification args with commitmentId:', commitmentId, '(serverless mode)');

    const contractArgs: ContractCompleteRegistrationArgs = {
      registration_response: attestationResponse,
      commitment_id: commitmentId,
    };

    console.log("AuthenticatorSyncer: Built registration verification args:", JSON.stringify(contractArgs));

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
    console.log('AuthenticatorSyncer: Building authentication options args (serverless mode)');

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

    console.log('AuthenticatorSyncer: Built authentication options args:', JSON.stringify(contractArgs));

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
    console.log('AuthenticatorSyncer: Building authentication verification args with commitmentId:', commitmentId, '(serverless mode)');

    const contractArgs: ContractVerifyAuthArgs = {
      authentication_response: authResponse,
      commitment_id: commitmentId,
    };

    console.log('AuthenticatorSyncer: Built authentication verification args:', JSON.stringify(contractArgs));

    return contractArgs;
  }

  // === HELPER METHODS ===

  /**
   * Parse contract response with robust error handling
   * Handles both legacy query responses and FinalExecutionOutcome from transactions
   */
  parseContractResponse(rawResult: FinalExecutionOutcome | any, methodName: string): any {
    console.log(`AuthenticatorSyncer: Parsing response for ${methodName}:`, rawResult);

    // Handle FinalExecutionOutcome from sendTransactionUntil
    if (rawResult && rawResult.status) {
      console.log(`AuthenticatorSyncer: Processing FinalExecutionOutcome for ${methodName}`);

      // Check main transaction status first (simpler path)
      if (typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status) {
        try {
          const base64Value = rawResult.status.SuccessValue;
          const decodedString = Buffer.from(base64Value, 'base64').toString();
          console.log(`AuthenticatorSyncer: Decoded SuccessValue for ${methodName}:`, decodedString);
          return JSON.parse(decodedString);
        } catch (parseError: any) {
          console.error(`AuthenticatorSyncer: Failed to parse SuccessValue for ${methodName}:`, parseError);
          throw new Error(`Failed to parse contract response JSON from SuccessValue: ${parseError.message}`);
        }
      }

      // Check for transaction failures
      if (typeof rawResult.status === 'object' && 'Failure' in rawResult.status) {
        const failure = rawResult.status.Failure;
        const executionError = failure.ActionError?.kind?.FunctionCallError?.ExecutionError;
        const errorMessage = executionError || JSON.stringify(failure);
        console.error(`AuthenticatorSyncer: Transaction failed for ${methodName}:`, errorMessage);
        throw new Error(`Transaction Error: ${errorMessage}`);
      }
    }

    // Fallback: Handle receipts_outcome if main status doesn't have SuccessValue
    if (rawResult && rawResult.receipts_outcome && Array.isArray(rawResult.receipts_outcome)) {
      console.log(`AuthenticatorSyncer: Checking receipts_outcome for ${methodName}`);

      // Find the first receipt with a successful function call result
      for (const receipt of rawResult.receipts_outcome) {
        if (receipt?.outcome?.status && typeof receipt.outcome.status === 'object' && 'SuccessValue' in receipt.outcome.status) {
          try {
            const base64Value = receipt.outcome.status.SuccessValue;
            const decodedString = Buffer.from(base64Value, 'base64').toString();
            console.log(`AuthenticatorSyncer: Decoded SuccessValue from receipt for ${methodName}:`, decodedString);
            return JSON.parse(decodedString);
          } catch (parseError: any) {
            console.error(`AuthenticatorSyncer: Failed to parse SuccessValue from receipt for ${methodName}:`, parseError);
            throw new Error(`Failed to parse contract response JSON from receipt SuccessValue: ${parseError.message}`);
          }
        }

        // Check for execution failures in receipts
        if (receipt?.outcome?.status && typeof receipt.outcome.status === 'object' && 'Failure' in receipt.outcome.status) {
          const failure = receipt.outcome.status.Failure;
          const executionError = failure.ActionError?.kind?.FunctionCallError?.ExecutionError;
          const errorMessage = executionError || JSON.stringify(failure);
          console.error(`AuthenticatorSyncer: Contract execution failed for ${methodName}:`, errorMessage);
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
      console.error(`AuthenticatorSyncer: Contract execution failed for ${methodName}:`, errorMessage);
      throw new Error(`Contract Error: ${errorMessage}`);
    }

    // Check for RPC errors
    if (rawResult && typeof (rawResult as any).error === 'object') {
      const rpcError = (rawResult as any).error;
      console.error(`AuthenticatorSyncer: RPC error from ${methodName}:`, rpcError);
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
      console.warn(`AuthenticatorSyncer: Unexpected rawResult structure from ${methodName}:`, rawResult);
      throw new Error('Failed to parse contract response: Unexpected format.');
    }

    // Parse JSON response
    try {
      return JSON.parse(contractResponseString);
    } catch (parseError: any) {
      console.error(`AuthenticatorSyncer: Failed to parse response from ${methodName}:`, contractResponseString, parseError);
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

  // === PRIVATE HELPER METHODS ===

  /**
   * Convert contract authenticator format to standardized StoredAuthenticator format
   *
   * This mapping function handles the complex data format conversion between how authenticators
   * are stored in the NEAR contract vs. how they're used throughout the application.
   *
   * @param contractAuth - Raw authenticator data from contract (ContractAuthenticator format)
   * @param credentialId - The credential ID (stored separately in contract as map key)
   * @param nearAccountId - The NEAR account ID that owns this authenticator
   * @returns Standardized StoredAuthenticator object for use throughout the app
   *
   * **Key Format Conversions:**
   * - `credential_public_key: number[]` → `credentialPublicKey: Uint8Array`
   * - `client_managed_near_public_key?: string` → `clientNearPublicKey?: string`
   * - `registered: string` (ISO date) → `registered: Date` object
   * - `last_used?: string` (ISO date) → `lastUsed?: Date` object
   * - `backed_up: boolean` → `backedUp: boolean` (camelCase conversion)
   * - Contract map key → `credentialID: string`
   * - nearAccountId parameter → `userId: string` (for compatibility)
   *
   * **Used by:**
   * - `findAuthenticatorsByUserId()` when processing contract query results
   * - `findAuthenticatorByCredentialId()` when processing single contract lookups
   * - Any operation that receives raw contract data and needs app-compatible format
   */
  private mapContractToStoredAuthenticator(
    contractAuth: ContractAuthenticator,
    credentialId: string,
    nearAccountId: string
  ): StoredAuthenticator {
    return {
      credentialID: credentialId,
      credentialPublicKey: new Uint8Array(contractAuth.credential_public_key),
      counter: contractAuth.counter,
      transports: contractAuth.transports as AuthenticatorTransport[],
      userId: nearAccountId,
      name: contractAuth.name,
      registered: new Date(contractAuth.registered),
      lastUsed: contractAuth.last_used ? new Date(contractAuth.last_used) : undefined,
      backedUp: contractAuth.backed_up,
      clientNearPublicKey: contractAuth.client_managed_near_public_key,
    };
  }

  private mapClientToStoredAuthenticator(clientAuth: ClientAuthenticatorData): StoredAuthenticator {
    return {
      credentialID: clientAuth.credentialID,
      credentialPublicKey: clientAuth.credentialPublicKey,
      counter: clientAuth.counter,
      transports: clientAuth.transports as AuthenticatorTransport[],
      userId: clientAuth.nearAccountId,
      name: clientAuth.name,
      registered: new Date(clientAuth.registered),
      lastUsed: clientAuth.lastUsed ? new Date(clientAuth.lastUsed) : undefined,
      backedUp: clientAuth.backedUp,
      clientNearPublicKey: clientAuth.clientNearPublicKey,
    };
  }

  /**
   * Synchronize local IndexDB cache with contract data for a specific user
   *
   * This is a crucial caching method that ensures local storage stays consistent with
   * the authoritative contract data. It handles the complex mapping between contract
   * storage format and client IndexDB format.
   *
   * @param nearAccountId - The NEAR account ID to sync cache for
   * @param contractData - Optional pre-fetched authenticator data from contract (avoids redundant contract calls)
   *
   * **Behavior:**
   * - If `contractData` provided: Uses pre-fetched data (performance optimization)
   * - If `contractData` not provided: Fetches fresh data from contract via `findAuthenticatorsByUserId()`
   * - Clears existing cache for the user via `indexDBManager.syncAuthenticatorsFromContract()`
   * - Converts contract format to IndexDB format (Date objects → ISO strings)
   * - Batch updates all authenticators for the user in a single operation
   * - Logs sync progress for debugging
   * - Gracefully handles sync errors without throwing (logs error instead)
   *
   * **Used by:**
   * - `findAuthenticatorsByUserId()` after contract queries
   * - `getLatestAuthenticatorByUserId()` when refreshing cache
   * - `refreshAuthenticatorCache()` for manual cache refresh
   */
  private async syncCacheFromContract(nearAccountId: string, contractData?: StoredAuthenticator[]): Promise<void> {
    try {
      const authenticators = contractData || await this.findAuthenticatorsByUserId(nearAccountId);

      // Convert to client format and sync
      const clientAuthenticators = authenticators.map(auth => ({
        credentialID: auth.credentialID,
        credentialPublicKey: auth.credentialPublicKey,
        counter: auth.counter,
        transports: auth.transports,
        clientNearPublicKey: auth.clientNearPublicKey,
        name: auth.name,
        registered: auth.registered instanceof Date ? auth.registered.toISOString() : auth.registered,
        lastUsed: auth.lastUsed ? (auth.lastUsed instanceof Date ? auth.lastUsed.toISOString() : auth.lastUsed) : undefined,
        backedUp: auth.backedUp,
      }));

      await indexDBManager.syncAuthenticatorsFromContract(nearAccountId, clientAuthenticators);

      console.log(`Synced ${authenticators.length} authenticators to cache for user ${nearAccountId}`);
    } catch (error) {
      console.error('Error syncing cache from contract:', error);
    }
  }

  /**
   * Synchronize a single authenticator to local IndexDB cache
   *
   * This method differs from `syncCacheFromContract()` by handling only ONE authenticator
   * rather than batch-syncing all authenticators for a user. It's used for incremental
   * cache updates when individual authenticators are found via contract queries.
   *
   * @param auth - The StoredAuthenticator data to sync to cache
   * @param nearAccountId - The NEAR account ID that owns this authenticator
   *
   * **Behavior:**
   * - Converts StoredAuthenticator format to ClientAuthenticatorData format for IndexDB
   * - Handles Date object → ISO string conversion for storage compatibility
   * - Sets `syncedAt` timestamp to track when cache was last updated
   * - Stores via `indexDBManager.storeAuthenticator()` (upsert operation)
   * - Gracefully handles storage errors without throwing (logs error instead)
   * - Preserves all authenticator metadata (counter, transports, keys, etc.)
   *
   * **Used by:**
   * - `findAuthenticatorByCredentialId()` after individual contract lookups
   * - Any operation that needs to cache a single authenticator without full refresh
   *
   * **vs syncCacheFromContract():**
   * - This: Single authenticator, incremental update, preserves other cached authenticators
   * - syncCacheFromContract(): All authenticators, full refresh, replaces entire user cache
   */
  private async syncAuthenticatorToCache(auth: StoredAuthenticator, nearAccountId: string): Promise<void> {
    try {
      const clientAuth: ClientAuthenticatorData = {
        nearAccountId,
        credentialID: auth.credentialID,
        credentialPublicKey: auth.credentialPublicKey,
        counter: auth.counter,
        transports: auth.transports,
        clientNearPublicKey: auth.clientNearPublicKey,
        name: auth.name,
        registered: auth.registered instanceof Date ? auth.registered.toISOString() : auth.registered,
        lastUsed: auth.lastUsed ? (auth.lastUsed instanceof Date ? auth.lastUsed.toISOString() : auth.lastUsed) : undefined,
        backedUp: auth.backedUp,
        syncedAt: new Date().toISOString(),
      };

      await indexDBManager.storeAuthenticator(clientAuth);
    } catch (error) {
      console.error('Error syncing authenticator to cache:', error);
    }
  }
}