import { view } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import { indexDBManager, type ClientAuthenticatorData } from './IndexDBManager';

// Types matching the contract interface
export interface ContractAuthenticator {
  credential_public_key: number[];
  counter: number;
  transports?: string[];
  client_managed_near_public_key?: string;
  name?: string;
  registered: string;
  last_used?: string;
  backed_up: boolean;
}

export interface StoredAuthenticator {
  credentialID: string;
  credentialPublicKey: Uint8Array;
  counter: number;
  transports?: string[];
  userId: string; // nearAccountId
  name?: string;
  registered: Date;
  lastUsed?: Date;
  backedUp: boolean;
  clientNearPublicKey?: string;
}

  /**
 * Client-side contract operations service for serverless mode
 * Provides the same interface as the server's authenticatorService but works directly with contracts
 */
export class ClientContractService {
  private contractId: string;
  private nearRpcProvider: Provider;

  constructor(contractId: string, nearRpcProvider: Provider) {
    this.contractId = contractId;
    this.nearRpcProvider = nearRpcProvider;
  }

  /**
   * Find authenticators by user (NEAR account ID)
   * Tries cache first, falls back to contract
   */
  async findByUserId(nearAccountId: string): Promise<StoredAuthenticator[]> {
    try {
      console.log(`🔍 [ClientContract] Finding authenticators for user: ${nearAccountId}`);

      // Try cache first
      const cached = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
      if (cached.length > 0) {
        console.log(`🔍 [ClientContract] Found ${cached.length} authenticators in cache`);
        return cached.map(this.mapClientToStoredAuthenticator);
      }

      console.log(`🔍 [ClientContract] Cache miss, fetching from contract`);

      // Cache miss, fetch from contract
      const result = await view({
        account: this.contractId,
        method: 'get_authenticators_by_user',
        args: { user_id: nearAccountId },
        deps: { rpcProvider: this.nearRpcProvider },
      }) as Array<[string, ContractAuthenticator]>;

      console.log(`🔍 [ClientContract] Contract returned ${result.length} authenticators`);

      const authenticators = result.map(([credentialId, auth]) =>
        this.mapContractToStoredAuthenticator(auth, credentialId, nearAccountId)
      );

      // Update cache with contract data
      await this.syncCacheFromContract(nearAccountId, authenticators);

      return authenticators;
    } catch (error) {
      console.error('🔍 [ClientContract] Error in findByUserId:', error);

      // If contract fails, try cache as backup
      const cached = await indexDBManager.getAuthenticatorsByUser(nearAccountId);
      console.log(`🔍 [ClientContract] Fallback to cache returned ${cached.length} authenticators`);
      return cached.map(this.mapClientToStoredAuthenticator);
    }
  }

  /**
   * Find authenticator by credential ID
   * Tries cache first, falls back to contract
   */
  async findByCredentialId(credentialId: string, nearAccountId?: string): Promise<StoredAuthenticator | undefined> {
    try {
      // If we have nearAccountId, try cache first
      if (nearAccountId) {
        const cached = await indexDBManager.getAuthenticatorByCredentialId(nearAccountId, credentialId);
        if (cached) {
          console.log(`🔍 [ClientContract] Found authenticator ${credentialId} in cache`);
          return this.mapClientToStoredAuthenticator(cached);
        }
      }

      // Cache miss - we need the nearAccountId to query the contract
      if (!nearAccountId) {
        console.warn(`🔍 [ClientContract] Cache miss for credential ${credentialId} and no nearAccountId provided`);
        return undefined;
      }

      console.log(`🔍 [ClientContract] Cache miss for credential ${credentialId}, fetching from contract`);

      const result = await view({
        account: this.contractId,
        method: 'get_authenticator',
        args: {
          user_id: nearAccountId,
          credential_id: credentialId
        },
        deps: { rpcProvider: this.nearRpcProvider },
      }) as ContractAuthenticator | null;

      if (!result) return undefined;

      const authenticator = this.mapContractToStoredAuthenticator(result, credentialId, nearAccountId);

      // Update cache
      await this.syncAuthenticatorToCache(authenticator, nearAccountId);

      return authenticator;
    } catch (error) {
      console.error('🔍 [ClientContract] Error in findByCredentialId:', error);

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
   */
  async getLatestByUserId(nearAccountId: string): Promise<{ credentialID: string } | undefined> {
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
        deps: { rpcProvider: this.nearRpcProvider },
      }) as string | null;

      const fromContract = result ? { credentialID: result } : undefined;

      // If found in contract, refresh cache
      if (fromContract) {
        await this.syncCacheFromContract(nearAccountId);
      }

      return fromContract;
    } catch (error) {
      console.error('🔍 [ClientContract] Error getting latest authenticator:', error);

      // Try cache as backup
      const cached = await indexDBManager.getLatestAuthenticatorByUser(nearAccountId);
      return cached || undefined;
    }
  }

  /**
   * Refresh cache from contract for a user
   */
  async refreshCache(nearAccountId: string): Promise<void> {
    try {
      console.log(`🔍 [ClientContract] Refreshing cache for user: ${nearAccountId}`);
      await this.syncCacheFromContract(nearAccountId);
    } catch (error) {
      console.error('🔍 [ClientContract] Error refreshing cache:', error);
    }
  }

  // === PRIVATE HELPER METHODS ===

  private mapContractToStoredAuthenticator(
    contractAuth: ContractAuthenticator,
    credentialId: string,
    nearAccountId: string
  ): StoredAuthenticator {
    return {
      credentialID: credentialId,
      credentialPublicKey: new Uint8Array(contractAuth.credential_public_key),
      counter: contractAuth.counter,
      transports: contractAuth.transports,
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
      transports: clientAuth.transports,
      userId: clientAuth.nearAccountId,
      name: clientAuth.name,
      registered: new Date(clientAuth.registered),
      lastUsed: clientAuth.lastUsed ? new Date(clientAuth.lastUsed) : undefined,
      backedUp: clientAuth.backedUp,
      clientNearPublicKey: clientAuth.clientNearPublicKey,
    };
  }

  private async syncCacheFromContract(nearAccountId: string, contractData?: StoredAuthenticator[]): Promise<void> {
    try {
      const authenticators = contractData || await this.findByUserId(nearAccountId);

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

      console.log(`🔍 [ClientContract] Synced ${authenticators.length} authenticators to cache for user ${nearAccountId}`);
    } catch (error) {
      console.error('🔍 [ClientContract] Error syncing cache from contract:', error);
    }
  }

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
      console.error('🔍 [ClientContract] Error syncing authenticator to cache:', error);
    }
  }

}