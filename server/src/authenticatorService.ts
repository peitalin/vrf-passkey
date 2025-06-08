import { authenticatorCacheOperations, mapCachedToStoredAuthenticator } from './database';
import { contractOperations } from './contractOperations';
import type { StoredAuthenticator } from './types';

export class AuthenticatorService {

  /**
   * Find authenticators by user (NEAR account ID)
   * Tries cache first, falls back to contract
   */
  async findByUserId(nearAccountId: string): Promise<StoredAuthenticator[]> {
    try {
      // Try cache first
      const cached = authenticatorCacheOperations.findByUserId(nearAccountId);
      if (cached.length > 0) {
        console.log(`Found ${cached.length} authenticators in cache for user ${nearAccountId}`);
        return cached.map(mapCachedToStoredAuthenticator);
      }

      // Cache miss, fetch from contract
      console.log(`Cache miss for user ${nearAccountId}, fetching from contract`);
      const fromContract = await contractOperations.findByUserId(nearAccountId);

      // Update cache with contract data
      await this.syncCacheFromContract(nearAccountId, fromContract);

      return fromContract;
    } catch (error) {
      console.error('Error in findByUserId:', error);
      // If contract fails, try cache as backup
      const cached = authenticatorCacheOperations.findByUserId(nearAccountId);
      return cached.map(mapCachedToStoredAuthenticator);
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
        const cached = authenticatorCacheOperations.findByCredentialId(nearAccountId, credentialId);
        if (cached) {
          console.log(`Found authenticator ${credentialId} in cache`);
          return mapCachedToStoredAuthenticator(cached);
        }
      } else {
        // Try global cache lookup
        const cached = authenticatorCacheOperations.findByCredentialIdGlobal(credentialId);
        if (cached) {
          console.log(`Found authenticator ${credentialId} in global cache`);
          return mapCachedToStoredAuthenticator(cached);
        }
      }

      // Cache miss - we need the nearAccountId to query the contract
      if (!nearAccountId) {
        console.warn(`Cache miss for credential ${credentialId} and no nearAccountId provided`);
        return undefined;
      }

      console.log(`Cache miss for credential ${credentialId}, fetching from contract`);
      const fromContract = await contractOperations.findByCredentialId(credentialId, nearAccountId);

      if (fromContract) {
        // Update cache
        await this.syncAuthenticatorToCache(fromContract, nearAccountId);
      }

      return fromContract;
    } catch (error) {
      console.error('Error in findByCredentialId:', error);
      // Try cache as backup
      if (nearAccountId) {
        const cached = authenticatorCacheOperations.findByCredentialId(nearAccountId, credentialId);
        return cached ? mapCachedToStoredAuthenticator(cached) : undefined;
      }
      return undefined;
    }
  }

  /**
   * Create new authenticator - writes to both contract and cache
   */
  async create(authenticator: {
    credentialID: string;
    credentialPublicKey: Uint8Array;
    counter: number;
    transports?: any[];
    nearAccountId: string;
    name?: string | null;
    registered: Date;
    backedUp: boolean;
    clientManagedNearPublicKey?: string | null;
  }): Promise<boolean> {
    try {
      // Write to contract first (source of truth)
      const contractSuccess = await contractOperations.create(authenticator);

      if (contractSuccess) {
        // Update cache
        authenticatorCacheOperations.upsert({
          nearAccountId: authenticator.nearAccountId,
          credentialID: authenticator.credentialID,
          credentialPublicKey: Buffer.from(authenticator.credentialPublicKey),
          counter: authenticator.counter,
          transports: authenticator.transports ? JSON.stringify(authenticator.transports) : null,
          clientManagedNearPublicKey: authenticator.clientManagedNearPublicKey || null,
          name: authenticator.name || null,
          registered: authenticator.registered.toISOString(),
          lastUsed: null,
          backedUp: authenticator.backedUp ? 1 : 0,
        });

        console.log(`Created authenticator ${authenticator.credentialID} in contract and cache`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('Error creating authenticator:', error);
      return false;
    }
  }

  /**
   * Update authenticator counter - writes to both contract and cache
   */
  async updateCounter(credentialId: string, counter: number, lastUsed: Date, nearAccountId: string): Promise<boolean> {
    try {
      // Update contract first
      const contractSuccess = await contractOperations.updateCounter(credentialId, counter, lastUsed, nearAccountId);

      if (contractSuccess) {
        // Update cache
        authenticatorCacheOperations.updateCounter(nearAccountId, credentialId, counter, lastUsed.toISOString());
        console.log(`Updated counter for ${credentialId} in contract and cache`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('Error updating authenticator counter:', error);
      return false;
    }
  }

  /**
   * Update client managed NEAR key - writes to both contract and cache
   */
  async updateClientManagedKey(credentialID: string, clientNearPublicKey: string, nearAccountId: string): Promise<boolean> {
    try {
      // Update contract first
      const contractSuccess = await contractOperations.updateClientManagedKey(credentialID, clientNearPublicKey, nearAccountId);

      if (contractSuccess) {
        // Update cache
        authenticatorCacheOperations.updateClientManagedKey(nearAccountId, credentialID, clientNearPublicKey);
        console.log(`Updated client managed key for ${credentialID} in contract and cache`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('Error updating client managed key:', error);
      return false;
    }
  }

  /**
   * Get latest authenticator by user - tries cache first
   */
  async getLatestByUserId(nearAccountId: string): Promise<{ credentialID: string } | undefined> {
    try {
      // Try cache first
      const cached = authenticatorCacheOperations.getLatestByUserId(nearAccountId);
      if (cached) {
        return cached;
      }

      // Cache miss, try contract
      const fromContract = await contractOperations.getLatestByUserId(nearAccountId);

      // If found in contract, refresh cache
      if (fromContract) {
        await this.syncCacheFromContract(nearAccountId);
      }

      return fromContract;
    } catch (error) {
      console.error('Error getting latest authenticator:', error);
      // Try cache as backup
      return authenticatorCacheOperations.getLatestByUserId(nearAccountId);
    }
  }

  /**
   * Sync cache from contract data
   */
  private async syncCacheFromContract(nearAccountId: string, contractData?: StoredAuthenticator[]): Promise<void> {
    try {
      const authenticators = contractData || await contractOperations.findByUserId(nearAccountId);

      // Clear existing cache for this user
      authenticatorCacheOperations.clear(nearAccountId);

      // Add all contract authenticators to cache
      for (const auth of authenticators) {
        authenticatorCacheOperations.upsert({
          nearAccountId,
          credentialID: auth.credentialID,
          credentialPublicKey: Buffer.from(auth.credentialPublicKey),
          counter: auth.counter,
          transports: auth.transports ? JSON.stringify(auth.transports) : null,
          clientManagedNearPublicKey: auth.clientManagedNearPublicKey || null,
          name: auth.name || null,
          registered: auth.registered instanceof Date ? auth.registered.toISOString() : auth.registered,
          lastUsed: auth.lastUsed ? (auth.lastUsed instanceof Date ? auth.lastUsed.toISOString() : auth.lastUsed) : null,
          backedUp: auth.backedUp ? 1 : 0,
        });
      }

      console.log(`Synced ${authenticators.length} authenticators to cache for user ${nearAccountId}`);
    } catch (error) {
      console.error('Error syncing cache from contract:', error);
    }
  }

  /**
   * Sync single authenticator to cache
   */
  private async syncAuthenticatorToCache(auth: StoredAuthenticator, nearAccountId: string): Promise<void> {
    try {
      authenticatorCacheOperations.upsert({
        nearAccountId,
        credentialID: auth.credentialID,
        credentialPublicKey: Buffer.from(auth.credentialPublicKey),
        counter: auth.counter,
        transports: auth.transports ? JSON.stringify(auth.transports) : null,
        clientManagedNearPublicKey: auth.clientManagedNearPublicKey || null,
        name: auth.name || null,
        registered: auth.registered instanceof Date ? auth.registered.toISOString() : auth.registered,
        lastUsed: auth.lastUsed ? (auth.lastUsed instanceof Date ? auth.lastUsed.toISOString() : auth.lastUsed) : null,
        backedUp: auth.backedUp ? 1 : 0,
      });
    } catch (error) {
      console.error('Error syncing authenticator to cache:', error);
    }
  }

  /**
   * Force refresh cache from contract
   */
  async refreshCache(nearAccountId: string): Promise<void> {
    console.log(`Force refreshing cache for user ${nearAccountId}`);
    await this.syncCacheFromContract(nearAccountId);
  }

  /**
   * Clear cache for user
   */
  clearCache(nearAccountId: string): void {
    authenticatorCacheOperations.clear(nearAccountId);
  }
}

// Export singleton instance
export const authenticatorService = new AuthenticatorService();