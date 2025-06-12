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
      // Debug: Check total cache entries
      const { db } = await import('./database');
      const totalCacheEntries = db.prepare('SELECT COUNT(*) as count FROM authenticators_cache').get() as { count: number };
      console.log(`🔍 Total entries in authenticators_cache: ${totalCacheEntries.count}`);

      // Try cache first
      const cached = authenticatorCacheOperations.findByUserId(nearAccountId);
      if (cached.length > 0) {
        console.log(`🔍 Found ${cached.length} authenticators in cache for user ${nearAccountId}`);
        return cached.map(mapCachedToStoredAuthenticator);
      }

      console.log(`🔍 No authenticators found in cache for user ${nearAccountId}`);

      // Cache miss, fetch from contract
      console.log(`🔍 Cache miss for user ${nearAccountId}, fetching from contract`);
      const fromContract = await contractOperations.findByUserId(nearAccountId);
      console.log(`🔍 Contract returned ${fromContract.length} authenticators for user ${nearAccountId}`);

      // Update cache with contract data
      await this.syncCacheFromContract(nearAccountId, fromContract);

      return fromContract;
    } catch (error) {
      console.error('🔍 Error in findByUserId:', error);
      // If contract fails, try cache as backup
      const cached = authenticatorCacheOperations.findByUserId(nearAccountId);
      console.log(`🔍 Fallback to cache returned ${cached.length} authenticators`);
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
      console.log(`🔍 [AuthenticatorService] Creating authenticator for ${authenticator.nearAccountId}:`, {
        credentialID: authenticator.credentialID,
        counter: authenticator.counter,
        transports: authenticator.transports,
        clientManagedKey: authenticator.clientManagedNearPublicKey ? 'PROVIDED' : 'NOT PROVIDED'
      });

      // Write to contract first (source of truth)
      console.log(`🔍 [AuthenticatorService] Writing to contract for ${authenticator.credentialID}`);
      const contractSuccess = await contractOperations.create(authenticator);
      console.log(`🔍 [AuthenticatorService] Contract create result for ${authenticator.credentialID}:`, contractSuccess);

      if (contractSuccess) {
        // Update cache
        console.log(`🔍 [AuthenticatorService] Updating cache for ${authenticator.credentialID}`);
        try {
          const cacheData = {
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
          };

          console.log(`🔍 [AuthenticatorService] Cache data for ${authenticator.credentialID}:`, {
            ...cacheData,
            credentialPublicKey: `Buffer(${cacheData.credentialPublicKey.length} bytes)`
          });

          authenticatorCacheOperations.upsert(cacheData);
          console.log(`✅ [AuthenticatorService] Cache update successful for ${authenticator.credentialID}`);

          // Verify cache storage immediately
          const verification = authenticatorCacheOperations.findByCredentialId(
            authenticator.nearAccountId,
            authenticator.credentialID
          );
          if (verification) {
            console.log(`✅ [AuthenticatorService] Cache verification successful for ${authenticator.credentialID}`);
          } else {
            console.error(`❌ [AuthenticatorService] Cache verification failed for ${authenticator.credentialID} - not found after upsert`);

            // Try one more time with explicit debug
            console.log(`🔍 [AuthenticatorService] Attempting cache upsert retry for ${authenticator.credentialID}`);
            authenticatorCacheOperations.upsert(cacheData);

            const retryVerification = authenticatorCacheOperations.findByCredentialId(
              authenticator.nearAccountId,
              authenticator.credentialID
            );
            if (retryVerification) {
              console.log(`✅ [AuthenticatorService] Cache verification successful on retry for ${authenticator.credentialID}`);
            } else {
              console.error(`❌ [AuthenticatorService] Cache verification failed on retry for ${authenticator.credentialID}`);
              // Log cache stats for debugging
              const { db } = await import('./database');
              const totalEntries = db.prepare('SELECT COUNT(*) as count FROM authenticators_cache').get() as { count: number };
              const userEntries = db.prepare('SELECT COUNT(*) as count FROM authenticators_cache WHERE nearAccountId = ?').get(authenticator.nearAccountId) as { count: number };
              console.log(`🔍 [AuthenticatorService] Cache debug - Total entries: ${totalEntries.count}, User entries: ${userEntries.count}`);
            }
          }

        } catch (cacheError: any) {
          console.error(`❌ [AuthenticatorService] Cache update failed for ${authenticator.credentialID}:`, {
            error: cacheError.message,
            stack: cacheError.stack,
            name: cacheError.name
          });
          // Don't fail the overall operation for cache issues, but log prominently
          console.warn(`⚠️ [AuthenticatorService] Continuing despite cache failure for ${authenticator.credentialID}`);
        }

        console.log(`✅ [AuthenticatorService] Created authenticator ${authenticator.credentialID} in contract and cache`);
        return true;
      } else {
        console.warn(`❌ [AuthenticatorService] Contract create failed for ${authenticator.credentialID}`);
        return false;
      }

    } catch (error: any) {
      console.error(`❌ [AuthenticatorService] Error creating authenticator ${authenticator.credentialID}:`, {
        error: error.message,
        stack: error.stack,
        name: error.name
      });
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