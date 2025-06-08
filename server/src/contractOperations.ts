import config from './config';
import { view } from '@near-js/client';
import { nearClient } from './nearService';
import type { StoredAuthenticator } from './types';

// Convert contract transport strings to AuthenticatorTransport enum values
function parseTransports(transports?: string[]): any[] | undefined {
  if (!transports) return undefined;

  return transports.map(t => {
    switch (t) {
      case 'usb': return 'usb';
      case 'nfc': return 'nfc';
      case 'ble': return 'ble';
      case 'internal': return 'internal';
      case 'hybrid': return 'hybrid';
      default: return t;
    }
  });
}

// Convert contract authenticator to StoredAuthenticator type
function mapContractAuthenticator(contractAuth: any, credentialID: string): StoredAuthenticator {
  return {
    credentialID,
    credentialPublicKey: new Uint8Array(contractAuth.credential_public_key),
    counter: contractAuth.counter,
    transports: parseTransports(contractAuth.transports),
    userId: '', // Will be set by caller
    name: contractAuth.name || null,
    registered: new Date(contractAuth.registered),
    lastUsed: contractAuth.last_used ? new Date(contractAuth.last_used) : undefined,
    backedUp: contractAuth.backed_up,
    clientManagedNearPublicKey: contractAuth.client_managed_near_public_key || null,
  };
}

export const contractOperations = {
  async findByUserId(nearAccountId: string): Promise<StoredAuthenticator[]> {
    try {
      console.log(`🔍 Calling contract.get_authenticators_by_user with user_id: ${nearAccountId}`);

      const result = await view({
        account: config.contractId,
        method: 'get_authenticators_by_user',
        args: { user_id: nearAccountId },
        deps: { rpcProvider: nearClient.getProvider() },
      }) as Array<[string, any]>;

      console.log(`🔍 Contract returned:`, result);

      return result.map(([credentialId, auth]) => {
        const mapped = mapContractAuthenticator(auth, credentialId);
        mapped.userId = nearAccountId;
        console.log(`🔍 Mapped authenticator:`, { credentialId, counter: auth.counter, transports: auth.transports });
        return mapped;
      });
    } catch (error) {
      console.error('🔍 Error finding authenticators by user ID:', error);
      return [];
    }
  },

  async findByCredentialId(credentialId: string, nearAccountId: string): Promise<StoredAuthenticator | undefined> {
    try {
      const result = await view({
        account: config.contractId,
        method: 'get_authenticator',
        args: {
          user_id: nearAccountId,
          credential_id: credentialId
        },
        deps: { rpcProvider: nearClient.getProvider() },
      }) as any;

      if (!result) return undefined;

      const mapped = mapContractAuthenticator(result, credentialId);
      mapped.userId = nearAccountId;
      return mapped;
    } catch (error) {
      console.error('Error finding authenticator by credential ID:', error);
      return undefined;
    }
  },

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
      const transportStrings = authenticator.transports?.map(t => {
        if (typeof t === 'string') return t;
        // Handle enum-like objects
        return t.toString().toLowerCase();
      });

      const contractArgs = {
        user_id: authenticator.nearAccountId,
        credential_id: authenticator.credentialID,
        credential_public_key: Array.from(authenticator.credentialPublicKey),
        counter: authenticator.counter,
        transports: transportStrings,
        client_managed_near_public_key: authenticator.clientManagedNearPublicKey || undefined,
        name: authenticator.name || undefined,
        registered: authenticator.registered.toISOString(),
        backed_up: authenticator.backedUp,
      };

      console.log(`🔍 Calling contract.store_authenticator with args:`, {
        user_id: contractArgs.user_id,
        credential_id: contractArgs.credential_id,
        counter: contractArgs.counter,
        transports: contractArgs.transports
      });

      const transactionOutcome = await nearClient.callFunction(
        config.contractId,
        'store_authenticator',
        contractArgs,
        '50000000000000', // 50 TGas
        '0'
      );

      // Check if the transaction was successful
      if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'SuccessValue' in transactionOutcome.status) {
        const successValue = transactionOutcome.status.SuccessValue;
        const result = JSON.parse(Buffer.from(successValue, 'base64').toString());
        console.log(`🔍 Contract store_authenticator result:`, result);
        return result === true;
      } else if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'Failure' in transactionOutcome.status) {
        console.error('🔍 Contract store_authenticator failed:', transactionOutcome.status.Failure);
        return false;
      }

      console.log(`🔍 Contract store_authenticator result:`, true);
      return true;
    } catch (error) {
      console.error('🔍 Error creating authenticator in contract:', error);
      return false;
    }
  },

  async updateCounter(credentialId: string, counter: number, lastUsed: Date, nearAccountId: string): Promise<boolean> {
    try {
      const transactionOutcome = await nearClient.callFunction(
        config.contractId,
        'update_authenticator_usage',
        {
          user_id: nearAccountId,
          credential_id: credentialId,
          new_counter: counter,
          last_used: lastUsed.toISOString(),
        },
        '30000000000000', // 30 TGas
        '0'
      );

      // Check if the transaction was successful
      if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'SuccessValue' in transactionOutcome.status) {
        const successValue = transactionOutcome.status.SuccessValue;
        const result = JSON.parse(Buffer.from(successValue, 'base64').toString());
        return result === true;
      }

      return true; // Assume success if no explicit failure
    } catch (error) {
      console.error('Error updating authenticator counter:', error);
      return false;
    }
  },

  async updateClientManagedKey(credentialID: string, clientNearPublicKey: string, nearAccountId: string): Promise<boolean> {
    try {
      const transactionOutcome = await nearClient.callFunction(
        config.contractId,
        'update_authenticator_near_key',
        {
          user_id: nearAccountId,
          credential_id: credentialID,
          client_managed_near_public_key: clientNearPublicKey,
        },
        '30000000000000', // 30 TGas
        '0'
      );

      // Check if the transaction was successful
      if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'SuccessValue' in transactionOutcome.status) {
        const successValue = transactionOutcome.status.SuccessValue;
        const result = JSON.parse(Buffer.from(successValue, 'base64').toString());
        return result === true;
      }

      return true; // Assume success if no explicit failure
    } catch (error) {
      console.error('Error updating client managed key:', error);
      return false;
    }
  },

  async getLatestByUserId(nearAccountId: string): Promise<{ credentialID: string } | undefined> {
    try {
      const result = await view({
        account: config.contractId,
        method: 'get_latest_authenticator_by_user',
        args: { user_id: nearAccountId },
        deps: { rpcProvider: nearClient.getProvider() },
      }) as string | null;

      return result ? { credentialID: result } : undefined;
    } catch (error) {
      console.error('Error getting latest authenticator:', error);
      return undefined;
    }
  },
};
