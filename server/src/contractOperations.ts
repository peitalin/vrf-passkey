import config from './config';
import { connect, keyStores, Account, Contract } from 'near-api-js';
import type { StoredAuthenticator } from './types';

const keyStore = new keyStores.InMemoryKeyStore();

// Contract interface for TypeScript
interface WebAuthnContract extends Contract {
  get_authenticators_by_user(args: { user_id: string }): Promise<Array<[string, any]>>;
  get_authenticator(args: { user_id: string, credential_id: string }): Promise<any | null>;
  store_authenticator(args: {
    user_id: string;
    credential_id: string;
    credential_public_key: number[];
    counter: number;
    transports?: string[];
    client_managed_near_public_key?: string;
    name?: string;
    registered: string;
    backed_up: boolean;
  }): Promise<boolean>;
  update_authenticator_usage(args: {
    user_id: string;
    credential_id: string;
    new_counter: number;
    last_used: string;
  }): Promise<boolean>;
  update_authenticator_near_key(args: {
    user_id: string;
    credential_id: string;
    client_managed_near_public_key: string;
  }): Promise<boolean>;
  get_latest_authenticator_by_user(args: { user_id: string }): Promise<string | null>;
}

let contractInstance: WebAuthnContract | null = null;

async function getContract(): Promise<WebAuthnContract> {
  if (contractInstance) {
    return contractInstance;
  }

  const near = await connect({
    networkId: config.networkId,
    nodeUrl: config.nodeUrl,
    keyStore,
  });

  const account = await near.account(config.relayerAccountId);

  contractInstance = new Contract(account, config.contractId, {
    viewMethods: [
      'get_authenticators_by_user',
      'get_authenticator',
      'get_latest_authenticator_by_user'
    ],
    changeMethods: [
      'store_authenticator',
      'update_authenticator_usage',
      'update_authenticator_near_key'
    ],
    useLocalViewExecution: false,
  }) as WebAuthnContract;

  return contractInstance;
}

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
      const contract = await getContract();
      const result = await contract.get_authenticators_by_user({ user_id: nearAccountId });

      return result.map(([credentialId, auth]) => {
        const mapped = mapContractAuthenticator(auth, credentialId);
        mapped.userId = nearAccountId;
        return mapped;
      });
    } catch (error) {
      console.error('Error finding authenticators by user ID:', error);
      return [];
    }
  },

  async findByCredentialId(credentialId: string, nearAccountId: string): Promise<StoredAuthenticator | undefined> {
    try {
      const contract = await getContract();
      const result = await contract.get_authenticator({
        user_id: nearAccountId,
        credential_id: credentialId
      });

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
      const contract = await getContract();

      const transportStrings = authenticator.transports?.map(t => {
        if (typeof t === 'string') return t;
        // Handle enum-like objects
        return t.toString().toLowerCase();
      });

      const result = await contract.store_authenticator({
        user_id: authenticator.nearAccountId,
        credential_id: authenticator.credentialID,
        credential_public_key: Array.from(authenticator.credentialPublicKey),
        counter: authenticator.counter,
        transports: transportStrings,
        client_managed_near_public_key: authenticator.clientManagedNearPublicKey || undefined,
        name: authenticator.name || undefined,
        registered: authenticator.registered.toISOString(),
        backed_up: authenticator.backedUp,
      });

      return result;
    } catch (error) {
      console.error('Error creating authenticator:', error);
      return false;
    }
  },

  async updateCounter(credentialId: string, counter: number, lastUsed: Date, nearAccountId: string): Promise<boolean> {
    try {
      const contract = await getContract();

      const result = await contract.update_authenticator_usage({
        user_id: nearAccountId,
        credential_id: credentialId,
        new_counter: counter,
        last_used: lastUsed.toISOString(),
      });

      return result;
    } catch (error) {
      console.error('Error updating authenticator counter:', error);
      return false;
    }
  },

  async updateClientManagedKey(credentialID: string, clientNearPublicKey: string, nearAccountId: string): Promise<boolean> {
    try {
      const contract = await getContract();

      const result = await contract.update_authenticator_near_key({
        user_id: nearAccountId,
        credential_id: credentialID,
        client_managed_near_public_key: clientNearPublicKey,
      });

      return result;
    } catch (error) {
      console.error('Error updating client managed key:', error);
      return false;
    }
  },

  async getLatestByUserId(nearAccountId: string): Promise<{ credentialID: string } | undefined> {
    try {
      const contract = await getContract();
      const result = await contract.get_latest_authenticator_by_user({ user_id: nearAccountId });

      return result ? { credentialID: result } : undefined;
    } catch (error) {
      console.error('Error getting latest authenticator:', error);
      return undefined;
    }
  },
};
