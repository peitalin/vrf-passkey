import {
  getSignerFromKeystore,
  getTestnetRpcProvider,
  view,
  functionCall
} from '@near-js/client';
import { KeyPairEd25519 } from '@near-js/crypto';
import { InMemoryKeyStore } from '@near-js/keystores';
import type { KeyStore } from '@near-js/keystores';
import { ActionType, type SerializableActionArgs } from './types';

const PASSKEY_CONTROLLER_CONTRACT_ID = process.env.PASSKEY_CONTROLLER_CONTRACT_ID!;
const RELAYER_ACCOUNT_ID = process.env.RELAYER_ACCOUNT_ID!;
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY!;
const NEAR_NETWORK_ID = process.env.NEAR_NETWORK_ID || 'testnet';

let keyStore: KeyStore;
let rpcProvider: any;
let signer: any;
let isInitialized = false;

export const initNear = async (): Promise<void> => {
  if (isInitialized) {
    console.log('NEAR connection already initialized.');
    return;
  }

  if (!PASSKEY_CONTROLLER_CONTRACT_ID || !RELAYER_ACCOUNT_ID || !RELAYER_PRIVATE_KEY) {
    throw new Error('Missing NEAR environment variables for passkey controller or relayer.');
  }

  // Initialize keystore
  keyStore = new InMemoryKeyStore();

  // Parse the private key and add to keystore
  // The RELAYER_PRIVATE_KEY should be in format "ed25519:base58privatekey"
  // We need to parse it and create the KeyPair
  if (!RELAYER_PRIVATE_KEY.startsWith('ed25519:')) {
    throw new Error('Private key must be in format "ed25519:base58privatekey"');
  }

  const privateKeyString = RELAYER_PRIVATE_KEY.substring(8); // Remove "ed25519:" prefix
  const keyPair = new KeyPairEd25519(privateKeyString);
  await keyStore.setKey(NEAR_NETWORK_ID, RELAYER_ACCOUNT_ID, keyPair);

  // Get RPC provider based on network
  if (NEAR_NETWORK_ID === 'mainnet') {
    // For mainnet, you'd use getMainnetRpcProvider() if available
    // or create a custom provider with mainnet RPC URL
    throw new Error('Mainnet support needs to be implemented');
  } else {
    rpcProvider = getTestnetRpcProvider();
  }

  // Get signer for the relayer account
  signer = getSignerFromKeystore(RELAYER_ACCOUNT_ID, NEAR_NETWORK_ID, keyStore);

  isInitialized = true;
  console.log(`NEAR connection initialized for network: ${NEAR_NETWORK_ID}, relayer: ${RELAYER_ACCOUNT_ID}`);
  console.log(`Passkey Controller Contract ID: ${PASSKEY_CONTROLLER_CONTRACT_ID}`);
};

const ensureNearInitialized = async () => {
  if (!isInitialized) {
    await initNear();
  }
};

// --- PasskeyController Contract Specific Functions ---

export const isPasskeyPkRegistered = async (passkeyPk: string): Promise<boolean> => {
  await ensureNearInitialized();
  return view({
    account: PASSKEY_CONTROLLER_CONTRACT_ID,
    method: 'is_passkey_pk_registered',
    args: { passkey_pk: passkeyPk },
    deps: { rpcProvider },
  });
};

export const getTrustedRelayer = async (): Promise<string> => {
  await ensureNearInitialized();
  return view({
    account: PASSKEY_CONTROLLER_CONTRACT_ID,
    method: 'get_trusted_relayer',
    args: {},
    deps: { rpcProvider },
  });
};

export const getOwnerId = async (): Promise<string> => {
  await ensureNearInitialized();
  return view({
    account: PASSKEY_CONTROLLER_CONTRACT_ID,
    method: 'get_owner_id',
    args: {},
    deps: { rpcProvider },
  });
};

export const addPasskeyPk = async (passkeyPk: string): Promise<any> => {
  await ensureNearInitialized();
  return functionCall({
    sender: RELAYER_ACCOUNT_ID,
    receiver: PASSKEY_CONTROLLER_CONTRACT_ID,
    method: 'add_passkey_pk',
    args: { passkey_pk: passkeyPk },
    gas: BigInt('30000000000000'), // 30 TGas
    deposit: BigInt('0'),
    deps: { rpcProvider, signer },
  });
};

export const removePasskeyPk = async (passkeyPk: string): Promise<any> => {
  await ensureNearInitialized();
  return functionCall({
    sender: RELAYER_ACCOUNT_ID,
    receiver: PASSKEY_CONTROLLER_CONTRACT_ID,
    method: 'remove_passkey_pk',
    args: { passkey_pk: passkeyPk },
    gas: BigInt('30000000000000'), // 30 TGas
    deposit: BigInt('0'),
    deps: { rpcProvider, signer },
  });
};

export const executeActions = async (
  passkeyPkUsed: string,
  actionToExecute: SerializableActionArgs
): Promise<any> => {
  await ensureNearInitialized();
  const argsForContract = {
    passkey_pk_used: passkeyPkUsed,
    action_to_execute: actionToExecute
  };

  return functionCall({
    sender: RELAYER_ACCOUNT_ID,
    receiver: PASSKEY_CONTROLLER_CONTRACT_ID,
    method: 'execute_actions',
    args: argsForContract,
    gas: BigInt('300000000000000'), // 300 TGas for complex operations
    deposit: BigInt('0'),
    deps: { rpcProvider, signer },
  });
};

export const encodeArgsForContract = (args: Record<string, any>): string => {
  return Buffer.from(JSON.stringify(args)).toString('base64');
};
