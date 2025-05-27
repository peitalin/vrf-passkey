import {
  getSignerFromKeystore,
  getTestnetRpcProvider,
  view,
} from '@near-js/client';
import {
    FunctionCall,
    createTransaction,
    type Transaction,
    type SignedTransaction,
    type Action
} from '@near-js/transactions';
import { KeyPairEd25519, type PublicKey as NearPublicKey } from '@near-js/crypto';
import { InMemoryKeyStore } from '@near-js/keystores';
import type { KeyStore } from '@near-js/keystores';
import type { Signer } from '@near-js/signers';
import type { Provider } from '@near-js/providers';
import type { AccessKeyView } from '@near-js/types';
import { ActionType, type SerializableActionArgs } from './types';
import bs58 from 'bs58';

// Helper function to recursively stringify BigInts (if needed for complex args, though not for these simple calls)
function deepStringifyBigInts(obj: any): any {
  if (obj === null) return null;
  if (typeof obj === 'bigint') {
    return obj.toString();
  }
  if (typeof obj !== 'object') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(deepStringifyBigInts);
  }
  const newObj: { [key: string]: any } = {};
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      newObj[key] = deepStringifyBigInts(obj[key]);
    }
  }
  return newObj;
}

const PASSKEY_CONTROLLER_CONTRACT_ID = process.env.PASSKEY_CONTROLLER_CONTRACT_ID!;
const RELAYER_ACCOUNT_ID = process.env.RELAYER_ACCOUNT_ID!;
const RELAYER_PRIVATE_KEY = process.env.RELAYER_PRIVATE_KEY!;
const NEAR_NETWORK_ID = process.env.NEAR_NETWORK_ID || 'testnet';
const HELLO_NEAR_CONTRACT_ID = 'cyan-loong.testnet'; // For the test functions

let keyStore: KeyStore;
let rpcProvider: Provider;
let signer: Signer;
let isInitialized = false;

export const initNear = async (): Promise<void> => {
  if (isInitialized) {
    console.log('NEAR connection already initialized.');
    return;
  }
  if (!PASSKEY_CONTROLLER_CONTRACT_ID || !RELAYER_ACCOUNT_ID || !RELAYER_PRIVATE_KEY) {
    throw new Error('Missing NEAR environment variables for passkey controller or relayer.');
  }
  keyStore = new InMemoryKeyStore();
  if (!RELAYER_PRIVATE_KEY.startsWith('ed25519:')) {
    throw new Error('Private key must be in format "ed25519:base58privatekey"');
  }
  const privateKeyString = RELAYER_PRIVATE_KEY.substring(8);
  const keyPair = new KeyPairEd25519(privateKeyString);
  await keyStore.setKey(NEAR_NETWORK_ID, RELAYER_ACCOUNT_ID, keyPair);
  if (NEAR_NETWORK_ID === 'mainnet') {
    throw new Error('Mainnet support needs to be implemented with a mainnet RPC provider.');
  } else {
    rpcProvider = getTestnetRpcProvider();
  }
  signer = await getSignerFromKeystore(RELAYER_ACCOUNT_ID, NEAR_NETWORK_ID, keyStore);
  isInitialized = true;
  console.log(`NEAR connection initialized for network: ${NEAR_NETWORK_ID}, relayer: ${RELAYER_ACCOUNT_ID}`);
  console.log(`Passkey Controller Contract ID: ${PASSKEY_CONTROLLER_CONTRACT_ID}`);
};

const ensureNearInitialized = async () => {
  if (!isInitialized) {
    await initNear();
  }
};

// --- Generic Helper to create and send a transaction with one FunctionCall action ---
async function executeFunctionCallAction(receiverId: string, methodName: string, args: Record<string, any>, gas: bigint, deposit: bigint): Promise<any> {
  await ensureNearInitialized();
  console.log(`Manually composing transaction for contract: ${receiverId}, method: ${methodName} with args:`, args);
  try {
    const publicKey = await signer.getPublicKey();
    if (!publicKey) throw new Error(`Could not get public key from signer for ${RELAYER_ACCOUNT_ID}`);

    const block = await rpcProvider.block({ finality: 'final' });
    const blockHash = Buffer.from(bs58.decode(block.header.hash));

    const accessKey = await rpcProvider.query<AccessKeyView>({
      request_type: 'view_access_key',
      finality: 'final',
      account_id: RELAYER_ACCOUNT_ID,
      public_key: publicKey.toString(),
    });
    const nonce = BigInt(accessKey.nonce) + BigInt(1);

    const contractCallArgsBuffer = Buffer.from(JSON.stringify(args));

    // Construct the action object to directly match the Borsh schema for FunctionCallAction
    const functionCallAction = {
      functionCall: {
        methodName: methodName,
        args: contractCallArgsBuffer,
        gas: gas,
        deposit: deposit,
      }
    };

    // Cast via unknown to satisfy TypeScript for this plain object structure.
    const actions: Action[] = [functionCallAction as unknown as Action];

    const transaction = createTransaction(
      RELAYER_ACCOUNT_ID,
      publicKey,
      receiverId,
      nonce,
      actions,
      blockHash
    );

    const signedTransactionTuple = await signer.signTransaction(transaction);
    const signedTx = signedTransactionTuple[1];

    console.log(`Transaction for ${methodName} on ${receiverId} created and signed. About to send.`);
    return rpcProvider.sendTransaction(signedTx);
  } catch (error) {
    console.error(`Error during manual transaction for ${methodName} on ${receiverId}:`, error);
    throw error;
  }
}

// --- PasskeyController Contract Specific Functions (View functions remain the same) ---
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

// --- Refactored Mutative Functions ---
export const addPasskeyPk = async (passkeyPk: string): Promise<any> => {
  return executeFunctionCallAction(
    PASSKEY_CONTROLLER_CONTRACT_ID,
    'add_passkey_pk',
    { passkey_pk: passkeyPk },
    BigInt('30000000000000'),
    BigInt('0')
  );
};

export const removePasskeyPk = async (passkeyPk: string): Promise<any> => {
  return executeFunctionCallAction(
    PASSKEY_CONTROLLER_CONTRACT_ID,
    'remove_passkey_pk',
    { passkey_pk: passkeyPk },
    BigInt('30000000000000'),
    BigInt('0')
  );
};

export const executeActions = async (
  passkeyPkUsed: string,
  actionToExecute: SerializableActionArgs
): Promise<any> => {
  const sanitizedActionToExecute: SerializableActionArgs = { ...actionToExecute };

  // Sanitize top-level numeric-like string fields first
  if (sanitizedActionToExecute.deposit !== undefined) sanitizedActionToExecute.deposit = String(sanitizedActionToExecute.deposit);
  if (sanitizedActionToExecute.gas !== undefined) sanitizedActionToExecute.gas = String(sanitizedActionToExecute.gas);
  if (sanitizedActionToExecute.amount !== undefined) sanitizedActionToExecute.amount = String(sanitizedActionToExecute.amount);
  if (sanitizedActionToExecute.allowance !== undefined) sanitizedActionToExecute.allowance = String(sanitizedActionToExecute.allowance);
  if (sanitizedActionToExecute.stake !== undefined) sanitizedActionToExecute.stake = String(sanitizedActionToExecute.stake);

  // Handle actionToExecute.args:
  // If it's an object, deep stringify BigInts then base64 encode.
  // If it's a string that looks like JSON, assume it's from client and base64 encode it.
  // If it's already a base64 string (doesn't look like JSON), pass it through.
  if (sanitizedActionToExecute.args) {
    if (typeof sanitizedActionToExecute.args === 'object') {
      const argsObjectWithStrBigInts = deepStringifyBigInts(sanitizedActionToExecute.args);
      const jsonStringArgs = JSON.stringify(argsObjectWithStrBigInts);
      sanitizedActionToExecute.args = Buffer.from(jsonStringArgs).toString('base64');
    } else if (typeof sanitizedActionToExecute.args === 'string') {
      const trimmedArgs = sanitizedActionToExecute.args.trim();
      if (trimmedArgs.startsWith('{') && trimmedArgs.endsWith('}')) {
        // Looks like a JSON string, assume it needs base64 encoding
        try {
          JSON.parse(trimmedArgs); // Validate if it's actual JSON
          console.log("executeActions: detected JSON string for args, base64 encoding it.");
          sanitizedActionToExecute.args = Buffer.from(trimmedArgs).toString('base64');
        } catch (e) {
          // Not valid JSON, or some other issue. Pass through, assuming it might be pre-encoded or a simple string arg.
          console.warn("executeActions: args string looked like JSON but failed to parse. Passing through.", e);
        }
      }
      // If it doesn't look like a JSON string, assume it's already base64 encoded or a simple string arg.
    }
  }

  const argsForContractMethod = {
    passkey_pk_used: passkeyPkUsed,
    action_to_execute: sanitizedActionToExecute
  };

  return executeFunctionCallAction(
    PASSKEY_CONTROLLER_CONTRACT_ID,
    'execute_delegated_actions',
    argsForContractMethod,
    BigInt('300000000000000'),
    BigInt('0')
  );
};

export const encodeArgsForContract = (args: Record<string, any>): string => {
  return Buffer.from(JSON.stringify(args)).toString('base64');
};


// --- Test functions for cyan-loong.testnet ---
/**
 * Calls the get_greeting view method on the cyan-loong.testnet contract.
 */
export const getGreeting = async (): Promise<string> => {
  await ensureNearInitialized();
  console.log(`Calling get_greeting on ${HELLO_NEAR_CONTRACT_ID}`);
  try {
    const result = await view({
      account: HELLO_NEAR_CONTRACT_ID,
      method: 'get_greeting',
      args: {},
      deps: { rpcProvider },
    });
    // The view function returns SerializedReturnValue, which can be the direct result
    // or a number if truncated. Assuming get_greeting returns a simple string directly.
    return result as string;
  } catch (error) {
    console.error('Error calling get_greeting:', error);
    throw error;
  }
};

/**
 * Calls the set_greeting method on the cyan-loong.testnet contract.
 * @param greeting The new greeting string.
 */
export const setGreeting = async (greeting: string): Promise<any> => {
  await ensureNearInitialized();
  console.log(`Calling set_greeting on ${HELLO_NEAR_CONTRACT_ID} with greeting: "${greeting}"`);
  return executeFunctionCallAction(
    HELLO_NEAR_CONTRACT_ID,  // <<<< CORRECTED: Use HELLO_NEAR_CONTRACT_ID as receiver
    'set_greeting',
    { greeting: greeting },
    BigInt('30000000000000'),
    BigInt('0')
  );
};
