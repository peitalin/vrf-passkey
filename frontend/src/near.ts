import { BrowserLocalStorageKeyStore } from '@near-js/keystores-browser';
import { Account } from "@near-js/accounts";
import { JsonRpcProvider } from "@near-js/providers";
import { NEAR } from "@near-js/tokens";
import { generateSeedPhrase } from "near-seed-phrase";

import {
//   createTopLevelAccount,
  generateRandomKeyPair,
  getSignerFromKeystore,
  getTestnetRpcProvider,
  addFullAccessKey,
} from '@near-js/client';

const NEAR_NETWORK_ID = import.meta.env.VITE_NEAR_NETWORK_ID || 'testnet';
const FUNDING_ACCOUNT_ID_FROM_ENV = import.meta.env.VITE_NEAR_SIGNER_ACCOUNT_ID;

class NearService {
    private account: Account;
    private provider: JsonRpcProvider;

    constructor() {

        const rpcUrl = NEAR_NETWORK_ID === 'mainnet'
            ? 'https://rpc.mainnet.near.org'
            : 'https://rpc.testnet.near.org'; // TODO: change to testnet

        const provider = new JsonRpcProvider({ url: rpcUrl });

        this.account = new Account(FUNDING_ACCOUNT_ID_FROM_ENV, provider);
        this.provider = provider;
    }

    async createTopLevelAccount(accountId: string, publicKey: string, initialBalance: string) {
        try {
            await this.account.createTopLevelAccount(
                accountId,
                publicKey,
                NEAR.toUnits(initialBalance),
            );
        } catch (error) {
            console.error("Error creating top level account:", error);
            throw error;
        }
    }

    generateSeedPhrase() {
        const { seedPhrase, publicKey, secretKey } = generateSeedPhrase();
        return {
            publicKey: publicKey,
            secretKey: secretKey,
        };
    }
}

export const nearService = new NearService();

// // Generate a new key
// const { seedPhrase, publicKey, secretKey } = generateSeedPhrase();
// console.log(`Created key ${secretKey} with seed phrase ${seedPhrase}`);

// await account.createTopLevelAccount(
//   `acc-${Date.now()}.testnet`,
//   publicKey,
//   NEAR.toUnits("0.1")
// );