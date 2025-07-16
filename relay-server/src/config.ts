import dotenv from 'dotenv';
dotenv.config();

export interface AppConfig {
  port: number | string;
  expectedOrigin: string;
  relayerAccountId: string;
  relayerPrivateKey: string;
  nearRpcUrl: string;
  networkId: string;
  defaultInitialBalance: bigint;
  webAuthnContractId: string;
}

const config: AppConfig = {
  port: process.env.PORT || 3000, // Changed from 3001 to match frontend expectation
  expectedOrigin: process.env.EXPECTED_ORIGIN || 'https://example.localhost', // Match frontend HTTPS protocol
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID || 'relayer.testnet',
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY || 'ed25519:examplePrivateKey...',
  nearRpcUrl: process.env.NEAR_RPC_URL || 'https://rpc.testnet.near.org',
  networkId: process.env.NEAR_NETWORK_ID || 'testnet',
  defaultInitialBalance: BigInt('30000000000000000000000'), // 0.03 NEAR initial balance when creating account
  webAuthnContractId: process.env.WEBAUTHN_CONTRACT_ID || 'web3-authn-v1.testnet',
};

export default config;