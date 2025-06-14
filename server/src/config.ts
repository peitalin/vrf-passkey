import dotenv from 'dotenv';
dotenv.config();

// Gas constants as strings
export const DEFAULT_GAS_STRING = "50000000000000"; // 50 TGas approx. (increased for complex yield operations)
export const VIEW_GAS_STRING    = "30000000000000"; // 30 TGas for view calls
export const GENERATE_AUTHENTICATION_OPTIONS_GAS_STRING = "30000000000000"; // 30 TGas
export const VERIFY_AUTHENTICATION_RESPONSE_GAS_STRING = "45000000000000"; // 45 TGas
// 45 TGas: higher for signature verification

// URL constants
export const NEAR_EXPLORER_BASE_URL = 'https://testnet.nearblocks.io';

export interface AppConfig {
  port: number | string;
  rpID: string;
  rpName: string;
  expectedOrigin: string;
  databasePath: string;
  useOptimisticAuth: boolean;
  relayerAccountId: string;
  relayerPrivateKey: string;
  contractId: string;
  nodeUrl: string;
  networkId: string;
}

// Main configuration object
const config: AppConfig = {
  port: process.env.PORT || 3001,
  rpID: process.env.RP_ID || 'example.localhost',
  rpName: process.env.RP_NAME || 'NEAR Passkey Relayer Demo',
  expectedOrigin: process.env.EXPECTED_ORIGIN || 'https://example.localhost',
  databasePath: '../../passkey_users.db', // relative to the src/database directory
  useOptimisticAuth: process.env.USE_OPTIMISTIC_AUTH === 'true' || false, // Flag for optimistic authentication
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID || 'relayer.testnet',
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY || 'ed25519:examplePrivateKey...',
  contractId: process.env.CONTRACT_ID || 'webauthn-contract.testnet',
  nodeUrl: process.env.NEAR_NODE_URL || 'https://rpc.testnet.near.org',
  networkId: process.env.NEAR_NETWORK_ID || 'testnet',
};

export default config;