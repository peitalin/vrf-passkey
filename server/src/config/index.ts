import dotenv from 'dotenv';
dotenv.config();

export interface AppConfig {
  port: number;
  rpID: string;
  rpName: string;
  expectedOrigin: string;
  relayerAccountId: string;
  useContractMethod: boolean; // Flag to switch between SimpleWebAuthn and NEAR contract
  databasePath: string;
}

export const config: AppConfig = {
  port: parseInt(process.env.PORT || '3001'),
  rpID: process.env.RP_ID || 'example.localhost',
  rpName: process.env.RP_NAME || 'My Passkey App',
  expectedOrigin: process.env.EXPECTED_ORIGIN || 'https://example.localhost',
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID || '',
  useContractMethod: process.env.USE_CONTRACT_METHOD === 'true' || true,
  databasePath: process.env.DATABASE_PATH || '../database.sqlite',
};

// Validate required configuration
if (!config.relayerAccountId) {
  throw new Error('RELAYER_ACCOUNT_ID environment variable is required');
}

export default config;