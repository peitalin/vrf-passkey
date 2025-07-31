import type { ServerConfig } from './types';

/**
 * Get configuration from environment variables
 * Works across Node.js, Vercel, and Cloudflare Workers
 */
export function getServerConfig(env?: Record<string, string>): ServerConfig {

  const requiredEnvVars = [
    'RELAYER_ACCOUNT_ID',
    'RELAYER_PRIVATE_KEY',
  ];

  const getEnvVar = (key: string): string => {
    const value = process?.env?.[key];
    if (!value && requiredEnvVars.includes(key)) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
    return value!;
  };

  return {
    // Required Environment Variables
    relayerAccountId: getEnvVar('RELAYER_ACCOUNT_ID'),
    relayerPrivateKey: getEnvVar('RELAYER_PRIVATE_KEY'),
    // Use defaults if not set
    nearRpcUrl: getEnvVar('NEAR_RPC_URL') || 'https://rpc.testnet.near.org',
    webAuthnContractId: getEnvVar('WEBAUTHN_CONTRACT_ID') || 'web3-authn-v2.testnet',
    networkId: getEnvVar('NETWORK_ID') || 'testnet',
    defaultInitialBalance: getEnvVar('DEFAULT_INITIAL_BALANCE') || '50000000000000000000000', // 0.05 NEAR
    defaultCreateAccountAndRegisterGas: getEnvVar('DEFAULT_CREATE_ACCOUNT_AND_REGISTER_GAS') || '50000000000000', // 50 TGas
  };
}


/**
 * Validate server configuration
 */
export function validateServerConfig(config: ServerConfig): void {
  const required = [
    'relayerAccountId',
    'relayerPrivateKey',
    'nearRpcUrl',
    'webAuthnContractId',
  ];

  for (const field of required) {
    if (!config[field as keyof ServerConfig]) {
      throw new Error(`Invalid server configuration: missing ${field}`);
    }
  }

  // Validate private key format
  if (!config.relayerPrivateKey.startsWith('ed25519:')) {
    throw new Error('Relayer private key must be in format "ed25519:base58privatekey"');
  }
}
