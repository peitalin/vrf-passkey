import type { ServerConfig } from './types';

/**
 * Get configuration from environment variables
 * Works across Node.js, Vercel, and Cloudflare Workers
 */
export function getServerConfig(env?: Record<string, string>): ServerConfig {
  // Support both process.env (Node.js/Vercel) and passed env object (Cloudflare Workers)
  const getEnvVar = (key: string): string => {
    const value = env?.[key] || (typeof process !== 'undefined' && process.env?.[key]);
    if (!value) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
    return value;
  };

  return {
    relayerAccountId: getEnvVar('RELAYER_ACCOUNT_ID'),
    relayerPrivateKey: getEnvVar('RELAYER_PRIVATE_KEY'),
    nearRpcUrl: getEnvVar('NEAR_RPC_URL'),
    webAuthnContractId: getEnvVar('WEBAUTHN_CONTRACT_ID'),
    networkId: getEnvVar('NETWORK_ID') || 'testnet',
    defaultInitialBalance: getEnvVar('DEFAULT_INITIAL_BALANCE') || '50000000000000000000000', // 0.05 NEAR
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

/**
 * Get default configuration for testing
 */
export function getTestServerConfig(): ServerConfig {
  return {
    relayerAccountId: 'test-relayer.testnet',
    relayerPrivateKey: 'ed25519:test-private-key',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    webAuthnContractId: 'web3-authn-v2.testnet',
    networkId: 'testnet',
    defaultInitialBalance: '50000000000000000000000',
  };
}