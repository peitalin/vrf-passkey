import { BUILD_PATHS } from '../build-paths.js';

// export const RPC_NODE_URL = 'https://rpc.testnet.near.org';
export const RPC_NODE_URL = 'https://test.rpc.fastnear.com';
export const WEBAUTHN_CONTRACT_ID = 'web3-authn-v2.testnet';
export const RELAYER_ACCOUNT_ID = 'web3-authn-v2.testnet';
export const NEAR_EXPLORER_BASE_URL = 'https://testnet.nearblocks.io';
// Gas constants as strings
export const DEFAULT_GAS_STRING = "30000000000000"; // 30 TGas


// === CONFIGURATION ===
export const SIGNER_WORKER_MANAGER_CONFIG = {
  TIMEOUTS: {
    DEFAULT: 10_000,      // 10s
    TRANSACTION: 30_000,  // 30s for contract verification + signing
    REGISTRATION: 30_000, // 30s for registration operations
  },
  WORKER: {
    URL: BUILD_PATHS.RUNTIME.SIGNER_WORKER,
    TYPE: 'module' as const,
    NAME: 'Web3AuthnSignerWorker',
  },
  RETRY: {
    MAX_ATTEMPTS: 3,
    BACKOFF_MS: 1000,
  }
} as const;