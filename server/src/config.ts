// Gas constants as strings
export const DEFAULT_GAS_STRING = "50000000000000"; // 50 TGas approx. (increased for complex yield operations)
export const VIEW_GAS_STRING    = "30000000000000"; // 30 TGas for view calls
export const VERIFY_REGISTRATION_RESPONSE_GAS_STRING = "30000000000000"; // 30 TGas
export const AUTHENTICATION_VERIFICATION_GAS_STRING  = "45000000000000"; // 45 TGas
// 45 TGas: higher for signature verification

// Main configuration object
const config = {
  port: process.env.PORT || 3001,
  rpID: process.env.RP_ID || 'example.localhost',
  rpName: process.env.RP_NAME || 'NEAR Passkey Relayer Demo',
  expectedOrigin: process.env.EXPECTED_ORIGIN || 'https://example.localhost',
  databasePath: '../../passkey_users.db', // relative to the src/database directory
  useContractMethod: true,
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID || 'relayer.testnet',
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY || 'ed25519:examplePrivateKey...',
  contractId: process.env.CONTRACT_ID || 'webauthn-contract.testnet',
  nodeUrl: process.env.NEAR_NODE_URL || 'https://rpc.testnet.near.org',
  networkId: process.env.NEAR_NETWORK_ID || 'testnet',
};

export default config;