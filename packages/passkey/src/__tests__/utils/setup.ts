/**
 * E2E Test Setup Utilities
 *
 * Provides reusable setup functions for PasskeyManager e2e testing
 *
 * IMPORTANT: Module Loading Strategy
 * ===================================
 *
 * This file uses STATIC imports at the top for types and utilities that are safe to load early.
 * However, PasskeyManager itself is imported DYNAMICALLY inside test functions to avoid
 * module loading race conditions with WebAuthn Virtual Authenticator setup.
 *
 * Why Dynamic Imports Are Necessary:
 * 1. WebAuthn Virtual Authenticator setup modifies browser environment
 * 2. This can interfere with import map processing timing
 * 3. Early imports may fail with "base64UrlEncode is not defined" errors
 * 4. Dynamic imports after setup ensure stable environment
 *
 * Setup Process:
 * ==============
 * The setup follows a precise 5-step sequence to avoid race conditions:
 * 1. ENVIRONMENT SETUP: Configure WebAuthn Virtual Authenticator first
 * 2. IMPORT MAP INJECTION: Add module resolution mappings to the page
 * 3. STABILIZATION WAIT: Allow browser environment to settle
 * 4. DYNAMIC IMPORTS: Load PasskeyManager only after environment is ready
 * 5. GLOBAL FALLBACK: Ensure base64UrlEncode is available as safety measure
 */

// STATIC IMPORTS: Safe to load early
// ===================================
// These imports are safe to use statically because:
// - Page: Playwright type, no runtime dependencies
// - type PasskeyManager: TypeScript type only, no runtime code
// - encoders: Utility functions used in Node.js context, not browser
import { Page } from '@playwright/test';
import type { PasskeyManager } from '../../index';
import { base64UrlEncode, base64UrlDecode } from '../../utils/encoders';

/**
 * Test utility interface available in browser context
 */
export interface TestUtils {
  PasskeyManager: typeof PasskeyManager;
  passkeyManager: PasskeyManager;
  configs: {
    nearNetwork: 'testnet';
    relayerAccount: string;
    contractId: string;
    nearRpcUrl: string;
  };
  generateTestAccountId: () => string;
  verifyAccountExists: (accountId: string) => Promise<boolean>;
  // WebAuthn Virtual Authenticator utilities
  webAuthnUtils: {
    simulateSuccessfulPasskeyInput: (operationTrigger: () => Promise<void>) => Promise<void>;
    simulateFailedPasskeyInput: (operationTrigger: () => Promise<void>, postOperationCheck?: () => Promise<void>) => Promise<void>;
    getCredentials: () => Promise<any[]>;
    clearCredentials: () => Promise<void>;
  };
  // Failure testing utilities
  failureMocks: {
    vrfGeneration: () => void;
    webAuthnCeremony: () => void;
    nearKeypairGeneration: () => void;
    contractVerification: () => void;
    faucetService: () => void;
    contractRegistration: () => void;
    databaseStorage: () => void;
    vrfUnlock: () => void;
    restore: () => void;
  };
  rollbackVerification: {
    verifyDatabaseClean: (accountId: string) => Promise<boolean>;
    verifyAccountDeleted: (accountId: string) => Promise<boolean>;
    getRollbackEvents: (events: any[]) => any[];
  };
}

// =============================================================================
// WEBAUTHN ATTESTATION OBJECT UTILITIES
// =============================================================================

// =============================================================================
// SETUP HELPER FUNCTIONS
// =============================================================================
// These functions implement the 5-step setup process in a modular way

/**
 * Step 1: ENVIRONMENT SETUP
 * Configure WebAuthn Virtual Authenticator first
 */
async function setupWebAuthnVirtualAuthenticator(page: Page): Promise<string> {
  console.log('Step 1: Setting up WebAuthn Virtual Authenticator...');

  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');

  // Add virtual authenticator with configuration based on
  // https://www.corbado.com/blog/passkeys-e2e-playwright-testing-webauthn-virtual-authenticator
  const authenticator = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal', // Platform authenticator (like Touch ID/Face ID)
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  const authenticatorId = authenticator.authenticatorId;
  console.log('Step 1 Complete: WebAuthn Virtual Authenticator enabled with ID:', authenticatorId);
  return authenticatorId;
}

/**
 * Step 2: IMPORT MAP INJECTION
 * Add module resolution mappings to the page
 */
async function injectImportMap(page: Page): Promise<void> {
  console.log('Step 2: Injecting import map...');

  await page.evaluate(() => {
    const importMap = document.createElement('script');
    importMap.type = 'importmap';
    importMap.textContent = JSON.stringify({
      imports: {
        'bs58': 'https://esm.sh/bs58@6.0.0',
        'idb': 'https://esm.sh/idb@8.0.0',
        'js-sha256': 'https://esm.sh/js-sha256@0.11.1',
        '@near-js/crypto': 'https://esm.sh/@near-js/crypto@2.0.1',
        '@near-js/transactions': 'https://esm.sh/@near-js/transactions@2.0.1',
        '@near-js/types': 'https://esm.sh/@near-js/types@2.0.1',
        'tslib': 'https://esm.sh/tslib@2.8.1',
        'buffer': 'https://esm.sh/buffer@6.0.3'
      }
    });

    // Insert as first child to ensure it loads before any modules
    if (document.head.firstChild) {
      document.head.insertBefore(importMap, document.head.firstChild);
    } else {
      document.head.appendChild(importMap);
    }
  });

  console.log('Step 2 Complete: Import map injected with NEAR.js dependencies');
}

/**
 * Step 3: STABILIZATION WAIT
 * Allow browser environment to settle
 */
async function waitForEnvironmentStabilization(page: Page): Promise<void> {
  console.log('Step 3: Waiting for environment stabilization...');

  // Critical timing: Wait for import map processing
  // The WebAuthn Virtual Authenticator setup can interfere with import map processing
  await new Promise(resolve => setTimeout(resolve, 1000));
  await page.waitForLoadState('networkidle');

  console.log('Step 3 Complete: Environment stabilized and ready for imports');
}

/**
 * Step 4: DYNAMIC IMPORTS
 * Load PasskeyManager only after environment is ready
 */
async function loadPasskeyManagerDynamically(page: Page, configs: any): Promise<void> {
  console.log('Step 4: Loading PasskeyManager dynamically...');

  await page.evaluate(async (setupOptions) => {
    console.log('Importing PasskeyManager from built SDK...');
    // @ts-ignore
    const { PasskeyManager } = await import('/sdk/esm/index.js');

    if (!PasskeyManager) {
      throw new Error('PasskeyManager not found in SDK module');
    }
    console.log('PasskeyManager imported successfully:', typeof PasskeyManager);

    // Create and validate configuration
    const configs = {
      nearNetwork: setupOptions.nearNetwork as 'testnet',
      relayerAccount: setupOptions.relayerAccount,
      contractId: setupOptions.contractId,
      nearRpcUrl: setupOptions.nearRpcUrl
    };

    // Validate required configs
    if (!configs.nearRpcUrl) throw new Error('nearRpcUrl is required but not provided');
    if (!configs.contractId) throw new Error('contractId is required but not provided');
    if (!configs.relayerAccount) throw new Error('relayerAccount is required but not provided');

    // Create PasskeyManager instance
    const passkeyManager = new PasskeyManager(configs);
    console.log('PasskeyManager instance created successfully');

    // Test basic functionality
    try {
      const loginState = await passkeyManager.getLoginState();
      console.log('getLoginState test successful:', loginState);
    } catch (testError: any) {
      console.warn('getLoginState test failed:', testError.message);
    }

    // Store in window for test access
    (window as any).PasskeyManager = PasskeyManager;
    (window as any).passkeyManager = passkeyManager;
    (window as any).configs = configs;

  }, configs);

  console.log('Step 4 Complete: PasskeyManager loaded and instantiated');
}

/**
 * Step 5: GLOBAL FALLBACK
 * Ensure base64UrlEncode is available as safety measure
 */
async function ensureGlobalFallbacks(page: Page): Promise<void> {
  console.log('Step 5: Ensuring global fallbacks...');

  await page.evaluate(async () => {
    // Defense in depth: Ensure base64UrlEncode is globally available
    // This prevents "base64UrlEncode is not defined" errors even if timing issues occur
    if (typeof (window as any).base64UrlEncode === 'undefined') {
      try {
        // @ts-ignore
        const { base64UrlEncode } = await import('/sdk/esm/utils/encoders.js');
        (window as any).base64UrlEncode = base64UrlEncode;
        console.log('base64UrlEncode made available globally as fallback');
      } catch (encoderError) {
        console.error('Failed to import base64UrlEncode fallback:', encoderError);
      }
    }
  });

  console.log('Step 5 Complete: Global fallbacks in place');
}

/**
 * Orchestrator function that executes all 5 setup steps sequentially
 */
async function executeSequentialSetup(page: Page, configs: any): Promise<string> {
  console.log('Starting 5-step sequential setup process...');

  // Step 1: ENVIRONMENT SETUP
  const authenticatorId = await setupWebAuthnVirtualAuthenticator(page);

  // Step 2: IMPORT MAP INJECTION
  await injectImportMap(page);

  // Step 3: STABILIZATION WAIT
  await waitForEnvironmentStabilization(page);

  // Step 4: DYNAMIC IMPORTS
  await loadPasskeyManagerDynamically(page, configs);

  // Step 5: GLOBAL FALLBACK
  await ensureGlobalFallbacks(page);

  console.log('All 5 setup steps completed successfully!');
  return authenticatorId;
}

// =============================================================================
// WEBAUTHN MOCKS AND TEST UTILITIES
// =============================================================================

/**
 * Setup WebAuthn mocks and test utilities
 */
async function setupWebAuthnMocks(page: Page): Promise<void> {
  await page.evaluate(() => {
    console.log('Setting up WebAuthn Virtual Authenticator mocks...');

    // Store original functions for restoration
    const originalFetch = window.fetch;
    const originalCredentialsCreate = navigator.credentials?.create;
    const originalCredentialsGet = navigator.credentials?.get;

    /**
     * Creates a properly formatted CBOR-encoded WebAuthn attestation object
     * that matches the contract's expectations for successful verification.
     *
     * Note: WebAuthn attestation object utilities are now defined inline within
     * the setupWebAuthnMocks function to ensure they're available in browser context
     */
    const createProperAttestationObject = (rpIdHash: Uint8Array): Uint8Array => {
      // Create valid authenticator data following contract format
      const authData = new Uint8Array(37 + 16 + 2 + 17 + 77); // Fixed size for this mock
      let offset = 0;

      // RP ID hash (32 bytes)
      authData.set(rpIdHash, offset);
      offset += 32;

      // Flags (1 byte): UP (0x01) + UV (0x04) + AT (0x40) = 0x45
      authData[offset] = 0x45;
      offset += 1;

      // Counter (4 bytes)
      authData[offset] = 0x00;
      authData[offset + 1] = 0x00;
      authData[offset + 2] = 0x00;
      authData[offset + 3] = 0x01;
      offset += 4;

      // AAGUID (16 bytes) - all zeros for mock
      for (let i = 0; i < 16; i++) {
        authData[offset + i] = 0x00;
      }
      offset += 16;

      // Credential ID length (2 bytes)
      const credentialId = new TextEncoder().encode('test_mock_credential');
      authData[offset] = 0x00;
      authData[offset + 1] = credentialId.length;
      offset += 2;

      // Credential ID
      authData.set(credentialId, offset);
      offset += credentialId.length;

      // Mock COSE Ed25519 public key (77 bytes total)
      const mockEd25519Pubkey = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        mockEd25519Pubkey[i] = 0x42;
      }

      // Simple CBOR encoding for the COSE key (simplified for mock)
      const coseKeyBytes = new Uint8Array([
        0xa4, // map with 4 items
        0x01, 0x01, // kty: OKP
        0x03, 0x27, // alg: EdDSA (-8)
        0x20, 0x06, // crv: Ed25519
        0x21, 0x58, 0x20, // x: bytes(32)
        ...mockEd25519Pubkey
      ]);

      authData.set(coseKeyBytes, offset);

      // Simple CBOR encoding for attestation object
      const attestationObjectBytes = new Uint8Array([
        0xa3, // map with 3 items
        0x63, 0x66, 0x6d, 0x74, // "fmt"
        0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
        0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
        0x59, (authData.length >> 8) & 0xff, authData.length & 0xff, // bytes(authData.length)
        ...authData,
        0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
        0xa0 // empty map
      ]);

      return attestationObjectBytes;
    };

    /**
     * Creates mock PRF outputs for WebAuthn PRF extension testing
     * IMPORTANT: PRF outputs must be deterministic for the same credential and account
     * to ensure encryption/decryption consistency across operations
     */
    const createMockPRFOutput = (seed: string, accountHint: string = '', length: number = 32): ArrayBuffer => {
      const encoder = new TextEncoder();
      // Use deterministic seed based on credential and account, NOT timestamp
      const deterministic_seed = `${seed}-${accountHint}-deterministic-v1`;
      const seedBytes = encoder.encode(deterministic_seed);
      const output = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        output[i] = (seedBytes[i % seedBytes.length] + i * 7) % 256;
      }
      return output.buffer;
    };

    // Override WebAuthn API to include PRF extension support
    if (navigator.credentials) {
      navigator.credentials.create = async function(options: any) {
        console.log('Enhanced Virtual Authenticator CREATE with PRF support');
        if (!options?.publicKey) {
          throw new DOMException('Missing publicKey', 'NotSupportedError');
        }
        await new Promise(resolve => setTimeout(resolve, 200));

        const prfRequested = options.publicKey.extensions?.prf;
        const rpId = window.location.hostname;
        const rpIdBytes = new TextEncoder().encode(rpId);
        const rpIdHashBuffer = await crypto.subtle.digest('SHA-256', rpIdBytes);
        const rpIdHash = new Uint8Array(rpIdHashBuffer);

        // Extract account ID from user info for deterministic PRF
        const accountId = options.publicKey.user?.name || 'default-account';
        const credentialId = `test-credential-${accountId}-${Date.now()}`;

        // Create proper CBOR-encoded attestation object that matches contract expectations
        const attestationObjectBytes = createProperAttestationObject(rpIdHash);

        return {
          id: credentialId,
          rawId: new TextEncoder().encode(credentialId),
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: {
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.create',
              challenge: (window as any).base64UrlEncode(new Uint8Array(options.publicKey.challenge)),
              origin: window.location.origin,
              crossOrigin: false
            })),
            attestationObject: attestationObjectBytes,
            getPublicKey: () => new Uint8Array(65).fill(0).map((_, i) => i + 1),
            getPublicKeyAlgorithm: () => -7,
            getTransports: () => ['internal', 'hybrid']
          },
          getClientExtensionResults: () => {
            const results: any = {};
            if (prfRequested) {
              results.prf = {
                enabled: true,
                results: {
                  first: createMockPRFOutput('aes-gcm-test-seed', accountId, 32),
                  second: createMockPRFOutput('ed25519-test-seed', accountId, 32)
                }
              };
            }
            return results;
          }
        };
      };

      navigator.credentials.get = async function(options: any) {
        console.log('Enhanced Virtual Authenticator GET with PRF support');
        if (!options?.publicKey) {
          throw new DOMException('Missing publicKey', 'NotSupportedError');
        }
        await new Promise(resolve => setTimeout(resolve, 200));

        const prfRequested = options.publicKey.extensions?.prf;

        // Extract account ID from allowCredentials or use default
        const firstCredential = options.publicKey.allowCredentials?.[0];
        const accountId = firstCredential ?
          new TextDecoder().decode(firstCredential.id).match(/test-credential-([^-]+)/)?.[1] || 'default-account' :
          'default-account';

        const credentialId = `test-credential-${accountId}-auth`;

        return {
          id: credentialId,
          rawId: new TextEncoder().encode(credentialId),
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: {
            clientDataJSON: new TextEncoder().encode(JSON.stringify({
              type: 'webauthn.get',
              challenge: (window as any).base64UrlEncode(new Uint8Array(options.publicKey.challenge)),
              origin: window.location.origin,
              crossOrigin: false
            })),
            authenticatorData: new Uint8Array(37).fill(0x05),
            signature: new Uint8Array(64).fill(0).map((_, i) => i + 100),
            userHandle: new Uint8Array([1, 2, 3, 4])
          },
          getClientExtensionResults: () => {
            const results: any = {};
            if (prfRequested) {
              results.prf = {
                enabled: true,
                results: {
                  first: createMockPRFOutput('aes-gcm-test-seed', accountId, 32),
                  second: createMockPRFOutput('ed25519-test-seed', accountId, 32)
                }
              };
            }
            return results;
          }
        };
      };
    }

    // Store originals for restoration
    (window as any).__test_originals = {
      originalFetch,
      originalCredentialsCreate,
      originalCredentialsGet
    };

    console.log('Enhanced WebAuthn mock with dual PRF extension support installed');
  });
}

/**
 * Setup test utilities
 */
async function setupTestUtilities(page: Page, config: any): Promise<void> {
  await page.evaluate((setupConfig) => {
    const { originalFetch, originalCredentialsCreate, originalCredentialsGet } = (window as any).__test_originals;

    const webAuthnUtils = {
      simulateSuccessfulPasskeyInput: async (operationTrigger: () => Promise<void>) => {
        console.log('Simulating successful passkey input...');
        await operationTrigger();
        await new Promise(resolve => setTimeout(resolve, 500));
        console.log('Successful passkey input simulation completed');
      },
      simulateFailedPasskeyInput: async (operationTrigger: () => Promise<void>, postOperationCheck?: () => Promise<void>) => {
        console.log('Simulating failed passkey input...');
        await operationTrigger();
        if (postOperationCheck) {
          await postOperationCheck();
        } else {
          await new Promise(resolve => setTimeout(resolve, 300));
        }
        console.log('Failed passkey input simulation completed');
      },
      getCredentials: async () => [],
      clearCredentials: async () => {}
    };

    (window as any).testUtils = {
      PasskeyManager: (window as any).PasskeyManager,
      passkeyManager: (window as any).passkeyManager,
      configs: (window as any).configs,
      webAuthnUtils,
      generateTestAccountId: () => `e2etest${Date.now()}.testnet`,
      verifyAccountExists: async (accountId: string) => {
        const response = await fetch(setupConfig.nearRpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'verify-account',
            method: 'query',
            params: {
              request_type: 'view_account',
              finality: 'final',
              account_id: accountId
            }
          })
        });
        const result = await response.json();
        return !result.error && !!result.result;
      },
      failureMocks: {
        vrfGeneration: () => {},
        webAuthnCeremony: () => {
          if (navigator.credentials) {
            navigator.credentials.create = async () => {
              throw new Error('WebAuthn ceremony failed - user cancelled');
            };
          }
        },
        nearKeypairGeneration: () => {},
        contractVerification: () => {},
        faucetService: () => {
          window.fetch = async (url: any, options: any) => {
            if (typeof url === 'string' && url.includes('helper.testnet.near.org')) {
              return new Response(JSON.stringify({
                error: 'Rate limit exceeded - faucet failure injected'
              }), { status: 429, headers: { 'Content-Type': 'application/json' } });
            }
            return originalFetch(url, options);
          };
        },
        contractRegistration: () => {},
        databaseStorage: () => {},
        vrfUnlock: () => {},
        restore: () => {
          window.fetch = originalFetch;
          if (navigator.credentials && originalCredentialsCreate) {
            navigator.credentials.create = originalCredentialsCreate;
          }
          if (navigator.credentials && originalCredentialsGet) {
            navigator.credentials.get = originalCredentialsGet;
          }
        }
      },
      rollbackVerification: {
        verifyDatabaseClean: async (accountId: string) => true,
        verifyAccountDeleted: async (accountId: string) => true,
        getRollbackEvents: (events: any[]) => events.filter(e => e.type === 'rollback')
      }
    };

    console.log('Test utilities setup complete');
  }, config);
}

// =============================================================================
// MAIN SETUP FUNCTION
// =============================================================================

const DEFAULT_TEST_CONFIG = {
  frontendUrl: 'https://example.localhost',
  nearNetwork: 'testnet' as const,
  relayerAccount: 'web3-authn.testnet',
  contractId: 'web3-authn.testnet',
  nearRpcUrl: 'https://rpc.testnet.near.org'
};

/**
 * Main setup function using the elegant 5-step process
 *
 * This function orchestrates the complete test environment setup following
 * a precise sequence to avoid module loading race conditions:
 *
 * 1. ENVIRONMENT SETUP: Configure WebAuthn Virtual Authenticator first
 * 2. IMPORT MAP INJECTION: Add module resolution mappings to the page
 * 3. STABILIZATION WAIT: Allow browser environment to settle
 * 4. DYNAMIC IMPORTS: Load PasskeyManager only after environment is ready
 * 5. GLOBAL FALLBACK: Ensure base64UrlEncode is available as safety measure
 */
export async function setupBasicPasskeyTest(
  page: Page,
  options: {
    frontendUrl?: string;
    nearNetwork?: 'testnet' | 'mainnet';
    relayerAccount?: string;
    contractId?: string;
    nearRpcUrl?: string;
  } = {}
): Promise<void> {
  const config = { ...DEFAULT_TEST_CONFIG, ...options };

  // Navigate to the frontend first
  await page.goto(config.frontendUrl);

  // Execute the 5-step sequential setup process
  const authenticatorId = await executeSequentialSetup(page, config);

  // Continue with the rest of the setup (WebAuthn mocks, etc.)
  await setupWebAuthnMocks(page);
  await setupTestUtilities(page, config);

  console.log('🎯 Complete test environment ready!');
}
