/**
 * E2E Test Setup Utilities
 *
 * Provides reusable setup functions for PasskeyManager e2e testing
 */

import { Page } from '@playwright/test';
import type { PasskeyManager } from '../../index';

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

/**
 * Default test configuration for NEAR testnet
 */
export const DEFAULT_TEST_CONFIG = {
  nearNetwork: 'testnet' as const,
  relayerAccount: 'web3-authn.testnet',
  contractId: 'web3-authn.testnet',
  nearRpcUrl: 'https://rpc.testnet.near.org',
  frontendUrl: 'https://example.localhost/'
};

/**
 * Simple test setup that just navigates to the frontend
 * The frontend should handle module loading via Vite
 *
 * @param page - Playwright page instance
 * @param options - Optional configuration overrides
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

  // Inject import map immediately after page load, before any imports
  await page.evaluate(() => {
    const importMap = document.createElement('script');
    importMap.type = 'importmap';
    importMap.textContent = JSON.stringify({
      imports: {
        'bs58': 'https://esm.sh/bs58@6.0.0',
        'idb': 'https://esm.sh/idb@8.0.0',
        'js-sha256': 'https://esm.sh/js-sha256@0.11.1'
      }
    });
    // Insert as first child to ensure it loads before any modules
    if (document.head.firstChild) {
      document.head.insertBefore(importMap, document.head.firstChild);
    } else {
      document.head.appendChild(importMap);
    }
    console.log('Import map injected');
  });
  await page.waitForLoadState('networkidle');

  // Set up real PasskeyManager with simple failure injection
  await page.evaluate(async (setupOptions) => {
    try {
      // Try relative import from the test location
      console.log('Trying relative import from test location...');
      // @ts-ignore - Runtime import path
      const relativeModule = await import('../../index.ts');
      const PasskeyManager = relativeModule.PasskeyManager;

      // Create configuration
      const configs = {
        nearNetwork: setupOptions.nearNetwork as 'testnet',
        relayerAccount: setupOptions.relayerAccount,
        contractId: setupOptions.contractId,
        nearRpcUrl: setupOptions.nearRpcUrl
      };

      // Create PasskeyManager instance (it will create DefaultNearClient automatically)
      const passkeyManager = new PasskeyManager(configs);

      // Store original functions for restoration
      const originalFetch = window.fetch;
      const originalCredentialsCreate = navigator.credentials?.create;

      // Create test utilities with simple mocking
      (window as any).testUtils = {
        PasskeyManager,
        passkeyManager,
        configs,

        // Helper functions
        generateTestAccountId: () => `e2etest${Date.now()}.testnet`,
        verifyAccountExists: async (accountId: string) => {
          const response = await fetch(setupOptions.nearRpcUrl, {
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

        // Simple failure injection by replacing global functions
        failureMocks: {
          // 1. WebAuthn ceremony failure
          webAuthnFailure: () => {
            if (navigator.credentials) {
              navigator.credentials.create = async () => {
                throw new Error('WebAuthn ceremony failed - user cancelled');
              };
            }
          },

          // 2. Faucet/account creation failure
          faucetFailure: () => {
            window.fetch = async (url: any, options: any) => {
              if (typeof url === 'string' && url.includes('helper.testnet.near.org')) {
                return new Response(JSON.stringify({
                  error: 'Rate limit exceeded - faucet failure injected'
                }), {
                  status: 429,
                  headers: { 'Content-Type': 'application/json' }
                });
              }
              return originalFetch(url, options);
            };
          },

          // 3. RPC failure (affects both queries and transactions)
          rpcFailure: () => {
            window.fetch = async (url: any, options: any) => {
              if (typeof url === 'string' && url.includes('rpc.testnet.near.org')) {
                return new Response(JSON.stringify({
                  error: { message: 'RPC server unavailable - network failure injected' }
                }), {
                  status: 500,
                  headers: { 'Content-Type': 'application/json' }
                });
              }
              return originalFetch(url, options);
            };
          },

          // 4. IndexedDB failure
          indexedDBFailure: () => {
            const originalOpen = window.indexedDB.open;
            window.indexedDB.open = function() {
              throw new Error('IndexedDB quota exceeded - storage failure injected');
            };
          },

          // Restore all mocks
          restore: () => {
            window.fetch = originalFetch;
            if (navigator.credentials && originalCredentialsCreate) {
              navigator.credentials.create = originalCredentialsCreate;
            }
          }
        }
      };

      console.log('PasskeyManager setup completed with failure mocking');

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error('PasskeyManager setup failed:', errorMessage);
      console.error('Full error object:', error);

      // Fallback to basic utilities
      (window as any).testUtils = {
        generateTestAccountId: () => `e2etest${Date.now()}.testnet`,
        verifyAccountExists: async () => false,
        passkeyManager: {
          registerPasskey: async () => {
            throw new Error('PasskeyManager setup failed: ' + errorMessage);
          }
        },
        failureMocks: {
          webAuthnFailure: () => {
            console.log('️Dummy webAuthnFailure mock (PasskeyManager setup failed)');
          },
          faucetFailure: () => {
            console.log('Dummy faucetFailure mock (PasskeyManager setup failed)');
          },
          rpcFailure: () => {
            console.log('Dummy rpcFailure mock (PasskeyManager setup failed)');
          },
          indexedDBFailure: () => {
            console.log('Dummy indexedDBFailure mock (PasskeyManager setup failed)');
          },
          restore: () => {
            console.log('Dummy restore mock (PasskeyManager setup failed)');
          }
        }
      };
    }
  }, {
    nearNetwork: config.nearNetwork,
    relayerAccount: config.relayerAccount,
    contractId: config.contractId,
    nearRpcUrl: config.nearRpcUrl
  });
}
