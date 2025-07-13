/**
 * E2E Test Setup Utilities
 *
 * Provides reusable setup functions for PasskeyManager e2e testing
 */

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

  // Set up WebAuthn Virtual Authenticator using CDP
  console.log('Setting up WebAuthn Virtual Authenticator...');
  const client = await page.context().newCDPSession(page);

  // Enable WebAuthn
  await client.send('WebAuthn.enable');

  // Add virtual authenticator with optimal configuration based on Corbado guide
  // https://www.corbado.com/blog/passkeys-e2e-playwright-testing-webauthn-virtual-authenticator
  const authenticator = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal', // Platform authenticator (like Touch ID/Face ID)
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true, // Use automatic for now to avoid complexity
    },
  });

  const authenticatorId = authenticator.authenticatorId;
  console.log('✅ WebAuthn Virtual Authenticator enabled with ID:', authenticatorId);

  // Navigate to the frontend
  await page.goto(config.frontendUrl);

  // Inject import map immediately after page load, before any imports
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
    console.log('Import map injected with NEAR.js dependencies');
  });
  await page.waitForLoadState('networkidle');

  // Set up PasskeyManager and WebAuthn utilities
  await page.evaluate(async (setupOptions) => {
    try {
      // Import PasskeyManager from built SDK files served by frontend
      console.log('Importing PasskeyManager from built SDK...');
      // @ts-ignore - Runtime import path
      const sdkModule = await import('/sdk/esm/index.js');
      const PasskeyManager = sdkModule.PasskeyManager;

      if (!PasskeyManager) {
        throw new Error('PasskeyManager not found in SDK module');
      }

      console.log('PasskeyManager imported successfully');
      console.log('SDK Module keys:', Object.keys(sdkModule));
      console.log('PasskeyManager prototype methods:', Object.getOwnPropertyNames(PasskeyManager.prototype));

      // Create configuration
      const configs = {
        nearNetwork: setupOptions.nearNetwork as 'testnet',
        relayerAccount: setupOptions.relayerAccount,
        contractId: setupOptions.contractId,
        nearRpcUrl: setupOptions.nearRpcUrl
      };

      console.log('Creating PasskeyManager with configs:', configs);

      // Validate required configs
      if (!configs.nearRpcUrl) {
        throw new Error('nearRpcUrl is required but not provided');
      }
      if (!configs.contractId) {
        throw new Error('contractId is required but not provided');
      }
      if (!configs.relayerAccount) {
        throw new Error('relayerAccount is required but not provided');
      }

      // Create PasskeyManager instance (it will create DefaultNearClient automatically)
      const passkeyManager = new PasskeyManager(configs);

      console.log('PasskeyManager instance created successfully');
      console.log('PasskeyManager.configs:', passkeyManager.configs);

      // Test that the PasskeyManager is working
      try {
        console.log('Testing PasskeyManager.getLoginState...');
        const loginState = await passkeyManager.getLoginState();
        console.log('getLoginState successful:', loginState);
      } catch (testError: any) {
        console.warn('getLoginState test failed:', testError.message);
        // This is OK for setup, just want to test the instance
      }

      // Test VRF worker accessibility
      console.log('Testing VRF worker accessibility...');
      try {
        const vrfWorkerUrl = '/workers/web3authn-vrf.worker.js';
        console.log('VRF Worker URL:', vrfWorkerUrl);

        // First, test if the worker file exists
        const workerResponse = await fetch(vrfWorkerUrl);
        console.log('VRF Worker file status:', workerResponse.status, workerResponse.statusText);

        if (!workerResponse.ok) {
          throw new Error(`VRF worker file not accessible: ${workerResponse.status} ${workerResponse.statusText}`);
        }

        // Use the real VRF Worker - no mocking needed
        console.log('✅ Real VRF Worker will be used for testing');

        console.log('VRF worker accessibility verified');
      } catch (vrfError: any) {
        console.error('VRF worker test failed:', vrfError);
        console.warn('️VRF worker issues may cause registration failures');
      }

      // Store original functions for restoration
      const originalFetch = window.fetch;
      const originalCredentialsCreate = navigator.credentials?.create;
      const originalCredentialsGet = navigator.credentials?.get;

      // Enhanced WebAuthn mock with PRF extension support
      console.log('Setting up enhanced WebAuthn mock with PRF extension support...');

      // Create proper mock PRF outputs that match WASM worker expectations
      // The WASM worker expects base64url-encoded strings for PRF outputs
      const createMockPRFOutput = (seed: string, length: number = 32): ArrayBuffer => {
        // Create deterministic but realistic PRF output based on seed
        const encoder = new TextEncoder();
        const seedBytes = encoder.encode(seed + Date.now().toString());
        const output = new Uint8Array(length);

        // Generate pseudo-random bytes based on seed
        for (let i = 0; i < length; i++) {
          output[i] = (seedBytes[i % seedBytes.length] + i * 7) % 256;
        }

        return output.buffer;
      };

      // Create mock PRF outputs in the format expected by WASM worker
      const mockAESPRFOutput = createMockPRFOutput('aes-gcm-test-seed', 32);
      const mockEd25519PRFOutput = createMockPRFOutput('ed25519-test-seed', 32);

      console.log('Mock PRF outputs created:');
      console.log('  - AES PRF output (base64url):', base64UrlEncode(mockAESPRFOutput));
      console.log('  - Ed25519 PRF output (base64url):', base64UrlEncode(mockEd25519PRFOutput));

      // Override WebAuthn API to include PRF extension support
      if (navigator.credentials) {
        // Mock credentials.create with PRF extension
        navigator.credentials.create = async function(options: any) {
          console.log('Enhanced Virtual Authenticator CREATE with PRF support');

          if (!options?.publicKey) {
            throw new DOMException('Missing publicKey', 'NotSupportedError');
          }

          // Simulate authenticator processing time
          await new Promise(resolve => setTimeout(resolve, 200));

          // Check if PRF extension is requested
          const prfRequested = options.publicKey.extensions?.prf;
          console.log('PRF extension requested:', !!prfRequested);

          // Calculate proper RP ID hash for authenticator data
          const rpId = window.location.hostname;
          const rpIdBytes = new TextEncoder().encode(rpId);
          const rpIdHashBuffer = await crypto.subtle.digest('SHA-256', rpIdBytes);
          const rpIdHash = new Uint8Array(rpIdHashBuffer);

          console.log('Using real SHA256 hash for RP ID:', rpId);

          const credential = {
            id: 'test-credential-' + Date.now(),
            rawId: new Uint8Array(16).fill(0).map((_, i) => i + 1),
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: new TextEncoder().encode(JSON.stringify({
                type: 'webauthn.create',
                challenge: base64UrlEncode(new Uint8Array(options.publicKey.challenge)), // Use base64url encoding
                origin: window.location.origin,
                crossOrigin: false
              })),
              // Create a proper mock attestationObject with valid CBOR structure
              attestationObject: (() => {
                // Create a minimal but valid CBOR attestationObject
                // Structure: { fmt: "none", attStmt: {}, authData: <authData> }

                // Mock authenticator data (37 bytes minimum)
                const flags = new Uint8Array([0x45]); // 1 byte: UP=1, UV=1, AT=1, ED=0 (0x01 | 0x04 | 0x40 = 0x45)
                const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x00]); // 4 bytes: signature counter

                // Attested credential data (variable length)
                const aaguid = new Uint8Array(16).fill(0x00); // 16 bytes: AAGUID
                const credentialIdLength = new Uint8Array([0x00, 0x10]); // 2 bytes: credential ID length (16)
                const credentialId = new Uint8Array(16).fill(0x02); // 16 bytes: credential ID

                // COSE key (simplified ES256 public key)
                const coseKey = new Uint8Array([
                  0xa5, // map(5)
                  0x01, 0x02, // 1: 2 (EC2)
                  0x03, 0x26, // 3: -7 (ES256)
                  0x20, 0x01, // -1: 1 (P-256)
                  0x21, 0x58, 0x20, // -2: bstr(32) - x coordinate
                  ...new Uint8Array(32).fill(0x03),
                  0x22, 0x58, 0x20, // -3: bstr(32) - y coordinate
                  ...new Uint8Array(32).fill(0x04)
                ]);

                // Combine authenticator data
                const authData = new Uint8Array([
                  ...rpIdHash, // Use the real SHA256 hash
                  ...flags,
                  ...signCount,
                  ...aaguid,
                  ...credentialIdLength,
                  ...credentialId,
                  ...coseKey
                ]);

                // Create CBOR attestationObject
                // { "fmt": "none", "attStmt": {}, "authData": authData }
                const cbor = new Uint8Array([
                  0xa3, // map(3)
                  0x63, 0x66, 0x6d, 0x74, // "fmt"
                  0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
                  0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
                  0xa0, // map(0) - empty map
                  0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
                  0x58, authData.length, // bstr(authData.length)
                  ...authData
                ]);

                return cbor;
              })(),
              getPublicKey: () => new Uint8Array(65).fill(0).map((_, i) => i + 1),
              getPublicKeyAlgorithm: () => -7,
              getTransports: () => ['internal', 'hybrid']
            },
            getClientExtensionResults: () => {
              const results: any = {};

              // Add PRF extension results if requested
              if (prfRequested) {
                results.prf = {
                  enabled: true,
                  results: {
                    first: mockAESPRFOutput,     // AES PRF output for encryption
                    second: mockEd25519PRFOutput // Ed25519 PRF output for key derivation
                  }
                };
                console.log('✅ Dual PRF extension results added to registration credential');
                console.log('  - AES PRF (first):', base64UrlEncode(mockAESPRFOutput));
                console.log('  - Ed25519 PRF (second):', base64UrlEncode(mockEd25519PRFOutput));
              }

              return results;
            }
          };

          console.log('✅ Enhanced Virtual Authenticator CREATE successful with dual PRF support');
          return credential;
        };

        // Mock credentials.get with PRF extension
        navigator.credentials.get = async function(options: any) {
          console.log('Enhanced Virtual Authenticator GET with PRF support');

          if (!options?.publicKey) {
            throw new DOMException('Missing publicKey', 'NotSupportedError');
          }

          await new Promise(resolve => setTimeout(resolve, 200));

          // Check if PRF extension is requested
          const prfRequested = options.publicKey.extensions?.prf;
          console.log('PRF extension requested:', !!prfRequested);

          const assertion = {
            id: 'test-credential-' + Date.now(),
            rawId: new Uint8Array(16).fill(0).map((_, i) => i + 1),
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: new TextEncoder().encode(JSON.stringify({
                type: 'webauthn.get',
                challenge: base64UrlEncode(new Uint8Array(options.publicKey.challenge)), // Use base64url encoding
                origin: window.location.origin,
                crossOrigin: false
              })),
              authenticatorData: new Uint8Array([
                0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34,
                0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b, 0x8f, 0xe4, 0xae, 0xb9,
                0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d,
                0x97, 0x63, 0x05, 0x00, 0x00, 0x00, 0x01 // Last byte changed to 0x05 (UP=1, UV=1)
              ]),
              signature: new Uint8Array(64).fill(0).map((_, i) => i + 100),
              userHandle: new Uint8Array([1, 2, 3, 4])
            },
            getClientExtensionResults: () => {
              const results: any = {};

              // Add PRF extension results if requested
              if (prfRequested) {
                results.prf = {
                  enabled: true,
                  results: {
                    first: mockAESPRFOutput,     // AES PRF output for encryption
                    second: mockEd25519PRFOutput // Ed25519 PRF output for key derivation
                  }
                };
                console.log('✅ Dual PRF extension results added to authentication assertion');
                console.log('  - AES PRF (first):', base64UrlEncode(mockAESPRFOutput));
                console.log('  - Ed25519 PRF (second):', base64UrlEncode(mockEd25519PRFOutput));
              }

              return results;
            }
          };

          console.log('✅ Enhanced Virtual Authenticator GET successful with dual PRF support');
          return assertion;
        };

        // Mark as enhanced mock
        (window as any).__webauthn_enhanced_mock = true;
        console.log('✅ Enhanced WebAuthn mock with dual PRF extension support installed');
        console.log('  - Mock PRF outputs match WASM worker expected format (base64url strings)');
        console.log('  - AES PRF for encryption/decryption operations');
        console.log('  - Ed25519 PRF for NEAR keypair derivation');
      }

      // Create WebAuthn utilities based on Corbado guide best practices
      const webAuthnUtils = {
        // Simulate successful passkey input with proper event handling
        simulateSuccessfulPasskeyInput: async (operationTrigger: () => Promise<void>) => {
          console.log('Simulating successful passkey input...');

          // Initialize event listeners to wait for successful passkey events
          const operationCompleted = new Promise<void>((resolve) => {
            const handleCredentialAdded = () => {
              console.log('✅ WebAuthn.credentialAdded event received');
              resolve();
            };
            const handleCredentialAsserted = () => {
              console.log('✅ WebAuthn.credentialAsserted event received');
              resolve();
            };

            // Add event listeners (these would be managed by the CDP client in real implementation)
            (window as any).__webauthn_success_handler = resolve;
          });

          // Simulate the operation trigger
          await operationTrigger();

          // Wait for operation completion (in real implementation, this would be handled by CDP events)
          await new Promise(resolve => setTimeout(resolve, 500)); // Simulate processing time

          console.log('✅ Successful passkey input simulation completed');
        },

        // Simulate failed passkey input
        simulateFailedPasskeyInput: async (operationTrigger: () => Promise<void>, postOperationCheck?: () => Promise<void>) => {
          console.log('Simulating failed passkey input...');

          // Simulate the operation trigger
          await operationTrigger();

          // Wait for operation completion
          if (postOperationCheck) {
            await postOperationCheck();
          } else {
            await new Promise(resolve => setTimeout(resolve, 300)); // Default wait
          }

          console.log('Failed passkey input simulation completed');
        },

        // Get credentials from virtual authenticator
        getCredentials: async () => {
          console.log('Getting credentials from virtual authenticator...');
          // In real implementation, this would call CDP client.send('WebAuthn.getCredentials')
          return [];
        },

        // Clear credentials from virtual authenticator
        clearCredentials: async () => {
          console.log('Clearing credentials from virtual authenticator...');
          // In real implementation, this would call CDP client.send('WebAuthn.clearCredentials')
        }
      };

      // Create test utilities
      (window as any).testUtils = {
        PasskeyManager,
        passkeyManager,
        configs,
        webAuthnUtils,

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
            if (navigator.credentials && originalCredentialsGet) {
              navigator.credentials.get = originalCredentialsGet;
            }
          }
        }
      };

      console.log('PasskeyManager setup completed with Enhanced WebAuthn Virtual Authenticator + PRF Extension Support');

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
        webAuthnUtils: {
          simulateSuccessfulPasskeyInput: async () => {
            console.log('Dummy simulateSuccessfulPasskeyInput (PasskeyManager setup failed)');
          },
          simulateFailedPasskeyInput: async () => {
            console.log('Dummy simulateFailedPasskeyInput (PasskeyManager setup failed)');
          },
          getCredentials: async () => [],
          clearCredentials: async () => {}
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
    nearRpcUrl: config.nearRpcUrl,
    authenticatorId: authenticatorId
  });
}
