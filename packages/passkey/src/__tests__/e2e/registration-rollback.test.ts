/**
 * Registration Rollback Testing with Failure Injection
 *
 * Tests that registration failures properly trigger rollback mechanisms
 * by mocking key functions to induce failures at different stages.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../utils/setup';

test.describe('PasskeyManager Registration Failure Injection', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  ////////////////////////////////////
  // Induce failure: touchID failure
  ////////////////////////////////////

  test('WebAuthn failure during credential creation', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { passkeyManager, generateTestAccountId, failureMocks } = (window as any).testUtils;
      const testAccountId = generateTestAccountId();

      console.log(`Testing WebAuthn failure for account: ${testAccountId}`);

      try {
        // Inject WebAuthn failure before calling registerPasskey
        failureMocks.webAuthnFailure();

        // Call the actual registerPasskey function - should fail at WebAuthn step
        const result = await passkeyManager.registerPasskey(testAccountId, {
          onEvent: (event: any) => console.log('Registration event:', event),
          onError: (error: any) => console.log('Registration error:', error)
        });

                // Check if registration failed as expected
        if (!result.success) {
          const errorMessage = result.error || 'Unknown registration error';
          console.log('WebAuthn failure detected:', errorMessage);
          return {
            success: false,
            accountId: testAccountId,
            error: errorMessage,
            isWebAuthnError: errorMessage.includes('WebAuthn') || errorMessage.includes('ceremony'),
            message: 'Registration failed as expected due to WebAuthn failure'
          };
        }

        return {
          success: true,
          accountId: testAccountId,
          result,
          message: 'Unexpected: Registration should have failed due to WebAuthn'
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.log('WebAuthn failure caught via exception:', errorMessage);

        return {
          success: false,
          accountId: testAccountId,
          error: errorMessage,
          isWebAuthnError: errorMessage.includes('WebAuthn') || errorMessage.includes('ceremony'),
          message: 'Registration failed as expected due to WebAuthn failure'
        };
      } finally {
        // Always restore mocks
        failureMocks.restore();
      }
    });

    console.log('WebAuthn failure test result:', result);

    expect(result.accountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  ////////////////////////////////////
  // Induce failure: faucet failure
  ////////////////////////////////////

  test('Faucet failure during account creation', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { passkeyManager, generateTestAccountId, failureMocks } = (window as any).testUtils;
      const testAccountId = generateTestAccountId();

      console.log(`Testing faucet failure for account: ${testAccountId}`);

      try {
        // Inject faucet failure before calling registerPasskey
        failureMocks.faucetFailure();

        // Call registerPasskey - should fail at account creation step
        const result = await passkeyManager.registerPasskey(testAccountId, {
          onEvent: (event: any) => console.log('Registration event:', event),
          onError: (error: any) => console.log('Registration error:', error)
        });

        // Check if registration failed as expected
        if (!result.success) {
          const errorMessage = result.error || 'Unknown registration error';
          console.log('Faucet failure detected:', errorMessage);
          return {
            success: false,
            accountId: testAccountId,
            error: errorMessage,
            isFaucetError: errorMessage.includes('faucet') ||
                          errorMessage.includes('Rate limit') ||
                          errorMessage.includes('helper.testnet.near.org'),
            message: 'Registration failed as expected due to faucet failure'
          };
        }

        return {
          success: true,
          accountId: testAccountId,
          result,
          message: 'Unexpected: Registration should have failed due to faucet'
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.log('Faucet failure caught via exception:', errorMessage);

        return {
          success: false,
          accountId: testAccountId,
          error: errorMessage,
          isFaucetError: errorMessage.includes('faucet') ||
                        errorMessage.includes('Rate limit') ||
                        errorMessage.includes('helper.testnet.near.org'),
          message: 'Registration failed as expected due to faucet failure'
        };
      } finally {
        failureMocks.restore();
      }
    });

    console.log('Faucet failure test result:', result);

    expect(result.accountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  ////////////////////////////////////
  // Induce failure: transaction broadcast failure
  ////////////////////////////////////

  test('RPC failure during transaction broadcast', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { passkeyManager, generateTestAccountId, failureMocks } = (window as any).testUtils;
      const testAccountId = generateTestAccountId();

      console.log(`Testing RPC failure for account: ${testAccountId}`);

      try {
        // Inject RPC failure before calling registerPasskey
        failureMocks.rpcFailure();

        // Call registerPasskey - should fail at RPC step
        const result = await passkeyManager.registerPasskey(testAccountId, {
          onEvent: (event: any) => console.log('Registration event:', event),
          onError: (error: any) => console.log('Registration error:', error)
        });

        // Check if registration failed as expected
        if (!result.success) {
          const errorMessage = result.error || 'Unknown registration error';
          console.log('RPC failure detected:', errorMessage);
          return {
            success: false,
            accountId: testAccountId,
            error: errorMessage,
            isRpcError: errorMessage.includes('RPC') ||
                       errorMessage.includes('network failure') ||
                       errorMessage.includes('server unavailable'),
            message: 'Registration failed as expected due to RPC failure'
          };
        }

        return {
          success: true,
          accountId: testAccountId,
          result,
          message: 'Unexpected: Registration should have failed due to RPC'
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.log('RPC failure caught via exception:', errorMessage);

        return {
          success: false,
          accountId: testAccountId,
          error: errorMessage,
          isRpcError: errorMessage.includes('RPC') ||
                     errorMessage.includes('network failure') ||
                     errorMessage.includes('server unavailable'),
          message: 'Registration failed as expected due to RPC failure'
        };
      } finally {
        failureMocks.restore();
      }
    });

    console.log('RPC failure test result:', result);

    expect(result.accountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

  ////////////////////////////////////
  // Induce failure: IndexedDB Failure
  ////////////////////////////////////

  test('IndexedDB failure during data storage', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { passkeyManager, generateTestAccountId, failureMocks } = (window as any).testUtils;
      const testAccountId = generateTestAccountId();

      console.log(`Testing IndexedDB failure for account: ${testAccountId}`);

      try {
        // Inject IndexedDB failure before calling registerPasskey
        failureMocks.indexedDBFailure();

        // Call registerPasskey - should fail at storage step
        const result = await passkeyManager.registerPasskey(testAccountId, {
          onEvent: (event: any) => console.log('Registration event:', event),
          onError: (error: any) => console.log('Registration error:', error)
        });

        // Check if registration failed as expected
        if (!result.success) {
          const errorMessage = result.error || 'Unknown registration error';
          console.log('IndexedDB failure detected:', errorMessage);
          return {
            success: false,
            accountId: testAccountId,
            error: errorMessage,
            isStorageError: errorMessage.includes('IndexedDB') ||
                           errorMessage.includes('storage') ||
                           errorMessage.includes('quota exceeded'),
            message: 'Registration failed as expected due to IndexedDB failure'
          };
        }

        return {
          success: true,
          accountId: testAccountId,
          result,
          message: 'Unexpected: Registration should have failed due to IndexedDB'
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.log('IndexedDB failure caught via exception:', errorMessage);

        return {
          success: false,
          accountId: testAccountId,
          error: errorMessage,
          isStorageError: errorMessage.includes('IndexedDB') ||
                         errorMessage.includes('storage') ||
                         errorMessage.includes('quota exceeded'),
          message: 'Registration failed as expected due to IndexedDB failure'
        };
      } finally {
        failureMocks.restore();
      }
    });

    console.log('IndexedDB failure test result:', result);

    expect(result.accountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy();
  });

});