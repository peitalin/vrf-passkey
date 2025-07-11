/**
 * PasskeyManager Registration Flow E2E Test
 *
 * Tests the complete registration user journey with realistic scenarios.
 * Uses real implementations and network calls - no mocking unless absolutely necessary.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';

test.describe('PasskeyManager Registration Flow', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Add 1 second delay to prevent NEAR account creation throttling
    await page.waitForTimeout(1000);
  });

  test('Registration Flow - Complete Happy Path', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const {
          passkeyManager,
          generateTestAccountId,
          verifyAccountExists
        } = (window as any).testUtils as TestUtils;
        const testAccountId = generateTestAccountId();

        console.log(`Testing complete registration flow for: ${testAccountId}`);

        // Track registration progress events
        const events: any[] = [];

        // Execute full registration flow using real PasskeyManager implementation
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          useRelayer: false, // Use real testnet faucet for realistic network conditions
          onEvent: (event: any) => {
            events.push(event);
            console.log(`Registration Event [${event.step}]: ${event.phase} - ${event.message}`);
          },
          onError: (error: any) => {
            console.error('Registration Error:', error);
          }
        });

        // Verify registration success
        if (!registrationResult.success) {
          throw new Error(`Registration failed: ${registrationResult.error}`);
        }

        // Verify account exists on chain using real NEAR RPC calls
        const accountExists = await verifyAccountExists(testAccountId);

        // Verify login state after registration using real WebAuthnManager
        const loginState = await passkeyManager.getLoginState(testAccountId);

        // Verify VRF credentials stored using real IndexedDB operations
        const hasCredentials = await passkeyManager.hasPasskeyCredential(testAccountId);

        return {
          success: true,
          testAccountId,
          registrationResult,
          accountExists,
          loginState,
          hasCredentials,
          eventPhases: events.map(e => e.phase),
          finalEvent: events[events.length - 1],
          vrfRegistration: registrationResult.vrfRegistration
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          stage: 'registration-flow'
        };
      }
    });

    // Assertions for complete registration flow
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    expect(result.testAccountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.registrationResult?.success).toBe(true);
    expect(result.registrationResult?.nearAccountId).toBe(result.testAccountId);
    expect(result.registrationResult?.clientNearPublicKey).toBeTruthy();
    expect(result.accountExists).toBe(true);
    expect(result.hasCredentials).toBe(true);

    // Verify VRF registration completed
    expect(result.vrfRegistration?.success).toBe(true);
    expect(result.vrfRegistration?.vrfPublicKey).toBeTruthy();
    expect(result.vrfRegistration?.contractVerified).toBe(true);

    // Verify login state after registration
    expect(result.loginState?.isLoggedIn).toBe(true);
    expect(result.loginState?.vrfActive).toBe(true);
    expect(result.loginState?.nearAccountId).toBe(result.testAccountId);

    // Verify event progression
    expect(result.eventPhases).toContain('webauthn-verification');
    expect(result.eventPhases).toContain('access-key-addition');
    expect(result.eventPhases).toContain('contract-registration');
    expect(result.eventPhases).toContain('database-storage');
    expect(result.finalEvent?.status).toBe('success');

    console.log(`Registration flow completed successfully for ${result.testAccountId}`);
  });

});