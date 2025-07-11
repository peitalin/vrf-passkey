/**
 * PasskeyManager Login Flow E2E Test
 *
 * Tests the complete login user journey with VRF authentication and session management.
 * Uses real implementations and network calls - no mocking unless absolutely necessary.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';

test.describe('PasskeyManager Login Flow', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Add 1 second delay to prevent NEAR account creation throttling
    await page.waitForTimeout(1000);
  });

  test('Login Flow - VRF Authentication with Session Management', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const {
          passkeyManager,
          generateTestAccountId
        } = (window as any).testUtils as TestUtils;
        const testAccountId = generateTestAccountId();

        console.log(`Testing complete login flow for: ${testAccountId}`);

        // Step 1: Register account first (prerequisite) - using real registration
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          useRelayer: false,
          onEvent: (event: any) => console.log(`Setup [${event.step}]: ${event.message}`)
        });

        if (!registrationResult.success) {
          throw new Error(`Setup failed: ${registrationResult.error}`);
        }

        // Step 2: Logout to clear VRF session - using real logout implementation
        await passkeyManager.logoutAndClearVrfSession();

        // Verify logged out state using real state checking
        const loggedOutState = await passkeyManager.getLoginState(testAccountId);

        // Step 3: Perform login flow using real login implementation
        const loginEvents: any[] = [];
        const loginResult = await passkeyManager.loginPasskey(testAccountId, {
          onEvent: (event: any) => {
            loginEvents.push(event);
            console.log(`Login Event [${event.step}]: ${event.phase} - ${event.message}`);
          },
          onError: (error: any) => {
            console.error('Login Error:', error);
          }
        });

        // Step 4: Verify login state after successful login
        const loggedInState = await passkeyManager.getLoginState(testAccountId);

        // Step 5: Test session persistence - get recent logins using real IndexedDB
        const recentLogins = await passkeyManager.getRecentLogins();

        return {
          success: true,
          testAccountId,
          registrationSuccess: registrationResult.success,
          loggedOutState,
          loginResult,
          loggedInState,
          recentLogins,
          loginEventPhases: loginEvents.map(e => e.phase),
          finalLoginEvent: loginEvents[loginEvents.length - 1]
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          stage: 'login-flow'
        };
      }
    });

    // Assertions for complete login flow
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    expect(result.registrationSuccess).toBe(true);

    // Verify logged out state
    expect(result.loggedOutState?.isLoggedIn).toBe(false);
    expect(result.loggedOutState?.vrfActive).toBe(false);

    // Verify login success
    expect(result.loginResult?.success).toBe(true);
    expect(result.loginResult?.loggedInNearAccountId).toBe(result.testAccountId);
    expect(result.loginResult?.clientNearPublicKey).toBeTruthy();

    // Verify logged in state
    expect(result.loggedInState?.isLoggedIn).toBe(true);
    expect(result.loggedInState?.vrfActive).toBe(true);
    expect(result.loggedInState?.nearAccountId).toBe(result.testAccountId);
    expect(result.loggedInState?.publicKey).toBeTruthy();

    // Verify recent logins tracking
    expect(result.recentLogins?.accountIds).toContain(result.testAccountId);
    expect(result.recentLogins?.lastUsedAccountId).toBe(result.testAccountId);

    // Verify login event progression
    expect(result.loginEventPhases).toContain('preparation');
    expect(result.loginEventPhases).toContain('webauthn-assertion');
    expect(result.loginEventPhases).toContain('vrf-unlock');
    expect(result.loginEventPhases).toContain('login-complete');
    expect(result.finalLoginEvent?.status).toBe('success');

    console.log(`Login flow completed successfully for ${result.testAccountId}`);
  });

});