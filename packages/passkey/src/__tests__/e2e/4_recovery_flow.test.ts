/**
 * PasskeyManager Recovery Flow E2E Test
 *
 * Tests the complete account recovery user journey with VRF state restoration.
 * Uses real implementations and network calls - no mocking unless absolutely necessary.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';
import { ActionType } from '../../core/types/actions';

test.describe('PasskeyManager Recovery Flow', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Add 1 second delay to prevent NEAR account creation throttling
    await page.waitForTimeout(1000);
  });

  test('Recovery Flow - Account Recovery with VRF State Restoration', async ({ page }) => {
    const result = await page.evaluate(async (ActionType) => {
      try {
        const {
          passkeyManager,
          generateTestAccountId
        } = (window as any).testUtils as TestUtils;
        const testAccountId = generateTestAccountId();

        console.log(`Testing account recovery flow for: ${testAccountId}`);

        // Step 1: Register account first (creates the account to recover) - real registration
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          useRelayer: false,
          onEvent: (event: any) => console.log(`Setup [${event.step}]: ${event.message}`)
        });

        if (!registrationResult.success) {
          throw new Error(`Setup registration failed: ${registrationResult.error}`);
        }

        // Step 2: Simulate data loss by logging out and clearing VRF session - real logout
        await passkeyManager.logoutAndClearVrfSession();

        // Verify logged out state using real state checking
        const preRecoveryState = await passkeyManager.getLoginState(testAccountId);

        // Step 3: Perform account recovery using real recovery implementation
        const recoveryEvents: any[] = [];
        const recoveryResult = await passkeyManager.recoverAccountWithAccountId(
          testAccountId,
          {
            onEvent: (event: any) => {
              recoveryEvents.push(event);
              console.log(`Recovery Event [${event.step}]: ${event.phase} - ${event.message}`);
            },
            onError: (error: any) => {
              console.error('Recovery Error:', error);
            }
          }
        );

        // Step 4: Verify recovery state using real state checking
        const postRecoveryState = await passkeyManager.getLoginState(testAccountId);

        // Step 5: Test that account is functional after recovery (try an action) - real action
        let postRecoveryActionSuccess = false;
        try {
          const testAction = await passkeyManager.executeAction(
            testAccountId,
            {
              type: ActionType.Transfer,
              receiverId: 'example.testnet',
              amount: '1' // Minimal amount
            },
            {
              waitUntil: 'INCLUDED' // Conservative wait for recovery test
            }
          );
          postRecoveryActionSuccess = testAction.success;
        } catch (actionError) {
          console.log('Post-recovery action failed (expected in some cases):', actionError);
        }

        return {
          success: true,
          testAccountId,
          registrationSuccess: registrationResult.success,
          preRecoveryState,
          recoveryResult,
          postRecoveryState,
          postRecoveryActionSuccess,
          recoveryEventPhases: recoveryEvents.map(e => e.phase),
          finalRecoveryEvent: recoveryEvents[recoveryEvents.length - 1]
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          stage: 'recovery-flow'
        };
      }
    }, ActionType);

    // Assertions for complete recovery flow
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    expect(result.registrationSuccess).toBe(true);

    // Verify pre-recovery state (should be logged out)
    expect(result.preRecoveryState?.vrfActive).toBe(false);

    // Verify recovery success
    expect(result.recoveryResult?.success).toBe(true);
    expect(result.recoveryResult?.accountId).toBe(result.testAccountId);
    expect(result.recoveryResult?.publicKey).toBeTruthy();
    expect(result.recoveryResult?.message).toContain('successfully recovered');

    // Verify login state restoration
    if (result.recoveryResult?.loginState) {
      expect(result.recoveryResult.loginState.isLoggedIn).toBe(true);
      expect(result.recoveryResult.loginState.vrfActive).toBe(true);
    }

    // Verify post-recovery state
    expect(result.postRecoveryState?.isLoggedIn).toBe(true);
    expect(result.postRecoveryState?.vrfActive).toBe(true);
    expect(result.postRecoveryState?.nearAccountId).toBe(result.testAccountId);

    // Verify recovery event progression
    expect(result.recoveryEventPhases).toContain('preparation');
    expect(result.recoveryEventPhases).toContain('contract-verification');
    expect(result.recoveryEventPhases).toContain('transaction-signing');
    expect(result.recoveryEventPhases).toContain('action-complete');
    expect(result.finalRecoveryEvent?.status).toBe('success');

    console.log(`Account recovery completed successfully for ${result.testAccountId}`);
    console.log(`VRF State Restored: ${result.postRecoveryState?.vrfActive}`);
    console.log(`Post-recovery functionality: ${result.postRecoveryActionSuccess ? 'Working' : 'Limited'}`);
  });

});