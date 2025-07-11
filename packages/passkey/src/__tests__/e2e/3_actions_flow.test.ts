/**
 * PasskeyManager Actions Flow E2E Test
 *
 * Tests the complete transaction execution user journey with VRF authentication.
 * Uses real implementations and network calls - no mocking unless absolutely necessary.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';
import { ActionType } from '../../core/types/actions';

test.describe('PasskeyManager Actions Flow', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Add 1 second delay to prevent NEAR account creation throttling
    await page.waitForTimeout(1000);
  });

  test('Actions Flow - Transfer Transaction with VRF Authentication', async ({ page }) => {
    const result = await page.evaluate(async (ActionType) => {
      try {
        const {
          passkeyManager,
          generateTestAccountId
        } = (window as any).testUtils as TestUtils;
        const senderAccountId = generateTestAccountId();
        const receiverAccountId = generateTestAccountId();

        console.log(`Testing transfer action flow: ${senderAccountId} -> ${receiverAccountId}`);

        // Step 1: Register sender account using real registration
        const registrationResult = await passkeyManager.registerPasskey(senderAccountId, {
          useRelayer: false,
          onEvent: (event: any) => console.log(`Setup [${event.step}]: ${event.message}`)
        });

        if (!registrationResult.success) {
          throw new Error(`Sender registration failed: ${registrationResult.error}`);
        }

        // Step 2: Verify login state before action using real state checking
        const preActionState = await passkeyManager.getLoginState(senderAccountId);

        // Step 3: Execute transfer action using real executeAction implementation
        const actionEvents: any[] = [];
        const transferResult = await passkeyManager.executeAction(
          senderAccountId,
          {
            type: ActionType.Transfer,
            receiverId: receiverAccountId,
            amount: '100000000000000000000000' // 0.1 NEAR in yoctoNEAR
          },
          {
            onEvent: (event: any) => {
              actionEvents.push(event);
              console.log(`Action Event [${event.step}]: ${event.phase} - ${event.message}`);
            },
            onError: (error: any) => {
              console.error('Action Error:', error);
            },
            waitUntil: 'EXECUTED_OPTIMISTIC' // Fast feedback for tests
          }
        );

        // Step 4: Verify transaction result
        const hasTransactionId = !!transferResult.transactionId;

        return {
          success: true,
          senderAccountId,
          receiverAccountId,
          registrationSuccess: registrationResult.success,
          preActionState,
          transferResult,
          hasTransactionId,
          actionEventPhases: actionEvents.map(e => e.phase),
          finalActionEvent: actionEvents[actionEvents.length - 1]
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          stage: 'actions-flow'
        };
      }
    }, ActionType);

    // Assertions for complete actions flow
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    expect(result.registrationSuccess).toBe(true);

    // Verify pre-action state (should be logged in from registration)
    expect(result.preActionState?.isLoggedIn).toBe(true);
    expect(result.preActionState?.vrfActive).toBe(true);

    // Verify transfer action success
    expect(result.transferResult?.success).toBe(true);
    expect(result.hasTransactionId).toBe(true);

    // Verify action event progression
    expect(result.actionEventPhases).toContain('preparation');
    expect(result.actionEventPhases).toContain('authentication');
    expect(result.actionEventPhases).toContain('broadcasting');
    expect(result.actionEventPhases).toContain('action-complete');
    expect(result.finalActionEvent?.status).toBe('success');

    console.log(`Transfer action completed: ${result.senderAccountId} -> ${result.receiverAccountId}`);
    console.log(`Transaction ID: ${result.transferResult?.transactionId}`);
  });

});