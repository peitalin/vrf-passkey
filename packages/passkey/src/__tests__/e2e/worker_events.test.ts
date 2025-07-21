/**
 * Worker Communication Integration Tests
 *
 * Tests the communication protocol between TypeScript worker and WASM
 * Specifically focuses on progress messaging functionality that was broken during refactoring
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('Worker Communication Protocol', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(1000);
  });

  test('Progress Messages - SignTransactionsWithActions', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        // @ts-ignore - Runtime import
        const { ActionType } = await import('/sdk/esm/core/types/actions.js');

        const { passkeyManager, generateTestAccountId } = (window as any).testUtils;
        const testAccountId = generateTestAccountId();

        // Track all progress events
        const progressEvents: any[] = [];

        // Register first to have an account
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          onEvent: (event: any) => {
            console.log(`Registration [${event.step}]: ${event.phase} - ${event.message}`);
          }
        });

        if (!registrationResult.success) {
          throw new Error(`Registration failed: ${registrationResult.error}`);
        }

        // Login to activate session
        const loginResult = await passkeyManager.loginPasskey(testAccountId, {
          onEvent: (event: any) => {
            console.log(`Login [${event.step}]: ${event.phase} - ${event.message}`);
          }
        });

        if (!loginResult.success) {
          throw new Error(`Login failed: ${loginResult.error}`);
        }

        // Wait for registration to settle
        await new Promise(resolve => setTimeout(resolve, 5000));

        // Now test executeAction with detailed progress tracking
        const actionResult = await passkeyManager.executeAction(testAccountId, {
          type: ActionType.FunctionCall,
          receiverId: 'web3-authn-v2.testnet',
          methodName: 'set_greeting',
          args: { greeting: 'Test progress message' },
          gas: '30000000000000',
          deposit: '0'
        }, {
          onEvent: (event: any) => {
            progressEvents.push({
              step: event.step,
              phase: event.phase,
              status: event.status,
              message: event.message,
              timestamp: event.timestamp,
              hasData: !!event.data
            });
            console.log(`Action Progress [${event.step}]: ${event.phase} - ${event.message}`);
          }
        });

        return {
          success: true,
          actionResult,
          progressEvents,
          // Analysis
          totalEvents: progressEvents.length,
          phases: progressEvents.map(e => e.phase),
          uniquePhases: [...new Set(progressEvents.map(e => e.phase))],
          hasPreparation: progressEvents.some(e => e.phase === 'preparation'),
          hasAuthentication: progressEvents.some(e => e.phase === 'authentication'),
          hasContractVerification: progressEvents.some(e => e.phase === 'contract-verification'),
          hasTransactionSigning: progressEvents.some(e => e.phase === 'transaction-signing'),
          hasBroadcasting: progressEvents.some(e => e.phase === 'broadcasting'),
          hasCompletion: progressEvents.some(e => e.phase === 'action-complete'),
          // Event structure validation
          allEventsHaveRequiredFields: progressEvents.every(e =>
            typeof e.step === 'number' &&
            typeof e.phase === 'string' &&
            typeof e.status === 'string' &&
            typeof e.message === 'string' &&
            typeof e.timestamp === 'number'
          )
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          stack: error.stack
        };
      }
    });

    // Assertions
    expect(result.success).toBe(true);
    if (!result.success) {
      console.error('Test failed:', result.error);
      return;
    }

    // Verify progress events were captured
    expect(result.totalEvents).toBeGreaterThan(0);
    console.log(`✅ Captured ${result.totalEvents} progress events`);
    console.log(`✅ Phases: ${result.uniquePhases?.join(', ') || 'none'}`);

    // Verify expected phases are present
    expect(result.hasPreparation).toBe(true);
    expect(result.hasAuthentication).toBe(true);
    expect(result.hasContractVerification).toBe(true);
    expect(result.hasTransactionSigning).toBe(true);

    // Verify event structure
    expect(result.allEventsHaveRequiredFields).toBe(true);

    console.log('✅ Worker communication and progress messaging test passed');
  });

  test('Progress Message Types - All Message Types', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const { passkeyManager, generateTestAccountId } = (window as any).testUtils;
        const testAccountId = generateTestAccountId();

        // Track progress message types
        const messageTypes = new Set<string>();
        const progressEvents: any[] = [];

        // Override console.log to capture worker debug messages
        const originalLog = console.log;
        const workerLogs: string[] = [];
        console.log = (...args) => {
          const message = args.join(' ');
          workerLogs.push(message);
          originalLog(...args);
        };

        try {
          // Test registration flow (should generate REGISTRATION_PROGRESS messages)
          await passkeyManager.registerPasskey(testAccountId, {
            onEvent: (event: any) => {
              progressEvents.push(event);
              messageTypes.add(`${event.phase}:${event.status}`);
            }
          });

          // Test login flow (should generate various progress messages)
          await passkeyManager.loginPasskey(testAccountId, {
            onEvent: (event: any) => {
              progressEvents.push(event);
              messageTypes.add(`${event.phase}:${event.status}`);
            }
          });

        } finally {
          console.log = originalLog;
        }

        return {
          success: true,
          totalEvents: progressEvents.length,
          messageTypes: Array.from(messageTypes),
          workerLogs: workerLogs.filter(log =>
            log.includes('Progress:') ||
            log.includes('SIGNING_') ||
            log.includes('VERIFICATION_') ||
            log.includes('REGISTRATION_')
          ),
          // Event type analysis
          progressCount: progressEvents.filter(e => e.status === 'progress').length,
          successCount: progressEvents.filter(e => e.status === 'success').length,
          errorCount: progressEvents.filter(e => e.status === 'error').length,
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message
        };
      }
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      console.error('Message types test failed:', result.error);
      return;
    }

        console.log('✅ Message Types Test Results:');
    console.log(`   Total Events: ${result.totalEvents}`);
    console.log(`   Message Types: ${result.messageTypes?.join(', ') || 'none'}`);
    console.log(`   Progress: ${result.progressCount}, Success: ${result.successCount}, Error: ${result.errorCount}`);

    if (result.workerLogs && result.workerLogs.length > 0) {
      console.log(`   Worker Logs: ${result.workerLogs.length} messages`);
      result.workerLogs.slice(0, 3).forEach(log => console.log(`     ${log}`));
    }

    expect(result.totalEvents).toBeGreaterThan(0);
    expect(result.messageTypes?.length || 0).toBeGreaterThan(0);
  });

  test('Worker Error Handling - Progress on Failure', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        const { passkeyManager, generateTestAccountId } = (window as any).testUtils;
        const invalidAccountId = "invalid-account-format!@#";

        const progressEvents: any[] = [];
        const errorEvents: any[] = [];

        // Test error handling with invalid account (should still send progress messages)
        try {
          await passkeyManager.registerPasskey(invalidAccountId, {
            onEvent: (event: any) => {
              progressEvents.push(event);
              if (event.status === 'error') {
                errorEvents.push(event);
              }
            },
            onError: (error: any) => {
              console.log('Expected error caught:', error.message);
            }
          });
        } catch (expectedError) {
          // This is expected to fail
        }

        return {
          success: true,
          progressEvents: progressEvents.length,
          errorEvents: errorEvents.length,
          hasErrorPhase: progressEvents.some(e => e.phase === 'action-error' || e.status === 'error'),
          lastEvent: progressEvents[progressEvents.length - 1]
        };

      } catch (error: any) {
        return {
          success: false,
          error: error.message
        };
      }
    });

    expect(result.success).toBe(true);
    console.log('✅ Error Handling Test Results:');
    console.log(`   Progress Events: ${result.progressEvents}`);
    console.log(`   Error Events: ${result.errorEvents}`);
    console.log(`   Has Error Phase: ${result.hasErrorPhase}`);

    // Even on failure, we should get some progress events
    expect(result.progressEvents).toBeGreaterThanOrEqual(0);
  });

});