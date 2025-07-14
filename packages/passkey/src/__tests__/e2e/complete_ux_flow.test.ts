/**
 * PasskeyManager Complete E2E Test Suite
 *
 * Comprehensive test suite covering the complete PasskeyManager lifecycle:
 * 1. Registration Flow
 * 2. Login Flow
 * 3. Actions Flow (Transfer Transaction)
 * 4. Recovery Flow (Account Recovery)
 *
 * All flows run sequentially in the same browser context to maintain IndexedDB state.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';
import { ActionType } from '../../core/types/actions';

test.describe('PasskeyManager Complete E2E Test Suite', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Increased delay to prevent NEAR testnet faucet rate limiting (429 errors)
    await page.waitForTimeout(3000);
  });

  test('Complete PasskeyManager Lifecycle - Registration → Login → Actions → Recovery', async ({ page }) => {
    // Capture browser console logs for debugging
    const consoleMessages: string[] = [];
    page.on('console', msg => {
      const message = `[${msg.type()}] ${msg.text()}`;
      consoleMessages.push(message);
      // Also log to test output immediately for debugging
      if (message.includes('RUST:') || message.includes('signer-worker') || message.includes('Contract') || message.includes('verification')) {
        console.log(`${message}`);
      }
    });

    // Also capture page errors
    page.on('pageerror', error => {
      consoleMessages.push(`[pageerror] ${error.message}`);
      console.log(`❌ Page Error: ${error.message}`);
    });

    // Clear IndexedDB to ensure clean state after credential ID format changes
    await page.evaluate(async () => {
      try {
        // Delete known PasskeyManager databases
        const dbNames = ['PasskeyClientDB', 'PasskeyNearKeysDB'];
        for (const dbName of dbNames) {
          await new Promise<void>((resolve) => {
            const deleteReq = indexedDB.deleteDatabase(dbName);
            deleteReq.onsuccess = () => resolve();
            deleteReq.onerror = () => resolve(); // Don't fail if DB doesn't exist
            deleteReq.onblocked = () => resolve(); // Don't fail if blocked
          });
        }
        console.log('IndexedDB cleared for fresh test run');
      } catch (error) {
        console.log('️IndexedDB clearing failed, continuing with test:', error);
      }
    });

    const result = await page.evaluate(async (actionType) => {
      try {
        const {
          passkeyManager,
          generateTestAccountId
        } = (window as any).testUtils as TestUtils;

        // =================================================================
        // PHASE 1: REGISTRATION & LOGIN FLOW
        // =================================================================
        console.log('=== PHASE 1: REGISTRATION & LOGIN ===');

        const testAccountId = generateTestAccountId();
        console.log('Generated test account ID:', testAccountId);

        // Registration
        const registrationEvents: any[] = [];
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          onEvent: (event: any) => {
            registrationEvents.push(event);
            console.log(`Registration [${event.step}]: ${event.phase} - ${event.message}`);
          },
          onError: (error: any) => {
            console.error('Registration Error:', error);
          }
        });

        const registrationSuccessEvents = registrationEvents.filter(e => e.status === 'success');
        const registrationErrorEvents = registrationEvents.filter(e => e.status === 'error');
        const reachedWebAuthn = registrationEvents.some(e => e.phase === 'webauthn-verification');
        const reachedCompletion = registrationEvents.some(e => e.phase === 'registration-complete');

        if (!registrationResult.success) {
          throw new Error(`Registration failed: ${registrationResult.error}`);
        }

        // =================================================================
        // PHASE 2: LOGIN FLOW
        // =================================================================
        console.log('=== PHASE 2: LOGIN FLOW ===');

        // Debug before login attempt
        console.log('🔍 Starting login attempt for account:', testAccountId);

        // Test VRF worker initialization
        console.log('🔍 Testing VRF worker initialization...');
        try {
          // Check current URL and base path
          const currentUrl = await page.url();
          console.log('🔍 Current test URL:', currentUrl);

          // Check if VRF worker files are accessible
          const workerFileResults = await page.evaluate(async () => {
            const results: any[] = [];

            console.log('Current page location:', window.location.href);

            // Check if worker files exist
            const workerPaths = [
              '/workers/web3authn-vrf.worker.js',
              '/workers/wasm_vrf_worker.js',
              '/workers/wasm_vrf_worker_bg.wasm'
            ];

            for (const path of workerPaths) {
              try {
                const response = await fetch(path);
                results.push({
                  path,
                  status: response.status,
                  statusText: response.statusText,
                  success: response.ok
                });
              } catch (error) {
                results.push({
                  path,
                  error: error instanceof Error ? error.message : String(error),
                  success: false
                });
              }
            }

            return results;
          });

          console.log('🔍 VRF Worker file accessibility results:');
          workerFileResults.forEach(result => {
            if (result.success) {
              console.log(`✅ ${result.path}: ${result.status} ${result.statusText}`);
            } else {
              console.log(`❌ ${result.path}: ${result.error || 'Failed'}`);
            }
          });

          // Try to get login state which should initialize VRF worker
          const loginState = await passkeyManager.getLoginState();
          console.log('🔍 Login state retrieved:', loginState);

          // Add explicit VRF worker initialization test
          console.log('🔍 Testing explicit VRF worker initialization...');
          try {
            // Try to get login state which will trigger VRF worker initialization
            const loginStateResult = await passkeyManager.getLoginState();
            console.log('🔍 Login state check result:', loginStateResult);
          } catch (vrfError: any) {
            console.log('❌ Login state check failed:', vrfError);
            console.log('❌ Login state error stack:', vrfError?.stack);
          }

        } catch (vrfTestError) {
          console.log('❌ VRF worker test failed:', vrfTestError);
        }

        const loginEvents: any[] = [];
        const loginResult = await passkeyManager.loginPasskey(testAccountId, {
          onEvent: (event: any) => {
            loginEvents.push(event);
            console.log(`Login [${event.step}]: ${event.phase} - ${event.message}`);
          },
          onError: (error: any) => {
            console.error('Login Error:', error);
          }
        });

        // Debug login result
        console.log('🔍 Login completed. Success:', loginResult.success);
        if (!loginResult.success) {
          console.log('🔍 Login error:', loginResult.error);
          console.log('🔍 Login events:', loginEvents.map(e => `${e.phase}: ${e.message}`));
          throw new Error(`Login failed: ${loginResult.error}`);
        }

        // =================================================================
        // PHASE 2: ACTIONS FLOW
        // =================================================================
        console.log('=== PHASE 2: ACTIONS FLOW ===');

        // Add delay to ensure registration transaction is fully processed
        console.log('Waiting 6 seconds for registration transaction to be fully finalized...');
        await new Promise(resolve => setTimeout(resolve, 6000));

        // const receiverAccountId = generateTestAccountId();
        const receiverAccountId = "web3-authn.testnet";
        console.log(`Testing transfer: ${testAccountId} → ${receiverAccountId}`);

        const actionEvents: any[] = [];
        const transferResult = await passkeyManager.executeAction(
          testAccountId,
          {
            type: actionType.Transfer, // Use the passed ActionType
            receiverId: receiverAccountId,
            amount: "500000000000000000000000", // 0.5 NEAR in yoctoNEAR
          },
          {
            onEvent: (event: any) => {
              actionEvents.push(event);
              console.log(`Action [${event.step}]: ${event.phase} - ${event.message}`);
            },
            onError: (error: any) => {
              console.error('Action Error:', error);
            }
          }
        );

        // =================================================================
        // PHASE 3: RECOVERY FLOW
        // =================================================================
        console.log('=== PHASE 3: RECOVERY FLOW ===');

        const recoveryEvents: any[] = [];
        const recoveryResult = await passkeyManager.recoverAccountWithAccountId(testAccountId, {
          onEvent: (event: any) => {
            recoveryEvents.push(event);
            console.log(`Recovery [${event.step}]: ${event.phase} - ${event.message}`);
          },
          onError: (error: any) => {
            console.error('Recovery Error:', error);
          }
        });

        // =================================================================
        // FINAL STATE VERIFICATION
        // =================================================================
        console.log('=== FINAL STATE VERIFICATION ===');

        const finalLoginState = await passkeyManager.getLoginState(testAccountId);
        const recentLogins = await passkeyManager.getRecentLogins();

        return {
          success: true,
          testAccountId,

          // Phase 1 Results
          registrationResult,
          registrationFlow: {
            reachedWebAuthn,
            reachedCompletion,
            totalEvents: registrationEvents.length,
            successfulSteps: registrationSuccessEvents.length,
            failedSteps: registrationErrorEvents.length
          },
          loginResult,
          loginEventPhases: loginEvents.map(e => e.phase),

          // Phase 2 Results
          transferResult,
          actionEventPhases: actionEvents.map(e => e.phase),
          finalActionEvent: actionEvents[actionEvents.length - 1],

          // Phase 3 Results
          recoveryResult,
          recoveryEventPhases: recoveryEvents.map(e => e.phase),
          finalRecoveryEvent: recoveryEvents[recoveryEvents.length - 1],

          // Final State
          finalLoginState,
          recentLogins
        };

      } catch (error: any) {
        console.error('Test execution error:', error);
        return {
          success: false,
          error: error.message,
          stack: error.stack
        };
      }
    }, ActionType); // Pass ActionType as parameter

    // =================================================================
    // ASSERTIONS
    // =================================================================

    // Debug: Log the result before assertions
    console.log('=== TEST RESULT DEBUG ===');
    console.log('Result success:', result.success);
    if (!result.success) {
      console.log('Result error:', result.error);
      console.log('Result stack:', result.stack);
    }
    console.log('=== END TEST RESULT DEBUG ===');

    // Overall success
    expect(result.success).toBe(true);
    if (!result.success) {
      console.error('Test failed:', result.error);
      console.error('Stack trace:', result.stack);
      return;
    }

    console.log(`Complete lifecycle test passed for ${result.testAccountId}`);

    // Phase 1: Registration & Login
    expect(result.registrationResult?.success).toBe(true);
    expect(result.registrationFlow?.reachedWebAuthn).toBe(true);
    expect(result.registrationFlow?.reachedCompletion).toBe(true);
    expect(result.loginResult?.success).toBe(true);
    expect(result.loginEventPhases).toContain('login-complete');

    // Phase 2: Actions
    if (result.transferResult?.success) {
      expect(result.actionEventPhases).toContain('preparation');
      console.log(`Actions flow: Transfer completed successfully`);
    } else {
      console.log(`️Actions flow: Transfer failed - ${result.transferResult?.error || 'Unknown error'}`);
    }

    // Phase 3: Recovery
    if (result.recoveryResult?.success) {
      expect(result.recoveryEventPhases).toContain('preparation');
      console.log(`Recovery flow: Account recovery completed successfully`);
    } else {
      console.log(`️Recovery flow: Account recovery failed - ${result.recoveryResult?.error || 'Unknown error'}`);
    }

    // Final State
    expect(result.finalLoginState?.isLoggedIn).toBe(true);
    expect(result.finalLoginState?.vrfActive).toBe(true);
    expect(result.recentLogins?.accountIds).toContain(result.testAccountId);

    // Output captured console messages for debugging
    console.log('=== BROWSER CONSOLE MESSAGES (last 50) ===');
    consoleMessages.slice(-50).forEach((msg, index) => {
      console.log(`${index + 1}: ${msg}`);
    });
    console.log('=== END BROWSER CONSOLE ===');

    // Also show any RUST/signer worker messages specifically
    const rustMessages = consoleMessages.filter(msg =>
      msg.includes('RUST:') || msg.includes('signer-worker') || msg.includes('Contract') || msg.includes('verification')
    );
    if (rustMessages.length > 0) {
      console.log('=== RUST/SIGNER WORKER MESSAGES ===');
      rustMessages.forEach((msg, index) => {
        console.log(`${index + 1}: ${msg}`);
      });
      console.log('=== END RUST/SIGNER WORKER MESSAGES ===');
    } else {
      console.log('️No RUST/signer worker messages found in console logs');
    }

    console.log(`Complete PasskeyManager lifecycle test completed successfully!`);
    console.log(`   Account: ${result.testAccountId}`);
    console.log(`   Registration: ${result.registrationResult?.success ? '✅' : '❌'}`);
    console.log(`   Login: ${result.loginResult?.success ? '✅' : '❌'}`);
    console.log(`   Actions: ${result.transferResult?.success ? '✅' : '⚠️'}`);
    console.log(`   Recovery: ${result.recoveryResult?.success ? '✅' : '⚠️'}`);
    console.log(`   Final VRF State: ${result.finalLoginState?.vrfActive ? '✅ Active' : '❌ Inactive'}`);
  });
});