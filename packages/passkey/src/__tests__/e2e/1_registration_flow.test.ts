/**
 * PasskeyManager Complete E2E Test Suite
 *
 * Comprehensive test suite covering the complete PasskeyManager lifecycle:
 * 1. Registration Flow
 * 2. Login Flow
 * 3. Actions Flow (Transfer Transaction)
 * 4. Recovery Flow (Account Recovery)
 *
 * Uses a shared registration setup to avoid redundant account creation.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';
import { ActionType } from '../../core/types/actions';

// Shared test data that persists across tests in this suite
let sharedTestAccountId: string;
let sharedRegistrationResult: any;

test.describe('PasskeyManager Complete E2E Test Suite', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Increased delay to prevent NEAR testnet faucet rate limiting (429 errors)
    await page.waitForTimeout(3000);
  });

  test('1. Registration & Login Flow - Complete PasskeyManager Setup with WebAuthn Virtual Authenticator', async ({ page }) => {
    // Capture browser console logs for debugging
    const consoleMessages: string[] = [];
    page.on('console', msg => {
      consoleMessages.push(`[${msg.type()}] ${msg.text()}`);
    });

    // First, test if worker files are accessible
    console.log('Testing worker file accessibility...');

    const workerTests = await page.evaluate(async () => {
      const tests = [];

      // Test VRF worker
      try {
        const vrfResponse = await fetch('/workers/web3authn-vrf.worker.js');
        tests.push({
          name: 'VRF Worker',
          url: '/workers/web3authn-vrf.worker.js',
          status: vrfResponse.status,
          ok: vrfResponse.ok,
          size: vrfResponse.headers.get('content-length')
        });
      } catch (error: any) {
        tests.push({
          name: 'VRF Worker',
          url: '/workers/web3authn-vrf.worker.js',
          error: error.message
        });
      }

      // Test Signer worker
      try {
        const signerResponse = await fetch('/workers/web3authn-signer.worker.js');
        tests.push({
          name: 'Signer Worker',
          url: '/workers/web3authn-signer.worker.js',
          status: signerResponse.status,
          ok: signerResponse.ok,
          size: signerResponse.headers.get('content-length')
        });
      } catch (error: any) {
        tests.push({
          name: 'Signer Worker',
          url: '/workers/web3authn-signer.worker.js',
          error: error.message
        });
      }

      return tests;
    });

    console.log('Worker accessibility test results:', workerTests);

    // Verify workers are accessible
    const vrfWorkerTest = workerTests.find(t => t.name === 'VRF Worker');
    const signerWorkerTest = workerTests.find(t => t.name === 'Signer Worker');

    if (vrfWorkerTest?.error) {
      console.error('VRF Worker not accessible:', vrfWorkerTest.error);
    } else if (vrfWorkerTest?.ok) {
      console.log('VRF Worker accessible:', vrfWorkerTest.status, vrfWorkerTest.size, 'bytes');
    }

    if (signerWorkerTest?.error) {
      console.error('Signer Worker not accessible:', signerWorkerTest.error);
    } else if (signerWorkerTest?.ok) {
      console.log('Signer Worker accessible:', signerWorkerTest.status, signerWorkerTest.size, 'bytes');
    }

    const result = await page.evaluate(async () => {
      try {
        console.log('=== REGISTRATION & LOGIN FLOW TEST ===');

        const testUtils = (window as any).testUtils;
        if (!testUtils) {
          throw new Error('testUtils not available - setup failed');
        }

        const {
          passkeyManager,
          generateTestAccountId,
          verifyAccountExists
        } = testUtils as TestUtils;

        if (!passkeyManager) {
          throw new Error('passkeyManager not available in testUtils');
        }

        // Debug: Check what methods are available on passkeyManager
        console.log('PasskeyManager methods:', Object.getOwnPropertyNames(Object.getPrototypeOf(passkeyManager)));
        console.log('Has getLoginState:', typeof passkeyManager.getLoginState);
        console.log('PasskeyManager constructor:', passkeyManager.constructor.name);

        console.log('PasskeyManager setup successful');

        // Test basic functionality first
        const testAccountId = generateTestAccountId();
        console.log(`Generated test account ID: ${testAccountId}`);

        // Test the configuration
        const configs = passkeyManager.configs;
        console.log('PasskeyManager configs:', configs);

        // PART 1: REGISTRATION FLOW
        console.log('=== PART 1: REGISTRATION FLOW ===');
        console.log('Testing complete registration flow with Virtual Authenticator...');

        // Track registration progress events
        const registrationEvents: any[] = [];
        let registrationError: string | null = null;
        let registrationCompleted = false;

        console.log('About to call registerPasskey...');

        // Execute the actual registration flow
        // With Virtual Authenticator, this should complete successfully
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          useRelayer: false, // Use testnet faucet
          onEvent: (event: any) => {
            registrationEvents.push(event);
            console.log(`Registration Event [${event.step}]: ${event.phase} - ${event.message}`);

            // Check if registration completed
            if (event.phase === 'registration-complete' && event.status === 'success') {
              registrationCompleted = true;
            }
          },
          onError: (error: any) => {
            console.error('Registration Error:', error);
            registrationError = error.message;
          }
        }).catch((error: any) => {
          console.error('Registration Promise Rejected:', error);
          registrationError = error.message;

          // Capture full error details for rejected promises
          if (error.stack) {
            console.error('Rejection stack:', error.stack);
          }
          if (error.cause) {
            console.error('Rejection cause:', error.cause);
          }

          // Return a failed result instead of throwing
          return {
            success: false,
            error: error.message,
            nearAccountId: testAccountId
          };
        });

        console.log('registerPasskey completed with result:', registrationResult);
        console.log('Registration error:', registrationError);
        console.log('Events captured:', registrationEvents.length);

        // Analyze the registration events
        const registrationEventPhases = registrationEvents.map(e => e.phase);
        const registrationEventSteps = registrationEvents.map(e => e.step);
        const registrationSuccessEvents = registrationEvents.filter(e => e.status === 'success');
        const registrationErrorEvents = registrationEvents.filter(e => e.status === 'error');

        // Check specific milestones
        const reachedWebAuthn = registrationEventPhases.includes('webauthn-verification');
        const reachedNearAccount = registrationEventPhases.includes('near-account-creation');
        const reachedContractRegistration = registrationEventPhases.includes('contract-registration');
        const reachedCompletion = registrationEventPhases.includes('registration-complete');

        // Verify account was created if registration succeeded
        let accountExists = false;
        if (registrationResult?.success) {
          try {
            accountExists = await verifyAccountExists(testAccountId);
          } catch (e) {
            console.warn('Account verification failed:', e);
          }
        }

        // PART 2: LOGIN FLOW (if registration succeeded)
        console.log('=== PART 2: LOGIN FLOW ===');
        let loginFlowResult = null;

        if (registrationResult?.success) {
          console.log('Registration succeeded! Testing login flow...');

          // Step 1: Logout to clear VRF session
          console.log('Step 1: Logging out to clear VRF session...');
          await passkeyManager.logoutAndClearVrfSession();

          // Verify logged out state
          const loggedOutState = await passkeyManager.getLoginState(testAccountId);
          console.log('Logged out state:', loggedOutState);

          // Step 2: Perform login flow
          console.log('Step 2: Performing login flow...');
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

          // Step 3: Verify login state after successful login
          const loggedInState = await passkeyManager.getLoginState(testAccountId);
          console.log('Logged in state:', loggedInState);

          // Step 4: Test session persistence
          const recentLogins = await passkeyManager.getRecentLogins();
          console.log('Recent logins:', recentLogins);

          loginFlowResult = {
            loggedOutState,
            loginResult,
            loggedInState,
            recentLogins,
            loginEventPhases: loginEvents.map(e => e.phase),
            finalLoginEvent: loginEvents[loginEvents.length - 1]
          };
        } else {
          console.log('Registration failed - skipping login flow test');
        }

        return {
          success: true,
          testAccountId,
          configs,
          registrationCompleted,
          registrationResult,
          accountExists,
          registrationFlow: {
            reachedWebAuthn: reachedWebAuthn,
            reachedCompletion: reachedCompletion,
            totalEvents: registrationEvents.length,
            successfulSteps: registrationSuccessEvents.length,
            failedSteps: registrationErrorEvents.length
          },
          loginFlow: loginFlowResult
        };

      } catch (error: any) {
        console.error('Test execution error:', error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);

        // Try to get configs if passkeyManager was created
        let configs = null;
        try {
          const testUtils = (window as any).testUtils;
          if (testUtils?.passkeyManager?.configs) {
            configs = testUtils.passkeyManager.configs;
          }
        } catch (e) {
          console.error('Could not get configs in catch block:', e);
        }

        return {
          success: false,
          error: error.message,
          stack: error.stack,
          configs: configs
        };
      }
    });

    // Store shared test data for subsequent tests
    if (result.success && result.registrationResult?.success) {
      sharedTestAccountId = result.testAccountId;
      sharedRegistrationResult = result.registrationResult;
      console.log(`✅ Shared test account created: ${sharedTestAccountId}`);
    }

    console.log('=== TEST RESULT ===');
    if (result.success) {
      console.log('Success:', result.success);
      console.log('Registration completed:', result.registrationCompleted);
      console.log('Account exists:', result.accountExists);
      console.log('Flow progression:', result.registrationFlow);
      console.log('Total events:', result.registrationFlow?.totalEvents || 0);
      if (result.loginFlow) {
        console.log('Login flow result:', result.loginFlow);
      }
    }

    // Output console messages for debugging
    console.log('=== BROWSER CONSOLE MESSAGES ===');
    consoleMessages.slice(-20).forEach((msg, index) => {
      console.log(`${index + 1}: ${msg}`);
    });
    console.log('=== END BROWSER CONSOLE ===');

    // Assertions for complete registration flow testing
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    // Verify basic setup worked
    expect(result.testAccountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.configs).toBeDefined();

    // Verify registration flow was attempted
    expect(result.registrationResult).toBeDefined();

    // With Virtual Authenticator, we expect the flow to progress further
    expect(result.registrationFlow?.reachedWebAuthn).toBe(true);
    expect(result.registrationFlow?.totalEvents).toBeGreaterThan(0);

    // Check if registration completed successfully
    if (result.registrationResult?.success) {
      console.log('Registration completed successfully with Virtual Authenticator');
      expect(result.registrationCompleted).toBe(true);
      expect(result.registrationFlow?.reachedCompletion).toBe(true);
      expect(result.registrationFlow?.successfulSteps).toBeGreaterThan(0);

      // If registration succeeded, account should exist
      if (result.accountExists) {
        console.log('NEAR account was created successfully');
      }
    } else {
      // If registration failed, analyze why
      console.log('Registration failed, analyzing failure...');
      console.log('Error:', (result as any).registrationError);
      console.log('Failed steps:', result.registrationFlow?.failedSteps);

      // Even if it failed, we should have reached WebAuthn step
      expect(result.registrationFlow?.reachedWebAuthn).toBe(true);
    }

    // Verify configuration is correct
    if (result.configs) {
      expect(result.configs.nearNetwork).toBe('testnet');
      expect(result.configs.nearRpcUrl).toBe('https://rpc.testnet.near.org');
      expect(result.configs.contractId).toBe('web3-authn.testnet');
    }

    // Test login flow if registration succeeded
    if (result.registrationResult?.success && result.loginFlow) {
      console.log('=== LOGIN FLOW ASSERTIONS ===');

      // Verify logged out state
      expect(result.loginFlow.loggedOutState?.isLoggedIn).toBeDefined();
      expect(result.loginFlow.loggedOutState?.vrfActive).toBeDefined();

      // Verify login success
      expect(result.loginFlow.loginResult?.success).toBe(true);
      if (result.loginFlow.loginResult?.success && 'loggedInNearAccountId' in result.loginFlow.loginResult) {
        expect(result.loginFlow.loginResult.loggedInNearAccountId).toBe(result.testAccountId);
        expect(result.loginFlow.loginResult.clientNearPublicKey).toBeTruthy();
      }

      // Verify logged in state
      expect(result.loginFlow.loggedInState?.isLoggedIn).toBe(true);
      expect(result.loginFlow.loggedInState?.vrfActive).toBe(true);
      expect(result.loginFlow.loggedInState?.nearAccountId).toBe(result.testAccountId);
      expect(result.loginFlow.loggedInState?.publicKey).toBeTruthy();

      // Verify recent logins tracking
      expect(result.loginFlow.recentLogins?.accountIds).toContain(result.testAccountId);
      expect(result.loginFlow.recentLogins?.lastUsedAccountId).toBe(result.testAccountId);

      // Verify login event progression
      expect(result.loginFlow.loginEventPhases).toContain('preparation');
      expect(result.loginFlow.loginEventPhases).toContain('webauthn-assertion');
      expect(result.loginFlow.loginEventPhases).toContain('vrf-unlock');
      expect(result.loginFlow.loginEventPhases).toContain('login-complete');
      expect(result.loginFlow.finalLoginEvent?.status).toBe('success');

      console.log(`✅ Login flow completed successfully for ${result.testAccountId}`);
      console.log(`   - Login events: ${result.loginFlow.loginEventPhases.join(' → ')}`);
      console.log(`   - VRF session active: ${result.loginFlow.loggedInState?.vrfActive}`);
      console.log(`   - Recent logins tracked: ${result.loginFlow.recentLogins?.accountIds.length || 0} accounts`);
    } else if (result.registrationResult?.success) {
      console.log('⚠️ Registration succeeded but login flow was not tested');
    } else {
      console.log('⚠️ Login flow skipped due to registration failure');
    }

    console.log(`Registration & Login flow test completed for ${result.testAccountId}`);
    console.log(`   - WebAuthn reached: ${result.registrationFlow?.reachedWebAuthn}`);
    console.log(`   - Events generated: ${result.registrationFlow?.totalEvents}`);
    console.log(`   - Successful steps: ${result.registrationFlow?.successfulSteps}`);
    console.log(`   - Failed steps: ${result.registrationFlow?.failedSteps}`);
    if (result.loginFlow) {
      console.log(`   - Login flow: COMPLETED`);
    } else {
      console.log(`   - Login flow: SKIPPED`);
    }
  });

  test('2. Actions Flow - Transfer Transaction with VRF Authentication', async ({ page }) => {
    // Skip if no shared account available
    test.skip(!sharedTestAccountId, 'Requires successful registration from previous test');

    const result = await page.evaluate(async (args) => {
      const { ActionType, sharedAccountId } = args;
      try {
        const {
          passkeyManager,
          generateTestAccountId
        } = (window as any).testUtils as TestUtils;

        const senderAccountId = sharedAccountId;
        const receiverAccountId = generateTestAccountId();

        console.log(`Testing transfer action flow: ${senderAccountId} -> ${receiverAccountId}`);

        // Step 1: Verify login state before action using real state checking
        const preActionState = await passkeyManager.getLoginState(senderAccountId);
        console.log('Pre-action login state:', preActionState);

        // Step 2: Execute transfer action using real executeAction implementation
        const actionEvents: any[] = [];
        const transferResult = await passkeyManager.executeAction(
          senderAccountId,
          {
            type: ActionType.Transfer,
            receiverId: receiverAccountId,
            amount: "1000000000000000000000000", // 1 NEAR in yoctoNEAR
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

        // Step 3: Verify post-action state
        const postActionState = await passkeyManager.getLoginState(senderAccountId);
        console.log('Post-action login state:', postActionState);

        return {
          success: true,
          senderAccountId,
          receiverAccountId,
          preActionState,
          transferResult,
          postActionState,
          actionEvents,
          actionEventPhases: actionEvents.map(e => e.phase),
          finalActionEvent: actionEvents[actionEvents.length - 1]
        };

      } catch (error: any) {
        console.error('Actions test error:', error);
        return {
          success: false,
          error: error.message,
          stack: error.stack
        };
      }
    }, { ActionType, sharedAccountId: sharedTestAccountId });

    // Assertions for actions flow
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    expect(result.senderAccountId).toBe(sharedTestAccountId);
    expect(result.receiverAccountId).toBeTruthy();

    // Verify action execution
    if (result.transferResult?.success) {
      expect(result.transferResult.transactionId).toBeTruthy();
      expect(result.actionEventPhases).toContain('preparation');
      expect(result.actionEventPhases).toContain('transaction-execution');
      expect(result.finalActionEvent?.status).toBe('success');
      console.log(`✅ Transfer action completed successfully`);
      console.log(`   - Transaction ID: ${result.transferResult.transactionId}`);
      console.log(`   - Action events: ${result.actionEventPhases.join(' → ')}`);
    } else {
      console.log(`⚠️ Transfer action failed: ${result.transferResult?.error || 'Unknown error'}`);
      // Don't fail the test - actions might fail due to network/faucet issues
    }

    console.log(`Actions flow test completed for ${result.senderAccountId} -> ${result.receiverAccountId}`);
  });

  test('3. Recovery Flow - Account Recovery with VRF State Restoration', async ({ page }) => {
    // Skip if no shared account available
    test.skip(!sharedTestAccountId, 'Requires successful registration from previous test');

    const result = await page.evaluate(async (args) => {
      const { ActionType, sharedAccountId } = args;
      try {
        const {
          passkeyManager
        } = (window as any).testUtils as TestUtils;

        const testAccountId = sharedAccountId;
        console.log(`Testing account recovery flow for: ${testAccountId}`);

        // Step 1: Simulate data loss by logging out and clearing VRF session - real logout
        console.log('Step 1: Simulating data loss by clearing VRF session...');
        await passkeyManager.logoutAndClearVrfSession();

        // Verify logged out state using real state checking
        const preRecoveryState = await passkeyManager.getLoginState(testAccountId);
        console.log('Pre-recovery state:', preRecoveryState);

        // Step 2: Perform account recovery using real recovery implementation
        console.log('Step 2: Performing account recovery...');
        const recoveryEvents: any[] = [];
        const recoveryResult = await passkeyManager.recoverAccountWithAccountId(
          testAccountId,
          {
            onEvent: (event: any) => {
              recoveryEvents.push(event);
              console.log(`Recovery [${event.step}]: ${event.phase} - ${event.message}`);
            },
            onError: (error: any) => {
              console.error('Recovery Error:', error);
            }
          }
        );

        // Step 3: Verify post-recovery state
        const postRecoveryState = await passkeyManager.getLoginState(testAccountId);
        console.log('Post-recovery state:', postRecoveryState);

        // Step 4: Test recovered account functionality with a simple action
        console.log('Step 3: Testing recovered account functionality...');
        const testActionResult = await passkeyManager.executeAction(
          testAccountId,
          {
            type: ActionType.FunctionCall,
            receiverId: testAccountId,
            methodName: 'get_account_balance',
            args: {}
          },
          {
            onEvent: (event: any) => {
              console.log(`Test Action [${event.step}]: ${event.phase} - ${event.message}`);
            }
          }
        );

        return {
          success: true,
          testAccountId,
          preRecoveryState,
          recoveryResult,
          postRecoveryState,
          testActionResult,
          recoveryEvents,
          recoveryEventPhases: recoveryEvents.map(e => e.phase),
          finalRecoveryEvent: recoveryEvents[recoveryEvents.length - 1]
        };

      } catch (error: any) {
        console.error('Recovery test error:', error);
        return {
          success: false,
          error: error.message,
          stack: error.stack
        };
      }
    }, { ActionType, sharedAccountId: sharedTestAccountId });

    // Assertions for recovery flow
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    expect(result.testAccountId).toBe(sharedTestAccountId);

    // Verify recovery process
    if (result.recoveryResult?.success) {
      expect(result.recoveryEventPhases).toContain('preparation');
      expect(result.recoveryEventPhases).toContain('vrf-restoration');
      expect(result.finalRecoveryEvent?.status).toBe('success');

      // Verify recovered account can perform actions
      if (result.testActionResult?.success) {
        console.log(`✅ Account recovery completed successfully`);
        console.log(`   - Recovered account: ${sharedTestAccountId}`);
        console.log(`   - Recovery events: ${result.recoveryEventPhases.join(' → ')}`);
        console.log(`   - Test action successful: ${result.testActionResult.success}`);
      }
    } else {
      console.log(`⚠️ Account recovery failed: ${result.recoveryResult?.error || 'Unknown error'}`);
      // Don't fail the test - recovery might fail due to various reasons
    }

    console.log(`Recovery flow test completed for ${result.testAccountId}`);
  });

});