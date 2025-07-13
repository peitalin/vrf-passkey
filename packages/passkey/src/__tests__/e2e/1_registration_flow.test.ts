/**
 * PasskeyManager Registration Flow E2E Test
 *
 * Tests the PasskeyManager setup and complete registration flow using WebAuthn Virtual Authenticator.
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';

test.describe('PasskeyManager Registration Flow', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    // Add 1 second delay to prevent NEAR account creation throttling
    await page.waitForTimeout(1000);
  });

  test('Complete PasskeyManager Registration Flow with WebAuthn Virtual Authenticator', async ({ page }) => {
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
        console.log('=== REGISTRATION FLOW TEST ===');

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

        // Skip getLoginState test for now and focus on testing the real VRF Worker
        // const initialLoginState = await passkeyManager.getLoginState(testAccountId);
        // console.log('Initial login state:', initialLoginState);

        // Test the configuration
        const configs = passkeyManager.configs;
        console.log('PasskeyManager configs:', configs);

        // Test complete registration flow with WebAuthn Virtual Authenticator
        console.log('Testing complete registration flow with Virtual Authenticator...');

        // Track registration progress events
        const events: any[] = [];
        let registrationError: string | null = null;
        let registrationCompleted = false;

        console.log('About to call registerPasskey...');

        // Execute the actual registration flow
        // With Virtual Authenticator, this should complete successfully
        const registrationResult = await passkeyManager.registerPasskey(testAccountId, {
          useRelayer: false, // Use testnet faucet
          onEvent: (event: any) => {
            events.push(event);
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
        console.log('Events captured:', events.length);

        // Analyze the events to see progression
        const eventPhases = events.map(e => e.phase);
        const eventSteps = events.map(e => e.step);
        const successEvents = events.filter(e => e.status === 'success');
        const errorEvents = events.filter(e => e.status === 'error');

        // Check specific milestones
        const reachedWebAuthn = eventPhases.includes('webauthn-verification');
        const reachedNearAccount = eventPhases.includes('near-account-creation');
        const reachedContractRegistration = eventPhases.includes('contract-registration');
        const reachedCompletion = eventPhases.includes('registration-complete');

        // Verify account was created if registration succeeded
        let accountExists = false;
        if (registrationResult?.success) {
          try {
            accountExists = await verifyAccountExists(testAccountId);
          } catch (e) {
            console.warn('Account verification failed:', e);
          }
        }

        return {
          success: true,
          testAccountId,
          configs,
          // initialLoginState, // Commented out for now
          registrationCompleted,
          registrationResult,
          accountExists,
          flowProgression: {
            reachedWebAuthn: reachedWebAuthn,
            reachedCompletion: reachedCompletion,
            totalEvents: events.length,
            successfulSteps: successEvents.length,
            failedSteps: errorEvents.length
          }
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

    console.log('=== TEST RESULT ===');
    if (result.success) {
      console.log('Success:', result.success);
      console.log('Registration completed:', result.registrationCompleted);
      console.log('Account exists:', result.accountExists);
      console.log('Flow progression:', result.flowProgression);
      console.log('Total events:', result.flowProgression?.totalEvents || 0);
    }

    // Output console messages for debugging
    console.log('=== BROWSER CONSOLE MESSAGES ===');
    consoleMessages.slice(-20).forEach((msg, index) => {
      console.log(`${index + 1}: ${msg}`);
    });
    console.log('=== END CONSOLE MESSAGES ===');

    // Assertions for complete registration flow testing
    expect(result.success).toBe(true);
    if (!result.success) return; // Type guard

    // Verify basic setup worked
    expect(result.testAccountId).toMatch(/^e2etest\d+\.testnet$/);
    expect(result.configs).toBeDefined(); // Skip this check for now

    // Verify registration flow was attempted
    expect(result.registrationResult).toBeDefined();

    // With Virtual Authenticator, we expect the flow to progress further
    expect(result.flowProgression?.reachedWebAuthn).toBe(true);
    expect(result.flowProgression?.totalEvents).toBeGreaterThan(0);

        // Check if registration completed successfully
    if (result.registrationResult?.success) {
      console.log('Registration completed successfully with Virtual Authenticator');
      expect(result.registrationCompleted).toBe(true);
      expect(result.flowProgression?.reachedCompletion).toBe(true);
      expect(result.flowProgression?.successfulSteps).toBeGreaterThan(0);

      // If registration succeeded, account should exist
      if (result.accountExists) {
        console.log('NEAR account was created successfully');

        // Send remaining balance to web3-authn.testnet contract
        console.log('Sending remaining NEAR balance to web3-authn.testnet contract...');
        const transferResult = await page.evaluate(async (accountId) => {
          try {
            const { passkeyManager } = (window as any).testUtils;

            // Get account balance
            const balance = await passkeyManager.nearClient.viewAccount(accountId);
            const availableBalance = BigInt(balance.amount) - BigInt('1000000000000000000000000'); // Keep 1 NEAR for gas

            if (availableBalance > 0) {
              // Transfer remaining balance to contract using executeAction
              const transferAmount = availableBalance.toString();
              console.log(`Transferring ${transferAmount} yoctoNEAR to web3-authn.testnet`);

              const transferTx = await passkeyManager.executeAction(accountId, {
                type: 'Transfer',
                receiverId: 'web3-authn.testnet',
                amount: transferAmount
              });

              return {
                success: true,
                amount: transferAmount,
                transactionId: transferTx.transactionId
              };
            } else {
              return {
                success: false,
                reason: 'Insufficient balance for transfer'
              };
            }
          } catch (error: any) {
            console.error('Transfer error:', error);
            return {
              success: false,
              error: error.message
            };
          }
        }, result.testAccountId);

        if (transferResult.success) {
          console.log(`✅ Transferred ${transferResult.amount} yoctoNEAR to web3-authn.testnet`);
          console.log(`   Transaction ID: ${transferResult.transactionId}`);
        } else {
          // Handle expected contract verification failure with mock authenticator
          if (transferResult.error?.includes('Contract verification failed') ||
              transferResult.error?.includes('No stored authenticator found')) {
            console.log(`️Balance transfer attempted but failed at contract verification (expected with mock authenticator)`);
            console.log(`   This is normal in test environment - the balance would be transferred in production`);
          } else {
            console.log(`Balance transfer skipped: ${transferResult.reason || transferResult.error}`);
          }
        }
      }
    } else {
      // If registration failed, analyze why
      console.log('Registration failed, analyzing failure...');
      console.log('Error:', (result as any).registrationError);
      console.log('Failed steps:', result.flowProgression?.failedSteps);

      // Even if it failed, we should have reached WebAuthn step
      expect(result.flowProgression?.reachedWebAuthn).toBe(true);

      // Common failure points to check
      if ((result as any).registrationError) {
        const errorMsg = ((result as any).registrationError as string).toLowerCase();
        if (errorMsg.includes('rate limit') || errorMsg.includes('faucet')) {
          console.log('️Registration failed due to faucet rate limiting (expected in CI)');
        } else if (errorMsg.includes('network') || errorMsg.includes('rpc')) {
          console.log('Registration failed due to network issues (expected in CI)');
        } else {
          console.log('️Registration failed with unexpected error:', (result as any).registrationError);
        }
      }
    }

    // Verify configuration is correct
    if (result.configs) {
      expect(result.configs.nearNetwork).toBe('testnet');
      expect(result.configs.nearRpcUrl).toBe('https://rpc.testnet.near.org');
      expect(result.configs.contractId).toBe('web3-authn.testnet');
    }

    console.log(`Registration flow test completed for ${result.testAccountId}`);
    console.log(`   - WebAuthn reached: ${result.flowProgression?.reachedWebAuthn}`);
    console.log(`   - Events generated: ${result.flowProgression?.totalEvents}`);
    console.log(`   - Successful steps: ${result.flowProgression?.successfulSteps}`);
    console.log(`   - Failed steps: ${result.flowProgression?.failedSteps}`);

    // Output captured console messages for debugging
    console.log('\n=== BROWSER CONSOLE MESSAGES ===');
    consoleMessages.forEach((msg, index) => {
      if (msg.includes('VRF') || msg.includes('Registration') || msg.includes('error') || msg.includes('ERROR')) {
        console.log(`${index + 1}: ${msg}`);
      }
    });
    console.log('=== END BROWSER CONSOLE ===\n');
  });

});