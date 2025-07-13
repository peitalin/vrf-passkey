/**
 * Debug test to check PasskeyManager configs issue
 */

import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, type TestUtils } from '../utils/setup';

test.describe('Debug Configs Issue', () => {

  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('Debug PasskeyManager configs', async ({ page }) => {
    const result = await page.evaluate(async () => {
      try {
        console.log('=== DEBUG CONFIGS TEST ===');

        const testUtils = (window as any).testUtils;
        console.log('testUtils:', testUtils);

        if (!testUtils) {
          return { success: false, error: 'testUtils not available' };
        }

        const { passkeyManager } = testUtils as TestUtils;
        console.log('passkeyManager:', passkeyManager);

        if (!passkeyManager) {
          return { success: false, error: 'passkeyManager not available' };
        }

        console.log('passkeyManager.configs:', passkeyManager.configs);
        console.log('typeof passkeyManager.configs:', typeof passkeyManager.configs);
        console.log('passkeyManager keys:', Object.keys(passkeyManager));

        const configs = passkeyManager.configs;
        console.log('configs variable:', configs);
        console.log('configs serialized:', JSON.stringify(configs));

        return {
          success: true,
          configsExists: !!configs,
          configsType: typeof configs,
          configsKeys: configs ? Object.keys(configs) : null,
          configsSerialized: configs ? JSON.stringify(configs) : null
        };

      } catch (error: any) {
        console.error('Debug test error:', error);
        return {
          success: false,
          error: error.message,
          stack: error.stack
        };
      }
    });

    console.log('Debug result:', result);
    expect(result.success).toBe(true);

    if (result.success) {
      expect(result.configsExists).toBe(true);
      console.log('✅ Configs exist and are accessible');
    }
  });
});