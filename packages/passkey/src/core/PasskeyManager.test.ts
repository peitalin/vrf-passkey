import { PasskeyManager } from './PasskeyManager';
import type { PasskeyConfig } from './types';

describe('PasskeyManager', () => {
  const mockConfig: PasskeyConfig = {
    serverUrl: 'https://test-server.com',
    nearNetwork: 'testnet',
    relayerAccount: 'relayer.testnet',
    optimisticAuth: true,
    debugMode: true
  };

  let manager: PasskeyManager;

  beforeEach(() => {
    manager = new PasskeyManager(mockConfig);
  });

  describe('Configuration', () => {
    it('should initialize with provided config', () => {
      const config = manager.getConfig();
      expect(config).toEqual(mockConfig);
    });

    it('should update configuration', () => {
      const updates = { debugMode: false };
      manager.updateConfig(updates);

      const config = manager.getConfig();
      expect(config.debugMode).toBe(false);
      expect(config.serverUrl).toBe(mockConfig.serverUrl); // Should retain original values
    });
  });

  describe('User State', () => {
    it('should initially have no logged in user', async () => {
      const isLoggedIn = await manager.isLoggedIn();
      expect(isLoggedIn).toBe(false);

      const currentUser = await manager.getCurrentUser();
      expect(currentUser).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should throw TransactionError when signing without logged in user', async () => {
      const transactionParams = {
        receiverId: 'test.testnet',
        methodName: 'test_method',
        args: { test: 'value' }
      };

      await expect(manager.signTransaction(transactionParams))
        .rejects
        .toThrow('No user logged in');
    });
  });
});