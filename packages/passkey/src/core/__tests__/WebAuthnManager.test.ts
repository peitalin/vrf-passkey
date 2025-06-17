// Mock IndexDBManager first
const mockIndexDBManager = {
  storeWebAuthnUserData: jest.fn().mockResolvedValue(undefined),
  getWebAuthnUserData: jest.fn().mockResolvedValue(null),
  getAllUsers: jest.fn().mockResolvedValue([]),
  hasPasskeyCredential: jest.fn().mockResolvedValue(false),
  getLastUser: jest.fn().mockResolvedValue(null),
  getAuthenticatorsByUser: jest.fn().mockResolvedValue([]),
  storeAuthenticator: jest.fn().mockResolvedValue(undefined),
  syncAuthenticatorsFromContract: jest.fn().mockResolvedValue(undefined)
};

jest.mock('../IndexDBManager', () => ({
  indexDBManager: mockIndexDBManager
}));

// Import after mocking
import { WebAuthnManager } from '../WebAuthnManager';

// Mock WebAuthn credential
const mockCredential = {
  id: 'test-credential-id',
  rawId: new ArrayBuffer(32),
  type: 'public-key',
  authenticatorAttachment: 'platform',
  getClientExtensionResults: jest.fn(() => ({
    prf: {
      results: {
        first: new ArrayBuffer(32)
      }
    }
  })),
  response: {
    clientDataJSON: new ArrayBuffer(128),
    attestationObject: new ArrayBuffer(256),
    getTransports: jest.fn(() => ['internal']),
    getAuthenticatorData: jest.fn(() => new ArrayBuffer(64)),
    getPublicKey: jest.fn(() => new ArrayBuffer(64)),
    getPublicKeyAlgorithm: jest.fn(() => -7)
  }
};

// Setup global mocks
const mockNavigator = {
  credentials: {
    create: jest.fn(),
    get: jest.fn()
  }
};

const mockCrypto = {
  getRandomValues: jest.fn((array: Uint8Array) => {
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
    return array;
  }),
  randomUUID: jest.fn(() => 'test-uuid-123')
};

const mockFetch = jest.fn();

// Setup globals
Object.defineProperty(global, 'navigator', {
  value: mockNavigator,
  writable: true
});

Object.defineProperty(global, 'crypto', {
  value: mockCrypto,
  writable: true
});

Object.defineProperty(global, 'fetch', {
  value: mockFetch,
  writable: true
});

Object.defineProperty(global, 'window', {
  value: {
    location: { hostname: 'localhost' },
    isSecureContext: true
  },
  writable: true
});

describe('WebAuthnManager', () => {
  let webAuthnManager: WebAuthnManager;

  beforeEach(() => {
    webAuthnManager = new WebAuthnManager();

    // Reset all mocks
    jest.clearAllMocks();

    // Default mock implementations
    mockNavigator.credentials.create.mockResolvedValue(mockCredential);
    mockNavigator.credentials.get.mockResolvedValue(mockCredential);
    mockFetch.mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue({
        options: {
          challenge: 'dGVzdC1jaGFsbGVuZ2UtZGVmYXVsdC0zMi1ieXRlcw', // Valid base64url encoded challenge
          rp: { name: 'Test RP', id: 'localhost' },
          user: { id: 'test-user', name: 'test', displayName: 'Test User' },
          pubKeyCredParams: [{ alg: -7, type: 'public-key' }]
        }
      })
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor and Basic Methods', () => {
    it('should create a WebAuthnManager instance', () => {
      expect(webAuthnManager).toBeInstanceOf(WebAuthnManager);
    });

    it('should clear all challenges', () => {
      expect(() => webAuthnManager.clearAllChallenges()).not.toThrow();
    });
  });

  describe('User Data Operations', () => {
    const testNearAccountId = 'test.testnet';
    const testUserData = {
      nearAccountId: testNearAccountId,
      clientNearPublicKey: 'ed25519:test-key',
      lastUpdated: Date.now(),
      prfSupported: true,
      passkeyCredential: {
        id: 'test-credential',
        rawId: 'test-raw-id'
      }
    };

    it('should store user data', async () => {
      await webAuthnManager.storeUserData(testUserData);
      expect(mockIndexDBManager.storeWebAuthnUserData).toHaveBeenCalledWith(testUserData);
    });

    it('should retrieve user data', async () => {
      mockIndexDBManager.getWebAuthnUserData.mockResolvedValue(testUserData);

      const result = await webAuthnManager.getUserData(testNearAccountId);

      expect(result).toEqual(testUserData);
      expect(mockIndexDBManager.getWebAuthnUserData).toHaveBeenCalledWith(testNearAccountId);
    });

    it('should return null for non-existent user', async () => {
      mockIndexDBManager.getWebAuthnUserData.mockResolvedValue(null);

      const result = await webAuthnManager.getUserData('nonexistent.testnet');

      expect(result).toBeNull();
    });

    it('should get all user data', async () => {
      const mockUsers = [
        { nearAccountId: 'user1.testnet', clientNearPublicKey: 'key1', lastUpdated: 1, prfSupported: true },
        { nearAccountId: 'user2.testnet', clientNearPublicKey: 'key2', lastUpdated: 2, prfSupported: true }
      ];

      mockIndexDBManager.getAllUsers.mockResolvedValue(mockUsers);

      const result = await webAuthnManager.getAllUserData();

      expect(result).toHaveLength(2);
      expect(result[0].nearAccountId).toBe('user1.testnet');
    });
  });

  describe('Convenience Methods', () => {
    it('should check if passkey credential exists', async () => {
      mockIndexDBManager.hasPasskeyCredential.mockResolvedValue(true);

      const result = await webAuthnManager.hasPasskeyCredential('test.testnet');

      expect(result).toBe(true);
      expect(mockIndexDBManager.hasPasskeyCredential).toHaveBeenCalledWith('test.testnet');
    });

    it('should get last used NEAR account ID', async () => {
      const mockUser = { nearAccountId: 'last.testnet', lastUpdated: Date.now() };
      mockIndexDBManager.getLastUser.mockResolvedValue(mockUser);

      const result = await webAuthnManager.getLastUsedNearAccountId();

      expect(result).toBe('last.testnet');
    });

    it('should return null when no last user exists', async () => {
      mockIndexDBManager.getLastUser.mockResolvedValue(null);

      const result = await webAuthnManager.getLastUsedNearAccountId();

      expect(result).toBeNull();
    });
  });

  describe('Server Communication', () => {
    const testServerUrl = 'https://test-server.com';
    const testNearAccountId = 'test.testnet';

    it('should get registration options from server', async () => {
      const mockResponse = {
        options: {
          challenge: 'c2VydmVyLWNoYWxsZW5nZS0zMi1ieXRlcy1oZXJl', // Valid base64url encoded challenge
          rp: { name: 'Test RP', id: 'localhost' },
          user: { id: 'test-user-id', name: 'test', displayName: 'Test User' },
          pubKeyCredParams: [{ alg: -7, type: 'public-key' }]
        },
        commitmentId: 'test-commitment'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const result = await webAuthnManager.getRegistrationOptionsFromServer(
        testServerUrl,
        testNearAccountId
      );

      expect(result).toMatchObject({
        challengeId: expect.any(String),
        commitmentId: 'test-commitment'
      });
      expect(mockFetch).toHaveBeenCalledWith(
        `${testServerUrl}/generate-registration-options`,
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accountId: testNearAccountId })
        })
      );
    });

    it('should handle server errors gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: jest.fn().mockResolvedValue({ error: 'Internal server error' })
      });

      await expect(
        webAuthnManager.getRegistrationOptionsFromServer(testServerUrl, testNearAccountId)
      ).rejects.toThrow('Internal server error');
    });

    it('should get authentication options from server', async () => {
      const mockResponse = {
        challenge: 'YXV0aC1jaGFsbGVuZ2UtMzItYnl0ZXMtaGVyZQ', // Valid base64url encoded challenge
        rpId: 'localhost',
        timeout: 60000
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue(mockResponse)
      });

      const result = await webAuthnManager.getAuthenticationOptionsFromServer(
        testServerUrl,
        testNearAccountId
      );

      expect(result).toMatchObject({
        challengeId: expect.any(String),
        options: mockResponse
      });
    });
  });

  describe('WebAuthn Registration with PRF', () => {
    const testServerUrl = 'https://test-server.com';
    const testNearAccountId = 'test.testnet';

    it('should register with PRF and server URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({
          options: {
            challenge: 'dGVzdC1jaGFsbGVuZ2UtMzItYnl0ZXMtaGVyZQ', // Valid base64url encoded challenge
            rp: { name: 'Test RP', id: 'localhost' },
            user: { id: 'test-user', name: 'test', displayName: 'Test User' },
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }]
          },
          commitmentId: 'test-commitment'
        })
      });

      const result = await webAuthnManager.registerWithPrfAndUrl(
        testServerUrl,
        testNearAccountId
      );

      expect(result.credential).toBeDefined();
      expect(result.prfEnabled).toBe(true);
      expect(result.commitmentId).toBe('test-commitment');
      expect(mockNavigator.credentials.create).toHaveBeenCalled();
    });

    it('should throw error when no server URL provided', async () => {
      await expect(
        webAuthnManager.registerWithPrfAndUrl(undefined, testNearAccountId)
      ).rejects.toThrow('Server URL is required for server-based registration');
    });
  });

  describe('WebAuthn Authentication with PRF', () => {
    const testNearAccountId = 'test.testnet';

    it('should authenticate with PRF (serverless mode)', async () => {
      const result = await webAuthnManager.authenticateWithPrf(testNearAccountId);

      expect(result.credential).toBeDefined();
      expect(result.prfOutput).toBeDefined();
      expect(mockNavigator.credentials.get).toHaveBeenCalled();
    });

    it('should authenticate with PRF and server URL', async () => {
      const testServerUrl = 'https://test-server.com';

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValue({
          challenge: 'YXV0aC1jaGFsbGVuZ2UtczItYnl0ZXMtbW9yZQ', // Valid base64url encoded challenge
          rpId: 'localhost'
        })
      });

      const result = await webAuthnManager.authenticateWithPrfAndUrl(
        testServerUrl,
        testNearAccountId
      );

      expect(result.credential).toBeDefined();
      expect(result.prfOutput).toBeDefined();
    });

    it('should throw error when authentication fails', async () => {
      mockNavigator.credentials.get.mockResolvedValue(null);

      await expect(
        webAuthnManager.authenticateWithPrf(testNearAccountId)
      ).rejects.toThrow('WebAuthn authentication failed');
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(
        webAuthnManager.getRegistrationOptionsFromServer('https://test.com', 'test.testnet')
      ).rejects.toThrow();
    });

    it('should handle IndexDB errors gracefully', async () => {
      mockIndexDBManager.storeWebAuthnUserData.mockRejectedValue(new Error('Storage error'));

      await expect(
        webAuthnManager.storeUserData({
          nearAccountId: 'test.testnet',
          lastUpdated: Date.now()
        })
      ).rejects.toThrow('Storage error');
    });
  });

  describe('Edge Cases', () => {
    it('should handle malformed server responses', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockRejectedValue(new Error('Invalid JSON'))
      });

      await expect(
        webAuthnManager.getRegistrationOptionsFromServer('https://test.com', 'test.testnet')
      ).rejects.toThrow();
    });

    it('should handle missing PRF support gracefully', async () => {
      const credentialWithoutPrf = {
        ...mockCredential,
        getClientExtensionResults: jest.fn(() => ({}))
      };

      mockNavigator.credentials.get.mockResolvedValue(credentialWithoutPrf);

      const result = await webAuthnManager.authenticateWithPrf('test.testnet');

      expect(result.credential).toBeDefined();
      expect(result.prfOutput).toBeUndefined();
    });
  });
});