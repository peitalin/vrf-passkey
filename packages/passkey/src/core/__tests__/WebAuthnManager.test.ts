/// <reference types="jest" />

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

      const result = await webAuthnManager.authenticateWithPrf(
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

  describe('VRF Operations', () => {
    const testPrfOutput = new ArrayBuffer(32);
    const mockVrfResult = {
      vrfPublicKey: 'test-vrf-public-key',
      encryptedVrfKeypair: {
        encrypted_vrf_data_b64u: 'test-encrypted-data',
        aes_gcm_nonce_b64u: 'test-nonce'
      }
    };

    it('should generate VRF keypair with PRF', async () => {
      // Mock the VRFManager method
      const mockGenerateVrfKeypairWithPrf = jest.fn().mockResolvedValue(mockVrfResult);
      (webAuthnManager as any).vrfManager.generateVrfKeypairWithPrf = mockGenerateVrfKeypairWithPrf;

      const result = await webAuthnManager.generateVrfKeypairWithPrf(testPrfOutput, false);

      expect(result).toEqual(mockVrfResult);
      expect(mockGenerateVrfKeypairWithPrf).toHaveBeenCalledWith(testPrfOutput, false, undefined);
    });

    it('should generate VRF keypair with PRF and challenge data in one call', async () => {
      const mockVrfResultWithChallenge = {
        ...mockVrfResult,
        vrfChallengeData: {
          vrfInput: 'test-vrf-input',
          vrfOutput: 'test-vrf-output',
          vrfProof: 'test-vrf-proof',
          vrfPublicKey: 'test-vrf-public-key',
          rpId: 'localhost'
        }
      };

      const vrfInputParams = {
        userId: 'test.testnet',
        rpId: 'localhost',
        sessionId: 'session-123',
        blockHeight: 1000,
        blockHashBytes: [1, 2, 3, 4],
        timestamp: Date.now()
      };

      // Mock the VRFManager method
      const mockGenerateVrfKeypairWithPrf = jest.fn().mockResolvedValue(mockVrfResultWithChallenge);
      (webAuthnManager as any).vrfManager.generateVrfKeypairWithPrf = mockGenerateVrfKeypairWithPrf;

      const result = await webAuthnManager.generateVrfKeypairWithPrf(testPrfOutput, true, vrfInputParams);

      expect(result).toEqual(mockVrfResultWithChallenge);
      expect(result.vrfChallengeData).toBeDefined();
      expect(mockGenerateVrfKeypairWithPrf).toHaveBeenCalledWith(testPrfOutput, true, vrfInputParams);
    });

    it('should generate VRF challenge with PRF', async () => {
      const mockVrfChallengeResult = {
        vrfInput: 'test-vrf-input',
        vrfOutput: 'test-vrf-output',
        vrfProof: 'test-vrf-proof',
        vrfPublicKey: 'test-vrf-public-key',
        rpId: 'localhost'
      };

      // Mock the VRFManager method
      const mockGenerateVrfChallengeWithPrf = jest.fn().mockResolvedValue(mockVrfChallengeResult);
      (webAuthnManager as any).vrfManager.generateVrfChallengeWithPrf = mockGenerateVrfChallengeWithPrf;

      const result = await webAuthnManager.generateVrfChallengeWithPrf(
        testPrfOutput,
        'encrypted-vrf-data',
        'test-nonce',
        'test.testnet',
        'localhost',
        'session-123',
        1000,
        [1, 2, 3, 4],
        Date.now()
      );

      expect(result).toEqual(mockVrfChallengeResult);
      expect(mockGenerateVrfChallengeWithPrf).toHaveBeenCalledWith(
        testPrfOutput,
        'encrypted-vrf-data',
        'test-nonce',
        'test.testnet',
        'localhost',
        'session-123',
        1000,
        [1, 2, 3, 4],
        expect.any(Number)
      );
    });

    it('should verify VRF authentication with contract', async () => {
      const mockNearRpcProvider = {
        viewBlock: jest.fn().mockResolvedValue({
          header: { height: 1000, hash: 'test-hash' }
        })
      };

      const mockVrfChallengeData = {
        vrfInput: 'test-vrf-input',
        vrfOutput: 'test-vrf-output',
        vrfProof: 'test-vrf-proof',
        vrfPublicKey: 'test-vrf-public-key',
        rpId: 'localhost',
        blockHeight: 1000,
        blockHash: 'test-hash'
      };

      const mockVerificationResult = {
        success: true,
        verified: true,
        transactionId: 'test-tx-id'
      };

      // Mock the contract calls method
      const mockVerifyVrfAuthentication = jest.fn().mockResolvedValue(mockVerificationResult);
      (webAuthnManager as any).contractCalls.verifyVrfAuthentication = mockVerifyVrfAuthentication;

      const result = await webAuthnManager.verifyVrfAuthentication(
        mockNearRpcProvider as any,
        'test-contract.testnet',
        mockVrfChallengeData,
        mockCredential as any,
        'test.testnet'
      );

      expect(result).toEqual(mockVerificationResult);
      expect(mockVerifyVrfAuthentication).toHaveBeenCalledWith(
        mockNearRpcProvider,
        'test-contract.testnet',
        mockVrfChallengeData,
        mockCredential,
        'test.testnet',
        undefined  // PRF output parameter (optional)
      );
    });

    it('should verify VRF registration with contract', async () => {
      const mockNearRpcProvider = {
        viewBlock: jest.fn().mockResolvedValue({
          header: { height: 1000, hash: 'test-hash' }
        })
      };

      const mockVrfChallengeData = {
        vrfInput: 'test-vrf-input',
        vrfOutput: 'test-vrf-output',
        vrfProof: 'test-vrf-proof',
        vrfPublicKey: 'test-vrf-public-key',
        rpId: 'localhost',
        blockHeight: 1000,
        blockHash: 'test-hash'
      };

      const mockRegistrationResult = {
        success: true,
        verified: true,
        transactionId: 'test-reg-tx-id'
      };

      // Mock the contract calls method
      const mockVerifyVrfRegistration = jest.fn().mockResolvedValue(mockRegistrationResult);
      (webAuthnManager as any).contractCalls.verifyVrfRegistration = mockVerifyVrfRegistration;

      const result = await webAuthnManager.verifyVrfRegistration(
        mockNearRpcProvider as any,
        'test-contract.testnet',
        mockVrfChallengeData,
        mockCredential as any,
        'test.testnet'
      );

      expect(result).toEqual(mockRegistrationResult);
      expect(mockVerifyVrfRegistration).toHaveBeenCalledWith(
        mockNearRpcProvider,
        'test-contract.testnet',
        mockVrfChallengeData,
        mockCredential,
        'test.testnet',
        undefined
      );
    });
  });
});