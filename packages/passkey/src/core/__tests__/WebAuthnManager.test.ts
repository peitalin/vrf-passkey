/// <reference types="jest" />

import type { Provider } from '@near-js/providers';
import { base64UrlDecode } from '../../utils/encoders';
import { VRFChallenge } from '../types/webauthn';
import { PasskeyManagerConfigs } from '../types/passkeyManager';

// Mock IndexedDBManager first
const mockIndexedDBManager = {
  storeWebAuthnUserData: jest.fn().mockResolvedValue(undefined),
  getWebAuthnUserData: jest.fn().mockResolvedValue(null),
  getAllUsers: jest.fn().mockResolvedValue([]),
  hasPasskeyCredential: jest.fn().mockResolvedValue(false),
  getLastUser: jest.fn().mockResolvedValue(null),
  getAuthenticatorsByUser: jest.fn().mockResolvedValue([]),
  storeAuthenticator: jest.fn().mockResolvedValue(undefined),
  syncAuthenticatorsFromContract: jest.fn().mockResolvedValue(undefined)
};


jest.mock('../IndexedDBManager', () => ({
  IndexedDBManager: mockIndexedDBManager
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
    webAuthnManager = new WebAuthnManager({
      contractId: 'test-contract.testnet',
      relayerAccount: 'test.testnet',
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://rpc.testnet.near.org',
    } as PasskeyManagerConfigs);

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
      expect(mockIndexedDBManager.storeWebAuthnUserData).toHaveBeenCalledWith(testUserData);
    });

    it('should retrieve user data', async () => {
      mockIndexedDBManager.getWebAuthnUserData.mockResolvedValue(testUserData);

      const result = await webAuthnManager.getUser(testNearAccountId);

      expect(result).toEqual(testUserData);
      expect(mockIndexedDBManager.getWebAuthnUserData).toHaveBeenCalledWith(testNearAccountId);
    });

    it('should return null for non-existent user', async () => {
      mockIndexedDBManager.getWebAuthnUserData.mockResolvedValue(null);

      const result = await webAuthnManager.getUser('nonexistent.testnet');

      expect(result).toBeNull();
    });

    it('should get all user data', async () => {
      const mockUsers = [
        { nearAccountId: 'user1.testnet', clientNearPublicKey: 'key1', lastUpdated: 1, prfSupported: true },
        { nearAccountId: 'user2.testnet', clientNearPublicKey: 'key2', lastUpdated: 2, prfSupported: true }
      ];

      mockIndexedDBManager.getAllUsers.mockResolvedValue(mockUsers);

      const result = await webAuthnManager.getAllUserData();

      expect(result).toHaveLength(2);
      expect(result[0].nearAccountId).toBe('user1.testnet');
    });
  });

  describe('Convenience Methods', () => {
    it('should check if passkey credential exists', async () => {
      mockIndexedDBManager.hasPasskeyCredential.mockResolvedValue(true);

      const result = await webAuthnManager.hasPasskeyCredential('test.testnet');

      expect(result).toBe(true);
      expect(mockIndexedDBManager.hasPasskeyCredential).toHaveBeenCalledWith('test.testnet');
    });

    it('should get last used NEAR account ID', async () => {
      const mockUser = { nearAccountId: 'last.testnet', lastUpdated: Date.now() };
      mockIndexedDBManager.getLastUser.mockResolvedValue(mockUser);

      const result = await webAuthnManager.getLastUsedNearAccountId();

      expect(result).toBe('last.testnet');
    });

    it('should return null when no last user exists', async () => {
      mockIndexedDBManager.getLastUser.mockResolvedValue(null);

      const result = await webAuthnManager.getLastUsedNearAccountId();

      expect(result).toBeNull();
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

    it('should verify VRF registration with contract', async () => {
      const mockNearRpcProvider: Partial<Provider> = {
        viewBlock: jest.fn().mockResolvedValue({
          header: { height: 1000, hash: 'test-hash' }
        })
      };

      const mockVrfChallengeData = new VRFChallenge({
        vrfInput: 'test-vrf-input',
        vrfOutput: 'test-vrf-output',
        vrfProof: 'test-vrf-proof',
        vrfPublicKey: 'test-vrf-public-key',
        userId: 'test.testnet',
        rpId: 'localhost',
        blockHeight: 1000,
        blockHash: 'test-hash'
      });

      const mockRegistrationResult = {
        success: true,
        verified: true,
        transactionId: 'test-reg-tx-id'
      };

      // Mock the contract calls method
      const mockVerifyVrfRegistration = jest.fn().mockResolvedValue(mockRegistrationResult);
      (webAuthnManager as any).contractCalls.verifyVrfRegistration = mockVerifyVrfRegistration;

      const result = await webAuthnManager.signVerifyAndRegisterUser({
        contractId: 'test-contract.testnet',
        vrfChallenge: mockVrfChallengeData,
        webauthnCredential: mockCredential as any,
        signerAccountId: 'test.testnet',
        nearAccountId: 'test.testnet',
        publicKeyStr: 'ed25519:test-key',
        nearRpcProvider: mockNearRpcProvider as Provider,
        onEvent: jest.fn()
      });

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