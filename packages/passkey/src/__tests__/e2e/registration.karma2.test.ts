/**
 * E2E Registration Tests - Testing core registration logic with mocked dependencies
 */

import { expect } from 'chai';
import sinon from 'sinon';
import { TestEnvironment } from '../mocks';
import type { PasskeyManager } from '../../core/PasskeyManager';
import type { RegistrationResult, RegistrationSSEEvent } from '../../core/types/passkeyManager';
import { VrfWorkerManager } from '../../core/WebAuthnManager/vrfWorkerManager';
import { SignerWorkerManager } from '../../core/WebAuthnManager/signerWorkerManager';

describe('Registration E2E - Core Logic Testing', () => {
  let testEnv: TestEnvironment;
  let passkeyManager: PasskeyManager;
  let vrfWorkerStubs: sinon.SinonStub[];
  let signerWorkerStubs: sinon.SinonStub[];

  beforeEach(async () => {
    // Reset any existing stubs first
    if ((window.fetch as any).restore) {
      (window.fetch as any).restore();
    }
    testEnv = new TestEnvironment();
    passkeyManager = testEnv.createPasskeyManager();

    // Mock VRF Worker Manager methods
    vrfWorkerStubs = [
      sinon.stub(VrfWorkerManager.prototype, 'initialize').resolves(undefined),
      sinon.stub(VrfWorkerManager.prototype, 'getVrfWorkerStatus').resolves({
        active: false,
        nearAccountId: null,
        sessionDuration: undefined
      }),
      sinon.stub(VrfWorkerManager.prototype, 'clearVrfSession').resolves(undefined),
      sinon.stub(VrfWorkerManager.prototype, 'forceCleanupVrfManager').resolves(undefined),
      sinon.stub(VrfWorkerManager.prototype, 'generateVrfKeypair').resolves({
        vrfPublicKey: 'test-vrf-public-key',
        vrfChallenge: {
          outputAs32Bytes: () => new Uint8Array(32),
          vrfPublicKey: 'test-vrf-public-key',
          vrfOutput: 'test-vrf-output-base64',
          vrfProof: 'test-vrf-proof-base64',
          vrfInput: 'test-vrf-input',
          userId: 'test.testnet',
          rpId: 'localhost',
          blockHeight: 1000,
          blockHash: 'test-block-hash'
        }
      }),
      sinon.stub(VrfWorkerManager.prototype, 'encryptVrfKeypairWithCredentials').resolves({
        vrfPublicKey: 'test-vrf-public-key',
        encryptedVrfKeypair: { data: 'encrypted-vrf-data' }
      }),
      sinon.stub(VrfWorkerManager.prototype, 'unlockVRFKeypair').resolves({ success: true })
    ];

    // Mock Signer Worker Manager methods
    signerWorkerStubs = [
      sinon.stub(SignerWorkerManager.prototype, 'deriveNearKeypairAndEncrypt').resolves({
        success: true,
        nearAccountId: 'test.testnet',
        publicKey: 'ed25519:TestPublicKey123'
      }),
      sinon.stub(SignerWorkerManager.prototype, 'checkCanRegisterUser').resolves({
        success: true,
        verified: true
      }),
      sinon.stub(SignerWorkerManager.prototype, 'signVerifyAndRegisterUser').resolves({
        verified: true,
        signedTransactionBorsh: [1, 2, 3, 4, 5]
      }),
      sinon.stub(SignerWorkerManager.prototype, 'extractCosePublicKey').resolves(new Uint8Array(64))
    ];

    // Mock WebAuthn to simulate successful passkey creation
    sinon.stub(navigator.credentials, 'create').resolves({
      id: 'test-credential-id',
      rawId: new ArrayBuffer(32),
      type: 'public-key',
      getClientExtensionResults: () => ({
        prf: { results: { first: new ArrayBuffer(32) } }
      }),
      response: {
        attestationObject: new ArrayBuffer(256),
        clientDataJSON: new ArrayBuffer(128),
        getTransports: () => ['internal']
      }
    } as any);

    // Mock NEAR RPC provider methods directly
    const mockNearRpcProvider = {
      viewAccessKey: sinon.stub().resolves({
        nonce: 0,
        permission: { FunctionCall: { allowance: '1000000000000000000000000' } },
        block_height: 1000,
        block_hash: 'test-hash'
      }),
      viewBlock: sinon.stub().resolves({
        header: { height: 1000, hash: 'test-hash' }
      }),
      viewAccount: sinon.stub().resolves({
        amount: '1000000000000000000000000',
        block_height: 1000,
        block_hash: 'test-hash'
      })
    };

    // Replace the RPC provider in PasskeyManager
    (passkeyManager as any).nearRpcProvider = mockNearRpcProvider;

    // Mock faucet service calls
    const fetchStub = sinon.stub(window, 'fetch');
    fetchStub.callsFake(async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      // Handle faucet service calls
      if (url.includes('helper.testnet.near.org')) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }

      // Handle contract verification calls (RPC)
      if (url.includes('rpc.testnet.near.org')) {
        return new Response(JSON.stringify({
          result: {
            transaction_outcome: { id: 'test-tx-hash' },
            status: { SuccessValue: '' }
          }
        }), { status: 200 });
      }

      return new Response(JSON.stringify({}), { status: 200 });
    });
  });

  afterEach(() => {
    sinon.restore();
    testEnv.resetAll();
  });

  it('should complete registration flow and validate core logic', async () => {
    const nearAccountId = 'test-registration.testnet';
    const events: RegistrationSSEEvent[] = [];

    // Execute registration
    const result: RegistrationResult = await passkeyManager.registerPasskey(nearAccountId, {
      onEvent: (event) => {
        events.push(event);
        console.log(`Registration: ${event.phase} - ${event.message}`);
      },
      onError: (error) => {
        console.error('Registration error:', error.message);
      }
    });

    // Verify registration succeeded
    expect(result.success).to.be.true;
    expect(result.nearAccountId).to.equal(nearAccountId);
    expect(result.clientNearPublicKey).to.match(/^ed25519:/);
    expect(result.transactionId).to.not.be.undefined;

    // Verify VRF registration component
    expect(result.vrfRegistration).to.not.be.undefined;
    expect(result.vrfRegistration?.success).to.be.true;
    expect(result.vrfRegistration?.vrfPublicKey).to.not.be.undefined;
    expect(result.vrfRegistration?.contractVerified).to.be.true;

    // Verify core registration phases were executed
    const phases = events.map(e => e.phase);
    expect(phases).to.include('webauthn-verification');
    expect(phases).to.include('user-ready');
    expect(phases).to.include('access-key-addition');
    expect(phases).to.include('database-storage');
    expect(phases).to.include('registration-complete');

    // Verify final success event
    const finalEvent = events.find(e => e.phase === 'registration-complete');
    expect(finalEvent?.status).to.equal('success');

    // Verify data storage worked
    const loginState = await passkeyManager.getLoginState(nearAccountId);
    expect(loginState.userData).to.not.be.undefined;
    expect(loginState.nearAccountId).to.equal(nearAccountId);
  }).timeout(15000);

  it('should validate registration inputs properly', async () => {
    // Test empty account ID
    let result = await passkeyManager.registerPasskey('', {
      onError: (error) => {
        expect(error.message).to.include('NEAR account ID is required');
      }
    });
    expect(result.success).to.be.false;

    // Test invalid account ID format
    result = await passkeyManager.registerPasskey('invalid-account-name', {
      onError: (error) => {
        expect(error.message).to.include('Invalid NEAR account ID');
      }
    });
    expect(result.success).to.be.false;
  });

  it('should handle WebAuthn ceremony failure', async () => {
    const nearAccountId = 'test-webauthn-fail.testnet';

    // Mock WebAuthn failure
    sinon.restore(); // Clear previous stubs
    sinon.stub(navigator.credentials, 'create').rejects(
      new Error('User canceled the operation')
    );

    const result = await passkeyManager.registerPasskey(nearAccountId, {
      onEvent: (event) => {
        if (event.phase === 'registration-error') {
          expect(event.error).to.include('User canceled');
        }
      },
      onError: (error) => {
        expect(error.message).to.include('User canceled');
      }
    });

    expect(result.success).to.be.false;
    expect(result.error).to.include('User canceled');
  });

  it('should handle faucet service failure', async () => {
    const nearAccountId = 'test-faucet-fail.testnet';

    // Mock faucet service failure
    sinon.restore(); // Clear previous stubs
    sinon.stub(window, 'fetch').callsFake(async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('helper.testnet.near.org')) {
        return new Response(JSON.stringify({ error: 'Faucet service unavailable' }), { status: 500 });
      }

      // Handle other calls normally
      return new Response(JSON.stringify({ result: {} }), { status: 200 });
    });

    const result = await passkeyManager.registerPasskey(nearAccountId, {
      onEvent: (event) => {
        console.log(`Event: ${event.phase} - ${event.message}`);
      },
      onError: (error) => {
        expect(error.message).to.include('Account creation failed');
      }
    });

    expect(result.success).to.be.false;
    expect(result.error).to.include('Account creation failed');
  }).timeout(15000);

  it('should handle network errors gracefully', async () => {
    const nearAccountId = 'test-network-error.testnet';

    // Mock network failure
    sinon.restore(); // Clear previous stubs
    sinon.stub(window, 'fetch').rejects(new Error('Network connection failed'));

    const result = await passkeyManager.registerPasskey(nearAccountId, {
      onError: (error) => {
        expect(error.message).to.include('Network connection failed');
      }
    });

    expect(result.success).to.be.false;
  });
});