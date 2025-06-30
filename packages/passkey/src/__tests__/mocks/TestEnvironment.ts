/**
 * TestEnvironment - Minimal test environment for PasskeyManager
 *
 * Only mocks RPC calls - uses real SDK components for everything else
 */

import sinon from 'sinon';
import { MockNearRpc } from './MockNearRpc';
import { PasskeyManager } from '../../core/PasskeyManager';
import type { PasskeyManagerConfigs } from '../../core/types/passkeyManager';

export interface TestMetrics {
  startTime: number;
  endTime?: number;
  totalTime?: number;
  steps: Array<{
    name: string;
    startTime: number;
    endTime: number;
    duration: number;
  }>;
}

export class TestEnvironment {
  readonly mockNearRpc: MockNearRpc;
  private passkeyManager?: PasskeyManager;
  private currentMetrics?: TestMetrics;
  private stubs: sinon.SinonStub[] = [];

  constructor() {
    this.mockNearRpc = new MockNearRpc();
    this.setupGlobalMocks();
  }

  /**
   * Initialize PasskeyManager with test configuration
   */
  createPasskeyManager(customConfig?: Partial<PasskeyManagerConfigs>): PasskeyManager {
    const defaultConfig: PasskeyManagerConfigs = {
      nearNetwork: 'testnet',
      relayerAccount: 'web3-authn.testnet',
      contractId: 'web3-authn.testnet',
      nearRpcUrl: 'https://rpc.testnet.near.org'
    };

    const config = { ...defaultConfig, ...customConfig };
    this.passkeyManager = new PasskeyManager(config, this.mockNearRpc as any);

    return this.passkeyManager;
  }

  /**
   * Create testnet account for testing
   */
  async createTestAccount(nearAccountId: string): Promise<string> {
    const publicKey = 'ed25519:' + Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex');
    await this.mockNearRpc.createTestnetAccount(nearAccountId, publicKey);
    return publicKey;
  }

  /**
   * Start performance measurement
   */
  startMetrics(): TestMetrics {
    this.currentMetrics = {
      startTime: performance.now(),
      steps: []
    };
    return this.currentMetrics;
  }

  /**
   * Finish performance measurement
   */
  finishMetrics(): TestMetrics {
    if (!this.currentMetrics) {
      throw new Error('Metrics not started');
    }

    const now = performance.now();
    this.currentMetrics.endTime = now;
    this.currentMetrics.totalTime = now - this.currentMetrics.startTime;

    return this.currentMetrics;
  }

  /**
   * Reset test state
   */
  resetAll(): void {
    this.mockNearRpc.clearAllAccounts();
    this.stubs.forEach(stub => stub.restore());
    this.stubs = [];
    
    // Also restore any global stubs
    if ((window.fetch as any).restore) {
      (window.fetch as any).restore();
    }
  }

    /**
   * Setup minimal global mocks - only mock browser APIs not available in Node.js
   */
  private setupGlobalMocks(): void {
    // Mock WebAuthn globals if not available in test environment
    if (!(window as any).navigator?.credentials) {
      this.stubs.push(sinon.stub(window, 'navigator').value({
        credentials: {
          create: sinon.stub(),
          get: sinon.stub()
        }
      }));
    }

    // Mock crypto if not available
    if (!(window as any).crypto) {
       this.stubs.push(sinon.stub(window, 'crypto').value({
        getRandomValues: (array: Uint8Array) => {
          for (let i = 0; i < array.length; i++) {
            array[i] = Math.floor(Math.random() * 256);
          }
          return array;
        },
        randomUUID: () => 'test-uuid-' + Math.random().toString(36).substr(2, 9)
      }));
    }

    // Mock window properties if not available
    if (!(window as any).isSecureContext) {
      (window as any).isSecureContext = true;
    }

    // Mock Worker for VRF worker
     this.stubs.push(sinon.stub(window, 'Worker').value(class MockWorker {
        postMessage = sinon.stub();
        terminate = sinon.stub();
        addEventListener = sinon.stub();
        removeEventListener = sinon.stub();
        onmessage = null;
        onerror = null;
     }));


    // Mock fetch for RPC calls
    const mockFetch = async (url: string, options: any) => {
      // Route NEAR RPC calls to mock
      if (url.includes('rpc.testnet.near.org') || url.includes('rpc.near.org')) {
        const body = JSON.parse(options?.body || '{}');

        // Handle different RPC methods
        switch (body.method) {
          case 'query':
            if (body.params?.request_type === 'view_access_key') {
              const result = await this.mockNearRpc.viewAccessKey(
                body.params.account_id,
                body.params.public_key
              );
              return new Response(JSON.stringify({ result }), { status: 200 });
            }
            break;
          case 'block':
            const result = await this.mockNearRpc.viewBlock({ finality: 'final' });
            return new Response(JSON.stringify({ result }), { status: 200 });
          case 'send_tx':
            const txResult = await this.mockNearRpc.broadcastTransaction(body.params.signed_tx_base64);
            return new Response(JSON.stringify({ result: txResult }), { status: 200 });
        }

        return new Response(JSON.stringify({ result: {} }), { status: 200 });
      }
      // You might want to let other calls pass through or mock them as well
      return new Response('{}', { status: 200 });
    };

    // Only stub fetch if not already stubbed
    try {
      if (!(window.fetch as any).isSinonProxy) {
        this.stubs.push(sinon.stub(window, 'fetch').callsFake(mockFetch as any));
      }
    } catch (error) {
      // If stubbing fails (e.g., already stubbed), restore and re-stub
      if ((window.fetch as any).restore) {
        (window.fetch as any).restore();
      }
      this.stubs.push(sinon.stub(window, 'fetch').callsFake(mockFetch as any));
    }
  }
}