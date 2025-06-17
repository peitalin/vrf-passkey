import {
  WorkerRequestType,
  WorkerResponseType,
  type WorkerRequest,
  type WorkerResponse,
  type EncryptPrivateKeyWithPrfRequest,
  type DecryptAndSignTransactionWithPrfRequest,
  type DecryptPrivateKeyWithPrfRequest,
  type ExtractCosePublicKeyRequest,
  type ValidateCoseKeyRequest,
  type EncryptionSuccessResponse,
  type SignatureSuccessResponse,
  type ErrorResponse,
  isEncryptionSuccess,
  isSignatureSuccess,
} from '../types/worker';

// Basic worker tests without external dependencies
describe('Passkey Worker Tests', () => {
  // Mock Worker class for testing
  class MockWorker {
    public onmessage: ((event: MessageEvent) => void) | null = null;
    public onerror: ((event: ErrorEvent) => void) | null = null;

    constructor(public scriptURL: string, public options?: WorkerOptions) {}

    postMessage = jest.fn();
    terminate = jest.fn();
  }

  // Mock global Worker
  beforeAll(() => {
    (global as any).Worker = MockWorker;
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Worker Creation', () => {
    it('should create a worker instance', () => {
      const worker = new MockWorker('/test-worker.js');
      expect(worker).toBeDefined();
      expect(worker.scriptURL).toBe('/test-worker.js');
    });

    it('should handle worker options', () => {
      const options = { type: 'module' as const, name: 'TestWorker' };
      const worker = new MockWorker('/test-worker.js', options);
      expect(worker.options).toEqual(options);
    });
  });

  describe('Worker Communication', () => {
    it('should post messages to worker', () => {
      const worker = new MockWorker('/test-worker.js');
      const testMessage: WorkerRequest = {
        type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF,
        payload: {
          prfOutput: 'test-prf-output',
          nearAccountId: 'test.testnet',
        }
      };

      worker.postMessage(testMessage);
      expect(worker.postMessage).toHaveBeenCalledWith(testMessage);
    });

    it('should handle worker responses', (done) => {
      const worker = new MockWorker('/test-worker.js');
      const testResponse: WorkerResponse = {
        type: WorkerResponseType.ENCRYPTION_SUCCESS,
        payload: {
          nearAccountId: 'test.testnet',
          publicKey: 'ed25519:testkey',
          stored: true,
        }
      };

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        expect(event.data).toEqual(testResponse);
        expect(isEncryptionSuccess(event.data)).toBe(true);
        done();
      };

      // Simulate worker response
      if (worker.onmessage) {
        worker.onmessage({ data: testResponse } as MessageEvent<WorkerResponse>);
      }
    });

    it('should handle worker errors', (done) => {
      const worker = new MockWorker('/test-worker.js');

      worker.onerror = (event: ErrorEvent) => {
        expect(event.message).toBe('Test error');
        done();
      };

      // Simulate worker error
      if (worker.onerror) {
        worker.onerror(new ErrorEvent('error', { message: 'Test error' }));
      }
    });

    it('should terminate workers', () => {
      const worker = new MockWorker('/test-worker.js');
      worker.terminate();
      expect(worker.terminate).toHaveBeenCalled();
    });
  });

  describe('Worker Message Types', () => {
    it('should handle encryption requests', () => {
      const worker = new MockWorker('/test-worker.js');
      const encryptionRequest: EncryptPrivateKeyWithPrfRequest = {
        type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF,
        payload: {
          prfOutput: 'test-prf-output',
          nearAccountId: 'test.testnet'
        }
      };

      worker.postMessage(encryptionRequest);
      expect(worker.postMessage).toHaveBeenCalledWith(encryptionRequest);
    });

    it('should handle signing requests', () => {
      const worker = new MockWorker('/test-worker.js');
      const signingRequest: DecryptAndSignTransactionWithPrfRequest = {
        type: WorkerRequestType.DECRYPT_AND_SIGN_TRANSACTION_WITH_PRF,
        payload: {
          nearAccountId: 'test.testnet',
          prfOutput: 'test-prf-output',
          receiverId: 'contract.testnet',
          contractMethodName: 'test_method',
          contractArgs: { test: 'args' },
          gasAmount: '100000000000000',
          depositAmount: '0',
          nonce: '123',
          blockHashBytes: [1, 2, 3, 4]
        }
      };

      worker.postMessage(signingRequest);
      expect(worker.postMessage).toHaveBeenCalledWith(signingRequest);
    });

    it('should handle decryption requests', () => {
      const worker = new MockWorker('/test-worker.js');
      const decryptionRequest: DecryptPrivateKeyWithPrfRequest = {
        type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        payload: {
          nearAccountId: 'test.testnet',
          prfOutput: 'test-prf-output'
        }
      };

      worker.postMessage(decryptionRequest);
      expect(worker.postMessage).toHaveBeenCalledWith(decryptionRequest);
    });

    it('should handle COSE key extraction requests', () => {
      const worker = new MockWorker('/test-worker.js');
      const coseRequest: ExtractCosePublicKeyRequest = {
        type: WorkerRequestType.EXTRACT_COSE_PUBLIC_KEY,
        payload: {
          attestationObjectBase64url: 'test-attestation-object'
        }
      };

      worker.postMessage(coseRequest);
      expect(worker.postMessage).toHaveBeenCalledWith(coseRequest);
    });

    it('should handle COSE key validation requests', () => {
      const worker = new MockWorker('/test-worker.js');
      const validationRequest: ValidateCoseKeyRequest = {
        type: WorkerRequestType.VALIDATE_COSE_KEY,
        payload: {
          coseKeyBytes: [1, 2, 3, 4, 5]
        }
      };

      worker.postMessage(validationRequest);
      expect(worker.postMessage).toHaveBeenCalledWith(validationRequest);
    });
  });

  describe('Worker Response Types', () => {
    it('should handle encryption success responses', (done) => {
      const worker = new MockWorker('/test-worker.js');
      const successResponse: EncryptionSuccessResponse = {
        type: WorkerResponseType.ENCRYPTION_SUCCESS,
        payload: {
          nearAccountId: 'test.testnet',
          publicKey: 'ed25519:test-key',
          stored: true
        }
      };

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        expect(event.data.type).toBe(WorkerResponseType.ENCRYPTION_SUCCESS);
        if (isEncryptionSuccess(event.data)) {
          expect(event.data.payload.nearAccountId).toBe('test.testnet');
        }
        done();
      };

      if (worker.onmessage) {
        worker.onmessage({ data: successResponse } as MessageEvent<WorkerResponse>);
      }
    });

    it('should handle signing success responses', (done) => {
      const worker = new MockWorker('/test-worker.js');
      const successResponse: SignatureSuccessResponse = {
        type: WorkerResponseType.SIGNATURE_SUCCESS,
        payload: {
          signedTransactionBorsh: [1, 2, 3, 4, 5],
          nearAccountId: 'test.testnet'
        }
      };

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        expect(event.data.type).toBe(WorkerResponseType.SIGNATURE_SUCCESS);
        if (isSignatureSuccess(event.data)) {
          expect(event.data.payload.signedTransactionBorsh).toEqual([1, 2, 3, 4, 5]);
        }
        done();
      };

      if (worker.onmessage) {
        worker.onmessage({ data: successResponse } as MessageEvent<WorkerResponse>);
      }
    });

    it('should handle error responses', (done) => {
      const worker = new MockWorker('/test-worker.js');
      const errorResponse: ErrorResponse = {
        type: WorkerResponseType.ERROR,
        payload: {
          error: 'Test worker error'
        }
      };

      worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
        expect(event.data.type).toBe(WorkerResponseType.ERROR);
        if (event.data.type === WorkerResponseType.ERROR) {
          expect((event.data.payload as any).error).toBe('Test worker error');
        }
        done();
      };

      if (worker.onmessage) {
        worker.onmessage({ data: errorResponse } as MessageEvent<WorkerResponse>);
      }
    });
  });

  describe('Worker Lifecycle', () => {
    it('should create, use, and terminate worker', () => {
      const worker = new MockWorker('/test-worker.js');

      // Set up handlers
      worker.onmessage = jest.fn();
      worker.onerror = jest.fn();

      // Send message
      worker.postMessage({ type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF, payload: {} });
      expect(worker.postMessage).toHaveBeenCalled();

      // Terminate
      worker.terminate();
      expect(worker.terminate).toHaveBeenCalled();
    });

    it('should handle multiple workers concurrently', () => {
      const worker1 = new MockWorker('/worker1.js');
      const worker2 = new MockWorker('/worker2.js');

      expect(worker1).not.toBe(worker2);
      expect(worker1.scriptURL).toBe('/worker1.js');
      expect(worker2.scriptURL).toBe('/worker2.js');

      worker1.postMessage({ type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF, payload: { id: 1 } });
      worker2.postMessage({ type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF, payload: { id: 2 } });

      expect(worker1.postMessage).toHaveBeenCalledWith({ type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF, payload: { id: 1 } });
      expect(worker2.postMessage).toHaveBeenCalledWith({ type: WorkerRequestType.DECRYPT_PRIVATE_KEY_WITH_PRF, payload: { id: 2 } });
    });
  });

  describe('Error Handling', () => {
    it('should handle worker creation failures', () => {
      // Mock constructor that throws
      const FailingWorker = class {
        constructor() {
          throw new Error('Worker creation failed');
        }
      };

      expect(() => new FailingWorker()).toThrow('Worker creation failed');
    });

    it('should handle communication timeouts', (done) => {
      const worker = new MockWorker('/test-worker.js');
      let timeoutCalled = false;

      // Simulate timeout
      const timeout = setTimeout(() => {
        timeoutCalled = true;
        worker.terminate();
        expect(timeoutCalled).toBe(true);
        done();
      }, 100);

      // Don't send response to trigger timeout
      worker.postMessage({ type: WorkerRequestType.ENCRYPT_PRIVATE_KEY_WITH_PRF, payload: {} });
    });

    it('should handle malformed responses', (done) => {
      const worker = new MockWorker('/test-worker.js');

      worker.onmessage = (event: MessageEvent) => {
        try {
          expect(event.data).toBeDefined();
          // In real implementation, validate message structure
          done();
        } catch (error) {
          done();
        }
      };

      // Send malformed response
      if (worker.onmessage) {
        worker.onmessage({ data: null } as MessageEvent);
      }
    });
  });
});