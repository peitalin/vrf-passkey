/**
 * VRF WASM Web Worker
 * This Web Worker loads the VRF WASM module and provides VRF keypair management.
 */

import type { VRFWorkerMessage, VRFWorkerResponse } from './types/vrf';
// Import VRF WASM module directly
import init, * as vrfWasmModule from '../wasm_vrf_worker/wasm_vrf_worker.js';
// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('./wasm_vrf_worker_bg.wasm', import.meta.url);
const { handle_message } = vrfWasmModule;

// === WASM MODULE MANAGEMENT ===

let wasmModule: any | null = null;
let wasmInitialized: boolean = false;

/**
 * Initialize WASM module for VRF operations with timeout protection
 */
async function initializeWasmModule(): Promise<void> {
  if (wasmInitialized) {
    console.log('[VRF-worker]: Already initialized, skipping...');
    return;
  }

  console.log('[VRF-worker]: Starting WASM initialization...');

  try {
    // Add timeout protection for WASM initialization
    const initPromise = (async () => {
      console.log('[VRF-worker]: WASM URL:', wasmUrl.href);
      console.log('[VRF-worker]: Available functions:', Object.keys(vrfWasmModule));

      // Initialize WASM module
      console.log('[VRF-worker]: Calling init()...');
      await init();
      console.log('[VRF-worker]: init() completed successfully');

      // Test that the handle_message function is available
      if (typeof handle_message !== 'function') {
        throw new Error('handle_message function not available after WASM initialization');
      }
      console.log('[VRF-worker]: handle_message function verified');
    })();

    // Race initialization against timeout
    await Promise.race([
      initPromise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('WASM initialization timeout after 20 seconds')), 20000)
      )
    ]);

    // Create wrapper with the proper handle_message function
    const wasmInstance = {
      handle_message: (message: VRFWorkerMessage): VRFWorkerResponse => {
        try {
          console.log('VRF WASM: Processing message:', message.type);

          // Call the actual WASM function
          const result = handle_message(message);
          return result;
        } catch (error: any) {
          console.error('VRF WASM: Error processing message:', error);
          return {
            id: message.id,
            success: false,
            error: error.message || 'WASM processing error'
          };
        }
      }
    };

    wasmModule = wasmInstance;
    wasmInitialized = true;

    console.log('✅ [VRF-worker]: WASM module loaded and initialized successfully');

    // Quick test of the WASM functionality
    try {
      const testResponse = wasmModule.handle_message({
        type: 'PING',
        id: 'init-test',
        data: {}
      });
      console.log('✅ [VRF-worker]: Initialization test successful:', testResponse.success);
    } catch (testError: any) {
      console.warn('️[VRF-worker]: Initialization test failed, but continuing:', testError.message);
    }

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown WASM initialization error';
    console.error('❌ [VRF-worker]: Failed to load WASM module:', errorMessage);
    console.error('❌ [VRF-worker]: Error details:', error);
    wasmInitialized = false;

    // Create a fallback module that returns errors
    wasmModule = {
      handle_message: (message: VRFWorkerMessage): VRFWorkerResponse => {
        return {
          id: message.id,
          success: false,
          error: `WASM initialization failed: ${errorMessage}`
        };
      }
    };

    // Re-throw the error to be handled by the caller
    throw new Error(`VRF WASM initialization failed: ${errorMessage}`);
  }
}

// === MESSAGE HANDLING ===

self.onmessage = async (event: MessageEvent) => {
  const data: VRFWorkerMessage = event.data;

  try {
    console.log('[VRF-worker]: Received message:', data.type);

    // Handle PING messages immediately for connectivity testing
    if (data.type === 'PING') {
      console.log('[VRF-worker]: Responding to PING');
      const pingResponse: VRFWorkerResponse = {
        id: data.id,
        success: true,
        data: {
          status: 'alive',
          wasmInitialized: wasmInitialized,
          timestamp: Date.now()
        }
      };
      self.postMessage(pingResponse);
      return;
    }

    // For other messages, ensure WASM is initialized
    if (!wasmInitialized) {
      console.log('🔧 [VRF-worker]: WASM not initialized, initializing now...');
      await initializeWasmModule();
    }

    if (!wasmInitialized || !wasmModule) {
      throw new Error('WASM module not initialized after initialization attempt');
    }

    console.log('[VRF-worker]: Processing message with WASM module');

    // Delegate to WASM module
    if (!wasmModule) {
      throw new Error('WASM module is null after initialization');
    }

    const response: VRFWorkerResponse = wasmModule.handle_message(data);

    // Send response back to main thread
    self.postMessage(response);

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown message handling error';
    console.error('[VRF-worker]: Message handling error:', errorMessage);

    // Send error response
    const errorResponse = createErrorResponse(data?.id, error);
    self.postMessage(errorResponse);
  }
};

// === ERROR HANDLING ===

function createErrorResponse(
  messageId: string | undefined,
  error: unknown
): VRFWorkerResponse {
  const errorMessage = error instanceof Error ? error.message : 'Unknown error in Web Worker';

  return {
    id: messageId,
    success: false,
    error: errorMessage
  };
}

self.onerror = (error) => {
  console.error('[VRF-worker]: Global error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[VRF-worker]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
};

// === INITIALIZATION ===

initializeWasmModule().catch(error => {
  console.error('[VRF-worker]: Startup initialization failed:', error);
});