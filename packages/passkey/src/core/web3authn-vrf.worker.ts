/**
 * VRF WASM Web Worker
 * This Web Worker loads the VRF WASM module and provides VRF keypair management.
 */

import type { VRFWorkerMessage, VRFWorkerResponse } from './types/vrf-worker';
// Import VRF WASM module directly
import init, * as vrfWasmModule from '../wasm_vrf_worker/wasm_vrf_worker';
// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('../wasm_vrf_worker/wasm_vrf_worker_bg.wasm', import.meta.url);
const { handle_message } = vrfWasmModule;

// === WASM MODULE MANAGEMENT ===

let wasmModule: any | null = null;
let wasmInitialized: boolean = false;

/**
 * Initialize WASM module for VRF operations with robust loading and timeout protection
 * Handles MIME type issues and server configuration problems automatically
 */
async function initializeWasmModule(): Promise<void> {
  if (wasmInitialized) {
    console.log('[vrf-worker]: Already initialized, skipping...');
    return;
  }

  console.log('[vrf-worker]: Starting WASM initialization...');

  try {
    // Add timeout protection for WASM initialization
    const initPromise = (async () => {
      console.log('[vrf-worker]: WASM URL:', wasmUrl.href);
      console.log('[vrf-worker]: Available functions:', Object.keys(vrfWasmModule));

      // Try robust WASM initialization with fallback strategies
      try {
        // First try: Direct WASM module initialization (streaming)
        console.log('[vrf-worker]: Attempting streaming WASM initialization...');
        await init();
        console.log('[vrf-worker]: Streaming init() completed successfully');
      } catch (streamError: any) {
        console.warn('[vrf-worker]: Streaming initialization failed, trying ArrayBuffer approach:', streamError.message);

        // Second try: Fetch WASM manually and use ArrayBuffer
        const response = await fetch(wasmUrl.href);
        if (!response.ok) {
          throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`);
        }

        const contentType = response.headers.get('content-type');
        console.log('[vrf-worker]: WASM fetch successful, content-type:', contentType);

        const arrayBuffer = await response.arrayBuffer();
        const wasmModule = await WebAssembly.compile(arrayBuffer);
        await init({ module: wasmModule });
        console.log('[vrf-worker]: ArrayBuffer init() completed successfully');
      }

      // Test that the handle_message function is available
      if (typeof handle_message !== 'function') {
        throw new Error('handle_message function not available after WASM initialization');
      }
      console.log('[vrf-worker]: handle_message function verified');
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

    console.log('✅ [vrf-worker]: WASM module loaded and initialized successfully');

    // Quick test of the WASM functionality
    try {
      const testResponse = wasmModule.handle_message({
        type: 'PING',
        id: 'init-test',
        data: {}
      });
      console.log('✅ [vrf-worker]: Initialization test successful:', testResponse.success);
    } catch (testError: any) {
      console.warn('️[vrf-worker]: Initialization test failed, but continuing:', testError.message);
    }

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown WASM initialization error';
    console.error('❌ [vrf-worker]: Failed to load WASM module:', errorMessage);
    console.error('❌ [vrf-worker]: Error details:', error);
    wasmInitialized = false;

    // Create a fallback module that returns errors
    wasmModule = {
      handle_message: (message: VRFWorkerMessage): VRFWorkerResponse => {
        const helpfulMessage = `
VRF WASM initialization failed. This may be due to:
1. Server MIME type configuration (WASM files should be served with 'application/wasm')
2. Network connectivity issues
3. CORS policy restrictions
4. Missing WASM files in deployment

Original error: ${errorMessage}

The SDK attempted multiple loading strategies but all failed.
For production deployment, ensure your server serves .wasm files with the correct MIME type.
        `.trim();

        return {
          id: message.id,
          success: false,
          error: helpfulMessage
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
    console.log('[vrf-worker]: Received message:', data.type);

    // Handle PING messages immediately for connectivity testing
    if (data.type === 'PING') {
      console.log('[vrf-worker]: Responding to PING');
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
      console.log('[vrf-worker]: WASM not initialized, initializing now...');
      await initializeWasmModule();
    }

    if (!wasmInitialized || !wasmModule) {
      throw new Error('WASM module not initialized after initialization attempt');
    }

    console.log('[vrf-worker]: Processing message with WASM module');

    // Delegate to WASM module
    if (!wasmModule) {
      throw new Error('WASM module is null after initialization');
    }

    const response: VRFWorkerResponse = wasmModule.handle_message(data);

    // Send response back to main thread
    self.postMessage(response);

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown message handling error';
    console.error('[vrf-worker]: Message handling error:', errorMessage);

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
  console.error('[vrf-worker]: Global error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[vrf-worker]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
};

// === INITIALIZATION ===

initializeWasmModule().catch(error => {
  console.error('[vrf-worker]: Startup initialization failed:', error);
});