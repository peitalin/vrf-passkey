/**
 * VRF WASM Web Worker
 * This Web Worker loads the VRF WASM module and provides VRF keypair management.
 */

import type { VRFWorkerMessage, VRFWorkerResponse } from './types/vrf-worker';

// Import VRF WASM module directly
import init, * as vrfWasmModule from '../wasm_vrf_worker/wasm_vrf_worker';
import { initializeWasm } from './utils/wasmLoader';
// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('../wasm_vrf_worker/wasm_vrf_worker_bg.wasm', import.meta.url);
const { handle_message } = vrfWasmModule;

// === WASM INITIALIZATION ===

/**
 * Initialize WASM module once at startup
 */
async function initializeWasmModule(): Promise<void> {
  await initializeWasm({
    workerName: 'vrf-worker',
    wasmUrl,
    initFunction: async (wasmModule?: any) => {
      await init(wasmModule ? { module: wasmModule } : undefined);
    },
    validateFunction: () => {
      if (typeof handle_message !== 'function') {
        throw new Error('handle_message function not available after WASM initialization');
      }
    },
    timeoutMs: 20000
  });

  console.log('✅ [vrf-worker]: WASM module loaded and initialized successfully');
}

// === MESSAGE HANDLING ===

self.onmessage = async (event: MessageEvent) => {
  const data: VRFWorkerMessage = event.data;

  try {
    console.log('[vrf-worker]: Received message:', data.type);

    // Call WASM handle_message directly with error handling
    const response: VRFWorkerResponse = handle_message(data);

    // Send response back to main thread
    self.postMessage(response);

  } catch (error: unknown) {
    console.error('[vrf-worker]: Message handling error:', error);

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

// Initialize WASM module at startup
initializeWasmModule().catch(error => {
  console.error('[vrf-worker]: Startup initialization failed:', error);
  // Worker will throw errors for all messages if WASM fails to initialize
});