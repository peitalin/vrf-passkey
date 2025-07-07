/**
 * Enhanced WASM Signer Worker (v2)
 * This worker uses Rust-based message handling for better type safety and performance
 * Similar to the VRF worker architecture
 */

import type { WorkerRequest, WorkerResponse } from './types/signer-worker';
// Import WASM binary directly
import init, * as wasmModule from '../wasm_signer_worker/wasm_signer_worker.js';
// Use a relative URL to the WASM file that will be copied by rollup to the same directory as the worker
const wasmUrl = new URL('./wasm_signer_worker_bg.wasm', import.meta.url);
const { handle_signer_message } = wasmModule;

// Buffer polyfill for Web Workers
// Workers don't inherit main thread polyfills, they run in an isolated environment
// Manual polyfill is required for NEAR crypto operations that depend on Buffer.
import { Buffer } from 'buffer';
globalThis.Buffer = Buffer;

let messageProcessed = false;

// === PROGRESS MESSAGE TYPES ===

// Progress message types that can be sent from WASM to the main thread
enum ProgressMessageType {
  VERIFICATION_PROGRESS = 'VERIFICATION_PROGRESS',
  VERIFICATION_COMPLETE = 'VERIFICATION_COMPLETE',
  SIGNING_PROGRESS = 'SIGNING_PROGRESS',
  SIGNING_COMPLETE = 'SIGNING_COMPLETE',
  REGISTRATION_PROGRESS = 'REGISTRATION_PROGRESS',
  REGISTRATION_COMPLETE = 'REGISTRATION_COMPLETE',
}

// Step identifiers for progress tracking
enum ProgressStep {
  PREPARATION = 'preparation',
  AUTHENTICATION = 'authentication',
  CONTRACT_VERIFICATION = 'contract_verification',
  TRANSACTION_SIGNING = 'transaction_signing',
  BROADCASTING = 'broadcasting',
  VERIFICATION_COMPLETE = 'verification_complete',
  SIGNING_COMPLETE = 'signing_complete',
}

/**
 * Function called by WASM to send progress messages
 * This is imported into the WASM module as sendProgressMessage
 *
 * Enhanced version that supports logs and creates consistent onProgressEvents output
 *
 * @param messageType - Type of message (e.g., 'VERIFICATION_PROGRESS', 'SIGNING_COMPLETE')
 * @param step - Step identifier (e.g., 'contract_verification', 'transaction_signing')
 * @param message - Human-readable progress message
 * @param data - JSON string containing structured data
 * @param logs - Optional JSON string containing array of log messages
 */
function sendProgressMessage(
  messageType: ProgressMessageType | string,
  step: ProgressStep | string,
  message: string,
  data: string,
  logs?: string
): void {
  try {
    console.debug(`[signer-worker-v2]: Progress update: ${messageType} - ${step} - ${message}`);

    // Parse structured data and logs
    let parsedData: any = {};
    let parsedLogs: string[] = [];

    try {
      parsedData = data ? JSON.parse(data) : {};
    } catch (error) {
      console.warn('[signer-worker-v2]: Failed to parse progress data:', error);
      parsedData = { rawData: data };
    }

    try {
      parsedLogs = logs ? JSON.parse(logs) : [];
    } catch (error) {
      console.warn('[signer-worker-v2]: Failed to parse progress logs:', error);
      parsedLogs = logs ? [logs] : [];
    }

    // Create onProgressEvents-compatible payload
    const progressPayload = {
      step: typeof step === 'string' ? step : ProgressStep[step as keyof typeof ProgressStep] || step,
      phase: step, // Use step as phase for compatibility
      status: messageType.includes('COMPLETE') ? 'success' : 'progress',
      message: message,
      timestamp: Date.now(),
      data: parsedData,
      logs: parsedLogs
    };

    // Send progress message to main thread
    const progressMessage = {
      type: messageType,
      payload: progressPayload,
      timestamp: Date.now()
    };

    self.postMessage(progressMessage);

  } catch (error: any) {
    console.error('[signer-worker-v2]: Failed to send progress message:', error);

    // Send error message as fallback
    self.postMessage({
      type: 'ERROR',
      payload: {
        error: `Progress message failed: ${error?.message || 'Unknown error'}`,
        context: { messageType, step, message }
      },
      timestamp: Date.now()
    });
  }
}

// Make sendProgressMessage available globally for WASM to call
(globalThis as any).sendProgressMessage = sendProgressMessage;

/**
 * Initialize WASM module
 */
async function initializeWasm(): Promise<void> {
  try {
    await init({ module_or_path: wasmUrl });
  } catch (error: any) {
    console.error('[signer-worker-v2]: WASM initialization failed:', error);
    throw new Error(`WASM initialization failed: ${error?.message || 'Unknown error'}`);
  }
}

self.onmessage = async (event: MessageEvent<WorkerRequest>): Promise<void> => {
  if (messageProcessed) {
    self.postMessage({
      type: 'ERROR',
      payload: { error: 'Worker has already processed a message' }
    });
    self.close();
    return;
  }

  messageProcessed = true;
  console.log('[signer-worker-v2]: Received message:', { type: event.data.type });

  try {
    // Initialize WASM
    await initializeWasm();

    // Convert TypeScript message to JSON and pass to Rust
    const messageJson = JSON.stringify(event.data);
    // Call the Rust message handler
    const responseJson = await handle_signer_message(messageJson);
    // Parse response and send back to main thread
    const response = JSON.parse(responseJson);

    self.postMessage(response);
    self.close();

  } catch (error: any) {
    console.error('[signer-worker-v2]: Message processing failed:', error);

    self.postMessage({
      type: 'ERROR',
      payload: {
        error: error?.message || 'Unknown error occurred',
        context: { type: event.data.type }
      }
    });
    self.close();
  }
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[signer-worker-v2]: Global error:', {
    message: typeof message === 'string' ? message : 'Unknown error',
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: error
  });
};

self.onunhandledrejection = (event) => {
  console.error('[signer-worker-v2]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
};