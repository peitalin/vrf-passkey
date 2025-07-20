/**
 * Worker Communication Protocol Documentation
 *
 * MESSAGING FLOW DOCUMENTATION:
 * =============================
 *
 * 1. PROGRESS MESSAGES (During Operation):
 *    Rust WASM → send_typed_progress_message() → TypeScript sendProgressMessage() → postMessage() → Main Thread
 *    - Used for real-time updates during long operations
 *    - Multiple progress messages can be sent per operation
 *    - Does not affect the final result
 *    - Types: ProgressMessageType, ProgressStep, ProgressStatus (auto-generated from Rust)
 *
 * 2. FINAL RESULTS (Operation Complete):
 *    Rust WASM → return value from handle_signer_message() → TypeScript worker → postMessage() → Main Thread
 *    - Contains the actual operation result (success/error)
 *    - Only one result message per operation
 *    - This is what the main thread awaits for completion
 *
 * TYPE SAFETY:
 * ============
 * All progress message types are auto-generated from Rust using wasm-bindgen:
 * - ProgressMessageType (enum): VERIFICATION_PROGRESS, SIGNING_PROGRESS, etc.
 * - ProgressStep (enum): preparation, contract_verification, transaction_signing, etc.
 * - ProgressStatus (enum): progress, success, error
 * - WorkerProgressMessage (struct): Complete message structure
 *
 * These types are available after build in: wasm_signer_worker.d.ts
 *
 * REGRESSION PREVENTION:
 * ======================
 * The auto-generated types from Rust ensure that:
 * 1. TypeScript compiler catches type mismatches at build time
 * 2. Progress message structure changes require updates in both Rust and TypeScript
 * 3. Enum values are consistent between Rust and TypeScript
 * 4. No manual type maintenance required - types stay in sync automatically
 */

// Basic interface for development - actual types are auto-generated from Rust
export interface BasicProgressMessage {
  message_type: string;
  step: string;
  message: string;
  status: string;
  timestamp: number;
  data?: string;
}

// Type guard for basic progress message validation during development
export function isBasicProgressMessage(obj: any): obj is BasicProgressMessage {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.message_type === 'string' &&
    typeof obj.step === 'string' &&
    typeof obj.message === 'string' &&
    typeof obj.status === 'string' &&
    typeof obj.timestamp === 'number'
  );
}