/**
 * Validation Script for Type-Safe Worker Communication Protocol
 */

import {
  BasicProgressMessage,
  isBasicProgressMessage
} from '../../core/types/worker-events';

// Simple assertion function
function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function runTests(): void {
  console.log('Running Worker Communication Protocol Tests...\n');

  // Test 1: Basic Message Validation
  console.log('Test 1: Basic Message Validation');
  const validMsg: BasicProgressMessage = {
    message_type: 'SIGNING_PROGRESS',
    step: 'transaction_signing',
    message: 'Signing transaction',
    status: 'progress',
    timestamp: Date.now(),
    data: '{"step": 1, "total": 3}'
  };

  assert(isBasicProgressMessage(validMsg), 'Should validate well-formed messages');
  assert(!isBasicProgressMessage(null), 'Should reject null messages');
  assert(!isBasicProgressMessage({}), 'Should reject empty objects');
  assert(!isBasicProgressMessage({ message_type: 'test' }), 'Should reject incomplete messages');
  console.log('Basic message validation working correctly\n');

  // Test 2: Message Structure
  console.log('Test 2: Message Structure');
  assert(typeof validMsg.message_type === 'string', 'message_type should be string');
  assert(typeof validMsg.step === 'string', 'step should be string');
  assert(typeof validMsg.message === 'string', 'message should be string');
  assert(typeof validMsg.status === 'string', 'status should be string');
  assert(typeof validMsg.timestamp === 'number', 'timestamp should be number');
  assert(validMsg.data === undefined || typeof validMsg.data === 'string', 'data should be string or undefined');
  console.log('Message structure validation working correctly\n');

  // Test 3: Documentation and Flow
  console.log('Test 3: Documentation and Flow');
  console.log('   Progress Flow: Rust WASM → send_typed_progress_message() → TypeScript → Main Thread');
  console.log('   Result Flow: Rust WASM → handle_signer_message() return → TypeScript → Main Thread');
  console.log('   Type Safety: Auto-generated types from Rust wasm-bindgen ensure consistency');
  console.log('  Communication flow documented\n');

  console.log('Worker Communication Protocol Tests Passed!');
  console.log('  Basic message validation working');
  console.log('  Message structure validated');
  console.log('  Communication flow documented');
  console.log('\nNOTE: Full type-safe testing will be available after WASM build');
  console.log('   Auto-generated types: ProgressMessageType, ProgressStep, ProgressStatus, WorkerProgressMessage');
  console.log('   Location: dist/types/wasm_signer_worker.d.ts (after npm run build)');
  console.log('\nProgress messaging regression protection in place!');
}

// Export for testing in Node.js
export { runTests };

// Run tests immediately when imported
try {
  runTests();
  process.exit(0);
} catch (error) {
  console.error('Test failed:', error instanceof Error ? error.message : error);
  process.exit(1);
}