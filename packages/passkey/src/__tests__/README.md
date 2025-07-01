# E2E Tests - Playwright

## Overview

This directory contains Playwright end-to-end tests for the passkey SDK. We use Playwright for comprehensive browser testing of:

- **WASM worker functionality** (VRF and Signer workers)
- **WebAuthn interactions** (TouchID, PRF operations)
- **Complete registration flows** (coming soon)

## Test Strategy

- **Rust Cargo**: Unit testing WASM worker functions
- **Playwright**: E2E testing of browser APIs, workers, and integration flows
- **Rollup**: Build system for production bundles

## Current Tests

### `wasm-workers.test.ts`

Comprehensive testing of SDK functionality:

1. **Basic SDK Loading**:
   - PasskeyManager class instantiation
   - Method existence verification (`registerPasskey`, `loginPasskey`, `getLoginState`)
   - Configuration validation

2. **RegisterPasskey Function Testing**:
   - ✅ **Method Signature Validation**: Verifies `registerPasskey` accepts correct parameters
   - ✅ **Event Flow Testing**: Validates complete registration event sequence:
     - `webauthn-verification` (progress → success)
     - `user-ready` (success with verification details)
     - `access-key-addition` (progress → success)
     - `database-storage` (success)
     - `registration-complete` (success)
   - ✅ **Error Handling**: Tests graceful error handling with proper event callbacks
   - ✅ **Callback System**: Validates `onEvent` and `onError` callback mechanisms
   - ✅ **Return Structure**: Verifies registration result contains expected fields

3. **Future WASM Worker Tests** (planned):
   - VRF Worker: keypair generation, challenge creation, cryptographic validation
   - Signer Worker: COSE key extraction, NEAR keypair derivation, transaction signing
   - Worker coordination and cross-worker data flow

### Testing Approach for RegisterPasskey

The `registerPasskey` function uses a **mock-based testing approach** that focuses on:

1. **Event-Driven Architecture**: Tests the complete event flow that UI components depend on
2. **Method Signature Validation**: Ensures the function accepts correct parameters and returns promises
3. **Error Boundary Testing**: Validates error handling and callback mechanisms
4. **Phase Verification**: Confirms all required registration phases are properly sequenced

#### Key Test Patterns:

```typescript
// Event flow validation
expect(result.actualPhases).toContain('webauthn-verification');
expect(result.actualPhases).toContain('user-ready');
expect(result.actualPhases).toContain('access-key-addition');
expect(result.actualPhases).toContain('database-storage');
expect(result.actualPhases).toContain('registration-complete');

// Callback mechanism testing
const capturedEvents: any[] = [];
await passkeyManager.registerPasskey('testuser.testnet', {
  onEvent: (event: any) => capturedEvents.push(event),
  onError: (error: any) => capturedErrors.push(error)
});
```

This approach allows testing the **integration contract** and **event architecture** without requiring real WebAuthn ceremonies or blockchain transactions.

## Running Tests

```bash
# List available tests
npm run test:show -- --list

# Run all tests (requires frontend to be running at localhost:5173)
npm run test:show

# Run specific test file
npm run test:show wasm-workers

# Run with headed browser (for debugging)
npm run test:show -- --headed

# Run specific browser project
npm run test:show -- --project=chromium-web3-authn
npm run test:show -- --project=webkit-touchid
```

## Browser Projects

### `chromium-web3-authn`
- Chrome with WebAuth Testing API enabled
- Experimental web platform features
- Virtual authenticator support
- Used for WebAuthn PRF testing

### `webkit-touchid`
- Safari-based testing
- TouchID simulation capabilities
- Platform authenticator testing

## Next Steps

Planned additional test suites:

1. **Registration Flow E2E**: Complete passkey registration with:
   - Testnet account creation (mocked RPC)
   - VRF keypair generation and encryption
   - NEAR keypair derivation
   - IndexedDB storage operations
   - Contract verification workflow

2. **Login Flow E2E**: Complete authentication testing
3. **Transaction Signing E2E**: End-to-end transaction workflows
4. **Error Handling**: Network failures, browser compatibility, etc.

## Development Notes

- Tests use `page.evaluate()` to run SDK code in browser context
- NEAR RPC calls are mocked using `page.route()`
- Worker files must be available at `/workers/` path
- All tests require the frontend dev server running

## PasskeyManager E2E Testing Strategy

### Overview
Comprehensive end-to-end testing using **real NEAR network integration** instead of mocked services. Tests validate the complete system against actual NEAR testnet conditions.

### Testing Philosophy
- **Real Browser APIs**: IndexedDB, Web Crypto, WebAuthn (with virtual authenticators)
- **Real NEAR Network**: Testnet RPC calls, block data, account operations
- **Real Account Creation**: Faucet service integration with rollback testing
- **Comprehensive Rollback**: Both IndexedDB cleanup AND onchain account deletion

### Current Test Coverage

#### 1. Real IndexedDB Operations
- **Atomic transactions** with proper rollback behavior
- **Data storage and retrieval** for passkey credentials

#### 2. Real NEAR RPC Integration
- **Block data retrieval** from testnet (`rpc.testnet.near.org`)
- **Account existence checks** (both existing and non-existent accounts)
- **Access key queries** and permission validation
- **Error handling** for network failures and invalid requests

#### 3. Real Account Creation with Rollback
- **Testnet faucet integration** (`helper.nearprotocol.com/account`)
- **Account verification** after creation
- **Rollback simulation** using `deleteAccount` transactions

### Browser Projects

#### `chromium-web3-authn`
- Chrome with Web Authentication testing API enabled
- Virtual authenticator support for WebAuthn operations
- Real IndexedDB and crypto operations

#### `webkit-touchid`
- Safari/WebKit with TouchID simulation
- Real biometric authentication testing
- SSL certificate handling for `https://example.localhost`

### Running Tests

```bash
# All tests (real NEAR network integration)
pnpm test

# Specific browser project
npx playwright test --project=chromium-web3-authn

# Single test scenario
npx playwright test --grep "rollback scenarios"
```
### Next Steps for Full WebAuthn Testing

1. **Virtual Authenticator Setup**
   ```typescript
   // Add to test setup
   await context.addInitScript(() => {
     if (window.PublicKeyCredential) {
       // Configure virtual authenticator for WebAuthn testing
     }
   });
   ```

2. **Real PasskeyManager Integration**
   ```typescript
   // Import real SDK (requires build system setup)
   import { PasskeyManager } from '@web3authn/passkey';

   // Test with real WebAuthn flows
   await passkeyManager.registerPasskey('test.testnet', {
     onEvent: (event) => console.log(event)
   });
   ```