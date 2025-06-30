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

Basic WASM worker functionality testing:

1. **VRF Worker Tests**:
   - Worker initialization and communication
   - VRF keypair generation with deterministic input
   - VRF challenge generation from in-memory keypair
   - Validates VRF output format and 32-byte challenge generation

2. **Signer Worker Tests**:
   - COSE public key extraction from attestation objects
   - COSE key validation
   - NEAR keypair derivation using mock PRF output
   - Ed25519 key format validation

3. **Worker Coordination Tests**:
   - Both workers operating simultaneously
   - Cross-worker data flow validation
   - Complete cryptographic workflow testing

## Running Tests

```bash
# List available tests
npm run test:e2e -- --list

# Run all tests (requires frontend to be running at localhost:5173)
npm run test:e2e

# Run specific test file
npm run test:e2e wasm-workers

# Run with headed browser (for debugging)
npm run test:e2e -- --headed

# Run specific browser project
npm run test:e2e -- --project=chromium-web3-authn
npm run test:e2e -- --project=webkit-touchid
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