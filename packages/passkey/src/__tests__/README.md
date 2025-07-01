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

# PasskeyManager Testing Suite

## Overview

This testing suite provides comprehensive coverage for the PasskeyManager SDK, including success flows, failure scenarios, and rollback verification.

## Test Structure

### E2E Tests
- `wasm-workers.test.ts` - Core functionality tests with real WASM workers
- `registration-rollback.test.ts` - Comprehensive failure scenario testing
- `example-template.test.ts` - Template for new test files

### Test Utilities
- `utils/setup.ts` - Reusable setup functions for PasskeyManager testing

## Registration Failure Testing Strategy

### Failure Categories

The `registerPasskey` function has multiple failure points that require different rollback strategies:

#### 1. **Early Failures (No Rollback Needed)**
These failures occur before any persistent state is created:

```typescript
// Input validation failures
- Invalid NEAR account ID format
- Insecure context (non-HTTPS)

// WebAuthn setup failures
- VRF keypair generation failure
- WebAuthn ceremony failure (user cancelled TouchID)
- NEAR keypair derivation failure
- Contract verification failure (checkCanRegisterUser)
```

**Testing Approach:**
- Mock the specific component to throw errors
- Verify failure occurs quickly without rollback events
- No cleanup verification needed

**Example:**
```typescript
test('should handle VRF generation failure', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const { passkeyManager } = (window as any).testUtils;

    // Mock VRF failure
    passkeyManager.webAuthnManager.generateVrfKeypair = async () => {
      throw new Error('VRF worker unavailable');
    };

    const events: any[] = [];
    const result = await passkeyManager.registerPasskey(testAccountId, {
      onEvent: (event: any) => events.push(event)
    });

    return {
      success: result.success,
      error: result.error,
      rollbackEvents: events.filter(e => e.message?.includes('Rolling back'))
    };
  });

  expect(result.success).toBe(false);
  expect(result.rollbackEvents.length).toBe(0); // No rollback needed
});
```

#### 2. **Account Creation Failures (No Rollback Needed)**
Account creation through faucet service fails before any persistent state:

```typescript
// Faucet service failures
- Rate limiting (HTTP 429)
- Service unavailable (HTTP 5xx)
- Network timeouts
```

**Testing Approach:**
- Mock `fetch` to simulate faucet failures
- Verify no account was created (no rollback needed)

**Example:**
```typescript
// Mock faucet service failure
window.fetch = async (url: any, options: any) => {
  if (url.includes('helper.testnet.near.org')) {
    return new Response('Rate limit exceeded', { status: 429 });
  }
  return originalFetch(url, options);
};
```

#### 3. **Account Rollback Failures**
These occur after account creation but before database storage:

```typescript
// Post-account-creation failures
- Contract registration failure (signVerifyAndRegisterUser)
- Transaction broadcast failure
- Access key propagation timeout
```

**Rollback Strategy:**
- Account deletion using pre-signed `deleteAccount` transaction
- Database cleanup not needed (nothing stored yet)

**Testing Approach:**
```typescript
test('should handle contract registration failure with account rollback', async ({ page }) => {
  // Mock contract registration failure
  passkeyManager.webAuthnManager.signVerifyAndRegisterUser = async () => {
    throw new Error('Contract registration failed');
  };

  // Verify account rollback occurs
  expect(rollbackEvents.some(e => e.message?.includes('Rolling back NEAR account'))).toBe(true);
});
```

#### 4. **Full Rollback Failures**
These occur after both account creation and database storage:

```typescript
// Late-stage failures
- VRF unlock failure (final step)
- Post-storage validation failures
```

**Rollback Strategy:**
- Database cleanup (`rollbackUserRegistration`)
- Account deletion using pre-signed transaction
- Contract state remains (immutable)

**Testing Approach:**
```typescript
test('should handle VRF unlock failure with full rollback', async ({ page }) => {
  // Mock VRF unlock failure after everything is complete
  passkeyManager.webAuthnManager.unlockVRFKeypair = async () => {
    throw new Error('VRF decryption failed');
  };

  // Verify both database and account rollback
  expect(rollbackEvents.some(e => e.message?.includes('Rolling back database'))).toBe(true);
  expect(rollbackEvents.some(e => e.message?.includes('Rolling back NEAR account'))).toBe(true);
});
```

### Rollback Verification

#### Database Rollback Verification
```typescript
async function verifyDatabaseClean(accountId: string) {
  const hasUserData = await passkeyManager.webAuthnManager.indexdbCalls.hasUserData(accountId);
  const hasKeyData = await passkeyManager.webAuthnManager.indexdbCalls.hasEncryptedKey(accountId);
  return !hasUserData && !hasKeyData;
}
```

#### Account Rollback Verification
```typescript
async function verifyAccountDeleted(accountId: string) {
  try {
    await nearRpcProvider.viewAccount(accountId);
    return false; // Account still exists
  } catch (error) {
    return error.message.includes('does not exist'); // Account deleted
  }
}
```

#### Contract Rollback Verification
```typescript
// Note: Contract state is immutable on blockchain
// Rollback is not possible for contract registrations
// Users can re-register to overwrite existing entries
```

### Advanced Failure Scenarios

#### 5. **Partial Rollback Failures**
Test cases where rollback itself fails:

```typescript
test('should handle rollback failures gracefully', async ({ page }) => {
  // Force registration failure
  passkeyManager.webAuthnManager.unlockVRFKeypair = async () => {
    throw new Error('Final step failure');
  };

  // Also mock rollback failure
  passkeyManager.webAuthnManager.rollbackUserRegistration = async () => {
    throw new Error('Database rollback failed');
  };

  // Should handle rollback failures gracefully
  expect(rollbackErrorEvents.length).toBeGreaterThan(0);
});
```

#### 6. **Concurrent Registration Failures**
Test multiple registrations failing independently:

```typescript
test('should handle concurrent registration failures', async ({ page }) => {
  const testAccounts = [account1, account2, account3];

  // Make only first account fail
  passkeyManager.webAuthnManager.signVerifyAndRegisterUser = async (options: any) => {
    if (options.nearAccountId === testAccounts[0]) {
      throw new Error('Concurrent test failure');
    }
    return originalFunction(options);
  };

  // Verify no cross-contamination between accounts
  const results = await Promise.allSettled(registrationPromises);
  expect(results[0].success).toBe(false); // First fails
  // Others might succeed
});
```

### Running Failure Tests

```bash
# Run all failure tests
npx playwright test registration-failure-rollback.test.ts

# Run specific failure category
npx playwright test registration-failure-rollback.test.ts -g "Input validation"

# Run with debug output
npx playwright test registration-failure-rollback.test.ts --headed --debug
```

### Adding New Failure Tests

1. **Identify the failure point** in the registration flow
2. **Determine rollback requirements** (none, account, database, full)
3. **Create targeted mock** for the specific failure
4. **Verify failure behavior** and rollback completion
5. **Add cleanup verification** as appropriate

```typescript
test('should handle [NEW_FAILURE_TYPE]', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const { passkeyManager, generateTestAccountId } = (window as any).testUtils;
    const testAccountId = generateTestAccountId();

    // 1. Mock the specific failure
    const original = passkeyManager.component.method;
    passkeyManager.component.method = async () => {
      throw new Error('Specific failure message');
    };

    const events: any[] = [];

    try {
      // 2. Execute registration
      const result = await passkeyManager.registerPasskey(testAccountId, {
        onEvent: (event: any) => events.push(event)
      });

      return { success: result.success, error: result.error, events };
    } finally {
      // 3. Restore original
      passkeyManager.component.method = original;
    }
  });

  // 4. Verify failure and rollback
  expect(result.success).toBe(false);
  expect(result.error).toContain('Specific failure message');

  // 5. Verify appropriate rollback level
  const rollbackEvents = result.events.filter(e => e.message?.includes('Rolling back'));
  // Adjust expectation based on failure point
});
```

This comprehensive testing strategy ensures that all failure scenarios are covered and rollback behavior is properly verified.