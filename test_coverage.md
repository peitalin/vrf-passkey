# PasskeyManager SDK Test Coverage Analysis

## Overview

This document outlines the testing strategy for hardening the PasskeyManager SDK API as we approach v1 feature completion. The analysis identifies critical components that need unit testing, integration testing, and end-to-end testing.

## Current Test Infrastructure

✅ **Existing Setup:**
- Jest test runner with TypeScript support
- jsdom environment for browser API simulation
- Test setup file: `src/test/setup.ts`
- Coverage reporting configured
- ESLint with Jest environment support

❌ **Missing:**
- Actual test files
- Mock implementations for browser APIs
- Test utilities and helpers
- CI/CD test automation

## Priority Testing Areas

### 🔴 **Critical Priority (Must Have for v1)**

#### 1. **Utility Functions** (`src/utils/`)
**Files:** `encoders.ts`, `strings.ts`

**Why Critical:** Pure functions with no side effects, easy to test, high impact on security.

**Test Cases:**
```typescript
// encoders.ts
describe('bufferEncode', () => {
  it('should encode ArrayBuffer to base64url string')
  it('should handle empty buffers')
  it('should remove padding characters')
  it('should replace + and / with - and _')
})

describe('bufferDecode', () => {
  it('should decode base64url string to ArrayBuffer')
  it('should handle missing padding')
  it('should sanitize invalid characters')
  it('should throw on malformed input')
  it('should handle edge cases (empty string, special chars)')
})

describe('publicKeyCredentialToJSON', () => {
  it('should convert AuthenticatorAttestationResponse')
  it('should convert AuthenticatorAssertionResponse')
  it('should handle missing transports')
  it('should throw on unsupported response types')
})
```

#### 2. **Routing Logic** (`src/core/utils/routing.ts`)
**Why Critical:** Core business logic that determines operation modes.

**Test Cases:**
```typescript
describe('determineOperationMode', () => {
  it('should return web2 mode when optimisticAuth is true')
  it('should return serverless mode when optimisticAuth is false')
  it('should include serverUrl in web2 mode')
  it('should not require server in serverless mode')
})

describe('validateModeRequirements', () => {
  it('should validate web2 mode requires serverUrl')
  it('should validate serverless mode requires nearRpcProvider')
  it('should return valid for correct configurations')
  it('should return specific error messages')
})

describe('getModeDescription', () => {
  it('should return descriptive strings for each mode')
})
```

#### 3. **PasskeyManager Core API** (`src/core/PasskeyManager/index.ts`)
**Why Critical:** Main public API surface that users interact with.

**Test Cases:**
```typescript
describe('PasskeyManager', () => {
  describe('constructor', () => {
    it('should initialize with valid config')
    it('should set default values for missing config')
    it('should throw on invalid config')
  })

  describe('configuration methods', () => {
    it('should get current config')
    it('should update config partially')
    it('should validate config updates')
  })

  describe('callFunction', () => {
    it('should dispatch transactions successfully')
    it('should handle RPC errors gracefully')
    it('should validate required parameters')
    it('should use correct gas and deposit defaults')
  })
})
```

### 🟡 **High Priority (Should Have for v1)**

#### 4. **IndexDBManager** (`src/core/IndexDBManager.ts`)
**Why Important:** Data persistence layer, complex async operations.

**Test Cases:**
```typescript
describe('IndexDBManager', () => {
  beforeEach(() => {
    // Mock IndexedDB
  })

  describe('user management', () => {
    it('should register new users')
    it('should retrieve existing users')
    it('should update user data')
    it('should handle duplicate registrations')
  })

  describe('authenticator storage', () => {
    it('should store authenticator data')
    it('should retrieve authenticators by user')
    it('should handle storage errors')
  })

  describe('account ID generation', () => {
    it('should generate valid NEAR account IDs')
    it('should sanitize usernames')
    it('should handle edge cases')
  })
})
```

#### 5. **ContractService** (`src/core/ContractService.ts`)
**Why Important:** Contract interaction logic, complex data transformations.

**Test Cases:**
```typescript
describe('ContractService', () => {
  describe('registration options', () => {
    it('should build valid registration arguments')
    it('should handle existing authenticators')
    it('should generate proper user IDs')
  })

  describe('authentication options', () => {
    it('should build authentication arguments')
    it('should handle allowCredentials')
    it('should set proper verification requirements')
  })

  describe('response parsing', () => {
    it('should parse contract responses correctly')
    it('should handle different response types')
    it('should throw on invalid responses')
  })
})
```

#### 6. **Core Operation Functions**
**Files:** `registration.ts`, `login.ts`, `actions.ts`

**Test Strategy:** Mock heavy dependencies, test business logic flows.

```typescript
describe('registerPasskey', () => {
  it('should complete serverless registration flow')
  it('should complete server-based registration flow')
  it('should handle WebAuthn failures')
  it('should validate PRF requirements')
  it('should emit correct events')
})

describe('loginPasskey', () => {
  it('should authenticate existing users')
  it('should handle serverless login')
  it('should validate PRF output')
  it('should update user data correctly')
})

describe('executeAction', () => {
  it('should sign and broadcast transactions')
  it('should handle authentication failures')
  it('should validate action parameters')
  it('should handle RPC errors')
})
```

### 🟢 **Medium Priority (Nice to Have for v1)**

#### 7. **WebAuthnManager** (`src/core/WebAuthnManager/index.ts`)
**Why Moderate:** Complex but well-encapsulated, harder to unit test due to browser APIs.

**Test Strategy:** Focus on testable methods, mock browser APIs.

```typescript
describe('WebAuthnManager', () => {
  describe('challenge management', () => {
    it('should register challenges')
    it('should validate and consume challenges')
    it('should cleanup expired challenges')
  })

  describe('user data operations', () => {
    it('should store user data')
    it('should retrieve user data')
    it('should handle missing users')
  })

  // Note: WebAuthn operations require extensive mocking
})
```

#### 8. **React Components and Hooks** (`src/react/`)
**Why Moderate:** Important for React users but requires React Testing Library.

**Test Strategy:** Component testing with user interactions.

```typescript
describe('PasskeyProvider', () => {
  it('should provide context to children')
  it('should initialize PasskeyManager correctly')
  it('should handle configuration changes')
})

describe('usePasskeyContext', () => {
  it('should return context values')
  it('should throw when used outside provider')
})
```

### 🔵 **Low Priority (Post-v1)**

#### 9. **WASM Worker** (`src/core/onetimePasskeySigner.worker.ts`)
**Why Low Priority:** Complex integration testing, requires WASM environment.

#### 10. **Type Definitions** (`src/types/`, `src/core/types/`)
**Why Low Priority:** TypeScript provides compile-time validation.

## Test Implementation Plan

### Phase 1: Foundation (Week 1)
1. **Setup comprehensive test utilities**
   ```typescript
   // src/test/utils.ts
   export const createMockPasskeyManager = (config?: Partial<PasskeyManagerConfig>) => { ... }
   export const mockWebAuthnAPI = () => { ... }
   export const createMockCredential = () => { ... }
   ```

2. **Implement utility function tests**
   - `encoders.test.ts`
   - `routing.test.ts`
   - `strings.test.ts`

3. **Setup CI/CD integration**
   - GitHub Actions workflow
   - Coverage reporting
   - Test failure notifications

### Phase 2: Core API (Week 2)
1. **PasskeyManager tests**
   - Constructor and configuration
   - Public method interfaces
   - Error handling

2. **IndexDBManager tests**
   - Mock IndexedDB operations
   - Data persistence scenarios
   - Error conditions

### Phase 3: Business Logic (Week 3)
1. **Core operation tests**
   - Registration flow logic
   - Login flow logic
   - Action execution logic

2. **ContractService tests**
   - Argument building
   - Response parsing
   - Error handling

### Phase 4: Integration (Week 4)
1. **End-to-end scenarios**
   - Complete registration flow
   - Complete login flow
   - Transaction signing flow

2. **React component tests**
   - Provider functionality
   - Hook behavior
   - User interactions

## Test Utilities Needed

### Mock Implementations
```typescript
// src/test/mocks/webauthn.ts
export const mockNavigatorCredentials = {
  create: jest.fn(),
  get: jest.fn()
}

// src/test/mocks/indexeddb.ts
export const mockIndexedDB = {
  open: jest.fn(),
  // ... other IDB methods
}

// src/test/mocks/worker.ts
export const mockWorker = {
  postMessage: jest.fn(),
  terminate: jest.fn(),
  onmessage: null,
  onerror: null
}
```

### Test Data Factories
```typescript
// src/test/factories.ts
export const createTestUser = (overrides?: Partial<User>) => ({ ... })
export const createTestCredential = () => ({ ... })
export const createTestConfig = () => ({ ... })
```

### Custom Matchers
```typescript
// src/test/matchers.ts
expect.extend({
  toBeValidNearAccountId(received) { ... },
  toBeValidBase64Url(received) { ... }
})
```

## Coverage Goals

### Minimum Coverage Targets for v1:
- **Utility functions**: 95%+ (pure functions, easy to test)
- **Core API methods**: 85%+ (main user-facing functionality)
- **Business logic**: 80%+ (registration, login, actions)
- **Data layer**: 75%+ (IndexDBManager, ContractService)
- **Overall project**: 80%+

### Coverage Exclusions:
- WASM worker code (integration tested separately)
- Type definition files
- Development/build configuration files
- Browser API polyfills

## Testing Best Practices

### 1. **Test Structure**
```typescript
describe('ComponentName', () => {
  describe('methodName', () => {
    it('should handle normal case')
    it('should handle edge case')
    it('should throw on invalid input')
  })
})
```

### 2. **Async Testing**
```typescript
it('should handle async operations', async () => {
  const result = await asyncFunction()
  expect(result).toBeDefined()
})
```

### 3. **Error Testing**
```typescript
it('should throw specific error', async () => {
  await expect(functionThatThrows()).rejects.toThrow('Expected error message')
})
```

### 4. **Mock Management**
```typescript
beforeEach(() => {
  jest.clearAllMocks()
})

afterEach(() => {
  jest.restoreAllMocks()
})
```

## Success Metrics

### Quantitative:
- [ ] 80%+ overall test coverage
- [ ] 95%+ utility function coverage
- [ ] 85%+ core API coverage
- [ ] All critical paths tested
- [ ] Zero test failures in CI/CD

### Qualitative:
- [ ] Confident in API stability
- [ ] Easy to add new tests
- [ ] Fast test execution (<30s)
- [ ] Clear test failure messages
- [ ] Comprehensive error scenario coverage

## Next Steps

1. **Immediate (This Week)**:
   - Set up test utilities and mocks
   - Implement utility function tests
   - Configure CI/CD pipeline

2. **Short Term (Next 2 Weeks)**:
   - Core API and business logic tests
   - Integration test scenarios
   - Coverage reporting

3. **Medium Term (Next Month)**:
   - React component tests
   - Performance testing
   - Security testing scenarios

4. **Long Term (Post-v1)**:
   - E2E testing with real browser automation
   - Load testing for concurrent operations
   - Security audit with penetration testing

---

**Note**: This testing strategy focuses on hardening the API for v1 release while maintaining development velocity. The priority system ensures critical functionality is thoroughly tested before public release.