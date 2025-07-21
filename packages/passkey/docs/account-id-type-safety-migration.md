# Account ID Type Safety Migration Plan

## Overview

This document outlines the migration plan to implement type-safe account ID handling throughout the SDK, distinguishing between `AccountId` and `AccountIdDeviceSpecific`.

## Type Definitions

### AccountId
- **Usage**: On-chain operations, PRF salt derivation, VRF operations, transaction signing
- **Format**: `"serp126.web3-authn-v2.testnet"`
- **Purpose**: Consistent operations that should work across all devices

### AccountIdDeviceSpecific
- **Usage**: IndexedDB storage, passkey storage, local identification
- **Format**: `"serp126.3.web3-authn-v2.testnet"` (device 3)
- **Purpose**: Device isolation to prevent Chrome sync conflicts

## Migration Strategy

### Phase 1: Update Core Type Definitions

#### 1.1 Export Account ID Types
- [x] Create `/core/types/accountIds.ts` with branded types
- [ ] Export types from `/core/types/index.ts`
- [ ] Add to main SDK exports

### Phase 2: Update Core Components

#### 2.1 PasskeyManager Interface
**File**: `packages/passkey/src/core/PasskeyManager/index.ts`

**Methods requiring AccountId**:
```typescript
registerPasskey(nearAccountId: AccountId, options: RegistrationOptions)
loginPasskey(nearAccountId: AccountId, options?: LoginOptions)
executeAction(nearAccountId: AccountId, actionArgs: ActionArgs, options?: ActionOptions)
exportNearKeypairWithTouchId(nearAccountId: AccountId)
recoverAccountWithAccountId(accountId: AccountId, options?: ActionOptions)
```

**Methods requiring AccountIdDeviceSpecific**:
```typescript
hasPasskeyCredential(nearAccountId: AccountIdDeviceSpecific) // Local storage lookup
getLoginState(nearAccountId?: AccountIdDeviceSpecific) // Local state
```

#### 2.2 WebAuthnManager Interface
**File**: `packages/passkey/src/core/WebAuthnManager/index.ts`

**Methods requiring AccountId**:
- `deriveNearKeypairAndEncrypt()` - PRF salt derivation
- `deriveVrfKeypairFromPrf()` - PRF salt derivation
- `generateVrfChallenge()` - Account-specific salt
- `unlockVRFKeypair()` - Decryption operations

**Methods requiring AccountIdDeviceSpecific**:
- `storeUserData()` - IndexedDB storage
- `storeAuthenticator()` - IndexedDB storage
- `getUserData()` - IndexedDB lookup
- `getAuthenticatorsByUser()` - IndexedDB lookup

### Phase 3: Update PasskeyManager Modules

#### 3.1 Registration Flow
**File**: `packages/passkey/src/core/PasskeyManager/registration.ts`

**Changes**:
- `registerPasskey(context, nearAccountId: AccountId)` - On-chain operations
- VRF challenge generation uses `AccountId`
- Storage operations use `AccountIdDeviceSpecific` (generate from base + device 0)

#### 3.2 Login Flow
**File**: `packages/passkey/src/core/PasskeyManager/login.ts`

**Changes**:
- `loginPasskey(context, nearAccountId: AccountId)` - On-chain operations
- VRF unlock uses `AccountId` for consistent PRF salt
- Local storage lookup uses `AccountIdDeviceSpecific`

#### 3.3 Device Linking Flow
**File**: `packages/passkey/src/core/PasskeyManager/linkDevice.ts`

**Changes**:
- QR generation accepts `AccountId`
- VRF operations use `AccountId` for consistent PRF salt
- Storage operations use `AccountIdDeviceSpecific` with device numbers
- Contract calls use `AccountId`

#### 3.4 Account Recovery
**File**: `packages/passkey/src/core/PasskeyManager/recoverAccount.ts`

**Changes**:
- Entry point accepts `AccountId`
- Local storage lookup uses `AccountIdDeviceSpecific`
- VRF operations use `AccountId`

#### 3.5 Actions/Transactions
**File**: `packages/passkey/src/core/PasskeyManager/actions.ts`

**Changes**:
- `executeAction(context, nearAccountId: AccountId)` - On-chain operations
- All transaction signing uses `AccountId`
- VRF operations use `AccountId`

### Phase 4: Update Storage Layers

#### 4.1 IndexedDB Manager
**File**: `packages/passkey/src/core/IndexedDBManager/passkeyClientDB.ts`

**Changes**:
- All storage methods accept `AccountIdDeviceSpecific`
- Database keys use device-specific format
- Add migration utilities for existing data

#### 4.2 VRF Keys Database
**File**: `packages/passkey/src/core/IndexedDBManager/passkeyNearKeysDB.ts`

**Changes**:
- Storage keys use `AccountIdDeviceSpecific`
- VRF keypair encryption uses `AccountId` for PRF salt

### Phase 5: Update TouchID/WebAuthn Components

#### 5.1 TouchID Prompt
**File**: `packages/passkey/src/core/WebAuthnManager/touchIdPrompt.ts`

**Changes**:
- `generateRegistrationCredentials()` - Use `AccountId` for user ID generation consistency
- `getCredentials()` - Accept `AccountIdDeviceSpecific` for local credential lookup
- PRF salt derivation always uses `AccountId`

#### 5.2 Worker Managers
**Files**:
- `packages/passkey/src/core/WebAuthnManager/vrfWorkerManager.ts`
- `packages/passkey/src/core/WebAuthnManager/signerWorkerManager.ts`

**Changes**:
- VRF unlock operations use `AccountId` for consistent PRF salt
- Worker messages specify account ID type clearly

### Phase 6: Update React Components

#### 6.1 Context Provider
**File**: `packages/passkey/src/react/context/index.tsx`

**Changes**:
- State management uses `AccountId` for active account
- Local storage operations use `AccountIdDeviceSpecific`

#### 6.2 Hooks
**Files**:
- `packages/passkey/src/react/hooks/useNearClient.ts`
- `packages/passkey/src/react/hooks/useRelayer.ts`

**Changes**:
- Public APIs use `AccountId`
- Internal storage operations use `AccountIdDeviceSpecific`

### Phase 7: Update Type Definitions

#### 7.1 Core Types
**Files**:
- `packages/passkey/src/core/types/passkeyManager.ts`
- `packages/passkey/src/core/types/webauthn.ts`
- `packages/passkey/src/core/types/signer-worker.ts`
- `packages/passkey/src/core/types/vrf-worker.ts`

**Changes**:
- Update interface definitions to use appropriate account ID types
- Add type guards where necessary
- Update JSDoc with type requirements

### Phase 8: Frontend Integration

#### 8.1 Frontend Components
**File**: `frontend/src/components/PasskeyLoginMenu.tsx`

**Changes**:
- User-facing operations use `AccountId`
- Local state uses `AccountIdDeviceSpecific` when needed

## Implementation Guidelines

### Type Conversion Patterns

```typescript
// Converting from user input (string) to AccountId
const baseAccountId = AccountId.validateBase(userInputAccountId);

// Converting from AccountId to AccountIdDeviceSpecific for storage
const deviceSpecificId = AccountId.toDeviceSpecific(baseAccountId, deviceNumber);

// Converting from AccountIdDeviceSpecific to AccountId for operations
const baseAccountId = AccountId.extractBase(storedAccountId);

// Type-safe checks
if (AccountId.isDeviceSpecific(accountId)) {
  const deviceNumber = AccountId.extractDeviceNumber(accountId);
}
```

### Error Handling

```typescript
// Safe conversion with validation
try {
  const baseAccountId = AccountId.validateBase(userInput);
  // Use for on-chain operations
} catch (error) {
  // Handle device-specific account ID passed where base expected
  const baseAccountId = AccountId.extractBase(userInput);
}
```

## Testing Strategy

### Unit Tests
- Test all conversion functions with edge cases
- Test type guards with various account ID formats
- Test error handling for invalid conversions

### Integration Tests
- Test device linking with type-safe IDs
- Test login/registration flows with both account ID types
- Test storage operations use correct account ID types

## Migration Checklist

### Phase 1: Foundation
- [x] Create `/core/types/accountIds.ts`
- [ ] Export types from main index
- [ ] Add unit tests for account ID utilities

### Phase 2: Core Updates
- [ ] Update PasskeyManager interface
- [ ] Update WebAuthnManager interface
- [ ] Add type annotations to method signatures

### Phase 3: Flow Updates
- [ ] Update registration flow
- [ ] Update login flow
- [ ] Update device linking flow
- [ ] Update account recovery flow
- [ ] Update action/transaction flow

### Phase 4: Storage Updates
- [ ] Update IndexedDB managers
- [ ] Add data migration utilities
- [ ] Test storage operations

### Phase 5: Component Updates
- [ ] Update TouchID components
- [ ] Update worker managers
- [ ] Test PRF salt consistency

### Phase 6: React Updates
- [ ] Update React context
- [ ] Update hooks
- [ ] Test frontend integration

### Phase 7: Type Updates
- [ ] Update all type definitions
- [ ] Add comprehensive JSDoc
- [ ] Run type checking across codebase

### Phase 8: Testing
- [ ] Add comprehensive unit tests
- [ ] Add integration tests
- [ ] Test migration scenarios
- [ ] Performance testing

## Benefits

1. **Type Safety**: Compile-time prevention of account ID misuse
2. **Clear Intent**: Code clearly shows which operations need which account type
3. **Bug Prevention**: Eliminates PRF salt inconsistency bugs
4. **Maintainability**: Easy to understand where each type should be used
5. **Refactoring Safety**: TypeScript will catch incorrect usage during refactoring

## Rollout Strategy

1. **Backward Compatibility**: Keep legacy functions during transition
2. **Gradual Migration**: Update modules one at a time
3. **Type Assertion**: Use type assertions for gradual adoption
4. **Testing**: Comprehensive testing at each phase
5. **Documentation**: Update all documentation with new patterns