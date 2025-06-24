# Relay Server Delegate Actions Implementation Plan

## Overview
Implement delegate actions to enable account creation where users sign transactions but the relayer pays gas fees. This follows NEAR's delegate action pattern where users authorize actions through their signatures while the relayer handles broadcasting and gas payment.

## Architecture

### Current State
- ✅ Express server with NEAR client integration
- ✅ Transaction queueing system to prevent nonce conflicts
- ✅ Relayer account management with proper keystore
- ✅ Basic routes structure (health, registration)

### Target Implementation
1. **User Flow**: Creates signed delegate action transaction → sends to relayer
2. **Relayer Flow**: Receives signed delegate → decodes → broadcasts with gas payment

## Required Dependencies

### Missing Dependencies
```json
{
  "@near-js/transactions": "^2.0.1",
  "@near-js/keystores-node": "^2.0.1"
}
```

The `@near-js/transactions` package provides:
- `encodeSignedDelegate` / `decodeSignedDelegate` functions
- `SignedDelegate` class
- Delegate action type definitions

## Implementation Plan

### Phase 1: Core Infrastructure
1. **Add missing dependencies** to package.json
2. **Create delegate service** (`src/services/delegateService.ts`)
   - Handle signed delegate decoding
   - Integrate with existing transaction queue
   - Error handling and validation
3. **Update NEAR service** to support delegate actions
   - Add `SignedTransactionComposer` integration
   - Extend transaction queueing for delegate actions

### Phase 2: API Endpoints
1. **Create `/relay` endpoint** (`src/routes/relay.ts`)
   - Accept encoded signed delegate actions
   - Validate delegate action structure
   - Queue and broadcast transactions
   - Return transaction results
2. **Add account creation endpoint** (`/relay/create-account`)
   - Specialized handling for account creation delegates
   - Additional validation for account creation rules

### Phase 3: Testing & Mock Implementation
1. **Add mock delegate creation** for testing
   - Server-side mock to generate signed delegates
   - Test endpoint for end-to-end validation
2. **Integration testing** with existing queue system
3. **Error handling** for various failure scenarios

## Technical Details

### Signed Delegate Structure
```typescript
interface SignedDelegate {
  delegateAction: DelegateAction;
  signature: Signature;
}

interface DelegateAction {
  senderId: string;
  receiverId: string;
  actions: Action[];
  nonce: bigint;
  maxBlockHeight: bigint;
  publicKey: PublicKey;
}
```

### API Contract

#### POST /relay
```typescript
// Request: Binary encoded SignedDelegate
Content-Type: application/octet-stream
Body: Uint8Array (encoded signed delegate)

// Response: JSON
{
  success: boolean;
  transactionHash?: string;
  outcome?: FinalExecutionOutcome;
  error?: string;
}
```

### Integration Points

#### With Existing Queue System
- Leverage existing `queueTransaction()` method
- Maintain nonce management for relayer account
- Preserve transaction ordering and conflict prevention

#### With Current Account Creation
- Extend beyond `LocalAccountCreator` to support delegate actions
- Maintain compatibility with existing account creation flow
- Add delegate-specific validation rules

## Implementation Steps

### Step 1: Dependencies & Types
- [x] Add `@near-js/transactions` dependency
- [x] Create types for delegate action requests/responses
- [x] Update existing types to support delegate actions

### Step 2: Core Service
- [x] Create `DelegateService` class
- [x] Implement decode/validation logic (placeholder for decode function)
- [x] Integrate with transaction queue

### Step 3: API Layer
- [x] Create relay routes
- [x] Add request validation middleware
- [x] Implement response formatting

### Step 4: Testing
- [x] Add mock delegate creation endpoint
- [x] Test integration with existing queue system
- [x] Validate error handling

## Implementation Status

### ✅ Completed
1. **Dependencies**: Added `@near-js/transactions` and `@near-js/keystores-node`
2. **Core Service**: Created `DelegateService` with full transaction queuing
3. **API Endpoints**:
   - `POST /relay/create-account` - Account creation via delegate actions
   - **Testing**: Comprehensive test script (`test-delegate-flow.js`) with local mock creation
4. **Integration**: Added relay routes to main router
5. **Types**: Extended type definitions for delegate actions
6. **Build**: Project compiles successfully

### ✅ Recently Resolved
1. **Decode Function**: Successfully implemented using Borsh deserialization
   - Added `borsh` dependency for deserialization
   - Used `deserialize(SCHEMA.SignedDelegate, bytes)` with existing schema
   - Properly encode/decode signed delegates using the standard pattern

### 🔄 Next Steps
1. **Environment Setup**: Configure proper relayer account and private key in `.env`
2. **Test with Real Data**: Test with actual signed delegates from frontend
3. **Frontend Integration**: Connect frontend to create and send signed delegates
4. **Production Setup**: Configure rate limiting, monitoring, and security measures

## Security Considerations

### Validation Requirements
- Verify delegate action signature authenticity
- Validate action types (restrict to allowed actions)
- Check account creation permissions
- Implement rate limiting for relay requests

### Gas Management
- Monitor relayer account balance
- Implement gas estimation for delegate actions
- Add configurable gas limits per action type

## Monitoring & Diagnostics

### Extend Existing Queue Diagnostics
- Track delegate action success/failure rates
- Monitor gas consumption by action type
- Add delegate-specific error categorization

### New Metrics
- Delegate actions processed per timeframe
- Average gas cost per delegate action type
- User account creation success rates via delegates