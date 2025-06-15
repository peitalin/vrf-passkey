# PRF Session Manager Architecture

## Overview

The PRF Session Manager is a generalized system that allows **one PRF attestation (TouchID) to be reused for N subsequent contract calls**. This dramatically improves user experience by reducing biometric authentication prompts while maintaining security through configurable policies.

### Current Problem
- Each contract call requires separate PRF authentication (TouchID)
- Login flow requires 2-3 TouchID prompts
- Poor UX for multi-step operations (DeFi, batch transactions)
- No session management for authenticated operations

### Solution
A session-based architecture where:
1. **Single TouchID** creates a PRF session
2. **Multiple contract calls** reuse the same PRF output
3. **Configurable policies** control session behavior
4. **Security boundaries** prevent misuse

## Architecture

### Core Components

#### 1. PRFSession Class
```typescript
class PRFSession {
  private prfOutput: ArrayBuffer;        // Encrypted PRF output
  private username: string;              // Session owner
  private expiresAt: number;             // Session expiration
  private allowedMethods: Set<string>;   // Whitelisted methods
  private usageCount: number;            // Call counter
  private maxUsage: number;              // Usage limit

  canExecute(methodName: string): boolean;
  executeContractCall(...): Promise<FinalExecutionOutcome>;
}
```

#### 2. Session Configuration
```typescript
interface PRFSessionConfig {
  ttlMs: number;                    // Time-to-live
  maxUsage: number;                 // Max calls per session
  allowedMethods: string[];         // Method whitelist
  requiresReauth?: string[];        // Methods needing fresh auth
  autoRefresh?: boolean;            // Auto-renew capability
}
```

#### 3. Enhanced PasskeyManager
```typescript
class PasskeyManager {
  private prfSessions: Map<string, PRFSession>;

  createPRFSession(username, config): Promise<PRFSession>;
  executeBatchWithPRF(username, calls[]): Promise<Results[]>;
  performOptimizedServerlessLogin(username): Promise<LoginResult>;
}
```

### Predefined Session Types

#### LOGIN_FLOW
- **Duration**: 1 minutes
- **Max Usage**: 2 calls
- **Allowed Methods**: `generate_authentication_options`, `verify_authentication_response`
- **Use Case**: Complete login/registration flows

#### TRANSACTION_BATCH
- **Duration**: 1 minutes
- **Max Usage**: 5 calls
- **Allowed Methods**: `transfer`, `call_contract`, `stake`
- **Use Case**: DeFi operations, batch transactions

#### ADMIN_SESSION
- **Duration**: 10 minutes
- **Max Usage**: 50 calls
- **Allowed Methods**: All methods
- **Sensitive Methods**: Require re-authentication
- **Use Case**: Administrative operations

## Memory Security Analysis

### Current Architecture Security Assessment

#### ✅ **Strong Points in Current Implementation**

**1. WASM Worker Isolation**
- Private keys **never exist in JavaScript memory**
- All cryptographic operations happen in Rust WASM sandbox
- Workers are **one-time use** and self-terminate after operations
- No persistent worker state between operations

**2. Rust Memory Safety**
- Rust's ownership system prevents many memory safety issues
- Stack-allocated arrays for sensitive data (e.g., `[u8; 32]` for keys)
- Automatic memory cleanup when variables go out of scope

**3. Current Key Handling Pattern**
```rust
fn decrypt_private_key_with_prf_internal(...) -> Result<SigningKey, JsValue> {
    // 1. Derive decryption key (stack allocated)
    let decryption_key = derive_encryption_key_from_prf_core(...)?;

    // 2. Decrypt private key (temporary string)
    let decrypted_private_key_str = decrypt_data_aes_gcm(...)?;

    // 3. Parse and create SigningKey (stack allocated seed)
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::from_bytes(&key_array);

    // 4. All intermediate values dropped when function returns
    Ok(signing_key)
}
```

### ⚠️ **Memory Security Risks for PRF Sessions**

#### **Risk 1: PRF Output Persistence**
**Current Threat**: PRF output stored in JavaScript memory for session duration

```typescript
class PRFSession {
  private prfOutput: ArrayBuffer;  // ⚠️ Sensitive data in JS memory
  // ... session reuses this for multiple calls
}
```

**Risk Level**: **HIGH** for 1-touch N-transaction model
- PRF output contains cryptographic material equivalent to private key access
- JavaScript memory is more vulnerable to inspection than WASM
- Longer session duration = longer exposure window
- Memory dumps, debugging tools, or XSS could potentially access

#### **Risk 2: JavaScript Memory Leaks**
**Potential Issues**:
- `ArrayBuffer` objects not properly cleared
- References held in closures or event handlers
- Browser dev tools memory snapshots
- Accidental logging of PRF data

### 🛡️ **Mitigation Strategies**

#### **Option 1: Non-Extractable CryptoKey Storage (RECOMMENDED)**

**Implementation**:
```typescript
class SecurePRFSession {
  private prfCryptoKey: CryptoKey;  // Non-extractable key

  async storePRF(prfOutput: ArrayBuffer): Promise<void> {
    // Import PRF as non-extractable CryptoKey
    this.prfCryptoKey = await crypto.subtle.importKey(
      'raw',
      prfOutput,
      { name: 'HKDF' },
      false,  // ⭐ Non-extractable - PRF can never be read back
      ['deriveKey', 'deriveBits']
    );

    // Clear original PRF output
    prfOutput.fill(0);
  }

  async executeContractCall(...): Promise<FinalExecutionOutcome> {
    // Derive encryption key for WASM (same as current WASM logic)
    const wasmKey = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        info: new TextEncoder().encode('near-key-encryption'),
        salt: new Uint8Array(0),
        hash: 'SHA-256'
      },
      this.prfCryptoKey,
      256  // 32 bytes for AES-256
    );

    try {
      // Send derived key to WASM worker (not original PRF)
      return await this.callWasmWorker(wasmKey);
    } finally {
      new Uint8Array(wasmKey).fill(0);
    }
  }
}
```

**Advantages**: ✅ **Highly Recommended**
- **Maximum Security**: PRF never exists in plaintext after initial storage
- **Non-extractable**: CryptoKey cannot be read back into JavaScript
- **Standards Compliant**: Proper use of HKDF for key derivation
- **No Architectural Changes**: Works with existing WASM worker design
- **Performance**: Minimal overhead, only derivation cost

#### **Option 2: Explicit Memory Zeroing (Rust)**

**Current Status**: ❌ **Not Implemented**
- No `zeroize` crate usage in current implementation
- No explicit memory clearing in sensitive functions
- Relies on Rust's automatic memory cleanup

**Implementation Strategy**:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
struct SecureBuffer {
    data: Vec<u8>,
}

fn decrypt_private_key_with_prf_internal(...) -> Result<SigningKey, JsValue> {
    let mut decryption_key = derive_encryption_key_from_prf_core(...)?;

    // ... use key for decryption

    // Explicit zeroing before drop
    decryption_key.zeroize();
    Ok(signing_key)
}
```

**Feasibility**: ✅ **High**
- Minimal code changes required
- Add `zeroize = "1.7"` to Cargo.toml
- Wrap sensitive data in `ZeroizeOnDrop` structs
- **Performance**: Negligible overhead (~1-2% for zeroing operations)

#### **Option 3: Encrypted PRF Storage (Alternative)**

**Implementation**:
```typescript
class EncryptedPRFSession {
  private encryptedPRF: ArrayBuffer;
  private sessionKey: CryptoKey;

  async storePRF(prfOutput: ArrayBuffer): Promise<void> {
    // Generate session-specific encryption key
    this.sessionKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Encrypt PRF output
    this.encryptedPRF = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) },
      this.sessionKey,
      prfOutput
    );

    // Clear original
    prfOutput.fill(0);
  }
}
```

**Benefits**: ✅ **Strong Protection**
- PRF never stored in plaintext in JavaScript
- Session key in non-extractable CryptoKey
- Additional layer of encryption

### 📊 **Risk Assessment Matrix**

| Scenario | Current Risk | With CryptoKey | With Zeroize | With Encryption |
|----------|-------------|----------------|--------------|-----------------|
| **Memory Dumps** | HIGH | **LOW** | MEDIUM | LOW |
| **XSS Attacks** | HIGH | **LOW** | HIGH | MEDIUM |
| **Debug Tools** | HIGH | **LOW** | MEDIUM | LOW |
| **Performance** | ✅ Fast | ✅ **Fast** | ✅ Fast | ⚠️ Medium |
| **Implementation** | ✅ Simple | ✅ **Easy** | ✅ Easy | ⚠️ Medium |
| **WASM Compat** | ✅ Full | ✅ **Full** | ✅ Full | ✅ Full |

### 🎯 **Recommended Implementation Strategy**

#### **Phase 1: Immediate (Week 1)**
**Implement Non-Extractable CryptoKey Storage (Option 1)**
```typescript
class SecurePRFSession {
  private prfCryptoKey: CryptoKey;

  async storePRF(prfOutput: ArrayBuffer): Promise<void> {
    this.prfCryptoKey = await crypto.subtle.importKey(
      'raw', prfOutput, { name: 'HKDF' }, false, ['deriveBits']
    );
    prfOutput.fill(0);
  }

  async executeContractCall(...): Promise<FinalExecutionOutcome> {
    const derivedKey = await crypto.subtle.deriveBits(
      { name: 'HKDF', info: new TextEncoder().encode('near-key-encryption'),
        salt: new Uint8Array(0), hash: 'SHA-256' },
      this.prfCryptoKey, 256
    );

    try {
      return await this.callWasmWorker(derivedKey);
    } finally {
      new Uint8Array(derivedKey).fill(0);
    }
  }
}
```

**Benefits**:
- ✅ **Maximum security** - PRF never readable after storage
- ✅ **Minimal changes** to existing architecture
- ✅ **Standards compliant** HKDF usage
- ✅ **No performance impact**

#### **Phase 2: Enhanced (Week 2)**
**Add Rust Memory Zeroing (Option 2)**
```rust
// Add to Cargo.toml
zeroize = "1.7"

// Modify sensitive functions
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
struct SensitiveData {
    decryption_key: Vec<u8>,
    private_key_bytes: Vec<u8>,
}
```

#### **Phase 3: Production Hardening (Week 3+)**
**Additional Security Measures**
- Session timeout enforcement
- Memory usage monitoring
- Audit logging for PRF operations
- Performance optimization

### 🔒 **Security Best Practices**

#### **For PRF Session Manager**
1. **Non-Extractable Storage**: Use CryptoKey for PRF storage
2. **Immediate Clearing**: Clear derived keys after each use
3. **Session Isolation**: Separate CryptoKey per user session
4. **Timeout Enforcement**: Aggressive session expiration
5. **Audit Logging**: Track PRF derivation and usage

#### **For Rust WASM Worker**
1. **Zeroize Integration**: Clear all sensitive intermediate values
2. **Stack Allocation**: Prefer stack over heap for sensitive data
3. **Minimal Lifetime**: Keep sensitive data in scope as briefly as possible
4. **Secure Defaults**: Zero-initialize all arrays before use

### 📈 **Performance Impact Analysis**

| Mitigation | Memory Overhead | CPU Overhead | Implementation Effort |
|------------|----------------|--------------|----------------------|
| **CryptoKey Storage** | -64 bytes/session | <2% | Low (1-2 days) |
| **Zeroize** | None | <1% | Low (1-2 days) |
| **Encrypted Storage** | +32 bytes/session | ~5% | Medium (1 week) |

### 🎯 **Conclusion**

**For the 1-touch N-transaction model**:

1. **Primary Solution**: **Non-extractable CryptoKey storage** provides maximum security with minimal implementation effort
2. **Defense in Depth**: Combine with Rust memory zeroing for comprehensive protection
3. **Implementation Priority**: High - CryptoKey approach should be implemented immediately
4. **Performance**: Negligible impact while providing strong security guarantees

The **CryptoKey approach eliminates the core risk** by ensuring PRF output can never be read back into JavaScript memory after initial storage, while maintaining full compatibility with the existing WASM worker architecture.

## Benefits

### User Experience
- ✅ **Single TouchID** for complex multi-step flows
- ✅ **Faster operations** - no repeated authentication delays
- ✅ **Batch transactions** - DeFi, gaming, social operations
- ✅ **Seamless login** - one touch for complete authentication

### Developer Experience
- ✅ **Configurable policies** for different use cases
- ✅ **Simple API** - create session, execute calls
- ✅ **Flexible architecture** - easy to extend
- ✅ **Type-safe** - full TypeScript support

### Security
- ✅ **Time-bounded sessions** - automatic expiration
- ✅ **Usage limits** - prevent session abuse
- ✅ **Method whitelisting** - restrict allowed operations
- ✅ **Sensitive operation protection** - force re-auth when needed

## Tradeoffs

### Advantages
| Aspect | Benefit |
|--------|---------|
| **UX** | 70-90% reduction in TouchID prompts |
| **Performance** | Faster multi-step operations |
| **Flexibility** | Configurable for any use case |
| **Security** | Granular control over permissions |
| **Scalability** | Handles complex application flows |

### Disadvantages
| Aspect | Concern | Mitigation |
|--------|---------|------------|
| **Memory** | PRF output stored in memory | Encrypted storage, auto-cleanup |
| **Session Hijacking** | PRF reuse vulnerability | Time limits, usage limits, method restrictions |
| **Complexity** | More complex architecture | Clear APIs, good documentation |
| **Key Rotation** | Long-lived sessions | Auto-refresh, configurable TTL |

### Security Considerations

#### Risks
- **PRF Output Exposure**: Stored in memory during session
- **Session Replay**: Potential for unauthorized reuse
- **Method Escalation**: Misuse of allowed methods

#### Mitigations
- **Encrypted Storage**: PRF output encrypted at rest
- **Time Bounds**: Sessions auto-expire
- **Usage Limits**: Maximum call count per session
- **Method Whitelisting**: Explicit permission model
- **Sensitive Method Protection**: Force re-auth for critical operations
- **Session Invalidation**: Manual session termination

## Implementation Plan

### Phase 1: Basic PRF Session (Week 1-2)
**Goal**: Single TouchID for login flow

#### Tasks
1. **Create PRFSession class**
   - Basic session management
   - Time-based expiration
   - Usage counting

2. **Enhance PasskeyManager**
   - Add `createPRFSession()` method
   - Add `callFunction2WithPRF()` integration
   - Session storage and cleanup

3. **Optimize Login Flow**
   - Replace 2-TouchID flow with 1-TouchID
   - Use session for `generate_authentication_options` + `verify_authentication_response`

4. **Testing**
   - Unit tests for session management
   - Integration tests for login flow
   - Security testing for session boundaries

#### Success Criteria
- ✅ Login requires only 1 TouchID
- ✅ Session automatically expires
- ✅ No security regressions

### Phase 2: Configurable Sessions (Week 3-4)
**Goal**: Flexible session configuration

#### Tasks
1. **Configuration System**
   - Define `PRFSessionConfig` interface
   - Create predefined session types
   - Method whitelisting implementation

2. **Enhanced Security**
   - Method-specific policies
   - Sensitive operation detection
   - Re-authentication triggers

3. **Batch Operations**
   - `executeBatchWithPRF()` method
   - Transaction batching support
   - Error handling and rollback

4. **Documentation**
   - API documentation
   - Usage examples
   - Security guidelines

#### Success Criteria
- ✅ Multiple session types supported
- ✅ Configurable security policies
- ✅ Batch operations working

### Phase 3: Advanced Features (Week 5-6)
**Goal**: Production-ready session management

#### Tasks
1. **Auto-Refresh**
   - Background PRF renewal
   - Seamless session extension
   - User notification system

2. **Session Analytics**
   - Usage tracking
   - Performance metrics
   - Security monitoring

3. **Advanced Policies**
   - Time-of-day restrictions
   - IP-based policies
   - Device fingerprinting

4. **Integration Examples**
   - DeFi batch operations
   - Gaming transaction flows
   - Social platform interactions

#### Success Criteria
- ✅ Auto-refresh working seamlessly
- ✅ Comprehensive monitoring
- ✅ Real-world use case examples

## API Examples

### Basic Usage
```typescript
// Create session for login
const session = await passkeyManager.createPRFSession(username, 'LOGIN_FLOW');

// Execute multiple calls with single TouchID
await session.executeContractCall('webauthn.near', 'generate_authentication_options', args);
await session.executeContractCall('webauthn.near', 'verify_authentication_response', args);
```

### Batch Operations
```typescript
// DeFi batch with single TouchID
const calls = [
  { contractId: 'dex.near', methodName: 'swap', args: swapArgs },
  { contractId: 'pool.near', methodName: 'add_liquidity', args: liquidityArgs },
  { contractId: 'staking.near', methodName: 'stake', args: stakeArgs }
];

const results = await passkeyManager.executeBatchWithPRF(username, calls);
```

### Custom Configuration
```typescript
// Custom session for specific app needs
const customConfig = {
  ttlMs: 3 * 60 * 1000,           // 3 minutes
  maxUsage: 15,                   // 15 operations
  allowedMethods: ['play_game', 'buy_item', 'trade_nft'],
  requiresReauth: ['buy_premium'] // Premium purchases need fresh auth
};

const gameSession = await passkeyManager.createPRFSession(username, customConfig);
```

## Migration Strategy

### Current State → Phase 1
- Replace `callFunction2()` calls in login flow
- Add session management to existing PasskeyManager
- Maintain backward compatibility

### Phase 1 → Phase 2
- Extend session configuration
- Add batch operation support
- Migrate complex flows to use sessions

### Phase 2 → Phase 3
- Add advanced features incrementally
- Monitor performance and security
- Optimize based on real usage patterns

## Success Metrics

### User Experience
- **TouchID Reduction**: 70%+ fewer biometric prompts
- **Operation Speed**: 50%+ faster multi-step flows
- **User Satisfaction**: Measured via feedback/analytics

### Technical
- **Session Security**: Zero session-related security incidents
- **Performance**: <100ms session overhead
- **Reliability**: 99.9%+ session success rate

### Business
- **Adoption**: Increased usage of multi-step features
- **Retention**: Improved user retention due to better UX
- **Developer Productivity**: Faster feature development

---

*This architecture represents a significant advancement in passkey-based authentication UX while maintaining strong security boundaries through configurable session management.*