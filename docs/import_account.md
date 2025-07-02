# Import Account Feature Plan

## Overview
Import existing NEAR account using private key, then register with WebAuthn contract.

## Implementation Steps

### 1. Input & Validation
- Accept NEAR private key (base58 encoded string)
- Validate key format and length
- Convert to Ed25519 keypair using `@near-js/crypto`

### 2. Account Discovery
- Extract public key from keypair
- Query NEAR RPC to find account ID associated with public key
- Use `viewAccessKey` across potential account IDs or reverse lookup

### 3. Modified Registration Flow
Reuse `registerPasskey()` but skip account creation:

**Keep:**
- WebAuthn credential creation (`navigator.credentials.create`)
- VRF keypair generation and encryption
- Contract registration (`signVerifyAndRegisterUser`)
- User data persistence to IndexedDB
- Authenticator data storage

**Skip:**
- Testnet faucet account creation
- Account existence checks (account already exists)

### 4. Data Flow
```
Private Key Input → Ed25519 Keypair → Account ID Lookup → WebAuthn Registration → VRF Setup → Contract Registration → Local Storage
```

### 5. New Components
- `importAccount()` method in PasskeyManager
- Private key input UI component
- Account lookup utilities in NearClient

### 6. Error Handling
- Invalid private key format
- Account not found for public key
- WebAuthn registration failures
- Contract registration conflicts (user already registered)

## Integration Points
- Add to PasskeyManager alongside `registerPasskey()`
- Share VRF and encryption flows with existing registration
- Reuse contract interaction patterns from current registration flow