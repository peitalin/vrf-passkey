# VRF WebAuthn Contract

A NEAR smart contract implementing VRF (Verifiable Random Function) based WebAuthn authentication for serverless, stateless authentication on the blockchain.

## Overview

This contract provides a dual protocol system for WebAuthn authentication:

1. **VRF WebAuthn Registration** (first-time users): One-time setup storing VRF + WebAuthn credentials
2. **VRF WebAuthn Authentication** (subsequent logins): Stateless verification using stored credentials

The VRF mechanism ensures fresh, unpredictable challenges while maintaining cryptographic verifiability without server-side session state.

## Core Functions

### Contract Initialization

#### `init(contract_name: String) -> Self`

Initializes the contract with default settings.

**Parameters:**
- `contract_name`: String identifier for the contract

**Example:**
```rust
let contract = WebAuthnContract::init("my-app.testnet".to_string());
```

---

### VRF Registration (First-Time Users)

#### `verify_registration_response(vrf_data: VRFVerificationData, webauthn_data: WebAuthnRegistrationData) -> VerifiedRegistrationResponse`

Verifies VRF proof + WebAuthn registration, stores credentials on-chain for future stateless authentication.

**Parameters:**

`VRFVerificationData`:
```rust
{
    vrf_input_data: Vec<u8>,    // Hashed session info, block data, domain separator
    vrf_output: Vec<u8>,        // 64-byte VRF output (used as WebAuthn challenge)
    vrf_proof: Vec<u8>,         // Cryptographic proof of VRF computation
    public_key: Vec<u8>,        // VRF public key (32 bytes, Ed25519)
    rp_id: String,              // Relying Party ID (domain)
}
```

`WebAuthnRegistrationData`:
```rust
{
    registration_response: RegistrationResponseJSON  // Standard WebAuthn registration
}
```

**Returns:**
```rust
{
    verified: bool,
    registration_info: Option<RegistrationInfo>
}
```

**Usage Flow:**
1. Client generates VRF keypair and constructs VRF input
2. Client computes VRF proof and output
3. Client uses VRF output (first 32 bytes) as WebAuthn challenge
4. Client performs WebAuthn registration with VRF-generated challenge
5. Client calls this function with VRF data + WebAuthn response
6. Contract verifies VRF proof and WebAuthn registration
7. Contract stores both VRF public key and WebAuthn credentials

---

### VRF Authentication (Subsequent Logins)

#### `verify_authentication_response(vrf_data: VRFAuthenticationData, webauthn_data: WebAuthnAuthenticationData) -> VerifiedAuthenticationResponse`

Verifies VRF proof + WebAuthn authentication using stored credentials (stateless).

**Parameters:**

`VRFAuthenticationData`:
```rust
{
    vrf_input_data: Vec<u8>,    // Fresh session info, block data, domain separator
    vrf_output: Vec<u8>,        // 64-byte VRF output (used as WebAuthn challenge)
    vrf_proof: Vec<u8>,         // Cryptographic proof of VRF computation
    public_key: Vec<u8>,        // VRF public key (must match stored key)
    rp_id: String,              // Relying Party ID (domain)
}
```

`WebAuthnAuthenticationData`:
```rust
{
    authentication_response: AuthenticationResponseJSON  // Standard WebAuthn authentication
}
```

**Returns:**
```rust
{
    verified: bool,
    authentication_info: Option<AuthenticationInfo>
}
```

**Usage Flow:**
1. Client constructs fresh VRF input with current session data
2. Client computes VRF proof and output using stored VRF private key
3. Client uses VRF output (first 32 bytes) as WebAuthn challenge
4. Client performs WebAuthn authentication with VRF-generated challenge
5. Client calls this function with VRF data + WebAuthn response
6. Contract verifies VRF proof matches stored public key
7. Contract verifies WebAuthn authentication against stored credentials
8. Authentication succeeds without server-side session state

---

### VRF Verification Methods

#### `verify_vrf_1(proof_bytes: Vec<u8>, public_key_bytes: Vec<u8>, input: Vec<u8>) -> VerifiedVRFAuthenticationResponse`

VRF verification using the `vrf-contract-verifier` library (lighter, custom implementation).

#### `verify_vrf_2(proof_bytes: Vec<u8>, public_key_bytes: Vec<u8>, input: Vec<u8>) -> VerifiedVRFAuthenticationResponse`

VRF verification using the `vrf-wasm` library (heavier, based on established fastcrypto crate).

**Parameters:**
- `proof_bytes`: VRF proof (typically 80 bytes)
- `public_key_bytes`: VRF public key (32 bytes, Ed25519)
- `input`: VRF input data (32 bytes, SHA256 hash)

**Returns:**
```rust
{
    verified: bool,
    vrf_output: Option<Vec<u8>>,           // 64-byte VRF output if verification succeeds
    authentication_info: Option<String>,
}
```

---

### VRF Settings Management

#### `update_vrf_settings(settings: VRFSettings)`

Updates global VRF configuration (contract owner only).

**Parameters:**
```rust
VRFSettings {
    max_input_age_ms: u64,    // Maximum age for VRF input components (default: 5 minutes)
    max_block_age: u64,       // Maximum block age for block hash validation (default: 100)
    enabled: bool,            // Feature flag for VRF functionality (default: true)
}
```

#### `get_vrf_settings() -> VRFSettings`

Returns current VRF configuration.

---

## VRF Input Construction

The VRF input data must be constructed according to the specification:

```rust
// VRF Input Components
let domain = b"web_authn_challenge_v1";           // Domain separator
let user_id = b"alice.testnet";                   // User identifier
let rp_id = b"example.com";                       // Relying Party ID
let session_id = b"session_uuid_12345";           // Unique session identifier
let block_height = 123456789u64;                  // NEAR block height for freshness
let block_hash = b"block_hash_32_bytes_example";   // NEAR block hash for binding
let timestamp = 1700000000u64;                    // Unix timestamp for auditability

// Construct and hash input
let mut input_data = Vec::new();
input_data.extend_from_slice(domain);
input_data.extend_from_slice(user_id);
input_data.extend_from_slice(rp_id);
input_data.extend_from_slice(session_id);
input_data.extend_from_slice(&block_height.to_le_bytes());
input_data.extend_from_slice(block_hash);
input_data.extend_from_slice(&timestamp.to_le_bytes());

let vrf_input = sha256(&input_data);  // 32-byte SHA256 hash
```

## Security Features

### Domain Separation
- VRF input includes domain separator and RP ID
- Prevents cross-domain attacks and credential reuse

### Freshness Guarantees
- NEAR block height and hash ensure temporal binding
- Configurable time and block age limits prevent replay attacks

### Stateless Authentication
- No server-side session storage required
- VRF public key verification ensures authentic challenges
- WebAuthn verification ensures user presence and authentication

### User Verification
- VRF mode enforces user verification (UV flag) for enhanced security
- Platform authenticators provide biometric authentication

## Error Handling

The contract provides detailed logging for debugging:

- ✅ Success: VRF verification, WebAuthn validation, credential storage
- ❌ Failures: Invalid VRF proofs, mismatched public keys, expired challenges
- 🔍 Debug: Challenge extraction, origin validation, signature verification

## Integration Notes

### Frontend Requirements
1. Generate VRF keypair (Ed25519)
2. Construct VRF input according to specification
3. Compute VRF proof and output
4. Use VRF output as WebAuthn challenge
5. Handle WebAuthn registration/authentication
6. Call contract methods with structured data

### Backend Requirements
1. NEAR blockchain connectivity
2. Block height and hash fetching for VRF input
3. Session management for VRF input construction
4. VRF library integration (either vrf-contract-verifier or vrf-wasm)

## Testing

The contract includes comprehensive test coverage:
- Unit tests for VRF verification logic
- Integration tests for end-to-end flows
- Mock data generation for development
- Performance optimization tests

Run tests with:
```bash
cargo test
```

## Deployment

Deploy to NEAR testnet:
```bash
./deploy.sh
```

Initialize the contract:
```bash
near call $CONTRACT_ID init '{"contract_name": "my-app.testnet"}' --accountId $ACCOUNT_ID
```

---

For detailed implementation examples and SDK integration, see the `/packages/passkey/` directory and frontend examples.