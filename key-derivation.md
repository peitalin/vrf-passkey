# WebAuthn + NEAR Key Management Architecture

This document outlines the secure key management architecture used in the WebAuthn + NEAR integration.
The system uses a **frontend-managed, randomly-generated** NEAR key approach with WebAuthn PRF-based encryption.

### Core Security Principles

1. **No Deterministic Derivation**: NEAR keys are generated using cryptographically secure random number generation
2. **Frontend Key Management**: All NEAR key operations happen on the client side
3. **Contract Verification Only**: Smart contracts verify WebAuthn credentials, never derive or manage NEAR keys
4. **PRF-Based Encryption**: Private keys are encrypted using WebAuthn PRF extension output
5. **Zero Key Correlation**: No mathematical relationship between WebAuthn credentials and NEAR keys

## Architecture Components

### Frontend (Browser/Client)
- **Key Generation**: Uses `getrandom()` for cryptographically secure random NEAR Ed25519 keypair generation
- **PRF Encryption**: Encrypts private keys using WebAuthn PRF extension output with HKDF
- **Local Storage**: Stores encrypted private keys in IndexedDB
- **Transaction Signing**: Decrypts and signs NEAR transactions locally in isolated WASM workers

### Contract (NEAR Blockchain)
- **WebAuthn Verification**: Validates WebAuthn challenges, origins, signatures, and RP IDs
- **Credential Storage**: Stores WebAuthn credential information only
- **Access Control**: Authorizes actions based on successful WebAuthn verification

### Security Flow

```
1. User Registration:
   Browser → WebAuthn Create → Random NEAR Keypair → PRF Encrypt → Store Locally
                          ↓
   Browser → WebAuthn Response → Contract Verify → ✅ Store Credential Info

2. Transaction Signing:
   Browser → WebAuthn Get + PRF → Decrypt NEAR Key → Sign Transaction → Broadcast
                               ↓
   Contract → Verify WebAuthn Response → ✅ Authorize Action
```

## Implementation Details

### Random Key Generation
```rust
// In WASM worker (Rust)
pub fn generate_near_keypair() -> Result<String, JsValue> {
    let mut private_key_bytes = [0u8; 32];
    getrandom(&mut private_key_bytes)?; // Cryptographically secure random

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    // ... encode in NEAR format
}
```

### PRF-Based Encryption
```rust
// Encrypt with WebAuthn PRF output
pub fn generate_and_encrypt_near_keypair_with_prf(
    prf_output_base64: &str,
) -> Result<String, JsValue> {
    // Generate random keypair
    let keypair_json = generate_near_keypair()?;

    // Derive encryption key from PRF
    let encryption_key = derive_encryption_key_from_prf_core(
        prf_output_base64,
        "near-key-encryption",
        ""
    )?;

    // Encrypt private key
    let encrypted_result = encrypt_data_aes_gcm(private_key, &encryption_key)?;
    // ...
}
```

### Contract Verification (No Key Derivation)
```rust
// Contract only verifies WebAuthn - no key operations
pub fn verify_registration_response(
    &self,
    attestation_response: RegistrationResponseJSON,
    // ... verification parameters
) -> VerifiedRegistrationResponse {
    // 1. Verify challenge, origin, RP ID
    // 2. Verify WebAuthn signature
    // 3. Store credential info ONLY

    VerifiedRegistrationResponse {
        verified: true,
        registration_info: Some(RegistrationInfo {
            credential_id: attested_cred_data.credential_id,
            credential_public_key: attested_cred_data.credential_public_key,
            counter: auth_data.counter,
            user_id: attestation_response.id,
            // NO derived_near_public_key field
        })
    }
}
```

## Security Benefits

### 1. **Private Key Isolation**
- NEAR private keys never leave the frontend
- Contract cannot derive private keys
- Separation of WebAuthn and NEAR key domains

### 2. **PRF Protection**
- Private keys encrypted with WebAuthn PRF extension output
- Requires both stored encrypted key and WebAuthn authentication to decrypt
- Provides additional layer of biometric/PIN protection

### 3. **Frontend Security**
- Uses browser's secure random number generation
- Keys encrypted at rest in IndexedDB
- Supports secure key backup/recovery flows


## Threat Model Protection

This architecture protects against:

- **Contract Compromise**: Contract cannot access or derive NEAR private keys
- **WebAuthn Key Compromise**: No mathematical path to NEAR keys
- **Key loss**: No servers, no reliance on central points of failure and loss of keys
- **Replay Attacks**: WebAuthn challenge/response prevents replay
- **Key Correlation**: No linkage between WebAuthn and NEAR key domains

## Production Considerations

- **Key Backup**: Implement secure key export/import for user recovery
- **Multi-Device**: PRF-based encryption enables secure cross-device sync
- **Fallback Auth**: Consider recovery mechanisms for WebAuthn unavailability
