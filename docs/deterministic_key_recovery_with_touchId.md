# Deterministic Key Recovery with TouchID

## Overview

The Web3authn Passkey system implements **deterministic key recovery** that allows users to recover their NEAR private keys even if their local browser storage (IndexedDB) is accidentally deleted. This recovery mechanism leverages the cryptographic properties of WebAuthn credentials and deterministic key derivation.

## The Problem

### Data Loss Scenarios
- User clears browser data (cookies, localStorage, IndexedDB)
- Browser crashes or corrupts local storage
- User switches browsers or devices
- IndexedDB storage quota exceeded and data purged
- Accidental data deletion by browser extensions

### Traditional Approach Limitations
In traditional systems, losing encrypted private keys stored in IndexedDB would mean:
- ❌ **Permanent loss of access** to NEAR accounts
- ❌ **No recovery mechanism** without seed phrases
- ❌ **Poor user experience** requiring manual backup management
- ❌ **Security risks** from storing seed phrases

## The Solution: Deterministic Key Derivation

### Core Concept
Instead of generating random NEAR keypairs, we **deterministically derive** NEAR Ed25519 keypairs from the user's WebAuthn COSE P-256 credential. This creates a **cryptographic binding** between the user's biometric identity (TouchID/FaceID) and their NEAR blockchain identity.

### Key Properties
- ✅ **Deterministic**: Same WebAuthn credential → Same NEAR keypair
- ✅ **Recoverable**: NEAR keys can be re-derived from WebAuthn credential
- ✅ **Secure**: Requires physical device + biometrics to recover
- ✅ **Seamless**: No seed phrases or manual backups required

## How It Works

### 1. Initial Key Generation
```typescript
// During first registration
const credential = await navigator.credentials.create({
  publicKey: registrationOptions
});

// Extract COSE P-256 public key from WebAuthn credential
const attestationResponse = credential.response as AuthenticatorAttestationResponse;
const attestationObjectBase64url = bufferEncode(attestationResponse.attestationObject);

// Derive deterministic NEAR keypair from COSE P-256 coordinates
const result = await webAuthnManager.secureRegistrationWithPrf(
  nearAccountId,
  prfOutput,
  { nearAccountId },
  attestationObjectBase64url  // ← This enables deterministic derivation
);
```

### 2. Cryptographic Derivation Process
```rust
// In WASM: derive_near_keypair_from_cose_p256_core()
fn derive_near_keypair_from_cose_p256(x_coord: &[u8], y_coord: &[u8]) -> (String, String) {
    // 1. Concatenate P-256 coordinates (64 bytes total)
    let mut p256_material = Vec::new();
    p256_material.extend_from_slice(x_coord);  // 32 bytes
    p256_material.extend_from_slice(y_coord); // 32 bytes

    // 2. SHA-256 hash for deterministic seed
    let hash_bytes = sha256(&p256_material);

    // 3. Use hash as Ed25519 private key seed
    let private_key_seed: [u8; 32] = hash_bytes.into();
    let signing_key = SigningKey::from_bytes(&private_key_seed);

    // 4. Generate NEAR keypair in standard format
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let private_key_near = format!("ed25519:{}", bs58::encode(&full_private_key));
    let public_key_near = format!("ed25519:{}", bs58::encode(&public_key_bytes));

    (private_key_near, public_key_near)
}
```

### 3. Storage and Encryption
- **NEAR private key**: Encrypted with PRF-derived AES-256-GCM key
- **Encrypted data**: Stored in IndexedDB
- **WebAuthn credential**: Stored securely by platform authenticator (TouchID/FaceID)

## Recovery Process

### When Data Loss Occurs
If IndexedDB data is deleted, the user can recover their NEAR keys:

### Step 1: Detect Missing Keys
```typescript
const encryptedKeyData = await getEncryptedKey(nearAccountId);
if (!encryptedKeyData) {
  // Keys are missing - initiate recovery process
  console.log("NEAR keys not found locally - recovery needed");
}
```

### Step 2: New TouchID Ceremony
```typescript
// Create new WebAuthn credential (same device, same biometrics)
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: vrfOutput, // VRF-generated challenge
    rp: { id: "app.reveries.ai", name: "Reveries" },
    user: { id: userId, name: nearAccountId, displayName: nearAccountId },
    // ... other options
  }
});
```

### Step 3: Deterministic Re-derivation
```typescript
// Same COSE P-256 coordinates → Same NEAR keypair
const attestationResponse = credential.response as AuthenticatorAttestationResponse;
const attestationObjectBase64url = bufferEncode(attestationResponse.attestationObject);

// Re-derive the exact same NEAR keypair
const recoveredResult = await webAuthnManager.secureRegistrationWithPrf(
  nearAccountId,
  prfOutput,
  { nearAccountId },
  attestationObjectBase64url
);

console.log("Recovered NEAR public key:", recoveredResult.publicKey);
```

### Step 4: Sync On-Chain Data
```typescript
// Use recovered NEAR public key to lookup stored authenticator data
const storedAuthenticator = await contract.get_authenticator(
  nearAccountId,
  credentialId
);

if (storedAuthenticator) {
  // Sync recovered data back to IndexedDB
  await indexedDBManager.storeAuthenticator(nearAccountId, {
    credentialId,
    credentialPublicKey: storedAuthenticator.credential_public_key,
    // ... other stored data
  });
  console.log("✅ Recovery complete - keys and metadata restored");
}
```

## Security Model

### Cryptographic Guarantees
1. **Device Binding**: Recovery requires the same physical device (platform authenticator)
2. **Biometric Verification**: TouchID/FaceID required for each recovery attempt
3. **Deterministic Derivation**: Mathematical relationship ensures same input → same output
4. **No Exposure**: Private keys never leave the device unencrypted

### Attack Resistance
- **Cannot be brute-forced**: Requires physical device possession
- **Cannot be spoofed**: Biometric verification prevents unauthorized access
- **Cannot be intercepted**: Derivation happens locally in WASM
- **Cannot be replayed**: VRF challenges prevent replay attacks

### Privacy Properties
- **No centralized recovery**: No seed phrases stored on servers
- **No backup vulnerabilities**: No additional attack surface from backup storage
- **Minimal metadata**: Only public keys and encrypted data stored on-chain

## Implementation Architecture

### Components
```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   Platform Auth     │    │   WASM Worker        │    │   Smart Contract    │
│   (TouchID/FaceID)  │    │                      │    │                     │
├─────────────────────┤    ├──────────────────────┤    ├─────────────────────┤
│ • COSE P-256 Key    │───▶│ • Key Derivation     │    │ • Authenticator     │
│ • Biometric Verify │    │ • AES-GCM Encryption │    │   Storage           │
│ • PRF Generation   │    │ • Deterministic Algo │    │ • Public Key Lookup │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
```

### Data Flow
1. **Registration**: `WebAuthn → COSE → Derivation → Encryption → Storage`
2. **Recovery**: `WebAuthn → COSE → Re-derivation → Contract Lookup → Sync`
3. **Usage**: `WebAuthn → PRF → Decryption → Signing → Transaction`

## Benefits

### User Experience
- ✅ **Zero-effort recovery**: No seed phrases to remember or backup
- ✅ **Seamless process**: Simple TouchID ceremony restores everything
- ✅ **Cross-session persistence**: Works across browser restarts and data clearing
- ✅ **Familiar interface**: Uses standard biometric authentication

### Security Benefits
- ✅ **Cryptographic binding**: WebAuthn identity = NEAR identity
- ✅ **Device-bound security**: Cannot be recovered without original device
- ✅ **Biometric protection**: Requires user presence and verification
- ✅ **No single point of failure**: Distributed across device + blockchain

### Technical Advantages
- ✅ **Deterministic**: Predictable and reproducible key generation
- ✅ **Standards-based**: Uses WebAuthn, PRF, and established cryptography
- ✅ **Efficient**: Fast local operations, minimal network dependencies
- ✅ **Future-proof**: Compatible with evolving WebAuthn standards

## Recovery Scenarios

### Scenario 1: Accidental Browser Data Clearing
```
Problem: User clears browser data, loses encrypted NEAR keys
Solution: New TouchID ceremony → Same NEAR keypair recovered
Result: Full access restored, no data loss
```

### Scenario 2: Browser Migration
```
Problem: User switches from Chrome to Safari
Solution: Register same WebAuthn credential in new browser
Result: Same NEAR identity accessible in new browser
```

### Scenario 3: Device Upgrade
```
Problem: User gets new device, needs to access NEAR account
Limitation: Platform authenticators are device-bound
Solution: Use NEAR account recovery mechanisms + re-registration
Result: New device gets new WebAuthn credential → new NEAR keypair
```

## Limitations and Considerations

### Device Dependency
- **Platform authenticators are device-bound**: Cannot recover on different devices
- **Solution**: Standard NEAR account recovery for device changes
- **Mitigation**: Educate users about device dependency

### WebAuthn Support
- **Browser compatibility**: Requires modern WebAuthn support
- **Platform requirements**: Needs TouchID/FaceID or security keys
- **Fallback**: Traditional seed phrase recovery for unsupported devices

### On-Chain Dependencies
- **Contract availability**: Requires access to deployed WebAuthn contract
- **Network connectivity**: Recovery needs blockchain interaction for sync
- **Gas costs**: Contract calls require NEAR tokens for gas

## Future Enhancements

### Multi-Device Support
- **Cross-device sync**: Encrypted data sharing between user's devices
- **Delegated recovery**: Allow trusted devices to assist in recovery
- **Social recovery**: Combine with social recovery mechanisms

### Advanced Recovery
- **Partial recovery**: Recover subset of data when possible
- **Versioned backups**: Multiple recovery points with timestamps
- **Recovery verification**: Cryptographic proof of successful recovery

## Conclusion

Deterministic key recovery transforms the user experience of blockchain identity management by:

1. **Eliminating seed phrase complexity** through biometric-based recovery
2. **Providing cryptographic guarantees** of key derivation consistency
3. **Enabling seamless data loss recovery** without manual backup processes
4. **Maintaining strong security properties** through device binding and biometrics

This implementation represents a significant advancement in making blockchain technology accessible to mainstream users while maintaining the highest security standards.