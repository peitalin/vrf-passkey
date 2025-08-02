# x5c Certificate Chain Validation Support Implementation

## Overview
The WebAuthn contract supports optional `x5c` certificate chain validation for both `packed` and `fido-u2f` attestation formats. This implementation aligns with the [WebAuthn Level 2 spec's requirements for conforming U2F authenticators](https://www.w3.org/TR/webauthn-2/#sctn-conforming-authenticators-u2f).

## Implemented Features

### 1. **Optional x5c Support**
- **Self-attestation**: Works without x5c (existing behavior preserved)
- **Certificate attestation**: Validates x5c certificate chains when present
- **Graceful fallback**: Falls back to self-attestation if x5c is invalid or missing

### 2. **Supported Attestation Formats**
- **`packed`**: Full x5c support with ES256 (P-256) signatures
- **`fido-u2f`**: Complete x5c support for U2F authenticators
- **`none`**: No changes (already supported)

### 3. **Certificate Parsing & Validation**
- Uses `x509-parser` crate for robust X.509 certificate parsing
- Extracts public keys from leaf certificates
- Validates uncompressed P-256 public key format (65 bytes, 0x04 prefix)
- Proper error handling for malformed certificates

## Implementation Details

### Key Functions

#### `validate_certificate_chain(x5c: &[CborValue]) -> Result<VerifyingKey, String>`
- Parses X.509 certificates from DER format
- Extracts P-256 public keys from certificate
- Returns `VerifyingKey` for signature verification

#### `verify_p256_signature_with_key(...)`
- Verifies signatures using certificate-derived public keys
- Handles both self-attestation and certificate-based attestation
- Uses the same verification logic as self-attestation

### Gas Costs

| Operation | Estimated Gas Cost | Notes |
|-----------|-------------------|-------|
| Self-attestation (no x5c) | ~2-3 TGas | Existing cost (unchanged) |
| Basic x5c validation | ~4-6 TGas | +1-3 TGas for certificate parsing |
| Invalid certificate parsing | ~1-2 TGas | Early error, minimal cost |

**Total overhead**: ~1-3 TGas for x5c validation

## WebAuthn Compliance

### Currently Supported
- Certificate chain parsing (leaf certificate)
- Public key extraction from certificates
- P-256 ECDSA signature verification
- Both packed and fido-u2f formats
- Proper error handling and fallbacks

### Test Coverage
- Self-attestation (no x5c) - backwards compatibility
- Invalid x5c format handling
- Empty certificate chain validation
- Certificate parsing error handling
- U2F with and without x5c
- Invalid public key handling


## Limitations

1. **Chain Depth**: Currently validates only leaf certificate
2. **Algorithm Support**: P-256/ES256 only (most common)
3. **Revocation**: No CRL/OCSP checking yet
4. **Root Trust**: No built-in trusted root store

## Full x5c Verification (vs. Our Implementation)

In a normal server environment, complete x5c verification involves:

### Full Chain Verification Process
1. **Parse the chain**: `x5c[0]` = leaf certificate, `x5c[1..n]` = intermediate certificates
2. **Validate each certificate**:
   - Valid X.509 certificate (DER-encoded)
   - Signed by the next certificate in the chain
   - All certificates are not expired (check validity dates)
3. **Check root trust**: Final certificate in chain matches a known trusted root CA
4. **Optional revocation**: Check via OCSP/CRL
5. **Optional metadata**: Use FIDO Metadata Service (MDS) for authenticator validation

### Feasibility on Web3Authn Contract

| Step | Feasible? | On-chain Cost | Implementation Status |
|------|-----------|---------------|----------------------|
| **Parse DER certs (leaf + intermediates)** | ✅ Yes | Moderate (+1-3 TGas per cert) | ✅ Leaf only |
| **Check signature of cert N with public key of cert N+1** | ✅ Yes (but slow) | High (+3-8 TGas per cert) | ❌ Not implemented |
| **Validate certificate time range (`notBefore`/`notAfter`)** | ✅ Yes | Moderate (+0.5 TGas) | ❌ Not implemented |
| **SHA256 hash root cert and compare to trusted list** | ✅ Yes | Low (+0.1-0.5 TGas) | ❌ Not implemented |
| **Verify cert chain depth (e.g. max 3)** | ✅ Yes | Low (+0.1 TGas) | ❌ Not implemented |
| **Verify metadata service, AAGUIDs, extensions** | ❌ No | — | ❌ Cannot implement |
| **Revocation checking (OCSP/CRL)** | ❌ No | — | ❌ Cannot implement |

### Cost Analysis for Full Chain Verification

**Current Implementation**: ~2-3 TGas (leaf cert parsing only)

**Full Chain Verification Costs**:
- **Basic chain (3 certs)**: +15-25 TGas
  - Parse 2 intermediate certs: +2-6 TGas
  - Verify 3 signatures: +9-24 TGas
  - Expiry checks: +1.5 TGas
  - Root trust check: +0.5 TGas
- **Complex chain (5+ certs)**: +30-60 TGas
- **Root CA storage**: +10-50 TGas (one-time setup)

**Total for full verification**: **20-100+ TGas per attestation**

### Why Full Chain Verification is Limited on NEAR

1. **No HTTP/Network Access**: Cannot query OCSP, CRL, or FIDO MDS
2. **Gas Costs**: 10-30x increase in verification costs
3. **Storage Costs**: Maintaining root CA stores would be expensive
4. **Complexity**: Intermediate certificate validation adds significant complexity
5. **Diminishing Returns**: Most security benefit comes from leaf cert validation

## Security Enhancement Discussion

### **NICE-TO-HAVE (if you can afford the gas)**

#### 1. **Certificate Chain Parsing of Intermediate Certs**
At the moment we only parse the leaf certificate. Future enhancments with Certificate Validity Checks are possible: Validate that leaf cert is not expired (validity dates are in the DER)
**Gas Cost**: +1-2 TGas for additional parsing

#### 2. **Basic Certificate Fingerprint Checks**
If you expect known vendor certs (e.g. YubiKey, Apple), you can SHA256 the leaf cert and match against hardcoded list.

```rust
// Simple vendor verification
const KNOWN_VENDOR_FINGERPRINTS: &[&[u8; 32]] = &[
    &YUBIKEY_ROOT_FINGERPRINT,
    &APPLE_WEBAUTHN_ROOT_FINGERPRINT,
    // Add more as needed
];

fn is_known_vendor_cert(cert_bytes: &[u8]) -> bool {
    let fingerprint = env::sha256(cert_bytes);
    KNOWN_VENDOR_FINGERPRINTS.iter().any(|&known| known == &fingerprint)
}
```

This is simple (1 hash + compare), and adds protection against unknown/unverified keys.

**Gas Cost**: +0.5 TGas for SHA256 + lookup

### **NOT NECESSARY ON-CHAIN**
These features are left outdue to complexity, gas costs, or external dependencies:

#### 1. **AAGUID Matching**
Validating against metadata requires a registry oracle which you can't query on-chain efficiently (requires promises, turning authentication into non-view calls).

*Note: See `aaguid_metadata_validation.md` for a future embedded approach that could work.*

#### 2. **Apple/Android Extension Claims**
These require parsing proprietary JSON or CBOR blobs and verifying against an HTTPS origin (e.g. Apple's attestation root).

#### 3. **Revocation, CRL, OCSP**
Totally out of scope as HTTP requests not available from within contracts

