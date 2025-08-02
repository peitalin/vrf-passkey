# WebAuthn Contract Limitations

## Constraints

| Feature | Status | Gas Cost | Impact | Details |
|---------|--------|----------|--------|---------|
| **x5c Chain Validation** | Leaf only | +1-3 TGas | Low | [x5c_support.md](limitations/x5c_support.md) |
| **Full Chain Verification** | Not implemented | +20-100 TGas | High | [x5c_support.md](limitations/x5c_support.md) |
| **AAGUID Validation** | Not implemented | +3-6 TGas | Medium | [aaguid_metadata_validation.md](limitations/aaguid_metadata_validation.md) |
| **Revocation Checking** | Impossible | N/A | High | [x5c_support.md](limitations/x5c_support.md) |
| **Auto Key Cleanup** | Manual only | +17-35 TGas | Medium | [link_device_cleanup_stale_keys.md](limitations/link_device_cleanup_stale_keys.md) |

### **Blockchain Constraints**
- ❌ **No HTTP access**: Cannot query OCSP, CRL, or FIDO MDS
- ⚠️ **Gas costs**: Full validation adds 10-30x overhead

## Detailed Documentation

### **[x5c Certificate Chain Validation](limitations/x5c_support.md)**
**Issue**: Limited certificate chain validation due to blockchain constraints
**Current**: Leaf certificate parsing only (+1-3 TGas)
**Challenge**: Full chain verification adds 20-100+ TGas (10-30x cost increase)
**Impossible**: OCSP/CRL revocation checking (no HTTP access)
**Solution**: Graceful fallback to self-attestation, optional vendor fingerprinting

### **[AAGUID Metadata Validation](limitations/aaguid_metadata_validation.md)**
**Issue**: Cannot validate authenticator trust against FIDO Metadata Service
**Current**: No AAGUID validation implemented
**Challenge**: No network access to query live FIDO MDS
**Proposed**: Embedded metadata subset with periodic contract upgrades
**Cost**: +3-6.5 TGas for full validation (17-32% increase)
**Benefits**: Authenticator trust, certification assurance, vulnerability protection

### **[Device Linking Stale Key Cleanup](limitations/link_device_cleanup_stale_keys.md)**
**Issue**: Temporary keys remain on user accounts if device linking fails
**Current**: Manual cleanup required by users
**Challenge**: Contract cannot directly delete user account keys (permission restrictions)
**Proposed**: Temporary access key delegation with yield-resume scheduling
**Cost**: +17-35 TGas for automated cleanup vs ~2-5 TGas manual
**Complexity**: Requires temporary access key delegation and race condition handling

