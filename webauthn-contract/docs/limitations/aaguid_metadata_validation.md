# AAGUID Metadata Validation

AAGUID (Authenticator Attestation Global Unique Identifier) validation against FIDO Metadata Service (MDS) data during WebAuthn registration may be possible. This doc outlines how it may be implemented with x5c certificate validation.

## Implementation Phases

- Validate AAGUID against embedded FIDO MDS data
- Check for known vulnerabilities, revocation status, and certification levels
- Support periodic MDS updates without full contract redeployment
- Maintain minimal gas overhead while enhancing security

### Phase 1: AAGUID Extraction & Storage
**Estimated Gas Cost**: +0.5-1 TGas

```rust
// Extract AAGUID from authenticator data (already parsed)
fn extract_aaguid_from_auth_data(auth_data: &AuthenticatorData) -> [u8; 16] {
    auth_data.aaguid
}

// Store AAGUID in registration info for future reference
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub aaguid: [u8; 16], // NEW: Store for validation
}
```

### Phase 2: Embedded MDS Metadata Store
**Estimated Gas Cost**: +1-2 TGas per validation

```rust
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthenticatorMetadata {
    pub aaguid: [u8; 16],
    pub description: String,
    pub certification_level: CertificationLevel,
    pub is_revoked: bool,
    pub known_vulnerabilities: Vec<String>,
    pub attestation_root_certificates: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub enum CertificationLevel {
    NotCertified,
    Level1,
    Level2,
    Level3Plus,
}

// Embedded metadata (updated periodically)
const EMBEDDED_MDS_METADATA: &[u8] = include_bytes!("../metadata/fido_mds_subset.json");
```

### Phase 3: Validation Logic
**Estimated Gas Cost**: +1-2 TGas

```rust
pub fn validate_aaguid_metadata(
    aaguid: &[u8; 16],
    require_certification: bool,
    allow_known_vulnerabilities: bool,
) -> Result<AuthenticatorMetadata, String> {
    // Load embedded metadata
    let metadata_store: HashMap<[u8; 16], AuthenticatorMetadata> =
        serde_json::from_slice(EMBEDDED_MDS_METADATA)
            .map_err(|_| "Failed to parse MDS metadata")?;

    // Lookup authenticator by AAGUID
    let metadata = metadata_store.get(aaguid)
        .ok_or("AAGUID not found in metadata service")?;

    // Check revocation status
    if metadata.is_revoked {
        return Err("Authenticator has been revoked".to_string());
    }

    // Check certification requirements
    if require_certification && matches!(metadata.certification_level, CertificationLevel::NotCertified) {
        return Err("Authenticator is not FIDO certified".to_string());
    }

    // Check known vulnerabilities
    if !allow_known_vulnerabilities && !metadata.known_vulnerabilities.is_empty() {
        return Err(format!("Authenticator has known vulnerabilities: {:?}",
                          metadata.known_vulnerabilities));
    }

    Ok(metadata.clone())
}
```

### Phase 4: Integration with Registration Flow
**Total Additional Cost**: +2-5 TGas

```rust
pub fn verify_and_register_user_with_metadata_validation(
    &mut self,
    vrf_data: VRFVerificationData,
    webauthn_registration: WebAuthnRegistrationCredential,
    deterministic_vrf_public_key: Vec<u8>,
    metadata_policy: MetadataValidationPolicy,
) -> VerifyRegistrationResponse {
    // ... existing verification logic ...

    // NEW: AAGUID metadata validation
    if let Some(policy) = metadata_policy {
        let aaguid = extract_aaguid_from_auth_data(&parsed_auth_data);

        match validate_aaguid_metadata(
            &aaguid,
            policy.require_certification,
            policy.allow_known_vulnerabilities,
        ) {
            Ok(metadata) => {
                log!("Authenticator validated: {}", metadata.description);
                // Optionally store metadata with registration
            }
            Err(e) => {
                log!("AAGUID validation failed: {}", e);
                if policy.enforce_validation {
                    return VerifyRegistrationResponse {
                        verified: false,
                        registration_info: None,
                    };
                }
                // Continue with warning if not enforced
                log!("Continuing registration despite AAGUID validation failure");
            }
        }
    }

    // ... continue with existing registration ...
}

#[derive(Serialize, Deserialize)]
pub struct MetadataValidationPolicy {
    pub require_certification: bool,
    pub allow_known_vulnerabilities: bool,
    pub enforce_validation: bool, // Fail registration if validation fails
}
```

## Metadata Management Strategy

### 1. **Embedded Subset Approach** (Recommended)
- Embed curated subset of FIDO MDS data in contract
- Include only essential fields: AAGUID, certification level, revocation status
- Update via contract upgrade (3-6 month cycles)
- **Pros**: Low gas cost, offline validation, no external dependencies
- **Cons**: Requires periodic updates, limited to subset

### 2. **Dynamic Loading** (Future Enhancement)
- Store metadata in contract storage
- Admin function to update metadata
- **Pros**: More frequent updates, larger dataset
- **Cons**: Higher gas costs, requires privileged operations

### 3. **Hybrid Approach**
- Embedded core metadata for common AAGUIDs
- Optional storage-based metadata for enterprise authenticators
- Fallback to embedded if storage lookup fails

## Gas Cost Breakdown

| Operation | Estimated Cost | Cumulative |
|-----------|---------------|------------|
| Current registration (baseline) | 15-20 TGas | 15-20 TGas |
| + x5c validation | +1-3 TGas | 16-23 TGas |
| + AAGUID extraction | +0.5 TGas | 16.5-23.5 TGas |
| + Metadata lookup | +1-2 TGas | 17.5-25.5 TGas |
| + Policy validation | +0.5-1 TGas | 18-26.5 TGas |

**Total overhead for full validation**: +3-6.5 TGas (17-32% increase)

## Security Benefits

1. **Authenticator Trust**: Verify authenticator is from known manufacturer
2. **Certification Assurance**: Ensure FIDO Alliance certification
3. **Vulnerability Protection**: Block authenticators with known security issues
4. **Compliance Support**: Meet enterprise security requirements
5. **Fraud Prevention**: Detect unauthorized/counterfeit authenticators


## Configuration Examples

### Strict Enterprise Policy
```rust
let strict_policy = MetadataValidationPolicy {
    require_certification: true,
    allow_known_vulnerabilities: false,
    enforce_validation: true,
};
```

### Permissive Consumer Policy
```rust
let permissive_policy = MetadataValidationPolicy {
    require_certification: false,
    allow_known_vulnerabilities: true,
    enforce_validation: false, // Log warnings only
};
```

### Balanced Production Policy
```rust
let balanced_policy = MetadataValidationPolicy {
    require_certification: true,
    allow_known_vulnerabilities: false,
    enforce_validation: true,
};
```