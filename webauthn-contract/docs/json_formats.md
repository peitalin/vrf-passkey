# WebAuthn Contract JSON Formats

This document describes the JSON serialization formats for the key structs and enums used in the WebAuthn contract.

## AuthenticatorOptions

Options for configuring WebAuthn authenticator behavior during registration.

### JSON Format
```json
{
  "user_verification": "Required" | "Preferred" | "Discouraged" | null,
  "origin_policy": {
    "Single": null
  } | {
    "Multiple": ["sub.example.com", "api.example.com"]
  } | "AllSubdomains" | null
}
```

### Examples

#### Require user verification with multiple allowed origins:
```json
{
  "user_verification": "Required",
  "origin_policy": {
    "Multiple": ["app.example.com", "admin.example.com"]
  }
}
```

#### Preferred user verification with all subdomains allowed:
```json
{
  "user_verification": "Preferred",
  "origin_policy": "AllSubdomains"
}
```

#### Default options (both fields null):
```json
{
  "user_verification": null,
  "origin_policy": null
}
```

## UserVerificationPolicy

User verification policy for WebAuthn authenticators.

### JSON Format
```json
"Required" | "Preferred" | "Discouraged"
```

### Examples

#### Require user verification (PIN, fingerprint, etc.):
```json
"Required"
```

#### Prefer user verification but don't require it:
```json
"Preferred"
```

#### Discourage user verification (for performance):
```json
"Discouraged"
```

## OriginPolicy

Origin policy for WebAuthn authenticators (stored in contract).

### JSON Format
```json
{
  "Single": "https://example.com"
} | {
  "Multiple": ["https://app.example.com", "https://admin.example.com"]
} | "AllSubdomains"
```

### Examples

#### Single origin (strict):
```json
{
  "Single": "https://example.com"
}
```

#### Multiple allowed origins:
```json
{
  "Multiple": ["https://app.example.com", "https://admin.example.com", "https://api.example.com"]
}
```

#### Allow all subdomains of RP ID:
```json
"AllSubdomains"
```

### Notes
- `Single` and `Multiple` variants store full URLs (with protocol)
- `AllSubdomains` allows any subdomain of the RP ID used during registration
- This is the stored policy in the contract, derived from `OriginPolicyInput`

## OriginPolicyInput

Origin policy input for WebAuthn registration (user-provided).

### JSON Format
```json
"Single" | {
  "Multiple": ["sub.example.com", "api.example.com"]
} | "AllSubdomains"
```

### Examples

#### Single origin (uses credential.origin):
```json
"Single"
```

#### Multiple allowed origins (additional to credential.origin):
```json
{
  "Multiple": ["sub.example.com", "api.example.com"]
}
```

#### Allow all subdomains of RP ID:
```json
"AllSubdomains"
```

### Notes
- `Single` uses the credential's origin as the only allowed origin
- `Multiple` adds additional origins to the credential's origin
- `AllSubdomains` allows any subdomain of the RP ID
- This is converted to `OriginPolicy` during registration
- The `Multiple` variant stores domain names (without protocol)

## Usage in Contract Functions

### Registration with AuthenticatorOptions
```rust
// Function signature
pub fn create_account_and_register_user(
    &mut self,
    authenticator_options: Option<AuthenticatorOptions>
) -> Promise
```

### Example calls with JSON

#### Single origin policy with required user verification:
```json
{
  "authenticator_options": {
    "user_verification": "Required",
    "origin_policy": "Single"
  }
}
```

#### Multiple origins policy with preferred user verification:
```json
{
  "authenticator_options": {
    "user_verification": "Preferred",
    "origin_policy": {
      "Multiple": ["app.example.com", "admin.example.com"]
    }
  }
}
```

#### All subdomains policy with discouraged user verification:
```json
{
  "authenticator_options": {
    "user_verification": "Discouraged",
    "origin_policy": "AllSubdomains"
  }
}
```

#### Default options (no authenticator_options parameter):
```json
{
  // No authenticator_options field - uses defaults
}
```

## Serialization Testing

The contract includes comprehensive tests to verify JSON serialization/deserialization:

```bash
# Run serialization tests
cargo test tests::test_authenticator_options_serialization -- --nocapture
cargo test tests::test_origin_policy_enum_serialization -- --nocapture
```

These tests verify:
- Round-trip serialization (struct → JSON → struct)
- All enum variants serialize correctly
- Edge cases (empty strings, empty vectors, special characters)
- Complex nested structures