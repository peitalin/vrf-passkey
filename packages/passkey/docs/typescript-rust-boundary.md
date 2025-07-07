# TypeScript/Rust Serialization Boundary - Robust Solutions

This document outlines solutions to make the TypeScript/Rust serialization boundary more robust, addressing issues around mismatched names, input validation, and type safety.

## Current Issues

1. **Manual Type Synchronization**: Parallel type definitions in TypeScript and Rust can drift out of sync
2. **Field Name Mismatches**: Inconsistent naming conventions (`rawId` vs `raw_id`)
3. **Runtime Errors**: No compile-time guarantees that serialized data matches expected types
4. **Fragile JSON Serialization**: Manual serialization prone to errors and inconsistencies

## Solution 1: wasm-bindgen with Structured Types (Recommended)

### Overview
Use `wasm-bindgen` to generate TypeScript bindings directly from Rust, eliminating JSON serialization entirely.

### Implementation
```rust
// In Rust
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct DualPrfOutputs {
    #[wasm_bindgen(getter_with_clone)]
    pub aes_prf_output: String,
    #[wasm_bindgen(getter_with_clone)]
    pub ed25519_prf_output: String,
}

#[wasm_bindgen]
pub fn derive_and_encrypt_keypair_structured(
    dual_prf_outputs: &DualPrfOutputs,
    near_account_id: &str,
) -> Result<EncryptionResult, JsValue> {
    // Direct type-safe access, no JSON parsing
}
```

```typescript
// Generated TypeScript bindings (automatic)
import { DualPrfOutputs, derive_and_encrypt_keypair_structured } from './wasm_signer_worker.js';

const prfOutputs = new DualPrfOutputs(aesPrf, ed25519Prf);
const result = derive_and_encrypt_keypair_structured(prfOutputs, accountId);
```

### Benefits
- ✅ Compile-time type safety
- ✅ No JSON serialization errors
- ✅ Automatic field name consistency
- ✅ Better performance (no string parsing)
- ✅ Rich TypeScript IntelliSense support

### Limitations
- Requires restructuring existing WASM functions
- Limited to simple data types (no complex enums or generics)

## Solution 2: TypeScript Generation from Rust (ts-rs)

### Overview
Automatically generate TypeScript types from Rust structs using `ts-rs`, maintaining single source of truth.

### Implementation
```rust
// In Rust
use ts_rs::TS;

#[derive(Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../core/types/generated/")]
#[serde(rename_all = "camelCase")]
pub struct DualPrfOutputs {
    pub aes_prf_output_base64: String,
    pub ed25519_prf_output_base64: String,
}
```

Generated TypeScript:
```typescript
// Generated automatically
export interface DualPrfOutputs {
  aesPrfOutputBase64: string;
  ed25519PrfOutputBase64: string;
}
```

### Benefits
- ✅ Single source of truth in Rust
- ✅ Automatic field name conversion (snake_case → camelCase)
- ✅ No manual type maintenance
- ✅ Build-time type generation

### Implementation Steps
1. Add `ts-rs = { version = "6.2", features = ["serde-compat"] }` to Cargo.toml
2. Add `#[derive(TS)]` and `#[ts(export)]` attributes to structs
3. Run `cargo test` to generate TypeScript files
4. Import generated types in TypeScript code

## Solution 3: Schema-Based Runtime Validation

### Overview
Use runtime validation with `zod` schemas to catch serialization errors early and provide detailed error messages.

### Implementation
```typescript
import { z } from 'zod';

export const DualPrfOutputsSchema = z.object({
  aesPrfOutputBase64: z.string().min(1, "AES PRF output required"),
  ed25519PrfOutputBase64: z.string().min(1, "Ed25519 PRF output required"),
}).strict();

export class SafeSerializer {
  static serializeForWasm<T>(data: T, schema: z.ZodSchema<T>): string {
    const validated = schema.parse(data);
    return JSON.stringify(validated);
  }

  static deserializeFromWasm<T>(json: string, schema: z.ZodSchema<T>): T {
    const parsed = JSON.parse(json);
    return schema.parse(parsed);
  }
}
```

Usage:
```typescript
// Safe serialization with validation
const request = SafeSerializer.serializeForWasm(
  { dualPrfOutputs, accountId },
  DualPrfDeriveKeypairRequestSchema
);

// Safe deserialization with validation
const response = SafeSerializer.deserializeFromWasm(
  wasmResult,
  KeyGenerationResponseSchema
);
```

### Benefits
- ✅ Runtime type checking
- ✅ Detailed error messages
- ✅ Works with existing JSON serialization
- ✅ Can be added incrementally

## Solution 4: Improved Serde Configuration

### Overview
Better serde attributes for consistent field mapping and validation in Rust.

### Implementation
```rust
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebAuthnCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub response: WebAuthnResponse,

    // Validation
    #[serde(deserialize_with = "validate_prf_outputs")]
    pub client_extension_results: Option<ExtensionResults>,
}

fn validate_prf_outputs<'de, D>(deserializer: D) -> Result<Option<ExtensionResults>, D::Error>
where
    D: Deserializer<'de>,
{
    // Custom validation logic
}
```

### Benefits
- ✅ Consistent field naming
- ✅ Built-in validation
- ✅ Better error messages
- ✅ Prevents unknown fields

## Recommended Migration Strategy

### Phase 1: Immediate Improvements (Low Risk)
1. Add `ts-rs` to generate TypeScript types from key Rust structs
2. Implement schema validation for critical data paths
3. Add better serde attributes for field mapping

### Phase 2: Structured Types (Medium Risk)
1. Convert high-traffic functions to use `wasm-bindgen` structured types
2. Keep JSON functions as fallbacks during transition
3. Add comprehensive tests for type consistency

### Phase 3: Full Migration (High Impact)
1. Replace all JSON serialization with structured types
2. Remove legacy JSON-based functions
3. Add build-time type consistency checks

## Build Process Integration

Add to `package.json`:
```json
{
  "scripts": {
    "generate-types": "./scripts/generate-types.sh",
    "prebuild": "npm run generate-types",
    "type-check": "tsc --noEmit"
  }
}
```

The build process will:
1. Generate TypeScript types from Rust
2. Validate type consistency
3. Run TypeScript compilation
4. Build WASM modules

## Error Handling Improvements

### Before (Error-Prone)
```typescript
const result = JSON.parse(wasmResponse);
const publicKey = result.public_key; // Might be undefined
```

### After (Type-Safe)
```typescript
// With structured types
const result = derive_keypair_structured(input);
const publicKey = result.publicKey; // TypeScript guarantees this exists

// With validation
const result = SafeSerializer.deserializeFromWasm(wasmResponse, ResponseSchema);
const publicKey = result.publicKey; // Runtime validation + type safety
```

## Conclusion

The combination of these approaches provides:

1. **Compile-time Safety**: TypeScript/Rust type consistency
2. **Runtime Safety**: Schema validation catches edge cases
3. **Developer Experience**: Better error messages and IntelliSense
4. **Maintainability**: Single source of truth for types
5. **Performance**: Reduced JSON parsing overhead

Start with **ts-rs** type generation and **zod** validation for immediate benefits, then gradually migrate to structured types for maximum type safety.