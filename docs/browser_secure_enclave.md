# Browser-Based Secure Enclave

## Overview

The Web3authn system implements a **browser-based secure enclave** that functions as an **encrypted vault + isolated execution environment**, authenticated by WebAuthn biometrics and attested by blockchain protocols.

## Architecture Components

### Core Components
- **Authentication Layer**: WebAuthn + NEAR blockchain protocol
- **Execution Environment**: WASM workers with memory isolation
- **Encrypted Storage**: PRF-derived AES-256-GCM vault
- **Isolation Boundary**: Worker + WASM security model
- **Attestation**: Blockchain-based proof of authentication

### Web3authn Secure Enclave
Authentication Layer (WebAuthn + NEAR)
↓
WASM Execution Environment (Isolated)
├── Private keys never leave WASM ✅
├── Signing operations contained ✅
├── Memory isolated from JavaScript ✅
├── Zero secret exposure ✅
└── Blockchain-attested operations via contract Web3authn protocol ✅


## Technical Architecture

### Isolation Boundaries
┌─────────────────────────────────────┐
│ JavaScript Context │
│ │
│ ┌─────────────────────────────┐ │
│ │ WASM Worker │ │
│ │ │ │
│ │ ┌─────────────────────┐ │ │
│ │ │ Secure Enclave │ │ │ ← Private keys live here
│ │ │ │ │ │
│ │ │ 🔐 Private Keys │ │ │ ← Never cross this boundary
│ │ │ 🔐 Signing Ops │ │ │
│ │ │ 🔐 Crypto Ops │ │ │
│ │ │ 🔐 Vault Data │ │ │
│ │ └─────────────────────┘ │ │
│ │ ↑ │ │
│ │ Only results flow out │ │
│ └─────────────────────────────┘ │
│ ↑ │
│ Only operation requests │
└─────────────────────────────────────┘


### Authentication Flow
User Biometric Action (TouchID/FaceID)
↓
WebAuthn PRF Generation
↓
NEAR Contract Verification
↓
WASM Worker Enclave Initialization
↓
Secure Operation Execution


## Advanced Capabilities

### Zero-Knowledge Proof Generation
```typescript
// Generate ZK proofs inside secure enclave
const zkProof = await enclave.execute({
  type: 'GENERATE_ZK_PROOF',
  params: {
    circuit: 'identity_verification',
    private_inputs: {
      secret: vault.getSecret('identity.secret'),
      nonce: randomNonce
    },
    public_inputs: {
      commitment: publicCommitment
    }
  }
});
```

### General Vault Operations
```typescript
// Store any type of secret securely
await enclave.storeSecret('apis.openai', 'sk-...');
await enclave.storeSecret('ssh.production', sshPrivateKey);
await enclave.storeSecret('database.connection', dbString);

// Use secrets without exposing them
const apiKey = await enclave.useSecret('apis.openai', (key) => {
  // This callback runs inside WASM enclave
  return makeAPICall(key, requestData);
});
```

## Comparison to Hardware Security

### Hardware HSM vs Browser Enclave

| Feature | Hardware HSM | Intel SGX | **Web3authn Enclave** |
|---------|--------------|-----------|------------------------|
| **Isolation** | Physical chip | CPU-level | WASM + Worker |
| **Authentication** | PIN/Token | OS-level | Web3Authn + VRF + Blockchain |
| **Portability** | Device-bound | Intel CPUs | Any modern browser |
| **Attestation** | Vendor certs | SGX quotes | NEAR contract |
| **Key Storage** | Hardware | Encrypted memory | Encrypted IndexedDB |
| **Programming** | Vendor SDKs | C/C++ | Rust/WASM |
| **Cost** | $100-1000+ | CPU dependency | Free |
| **Deployment** | Physical setup | OS integration | Web deployment |



## Suggestions to Sharpen the Idea

- Consider TEE-backed WebAssembly runtimes (WASI + TEE on native platforms) as future upgrade path
- Add remote attestation hash of WASM binary to NEAR for integrity checks
- Implement WebAssembly memory hardening:
  - Zero memory after use
  - Use deterministic stack allocation to reduce side channels
- Add session transcript signing to bind biometric ops to WASM execution state

## Suggestions to Sharpen the Idea
Consider supporting TEE-backed WebAssembly runtimes (e.g. using WebAssembly System Interface (WASI) + TEE on native platforms) as a future upgrade path.

Add remote attestation hash of the WASM binary to NEAR for integrity checks (i.e. hash the WASM blob and sign it).



## 🛡 Security Hardening
### 1. Sandboxed Iframes

```html
<iframe sandbox="allow-scripts" src="/wasm-safe-shell.html"></iframe>
```

- Cannot access `window.parent` or main thread context.
- Even if extensions tamper with the main page, they **cannot tamper with iframe contents** unless they break the same-origin policy.
- Possibly use this with private key export / QR code export

### 2. Inline WASM Integrity Verification

- Hash the WASM blob using SHA-256 before instantiating it.
- Compare against a pinned, trusted hash (e.g., from build time or backend).
- Only instantiate if the hash matches.


## Threat Matrix

| Vector                       | Can you block it? | How                                                              |
|-----------------------------|-------------------|------------------------------------------------------------------|
| **XSS**                      | ✅ Mostly          | Avoid `innerHTML`, `eval()`; use CSP + Trusted Types             |
| **Extension overwriting JS** | ❌ Not fully       | Isolate in WASM, use sandboxed iframes, transfer secrets away    |
| **WASM worker tampering**    | ❌ Possible        | Use integrity checks + same-origin isolation                     |
| **PRF-derived secrets**      | ✅ Somewhat safe   | Gated by Touch ID, kept inside WASM, never returned              |

## WASM Worker Integrity ≈ TEE Measurement

Attesting a WASM worker is conceptually similar to how a Trusted Execution Environment (TEE) works.

### Runtime Flow

1. Load the WASM blob (`fetch` or `ArrayBuffer`)
2. Hash it using **SHA-256**
3. Compare to a pinned trusted hash
4. Only then: `WebAssembly.instantiate(...)`
5. Immediately destroy the worker after use

### Security Benefits

- **Stateless TCB**: no persistent memory between calls
- **Tamper detection** before execution
- **Runtime verification** on every use

### ️ Caveats

| Caveat                                                  | Notes                                                                                                                 |
|----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| ✅ WASM workers are thread-isolated                      | Extensions must go out of their way to intercept                                                                     |
| ❌ JS that does the hashing is still in attack surface    | Extensions could override `crypto.subtle`, intercept `fetch`, etc.                                                  |
| ✅ Transferables + memory zeroing help                   | Detach PRF or key buffers from JS memory immediately                                                                |
| 🔒 Not a full TEE                                        | No hardware root of trust unless future browser support (e.g., WASI + Secure Element)                               |

## WASM Hash Verification + NEAR Attestation

### Part 1: Verifying Hash in a WASM-Based Service Worker

**Why this is better than JS:**

- Moves hash logic out of tamperable JS
- Compiled Rust/WASM cannot be monkey-patched
- Prevents access to `crypto.subtle`, `fetch`, etc.

**Implementation Steps:**

1. Load WASM blob in service worker
2. Hash it using `sha2` (`Sha256::digest(...)`)
3. Compare to a hardcoded or signed trusted hash
4. Only if valid, spawn the ephemeral signing worker

### Part 2: Attesting to NEAR Smart Contract

**Purpose**: Prove that a specific trusted WASM worker was used for signing.

#### Workflow

**At Build Time:**

- Compute `SHA-256` of the signing WASM blob
- Store the hash on NEAR via a trusted smart contract

**At Runtime (in Browser):**

1. Hash the blob before use
2. Sign the hash using a **WebAuthn-derived key**
3. Call a NEAR contract method:

```rust
fn attest_worker_hash(worker_hash: Base64, signature: Base64, pubkey: Base64)
```

**On-Chain:**

- Verifies `worker_hash` matches a trusted hash
- Verifies the `signature` against a registered public key
- Optionally logs or stores the attestation

## TEE vs WASM Worker Attestation

| TEE Measurement                                 | WASM Hash Verification                                  |
|------------------------------------------------|---------------------------------------------------------|
| Hardware-measured SHA-256 of binary             | WASM-calculated SHA-256 of module                      |
| Sealed/signed inside chip                       | Pinned or signed hash checked in client or on-chain     |
| Enclave-executed code                           | Worker-executed WASM (sandboxed, disposable)            |
