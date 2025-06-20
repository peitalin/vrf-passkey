# Session-Scoped WebAuthn Authorization with VRF Challenges

## Purpose

Enable a single WebAuthn biometric attestation (e.g., TouchID) to unlock a **bounded session** for executing multiple smart contract actions without re-prompting the user for each one.

Session scope is securely derived from a VRF-based challenge and verified WebAuthn signature, providing:
- A seamless UX
- Biometric device binding
- Cryptographic session proof

---

## Use Cases

- Signing multiple transactions (e.g., batch transfers)
- Authorizing contract calls under a temporary or function-scoped session
- Improving UX without sacrificing cryptographic guarantees

---

## Design Overview

1. Client decrypts a **VRF secret key** inside a WASM worker using WebAuthn PRF.
2. Generates a **VRF challenge** using a recent block hash.
3. Signs the VRF output using WebAuthn.
4. Submits session request to contract, which:
   - Verifies the WebAuthn signature
   - Verifies the VRF proof
   - Stores session scope (duration, count, function allowlist, etc.)

5. Subsequent transactions during the session:
   - Refer to the session ID
   - Must originate from the same account/device
   - Are authorized based on constraints

---

## Security Assumptions and Tradeoffs

| Assumption | Justification |
|------------|---------------|
| VRF key is decrypted only inside WASM worker | Isolates key from main thread/JS tampering |
| Session scope is limited (N calls, T ms) | Prevents abuse from stolen session tokens |
| Client has incentive not to cheat | User is authorizing on their own behalf |
| WebAuthn PRF output is unique per device & biometric | Prevents spoofing or offline replay |

**Tradeoffs:**
- Reusing VRF challenge in a session **removes freshness guarantees per tx**
- If client tampers with WASM, they can forge session start (but only for themselves)
- On-chain state needed to track session expiration, limits

---

## Implementation Plan

### Contract State

```rust
struct Session {
    vrf_pubkey: Vec<u8>,
    challenge: Vec<u8>, // VRF output
    expires_at: u64,    // Block timestamp or height
    remaining_calls: u8,
    allowed_methods: Vec<String>,
}
