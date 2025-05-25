# Server-Side Implementation for Passkey-Based NEAR Transactions

This document outlines the server-side logic required to enable users to authorize NEAR transactions using their passkeys. The server will handle COSE public key processing, WebAuthn assertion verification, and relaying authorized transactions to a Signer Smart Contract on the NEAR blockchain.

## Core Components & Flow:

1.  **User Onboarding / Passkey Registration:**
    *   Frontend: User initiates passkey registration.
    *   Frontend: `navigator.credentials.create()` is called.
    *   Frontend: Sends the `PublicKeyCredential` (specifically the raw COSE public key from `credential.response.getPublicKey()` and `credential.id`) to the server.
    *   Server: Handles COSE to NEAR Public Key conversion (Endpoint 1).
    *   Server: Stores the original COSE public key and the derived NEAR public key, associated with the user and their `credential.id`.
    *   Server: Calls the Signer Smart Contract to register the derived NEAR public key (`add_passkey_pk`).

2.  **Transaction Authorization & Execution:**
    *   Frontend: User initiates a NEAR transaction.
    *   Frontend: Requests a challenge from the server (Endpoint 2a).
    *   Server: Generates a unique challenge, stores it with transaction details, and returns it to the frontend (Endpoint 2b).
    *   Frontend: `navigator.credentials.get()` is called using the challenge.
    *   Frontend: Sends the `AuthenticatorAssertionResponse` and original transaction details (or reference) to the server (Endpoint 3).
    *   Server: Verifies the WebAuthn assertion.
    *   Server: If valid, calls the Signer Smart Contract to execute the transaction (`execute_actions`).

## I. Endpoint 1: COSE Public Key Processing & NEAR PK Derivation

*   **Endpoint:** `/register-passkey` (or similar, e.g., `/users/:userId/passkeys`)
*   **Method:** `POST`
*   **Request Body (JSON):**
    ```json
    {
      "username": "alice", // Or some internal user ID
      "passkeyCredentialId": "base64url_encoded_credential_id",
      "cosePublicKey": "base64_encoded_array_buffer_of_cose_pk", // Raw COSE public key
      "transports": ["internal", "hybrid"] // Optional: from credential.response.getTransports()
    }
    ```
*   **Server Logic:**
    1.  **Decode Inputs:**
        *   Decode `passkeyCredentialId` from base64url.
        *   Decode `cosePublicKey` from base64 to an `ArrayBuffer` or `Buffer`.
    2.  **Parse COSE Public Key (using `cbor-x` or similar):**
        *   `const coseKey = decode(cosePublicKeyBuffer);`
        *   Inspect `coseKey` to determine key type (kty), algorithm (alg), curve (crv), and extract raw key material (x, y coordinates for P-256; or x for Ed25519).
            *   Reference: [COSE Key Parameters](https://datatracker.ietf.org/doc/html/rfc8152#section-7.1)
            *   P-256 (EC2, ES256): kty=2, alg=-7, crv=1. Extract x (label -2) and y (label -3).
            *   Ed25519 (OKP, EdDSA): kty=1, alg=-8, crv=6. Extract x (label -2).
    3.  **Convert/Derive NEAR-Compatible Public Key:**
        *   **If Ed25519 from COSE:**
            *   The raw `x` value (32-byte buffer) *is* the Ed25519 public key.
            *   Convert this to NEAR's string format (e.g., `ed25519:` prefix + base58 encoding of the 32-byte key).
            *   Use `@near-js/crypto` `PublicKey` class: `new PublicKey({ type: 0, data: ed25519Buffer }).toString()`.
        *   **If P-256 from COSE (More Common for WebAuthn):** This is the complex step, as P-256 (ECDSA) and Ed25519 (EdDSA) are different cryptographic systems. A direct conversion is not possible. Instead, we deterministically *derive* an Ed25519 key pair from the P-256 public key.
            *   **Obtain P-256 Public Key Components:** The P-256 public key is defined by its `x` and `y` coordinates on the curve. These are extracted from the COSE key (e.g., label -2 for `x`, label -3 for `y`).
            *   **Create a Deterministic Seed:**
                1.  Concatenate the raw byte representations of the `x` and `y` coordinates in a consistent order (e.g., `x_bytes` followed by `y_bytes`).
                2.  Hash this concatenated byte string using a strong cryptographic hash function like SHA-256. This produces a 32-byte hash.
                `p256_components_hash = SHA256(concatenate(x_bytes, y_bytes))`
            *   **Derive Ed25519 Key Pair from Seed:**
                1.  Use the 32-byte `p256_components_hash` as a seed to generate a new Ed25519 key pair.
                2.  NEAR's crypto libraries (e.g., `@near-js/crypto`) provide `KeyPair.fromSeed(seed)` for this.
                `const nearKeyPair = KeyPair.fromSeed(p256_components_hash);`
            *   **Obtain Derived NEAR Public Key:** The public key part of this `nearKeyPair` is the Ed25519 public key that will be used with NEAR.
            *   `const derivedNearPublicKeyString = nearKeyPair.getPublicKey().toString();`
            *   **Important:** This `derivedNearPublicKeyString` is what's registered on the NEAR Signer Smart Contract. The user authenticates using their original P-256 passkey (proving control). The server verifies this P-256 authentication. If successful, the server knows the user has authorized an action related to the `derivedNearPublicKeyString` (because the derivation is deterministic). The server then instructs the Signer Smart Contract to proceed, referencing the `derivedNearPublicKeyString`. The original P-256 private key never leaves the user's authenticator, and the server does not need to store or use the derived Ed25519 private key for this flow.
    4.  **Store Passkey Information:**
        *   Persistently store (e.g., in a database):
            *   `userId` or `username`.
            *   `passkeyCredentialId` (binary/Buffer form, used for `allowCredentials`).
            *   The *original* raw `cosePublicKey` (binary/Buffer form, needed for future assertion verifications).
            *   The `derivedNearPublicKeyString`.
            *   (Optional) `transports`.
            *   (Optional, for security) Initial signature counter if available from authenticator data during registration.
    5.  **Register with Signer Smart Contract:**
        *   Using the server's relayer account, call the `add_passkey_pk` method on the user's `PasskeyControlledAccount` smart contract (or the designated Signer SC instance for that user).
        *   Pass the `derivedNearPublicKeyString`.
*   **Server Response:**
    *   Success: `201 Created` or `200 OK` with a confirmation message.
    *   Failure: Appropriate error status code and message.

## II. Endpoint 2: Initiate Passkey Transaction & Get Challenge

*   **Endpoint:** `/initiate-passkey-transaction` (or `/transactions/challenge`)
*   **Method:** `POST`
*   **Request Body (JSON):**
    ```json
    {
      "username": "alice",
      "passkeyCredentialId": "base64url_encoded_credential_id", // Optional: if server needs to select specific key
      "transactionDetails": {
        // Details of the NEAR transaction the user wants to perform,
        // structure this based on what your `SerializableAction` on the SC expects.
        // Example:
        "actions": [
          {
            "action_type": "Transfer",
            "receiver_id": "bob.near",
            "amount": "100000000000000000000000" // 0.1 NEAR in yoctoNEAR as string
          }
        ]
      }
    }
    ```
*   **Server Logic:**
    1.  Generate a cryptographically secure, unique challenge string (e.g., 32 random bytes, base64url encoded).
    2.  Temporarily store this challenge on the server (e.g., in Redis, or a short-lived database record) associated with:
        *   `username` or `userId`.
        *   The `passkeyCredentialId` to be used (if provided by client, otherwise server might look up user's available passkeys).
        *   The `transactionDetails` (to prevent replay of the challenge for a different transaction).
        *   Expiry time for the challenge (e.g., 2-5 minutes).
    3.  Lookup the `passkeyCredentialId` for the user if not provided or to validate it.
*   **Server Response (JSON):**
    ```json
    {
      "challenge": "base64url_encoded_challenge_string",
      "rpId": "your_relying_party_id.com", // Your website's RP ID
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "base64url_encoded_credential_id_for_user_passkey"
        }
      ],
      "userVerification": "preferred" // Or "required" / "discouraged"
    }
    ```
    This response structure matches what `navigator.credentials.get()` expects for its `publicKey` options.

## III. Endpoint 3: Verify Assertion & Execute Transaction via Smart Contract

*   **Endpoint:** `/execute-passkey-transaction` (or `/transactions/execute`)
*   **Method:** `POST`
*   **Request Body (JSON):**
    ```json
    {
      "username": "alice",
      "credentialId": "base64url_encoded_credential_id_used",
      "clientDataJSON": "base64url_encoded_client_data_json",
      "authenticatorData": "base64url_encoded_authenticator_data",
      "signature": "base64url_encoded_signature",
      "userHandle": "base64url_encoded_user_handle_if_any", // Optional
      "originalChallenge": "base64url_encoded_challenge_string_used" // Important for server to match
      // Include original transactionDetails or a reference to it (e.g., a session ID from Endpoint 2)
    }
    ```
*   **Server Logic:**
    1.  **Decode Inputs:** Decode all base64url encoded fields.
    2.  **Retrieve Stored Data:**
        *   Fetch the temporarily stored challenge details using `originalChallenge` and `username`. Verify it hasn't expired and matches the user.
        *   Fetch the user's stored *original COSE public key* associated with the decoded `credentialId`.
        *   Fetch the `derivedNearPublicKeyString` associated with this `credentialId`.
    3.  **Verify WebAuthn Assertion (using a library like `@simplewebauthn/server`):**
        *   The library will typically require:
            *   The expected `challenge` (retrieved from temporary storage).
            *   The expected `origin` (your website's origin).
            *   The expected `rpId`.
            *   The user's *original COSE public key` (retrieved from your database).
            *   The received `clientDataJSON`, `authenticatorData`, `signature`.
            *   Signature counter verification (if implemented).
        *   If verification fails, respond with an error.
    4.  **If Assertion is Valid:**
        *   Invalidate the used challenge to prevent replay.
        *   Prepare the `SerializableAction` array based on the `transactionDetails` stored from Endpoint 2.
        *   Using the server's relayer account, call the `execute_actions` method on the user's `PasskeyControlledAccount` smart contract.
            *   Parameters for `execute_actions`:
                *   `passkey_pk_used`: The `derivedNearPublicKeyString` for the passkey that was just successfully used.
                *   `actions_to_execute`: The `SerializableAction` array.
    5.  **Handle Smart Contract Call Result:**
        *   Wait for the result of the relayed transaction.
*   **Server Response:**
    *   Success: `200 OK` with NEAR transaction result/hash.
    *   Failure: Appropriate error status code and message (e.g., assertion failed, smart contract call failed).

This provides a detailed plan for your server-side implementation.