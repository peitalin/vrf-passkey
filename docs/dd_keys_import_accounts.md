# Deterministically Derived Keys, Account Import & Recovery

## Overview

This document describes the Web3authn Passkey system's approach to **Deterministically Derived (DD) keypairs**, which enables both seamless account recovery and account import/association functionality while maintaining cryptographic security and user experience.

### Core Concepts

- **DD-keypairs**: Same Passkey always derives the same NEAR keypair through deterministic cryptographic derivation
- **Multi-device Access**: Adding new devices to existing NEAR accounts (like adding a phone to your Apple ID)
- **Recovery**: Restoring access to DD-derived accounts when local data is lost

## Deterministically Derived Keypairs

### The Problem with Traditional Key Management

Traditional blockchain wallets face critical usability issues:
- **Data Loss**: Clearing browser data = permanent account loss
- **Backup Complexity**: Users must manually manage seed phrases
- **Recovery Friction**: Complex restoration processes hurt adoption
- **Security Risks**: Seed phrases are vulnerable to theft/loss

### DD-Keypair Solution

Instead of random key generation, we **deterministically derive** NEAR Ed25519 keypairs from WebAuthn COSE P-256 credentials:

```
WebAuthn Passkey → COSE P-256 Coordinates → SHA-256 → Ed25519 Seed → NEAR Keypair
```

### Key Properties
- **Deterministic**: Same passkey → Same NEAR keypair (always)
- **Recoverable**: NEAR keys can be re-derived from passkey
- **Device-bound**: Requires original device + biometrics
- **Zero-backup**: No seed phrases or manual backups needed

### Cryptographic Derivation
```rust
fn derive_near_keypair_from_cose_p256(x_coord: &[u8], y_coord: &[u8]) -> (String, String) {
    // 1. Concatenate P-256 coordinates (64 bytes)
    let mut p256_material = Vec::new();
    p256_material.extend_from_slice(x_coord);  // 32 bytes
    p256_material.extend_from_slice(y_coord); // 32 bytes

    // 2. SHA-256 hash for deterministic seed
    let hash_bytes = sha256(&p256_material);

    // 3. Use as Ed25519 private key seed
    let private_key_seed: [u8; 32] = hash_bytes.into();
    let signing_key = SigningKey::from_bytes(&private_key_seed);

    // 4. Generate NEAR keypair
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let private_key_near = format!("ed25519:{}", bs58::encode(&full_private_key));
    let public_key_near = format!("ed25519:{}", bs58::encode(&public_key_bytes));

    (private_key_near, public_key_near)
}
```

## Multi-Device Access

### The User Need

Users want to access the same NEAR account from multiple devices:
- **Laptop + Phone**: Same account across devices
- **Work + Personal**: Different browsers, same identity
- **Family Sharing**: Spouse's device accessing joint account
- **Device Upgrade**: Moving from old to new device

### The Solution: Add Keys (Not Import)

Instead of "importing" accounts (which implies taking over), we **add keys** for multi-device access:

```
Existing Account → Add New Device Key → Multi-device Control
```

### Technical Implementation

#### Step 1: Add Keys Request
```typescript
async function addKeysToAccount(privateKey: string): Promise<AddKeysResult> {
  // Convert private key to keypair from existing device
  const existingDeviceKeypair = Ed25519Keypair.fromSecretKey(privateKey);

  // Derive DD-keypair for current device
  const currentDeviceKeypair = await deriveDDKeypair();

  // Find account controlled by existing device
  const accountId = await lookupAccountByPublicKey(existingDeviceKeypair.publicKey());

  if (!accountId) {
    throw new Error('No NEAR account found for this private key');
  }

  // Add current device's DD-keypair as additional access key
  return await addDeviceToAccount(accountId, existingDeviceKeypair, currentDeviceKeypair);
}
```

#### Step 2: Device Addition
```typescript
async function addDeviceToAccount(
  accountId: string,
  existingKeypair: Keypair,
  newDeviceKeypair: Keypair
): Promise<AddKeysResult> {

  // Create add key action
  const addKeyAction = {
    type: 'AddKey',
    public_key: newDeviceKeypair.publicKey(),
    access_key: {
      nonce: 0,
      permission: 'FullAccess'
    }
  };

  // Sign with existing device (one-time operation)
  const signedTransaction = await signTransaction(accountId, [addKeyAction], existingKeypair);
  await sendTransaction(signedTransaction);

  // Get total key count for confirmation
  const totalKeys = await getTotalAccessKeys(accountId);

  return {
    success: true,
    accountId,
    totalKeys,
    message: `This device can now control ${accountId} (${totalKeys} devices total)`
  };
}
```

#### Step 3: Web3authn Registration
```typescript
// Register current device's DD-keypair with web3authn contract
await webauthnManager.signVerifyAndRegisterUser({
  vrfChallenge,
  credential,
  contractId: 'web3-authn.testnet',
  signerAccountId: accountId, // The multi-device account
  nearAccountId: accountId,
  publicKeyStr: currentDeviceKeypair.publicKey(),
  nearClient,
  onEvent
});
```

#### Step 4: Key Management Interface
```typescript
// Provide UI for managing all device keys
async function getAccountKeys(accountId: string): Promise<AccountKeysView> {
  const allKeys = await nearClient.viewAccessKeys(accountId);
  const currentDeviceKey = await deriveDDKeypair().publicKey();

  return {
    accountId,
    keys: allKeys.map(key => ({
      publicKey: key.public_key,
      isCurrentDevice: key.public_key === currentDeviceKey,
      deviceType: isPasskeyDerived(key.public_key) ? 'passkey' : 'traditional',
      canDelete: allKeys.length > 1 // Always keep at least one key
    }))
  };
}
```

### User Experience

From the user's perspective, "add keys" works like multi-device access:
1. **Input**: Paste private key from another device
2. **Result**: Current device can now control the same account
3. **Usage**: All transactions signed with current device's passkey (TouchID/FaceID)
4. **Management**: View and manage all device keys

Benefits:
- **Multi-device**: Both devices continue to work
- **No migration**: Existing devices unaffected
- **Familiar**: Like adding a phone to Apple ID
- **Transparent**: See all devices with access

## Recovery Mechanisms

### When Recovery is Needed
- Browser data cleared (IndexedDB deleted)
- Device migration scenarios
- Corrupted local storage
- Accidental data deletion

### Recovery Approach 1: Account ID Input

User provides NEAR account ID for recovery:

```typescript
async function recoverByAccountId(accountId: string): Promise<RecoveryResult> {
  // 1. Derive DD-keypair from current passkey
  const ddKeypair = await deriveDDKeypairFromPasskey();

  // 2. Check if account's current keys match DD-derived key
  const accountKeys = await nearClient.viewAccessKeys(accountId);
  const ddPublicKey = ddKeypair.publicKey();

  const hasMatchingKey = accountKeys.some(key => {
    key.public_key === ddPublicKey
  });

  if (!hasMatchingKey) {
    throw new Error(`Account ${accountId} was not created with this passkey`);
  }

  // 3. Recover account data
  return await performRecovery(accountId, ddKeypair);
}
```

### Recovery Approach 2: Passkey Selection

Display all passkeys for current domain:

```typescript
async function recoverByPasskeySelection(): Promise<RecoveryResult> {
  // 1. Get all stored passkeys for this domain
  const credentials = await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(32),
      allowCredentials: [], // Empty = show all for domain
      userVerification: 'required'
    }
  });

  // 2. For each credential, derive keypair and lookup account
  const accountOptions = [];
  for (const credential of credentials) {
    const ddKeypair = await deriveDDKeypairFromCredential(credential);
    const accountId = await lookupAccountByPublicKey(ddKeypair.publicKey());

    if (accountId) {
      accountOptions.push({ credential, accountId, ddKeypair });
    }
  }

  // 3. Present account selection UI
  const selectedAccount = await showAccountSelectionUI(accountOptions);

  // 4. Perform recovery for selected account
  return await performRecovery(selectedAccount.accountId, selectedAccount.ddKeypair);
}
```

### Recovery Process
```typescript
async function performRecovery(accountId: string, ddKeypair: Keypair): Promise<RecoveryResult> {
  // 1. Sync on-chain authenticator data
  const storedAuthenticator = await webauthnContract.get_authenticator(
    accountId,
    credentialId
  );

  if (!storedAuthenticator) {
    throw new Error('No web3authn registration found for this account');
  }

  // 2. Restore local IndexedDB data
  await indexedDBManager.storeAuthenticator(accountId, {
    credentialId: storedAuthenticator.credential_id,
    credentialPublicKey: storedAuthenticator.credential_public_key,
    clientNearPublicKey: ddKeypair.publicKey(),
    lastUpdated: Date.now()
  });

  // 3. Restore encrypted VRF keypair
  const encryptedVrfData = storedAuthenticator.encrypted_vrf_keypair;
  if (encryptedVrfData) {
    await indexedDBManager.storeEncryptedVrfKeypair(accountId, encryptedVrfData);
  }

  return {
    success: true,
    accountId,
    publicKey: ddKeypair.publicKey(),
    message: 'Account successfully recovered'
  };
}
```

## Security Model

### DD-Keypair Security
- **Device Binding**: Recovery requires original device
- **Biometric Protection**: TouchID/FaceID for each operation
- **Deterministic Derivation**: Mathematical guarantee of consistency
- **No Private Key Exposure**: Keys never leave device unencrypted

### Multi-Device Security
- **Access Key Model**: Each device gains control via NEAR access keys
- **One-time Setup**: Existing device key used once to add new device
- **Shared Control**: All devices have equal account control
- **Revocable**: Device access can be added/removed as needed
- **Transparent**: All access keys visible and manageable

### Recovery Security
- **Cryptographic Verification**: Account ownership proven via key derivation
- **Device Requirement**: Cannot recover without original device
- **Contract Validation**: On-chain data confirms legitimate registration
- **No Central Authority**: Fully decentralized recovery process

## Implementation Architecture

### Data Flow Overview
```
Registration:  Passkey → DD-Keypair → Web3authn Registration → Account Control
Add Keys:      Existing Device Key → Account Lookup → Add New Device → Multi-device Control
Recovery:      Passkey → DD-Keypair → Verify Ownership → Restore Local Data
```

### Component Integration
```
┌─────────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   WebAuthn/Passkey │    │   DD-Keypair     │    │   NEAR Account      │
│                     │    │   Derivation     │    │                     │
├─────────────────────┤    ├──────────────────┤    ├─────────────────────┤
│ • TouchID/FaceID    │───▶│ • COSE → Ed25519 │───▶│ • Access Keys       │
│ • COSE P-256 Key    │    │ • Deterministic  │    │ • Transaction Sign  │
│ • PRF Generation    │    │ • Device-bound   │    │ • State Changes     │
└─────────────────────┘    └──────────────────┘    └─────────────────────┘
```

## Implementation Plan

### Phase 1: Account Recovery Implementation

#### Step 1: DD-Keypair Derivation in WASM Worker
**Files to modify:**
- `packages/passkey/src/wasm_signer_worker/src/lib.rs`
- `packages/passkey/src/core/types/signer-worker.ts`

**Implementation:**
1. Add new WASM function `derive_deterministic_keypair_from_passkey()`
   - Uses existing COSE extraction + deterministic derivation logic
   - Returns public key (for account lookup) and encrypted private key
2. Add TypeScript types for DD-keypair derivation requests/responses
3. Add worker request type `DERIVE_DETERMINISTIC_KEYPAIR_FROM_PASSKEY`

#### Step 2: Account Lookup Service
**Files to create/modify:**
- `packages/passkey/src/core/PasskeyManager/accountLookup.ts` (new)
- `packages/passkey/src/core/WebAuthnManager/index.ts`

**Implementation:**
1. Create `AccountLookupService` class:
   - `findAccountByPublicKey(publicKey)` - Query NEAR RPC for accounts
   - `verifyAccountOwnership(accountId, publicKey)` - Check access keys
   - `getAccountAccessKeys(accountId)` - List all keys for management
2. Add account lookup methods to WebAuthnManager

#### Step 3: Recovery Flow Implementation
**Files to implement:**
- `packages/passkey/src/core/PasskeyManager/recoverAccount.ts`
- `packages/passkey/src/core/WebAuthnManager/index.ts`

**Implementation:**
1. **`recoverByAccountId(accountId)`**:
   ```typescript
   async recoverByAccountId(accountId: string): Promise<RecoveryResult> {
     // 1. Deterministically derive keypair (DDK) from current passkey
     const ddKeypair = await this.webAuthnManager.deriveDeterministicKeypairFromPasskey();

     // 2. Verify account ownership
     const hasAccess = await this.accountLookup.verifyAccountOwnership(accountId, ddKeypair.publicKey);
     if (!hasAccess) throw new Error('Account not created with this passkey');

     // 3. Restore data from contract and IndexedDB
     return await this.performRecovery(accountId, ddKeypair);
   }
   ```

2. **`recoverByPasskeySelection()`**:
   ```typescript
   async recoverByPasskeySelection(): Promise<RecoveryResult> {
     // 1. Enumerate available passkeys
     const credentials = await navigator.credentials.get({...});

     // 2. For each credential, derive keypair and lookup account
     const accountOptions = [];
     for (const cred of credentials) {
       const ddKeypair = await this.deriveDDKeypairFromCredential(cred);
       const accountId = await this.accountLookup.findAccountByPublicKey(ddKeypair.publicKey);
       if (accountId) accountOptions.push({ accountId, ddKeypair });
     }

     // 3. User selects account, perform recovery
     const selected = await this.showAccountSelection(accountOptions);
     return await this.performRecovery(selected.accountId, selected.ddKeypair);
   }
   ```

#### Step 4: Data Restoration
**Files to modify:**
- `packages/passkey/src/core/WebAuthnManager/index.ts`
- `packages/passkey/src/core/IndexedDBManager/index.ts`

**Implementation:**
1. Add `performRecovery()` method:
   - Query web3authn contract for stored authenticator data
   - Restore authenticator data to IndexedDB
   - Restore encrypted VRF keypair
   - Update last login timestamp
2. Add IndexedDB restoration methods for bulk data import

### Phase 2: Key Management Implementation

#### Step 5: Add Device Key Management
**Files to create/modify:**
- `packages/passkey/src/core/PasskeyManager/addKey.ts`
- `packages/passkey/src/core/PasskeyManager/index.ts`

**Implementation:**
1. **`addKeysToAccount(privateKey)`**:
   ```typescript
   async addKeysToAccount(privateKey: string): Promise<AddKeysResult> {
     // 1. Convert private key to keypair (existing device)
     const existingKeypair = Ed25519Keypair.fromSecretKey(privateKey);

     // 2. Find account controlled by existing device
     const accountId = await this.accountLookup.findAccountByPublicKey(existingKeypair.publicKey());
     if (!accountId) throw new Error('No account found for this private key');

     // 3. Derive DD-keypair for current device
     const currentDeviceKeypair = await this.webAuthnManager.deriveDDKeypairFromPasskey();

     // 4. Create AddKey transaction using existing WASM infrastructure
     return await this.webAuthnManager.addDeviceKey({
       accountId,
       existingKeypair,
       newDeviceKeypair: currentDeviceKeypair
     });
   }
   ```

2. **Use existing WASM worker `add_key_with_prf()` function** - already implemented!

#### Step 6: Key Deletion Management
**Files to modify:**
- `packages/passkey/src/core/PasskeyManager/index.ts`
- `packages/passkey/src/core/WebAuthnManager/index.ts`

**Implementation:**
1. **`deleteDeviceKey(accountId, publicKeyToDelete)`**:
   ```typescript
   async deleteDeviceKey(accountId: string, publicKeyToDelete: string): Promise<DeleteKeyResult> {
     // 1. Verify user has access and key exists
     const accountKeys = await this.accountLookup.getAccountAccessKeys(accountId);
     const keyToDelete = accountKeys.find(k => k.public_key === publicKeyToDelete);
     if (!keyToDelete) throw new Error('Key not found');

     // 2. Ensure at least one key remains
     if (accountKeys.length <= 1) throw new Error('Cannot delete last access key');

     // 3. Use existing WASM worker delete_key_with_prf() function
     return await this.webAuthnManager.deleteKey({
       accountId,
       publicKeyToDelete,
       // Uses current device's VRF + WebAuthn for auth
     });
   }
   ```

2. **Use existing WASM worker `delete_key_with_prf()` function** - already implemented!

#### Step 7: Key Management UI Integration
**Files to modify:**
- `packages/passkey/src/core/PasskeyManager/index.ts`

**Implementation:**
1. **`getDeviceKeys(accountId)`** - List all access keys with metadata:
   ```typescript
   async getDeviceKeys(accountId: string): Promise<DeviceKeysView> {
     const allKeys = await this.accountLookup.getAccountAccessKeys(accountId);
     const currentDeviceKey = await this.getCurrentDevicePublicKey();

     return {
       accountId,
       keys: allKeys.map(key => ({
         publicKey: key.public_key,
         isCurrentDevice: key.public_key === currentDeviceKey,
         deviceType: this.isPasskeyDerived(key.public_key) ? 'passkey' : 'traditional',
         canDelete: allKeys.length > 1
       }))
     };
   }
   ```

### Integration Points

**Leverage Existing Infrastructure:**
1. **WASM Workers**: Use existing `web3authn-signer.worker.ts` for all crypto operations
2. **WebAuthnManager**: Extend with DD-keypair derivation and recovery methods
3. **IndexedDBManager**: Add bulk restoration methods
4. **TouchIdPrompt**: Reuse for recovery authentication
5. **Action System**: Use existing `executeAction()` for AddKey/DeleteKey transactions

**New Methods to Add:**
- `PasskeyManager.recoverAccount()`
- `PasskeyManager.addKeysToAccount()`
- `PasskeyManager.deleteDeviceKey()`
- `PasskeyManager.getDeviceKeys()`
- `WebAuthnManager.deriveDDKeypairFromPasskey()`
- `WebAuthnManager.performRecovery()`

**Key Advantages:**
- ✅ Reuses 90% of existing infrastructure
- ✅ WASM worker functions already implemented for key operations
- ✅ Consistent with existing PasskeyManager API patterns
- ✅ No new dependencies or major architectural changes

## User Flows

### New User Registration
1. **TouchID Ceremony**: Create WebAuthn credential
2. **DD-Keypair Derivation**: Generate NEAR keypair from passkey
3. **Account Creation**: Create NEAR account via faucet/relayer
4. **Web3authn Registration**: Register with web3authn contract
5. **Ready**: Account usable with passkey authentication

### Multi-Device Key Addition
1. **Add Keys Request**: User provides private key from another device
2. **Account Discovery**: Find account controlled by existing device
3. **Device Addition**: Add current device's DD-keypair as access key
4. **Web3authn Registration**: Register new device with contract
5. **Key Management**: View and manage all device keys
6. **Complete**: Account accessible from multiple devices

### Data Loss Recovery
1. **Recovery Initiation**: User reports lost data
2. **Method Selection**: Choose account ID input or passkey selection
3. **Ownership Verification**: Prove account was DD-derived
4. **Data Restoration**: Sync on-chain data to local storage
5. **Complete**: Full account access restored

## Benefits

### For Users
- **Zero-backup Recovery**: No seed phrases to manage
- **Familiar Security**: TouchID/FaceID for all operations
- **Multi-device Access**: Same account across all devices
- **No Migration Stress**: Existing devices continue working
- **Transparent Control**: See and manage all device access

### For Developers
- **Deterministic Security**: Predictable key derivation
- **Standard Compliance**: Uses WebAuthn, NEAR, established crypto
- **Flexible Architecture**: Supports both DD and multi-device accounts
- **Simple Key Management**: Standard NEAR access key operations
- **Future-proof**: Compatible with evolving standards

## Limitations & Considerations

### Device Dependency
- **Platform Authenticators**: Bound to specific devices
- **Migration Complexity**: Moving between devices requires account recovery
- **Mitigation**: Clear user education about device binding

### Recovery Scope
- **DD-derived Accounts**: Full recovery possible
- **Imported Accounts**: Recovery limited to access key control
- **Solution**: Encourage users to understand difference

### Network Dependencies
- **Blockchain Access**: Recovery requires NEAR network connectivity
- **Contract Availability**: Depends on web3authn contract deployment
- **Gas Requirements**: Operations need NEAR tokens for gas

## Future Enhancements

### Multi-Device Support
- **Secure Sync**: Encrypted data sharing between user devices
- **Device Registration**: Allow multiple devices per account
- **Delegation Model**: Trusted device recovery assistance

### Enhanced Multi-Device
- **Batch Device Addition**: Add multiple devices in single operation
- **Device Discovery**: Auto-detect other devices on same network
- **Family Sharing**: Managed access for family members
- **Device Management**: Rich UI for organizing device access

### Advanced Recovery
- **Social Recovery**: Combine with trusted contacts
- **Partial Recovery**: Recover subset of account data
- **Recovery History**: Track and verify recovery operations

## Conclusion

The combination of deterministically derived keypairs with multi-device access creates a powerful user experience that:

1. **Eliminates backup complexity** through deterministic derivation
2. **Enables multi-device access** like modern consumer services (Apple ID, Google account)
3. **Provides seamless recovery** without manual backup processes
4. **Maintains strong security** through device binding and biometrics
5. **Supports familiar workflows** via "add device" functionality
6. **Offers transparent control** with visible key management

This architecture bridges the gap between traditional wallet functionality and next-generation biometric security, providing the multi-device experience users expect while maintaining blockchain's cryptographic guarantees.