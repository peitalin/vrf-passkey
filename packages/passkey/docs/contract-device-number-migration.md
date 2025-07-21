# Contract Device Number Migration Plan

## Overview

This document outlines the plan to update the smart contract and SDK to properly handle device numbers for multi-device passkey management.

## 🛡️ **Critical Safety Design**

**Recovery uses discoverable credentials (resident keys) to prevent data conflicts:**
- Users explicitly select from available passkeys (e.g., "alice.2.near" for Device 2)
- Each passkey has a unique user ID containing the device number
- No risk of overwriting existing device data during recovery
- Wrong selection fails gracefully with access key error (no data corruption)

## 🔢 **Device Numbering Update (UX Improvement)**

**Change device numbering from 0-indexed to 1-indexed for intuitive UX:**

| Device | Current (Confusing) | New (Intuitive) | Display Name |
|--------|-------------------|-----------------|--------------|
| 1st | `alice.near` (device 0) | `alice.near` (device 1) | "alice.near (Device 1)" |
| 2nd | `alice.1.near` (device 1) | `alice.2.near` (device 2) | "alice.2.near (Device 2)" |
| 3rd | `alice.2.near` (device 2) | `alice.3.near` (device 3) | "alice.3.near (Device 3)" |

**Benefits:**
- User ID device number matches display number (alice.2.near = Device 2)
- Eliminates confusion where alice.1.near was actually the 2nd device
- More intuitive for users: "Device 2" actually has ".2." in the user ID

**Implementation Changes Required:**
- Update `generateDeviceSpecificUserId()` to start at device 2 for second device
- Update `generateDeviceSpecificAccountId()` to use 1-indexed numbering
- Update contract device counter to start from 1 instead of 0
- Update all registration/linking flows to use device number 1 for first device

## Current State Analysis

### Contract State Changes Required

#### 1. Update `StoredAuthenticator` Structure
**File**: `webauthn-contract/src/contract_state.rs`

```rust
/// Current structure (BEFORE)
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub vrf_public_keys: Vec<Vec<u8>>,
}

/// Updated structure (AFTER)
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub vrf_public_keys: Vec<Vec<u8>>,
    pub device_number: u8, // NEW: Device number for this authenticator
}
```

#### 2. Contract State Already Has Device Counter
✅ **Already exists**: `account_device_counters: LookupMap<AccountId, u32>`
- Tracks next available device number per account
- Used to assign device numbers during device linking

## Contract Method Updates Required

### 1. Registration Methods

#### `verify_and_register_user`
**File**: `webauthn-contract/src/verify_registration_response.rs`

**Current Signature:**
```rust
pub fn verify_and_register_user(
    &mut self,
    account_id: AccountId,
    // ... other params
) -> bool
```

**Updated Signature:**
```rust
pub fn verify_and_register_user(
    &mut self,
    account_id: AccountId,
    device_number: Option<u8>, // NEW: Optional device number (defaults to 1)
    // ... other params
) -> bool
```

**Logic Changes:**
```rust
impl WebAuthnContract {
    pub fn verify_and_register_user(
        &mut self,
        account_id: AccountId,
        device_number: Option<u8>,
        // ... other params
    ) -> bool {
        // Determine device number
        let device_num = device_number.unwrap_or(0);

        // For new accounts (device 0), initialize counter
        if device_num == 0 {
            self.account_device_counters.insert(&account_id, &1);
        }

        // Create authenticator with device number
        let authenticator = StoredAuthenticator {
            credential_public_key: credential_public_key.clone(),
            transports: Some(transports),
            registered: near_sdk::env::block_timestamp_ms().to_string(),
            vrf_public_keys: vec![vrf_public_key],
            device_number: device_num, // Store device number
        };

        // ... rest of registration logic
    }
}
```

### 2. Device Linking Methods

#### `store_device_linking_mapping`
**File**: `webauthn-contract/src/link_device.rs`

**Enhancement Needed:**
```rust
pub fn store_device_linking_mapping(
    &mut self,
    device_public_key: String,
    target_account_id: AccountId,
) {
    // Get next device number for this account
    let current_counter = self.account_device_counters.get(&target_account_id).unwrap_or(0);
    let device_number = current_counter;

    // Increment counter for next device
    self.account_device_counters.insert(&target_account_id, &(current_counter + 1));

    // Store mapping with device number
    self.device_linking_map.insert(
        &device_public_key,
        &(target_account_id, device_number as u32)
    );

    // ... rest of logic
}
```

### 3. Getter Methods

#### New Method: `get_authenticator_by_credential_id`
```rust
pub fn get_authenticator_by_credential_id(
    &self,
    credential_id: String,
) -> Option<(AccountId, StoredAuthenticator)> {
    // Use reverse lookup to find account, then get authenticator with device_number
    if let Some(account_id) = self.credential_to_users.get(&credential_id) {
        if let Some(authenticators) = self.authenticators.get(&account_id) {
            if let Some(authenticator) = authenticators.get(&credential_id) {
                return Some((account_id, authenticator));
            }
        }
    }
    None
}

pub fn get_all_authenticators_for_account(
    &self,
    account_id: AccountId,
) -> Vec<(String, StoredAuthenticator)> {
    // Return all authenticators with their device numbers
    self.authenticators
        .get(&account_id)
        .map(|auth_map| {
            auth_map.iter().map(|(id, auth)| (id.clone(), auth.clone())).collect()
        })
        .unwrap_or_default()
}
```

## Detailed SDK Contract Call Locations

Based on codebase analysis, here are the specific locations where contract calls are made:

### Contract Call Locations Summary

| File | Function | Contract Method | Device Number Needed |
|------|----------|----------------|---------------------|
| `registration.ts` | `registerPasskey` | `verify_and_register_user` | ✅ Always 0 |
| `linkDevice.ts` | `checkForDeviceKeyAdded` | `get_device_linking_account` | ❌ Read-only |
| `linkDevice.ts` | `scanAndLinkDevice` | `store_device_linking_mapping` | ❌ Contract assigns |
| `linkDevice.ts` | `migrateKeysAndCredentials` | `verify_and_register_user` | ✅ From session |
| `createAccountTestnetFaucet.ts` | `createAccountAndRegisterWithTestnetFaucet` | `verify_and_register_user` | ✅ Always 0 |
| `createAccountRelayServer.ts` | `createAccountAndRegisterWithRelayServer` | `create_account_and_register_user` | ✅ Always 0 |
| `WebAuthnManager/index.ts` | `signVerifyAndRegisterUser` | `verify_and_register_user` | ✅ Pass through |
| `signerWorkerManager.ts` | `signVerifyAndRegisterUser` | `verify_and_register_user` | ✅ Pass through |

## SDK Updates Required

### 1. Registration Flow Updates
**File**: `packages/passkey/src/core/PasskeyManager/registration.ts`

#### Current vs Updated Flow:

```typescript
// BEFORE: No device number consideration
export async function registerPasskey(
  context: PasskeyManagerContext,
  nearAccountId: string,
  options: RegistrationOptions
): Promise<RegistrationResult> {
  // ... generate credentials

  // Call contract without device number
  const contractResult = await context.webAuthnManager.signTransactionWithActions({
    // ... transaction details
    actions: [{
      actionType: ActionType.FunctionCall,
      method_name: 'verify_and_register_user',
      args: JSON.stringify({
        account_id: nearAccountId,
        // ... other args (NO device_number)
      }),
    }]
  });
}

// AFTER: Include device number (defaults to 1 for first device)
export async function registerPasskey(
  context: PasskeyManagerContext,
  nearAccountId: AccountId, // Now uses type-safe AccountId
  options: RegistrationOptions
): Promise<RegistrationResult> {
  // ... generate credentials

  // First device always gets device number 1
  const deviceNumber = 1;

  // Generate device-specific account ID for local storage
  const deviceSpecificAccountId = AccountId.toDeviceSpecific(nearAccountId, deviceNumber);

  // Call contract WITH device number
  const contractResult = await context.webAuthnManager.signTransactionWithActions({
    // ... transaction details
    actions: [{
      actionType: ActionType.FunctionCall,
      method_name: 'verify_and_register_user',
      args: JSON.stringify({
        account_id: nearAccountId,
        device_number: deviceNumber, // NEW: Include device number
        // ... other args
      }),
    }]
  });

  // Store locally using device-specific account ID
  await context.webAuthnManager.storeUserData({
    nearAccountId: deviceSpecificAccountId, // Use device-specific ID
    // ... other data
  });
}
```

### 2. Device Linking Flow Updates
**File**: `packages/passkey/src/core/PasskeyManager/linkDevice.ts`

#### Key Updates Needed:

```typescript
// In migrateKeysAndCredentials method:
private async migrateKeysAndCredentials() {
  const realAccountId = this.session.accountId;
  const baseAccountId = AccountId.extractBase(realAccountId);

  // Get device number from session (discovered during polling)
  const deviceNumber = this.session.deviceNumber; // This comes from contract

  // Generate credentials with device number for contract call
  const credential = await this.context.webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
    nearAccountId: realAccountId,
    challenge: vrfChallenge.outputAs32Bytes(),
    deviceNumber, // Pass device number to credential generation
  });

  // Register with contract, including device number
  const registrationTxResult = await this.context.webAuthnManager.signTransactionWithActions({
    actions: [{
      actionType: ActionType.FunctionCall,
      method_name: 'verify_and_register_user',
      args: JSON.stringify({
        account_id: baseAccountId, // Use base account ID for contract
        device_number: deviceNumber, // Include device number from linking process
        // ... other registration args
      }),
    }]
  });
}
```

### 3. Account Recovery Flow Updates
**File**: `packages/passkey/src/core/PasskeyManager/recoverAccount.ts`

#### Correct Recovery Logic (Credential ID → Device Number):

```typescript
export async function recoverAccount(
  context: PasskeyManagerContext,
  accountId: AccountId,
  options?: ActionOptions,
  reuseCredential?: PublicKeyCredential
): Promise<RecoveryResult> {

  // 1. Get TouchID credential from user (this creates the credential ID)
  const credential = reuseCredential || await context.webAuthnManager.touchIdPrompt.getCredentials({
    nearAccountId: accountId, // Base account ID for TouchID prompt
    challenge: crypto.getRandomValues(new Uint8Array(32)), // Recovery challenge
    authenticators: [], // Discovery mode - let TouchID find available credentials
  });

  // 2. Extract credential ID from the TouchID response
  const credentialId = base64UrlEncode(new Uint8Array(credential.rawId));

  // 3. Use credential ID to lookup authenticator directly from contract
  const lookupResult = await context.nearClient.callFunction(
    context.webAuthnManager.configs.contractId,
    'get_authenticator_by_credential_id',
    { credential_id: credentialId }
  );

  if (!lookupResult) {
    throw new Error('No authenticator found for this credential');
  }

  // 4. Extract account ID and device number from contract response
  const [contractAccountId, authenticator] = lookupResult;
  const deviceNumber = authenticator.device_number;

  // 5. Construct device-specific account ID for local storage lookup
  const deviceSpecificAccountId = AccountId.toDeviceSpecific(contractAccountId, deviceNumber);

  // 6. Attempt recovery using this specific device's data
  return await attemptRecoveryWithDevice(
    context,
    deviceSpecificAccountId,
    authenticator,
    credential
  );
}

async function attemptRecoveryWithDevice(
  context: PasskeyManagerContext,
  deviceSpecificAccountId: AccountIdDeviceSpecific,
  authenticator: StoredAuthenticator,
  credential: PublicKeyCredential
): Promise<RecoveryResult> {
  // Use device-specific account ID for local storage operations
  const encryptedVrfKeypair = await IndexedDBManager.nearKeysDB.getEncryptedKey(deviceSpecificAccountId);

  if (!encryptedVrfKeypair) {
    throw new Error(`No VRF keypair found for device-specific account: ${deviceSpecificAccountId}`);
  }

  // Extract base account ID for VRF operations (consistent PRF salt)
  const baseAccountId = AccountId.extractBase(deviceSpecificAccountId);

  // Decrypt VRF keypair using credential PRF output
  const vrfKeypair = await context.webAuthnManager.decryptVrfKeypairWithCredential(
    credential,
    encryptedVrfKeypair,
    baseAccountId // Use base account ID for consistent PRF salt
  );

  return {
    success: true,
    accountId: baseAccountId,
    deviceNumber: authenticator.device_number,
    vrfKeypair,
    credential,
  };
}
```

### 4. Login Flow Updates
**File**: `packages/passkey/src/core/PasskeyManager/login.ts`

#### Enhanced Login with Device Number Awareness:

```typescript
export async function loginPasskey(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options?: LoginOptions
): Promise<LoginResult> {

  // 1. Look up local authenticators - try device-specific storage
  let userData;
  let deviceNumber = 0;

  // Try to find device-specific user data (check device 0, 1, 2, etc.)
  for (let i = 0; i < 10; i++) { // Reasonable upper bound
    const deviceSpecificId = AccountId.toDeviceSpecific(nearAccountId, i);
    try {
      userData = await context.webAuthnManager.getUserData(deviceSpecificId);
      if (userData) {
        deviceNumber = i;
        break;
      }
    } catch (error) {
      continue; // Try next device number
    }
  }

  if (!userData) {
    throw new Error('No local user data found for any device');
  }

  // 2. Use base account ID for VRF operations (consistent PRF salt)
  const vrfChallenge = await context.webAuthnManager.generateVrfChallenge({
    userId: nearAccountId, // Use base account ID for VRF
    // ... other params
  });

  // 3. Get credentials using device-specific account ID
  const deviceSpecificAccountId = AccountId.toDeviceSpecific(nearAccountId, deviceNumber);
  const authenticators = await context.webAuthnManager.getAuthenticatorsByUser(deviceSpecificAccountId);

  // ... rest of login flow
}
```

## Migration Strategy

### Phase 1: Contract Updates
1. **Update contract state structure**
   - Add `device_number: u8` to `StoredAuthenticator`
   - Deploy contract upgrade

2. **Update contract methods**
   - Modify `verify_and_register_user` to accept `device_number`
   - Update device linking logic to assign device numbers
   - Add new getter methods for device-aware queries

### Phase 2: SDK Core Updates
1. **Update WebAuthn manager types**
   - Add device number to authenticator types
   - Update contract call interfaces

2. **Update PasskeyManager flows**
   - Registration: Always use device number 1
   - Device linking: Use device number from contract
   - Recovery: Query all devices and try each one
   - Login: Detect device number from local storage

### Phase 3: Data Migration
1. **Existing users migration**
   - All existing authenticators default to device_number: 0
   - No breaking changes for single-device users

2. **Storage key migration**
   - Migrate existing IndexedDB data to device-specific keys
   - Maintain backward compatibility during transition

### Phase 4: Testing
1. **Multi-device scenarios**
   - Test registration → device linking → recovery flows
   - Verify device number consistency across flows

2. **Edge cases**
   - Account recovery with multiple devices
   - Device linking with existing multi-device accounts

## Detailed Implementation Plan

### Specific SDK File Updates

#### 1. Core WebAuthn Manager Updates
**File**: `packages/passkey/src/core/WebAuthnManager/index.ts`

```typescript
// Update signVerifyAndRegisterUser method signature
async signVerifyAndRegisterUser({
  contractId,
  credential,
  vrfChallenge,
  deterministicVrfPublicKey,
  signerAccountId,
  nearAccountId,
  nearPublicKeyStr,
  nearClient,
  deviceNumber = 0, // NEW: Add device number parameter
  onEvent,
}: {
  // ... existing params
  deviceNumber?: number; // NEW: Optional device number
}) {
  // Pass device number to signer worker
  const registrationResult = await this.signerWorkerManager.signVerifyAndRegisterUser({
    // ... existing params
    deviceNumber, // NEW: Pass through device number
  });
}
```

#### 2. Signer Worker Manager Updates
**File**: `packages/passkey/src/core/WebAuthnManager/signerWorkerManager.ts`

```typescript
async signVerifyAndRegisterUser({
  vrfChallenge,
  credential,
  contractId,
  deterministicVrfPublicKey,
  signerAccountId,
  nearAccountId,
  nearPublicKeyStr,
  nearClient,
  nearRpcUrl,
  deviceNumber = 0, // NEW: Add device number parameter
  onEvent,
}: {
  // ... existing params
  deviceNumber?: number; // NEW: Optional device number
}) {
  // Include device number in WASM worker payload
  const response = await this.executeWorkerOperation({
    message: {
      type: WorkerRequestType.SignVerifyAndRegisterUser,
      payload: {
        // ... existing payload
        deviceNumber, // NEW: Include device number
      }
    },
  });
}
```

#### 3. Faucet Function Updates
**File**: `packages/passkey/src/core/PasskeyManager/faucets/createAccountTestnetFaucet.ts`

```typescript
// Update contract registration call
const contractRegistrationResult = await webAuthnManager.signVerifyAndRegisterUser({
  contractId: webAuthnManager.configs.contractId,
  credential: credential,
  vrfChallenge: vrfChallenge,
  deterministicVrfPublicKey: deterministicVrfPublicKey,
  signerAccountId: nearAccountId,
  nearAccountId: nearAccountId,
  nearPublicKeyStr: publicKey,
  nearClient: nearClient,
  deviceNumber: 0, // NEW: First device is always 0
  onEvent: (progress) => {
    // ... event handling
  },
});
```

**File**: `packages/passkey/src/core/PasskeyManager/faucets/createAccountRelayServer.ts`

```typescript
// Update relay server request data
const requestData = {
  new_account_id: nearAccountId,
  new_public_key: publicKey,
  device_number: 0, // NEW: First device is always 0
  vrf_data: {
    // ... existing VRF data
  },
  webauthn_registration: serializedCredential,
  deterministic_vrf_public_key: Array.from(base64UrlDecode(deterministicVrfPublicKey))
};
```

#### 4. WASM Worker Updates
**Files**:
- `packages/passkey/src/wasm_signer_worker/src/types/requests.rs`
- `packages/passkey/src/wasm_signer_worker/src/lib.rs`

```rust
// Update SignVerifyAndRegisterUserRequest
#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignVerifyAndRegisterUserRequest {
    // ... existing fields
    pub device_number: Option<u8>, // NEW: Device number for registration
}

// Update contract call in WASM worker
let contract_args = serde_json::json!({
    "account_id": request.near_account_id,
    "device_number": request.device_number.unwrap_or(0), // NEW: Include device number
    "vrf_data": vrf_data,
    "webauthn_registration": webauthn_registration,
    "deterministic_vrf_public_key": request.deterministic_vrf_public_key,
});
```

#### 5. Type Definitions Updates
**File**: `packages/passkey/src/core/types/signer-worker.ts`

```typescript
export interface SignVerifyAndRegisterUserRequest {
  // ... existing fields
  deviceNumber?: number; // NEW: Optional device number
}
```

#### 6. Contract Recovery Methods
**File**: `packages/passkey/src/core/PasskeyManager/recoverAccount.ts`

✅ **SAFE RECOVERY DESIGN**: Uses discoverable credentials (resident keys) for conflict-free recovery:
- User clicks "Recover Account" → System lists all discoverable passkeys for domain
- User explicitly selects specific passkey (e.g., "alice.2.near" for Device 2)
- Recovery uses the selected passkey's exact user ID → no overwriting risk
- Wrong selection fails gracefully with access key error (no data corruption)

**Recovery Implementation**:

```typescript
export async function recoverAccount(
  context: PasskeyManagerContext,
  selectedPasskeyUserID: string, // From discoverable credential selection (e.g., "alice.2.near")
  options?: ActionOptions,
  reuseCredential?: PublicKeyCredential
): Promise<RecoveryResult> {

  // STEP 1: Use the selected passkey's exact user ID (already contains device info)
  const credential = reuseCredential || await context.webAuthnManager.touchIdPrompt.getCredentials({
    nearAccountId: selectedPasskeyUserID, // User-selected from discoverable credentials
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    authenticators: [], // Discovery mode
  });

  // STEP 2: Extract base account ID and device number from user ID
  const baseAccountId = AccountId.extractBase(selectedPasskeyUserID);
  const deviceNumber = AccountId.extractDeviceNumber(selectedPasskeyUserID);

  // STEP 3: Verify access key exists on-chain (security check)
  const userData = await context.webAuthnManager.getUser(selectedPasskeyUserID);
  if (!userData?.clientNearPublicKey) {
    throw new Error(`No NEAR public key found for ${selectedPasskeyUserID}`);
  }

  const hasAccess = await context.nearClient.viewAccessKey(baseAccountId, userData.clientNearPublicKey);
  if (!hasAccess) {
    throw new Error(`Access key does not exist for ${baseAccountId}. Wrong passkey selected.`);
  }

  // STEP 4: Direct local storage lookup using the exact passkey user ID
  const encryptedVrfKeypair = await IndexedDBManager.nearKeysDB.getEncryptedKey(selectedPasskeyUserID);

  if (!encryptedVrfKeypair) {
    throw new Error(`No VRF keypair found for ${selectedPasskeyUserID}`);
  }

  // STEP 5: Decrypt with the PRF output from the credential
  const vrfKeypair = await context.webAuthnManager.decryptVrfKeypairWithCredential(
    credential,
    encryptedVrfKeypair,
    baseAccountId // Use base account ID for PRF salt consistency
  );

  return {
    success: true,
    accountId: baseAccountId,
    deviceNumber: deviceNumber,
    vrfKeypair,
    credential,
    selectedPasskeyUserID,
  };
}

// Discovery Phase: List available passkeys for user selection
export async function getAvailablePasskeysForRecovery(
  context: PasskeyManagerContext
): Promise<Array<{ userID: string, displayName: string, deviceNumber: number }>> {

  // Get all discoverable credentials (resident keys) for this domain
  const allUserData = await context.webAuthnManager.getAllUserData();

  return allUserData.map(userData => ({
    userID: userData.nearAccountId, // e.g., "alice.near", "alice.2.near", "alice.3.near"
    displayName: generateDisplayName(userData.nearAccountId),
    deviceNumber: AccountId.extractDeviceNumber(userData.nearAccountId),
  }));
}

function generateDisplayName(userID: string): string {
  const baseAccount = AccountId.extractBase(userID);
  const deviceNumber = AccountId.extractDeviceNumber(userID);

  return `${baseAccount} (Device ${deviceNumber})`;
}
```

## Benefits

1. **Proper Multi-Device Support**: Each device gets unique identification
2. **Account Recovery**: Can recover using any linked device's local data
3. **Storage Isolation**: Prevents Chrome sync conflicts between devices
4. **Future-Proof**: Supports unlimited device linking per account

## Backward Compatibility

- All existing single-device users automatically get `device_number: 0`
- No breaking changes to existing flows
- Gradual migration path for multi-device features