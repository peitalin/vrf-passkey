# create_account_and_register_user() Integration Plan

## Overview

The `create_account_and_register_user()` function in the WebAuthn contract provides atomic account creation with WebAuthn registration. This needs to be integrated through a new relay-server endpoint and function abstraction in the passkey SDK.

## Current State

- ✅ Contract function `create_account_and_register_user()` is implemented
- ✅ Atomic transaction combines VRF proof + WebAuthn verification + account creation + NEAR transfer
- ❌ Relay-server endpoint is missing
- ❌ Registration flow abstraction is missing

## Implementation Requirements

### 1. Relay-Server Endpoint Implementation

Add a new `/create_account_and_register_user` endpoint to the relay-server:

```typescript
// In relay-server/src/routes/accounts.ts
app.post('/create_account_and_register_user', async (req, res) => {
  const {
    new_account_id,
    new_public_key,
    vrf_data,
    webauthn_registration,
    deterministic_vrf_public_key
  } = req.body;

  // Call contract function with server-controlled initial balance
  const result = await contractCalls.create_account_and_register_user({
    new_account_id,
    new_public_key,
    vrf_data,
    webauthn_registration,
    deterministic_vrf_public_key,
    initialBalance: "0.1" // Server decides this parameter
  });

  res.json(result);
});
```

**Key Points:**
- Frontend sends all contract parameters except `initialBalance`
- Server controls the `initialBalance` (set to 0.1 NEAR)
- Endpoint makes single atomic contract call

### 2. Registration Flow Abstraction

Abstract both registration flows into separate functions for easier testing and maintenance:

#### 2.1 Relay-Server Flow Function

```typescript
// In packages/passkey/src/core/PasskeyManager/registration.ts
async function create_account_and_register_with_relay_server(
  accountId: string,
  publicKey: string,
  vrfData: VRFData,
  webauthnRegistration: WebAuthnRegistration,
  deterministicVrfPublicKey?: Uint8Array
): Promise<RegistrationResult> {
  // Single call to relay-server endpoint
  const response = await fetch(`${relayServerUrl}/create_account_and_register_user`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      new_account_id: accountId,
      new_public_key: publicKey,
      vrf_data: vrfData,
      webauthn_registration: webauthnRegistration,
      deterministic_vrf_public_key: deterministicVrfPublicKey
    })
  });

  return await response.json();
}
```

#### 2.2 Testnet Faucet Flow Function

```typescript
// In packages/passkey/src/core/PasskeyManager/registration.ts
async function create_account_and_register_with_testnet_faucet(
  accountId: string,
  publicKey: string,
  vrfData: VRFData,
  webauthnRegistration: WebAuthnRegistration,
  deterministicVrfPublicKey?: Uint8Array
): Promise<RegistrationResult> {
  // Sequential calls (existing logic)
  // 1. Create account via testnet faucet
  await createAccountTestnetFaucet(accountId, publicKey);

  // 2. Register user with contract
  const result = await signVerifyAndRegisterUser({
    vrfData,
    webauthnRegistration,
    deterministicVrfPublicKey
  });

  return result;
}
```

#### 2.3 Updated Main Registration Logic

```typescript
// In packages/passkey/src/core/PasskeyManager/registration.ts
export async function registerUser(params: RegistrationParams): Promise<RegistrationResult> {
  // ... existing VRF and WebAuthn generation logic ...

  // Choose registration flow based on configuration
  if (config.useRelayer && config.relayServerUrl) {
    return await create_account_and_register_with_relay_server(
      accountId,
      publicKey,
      vrfData,
      webauthnRegistration,
      deterministicVrfPublicKey
    );
  } else {
    return await create_account_and_register_with_testnet_faucet(
      accountId,
      publicKey,
      vrfData,
      webauthnRegistration,
      deterministicVrfPublicKey
    );
  }
}
```

### 3. Registration Rollback Logic Updates

#### Current Rollback (useRelayer == false)
- Creates preSignedDeleteAccount transaction
- Requires manual cleanup if registration fails

#### New Rollback (useRelayer == true)
- **No preSignedDeleteAccount needed** - atomic transaction handles rollback
- If `create_account_and_register_user()` fails, nothing is created
- Simpler error handling and cleanup
- preSignedDeleteAccount transaction is returned from the wasm-signer-worker anyway, but can be ignored safely.

### 4. Testing Updates Required

#### 4.1 E2E Test Updates

**File: `packages/passkey/src/__tests__/e2e/complete_ux_flow.test.ts`**
- Update test to handle both registration flows
- Test atomic registration when useRelayer is true
- Test sequential registration when useRelayer is false

#### 4.2 Setup Updates

**File: `packages/passkey/src/__tests__/setup.ts`**
- Add configuration for testing both flows
- Mock relay-server endpoint for testing
- Configure test environment switching

#### 4.3 Rollback Test Updates

**File: `packages/passkey/src/__tests__/e2e/registration-rollback.test.ts`**
- Test rollback behavior for both flows
- Test atomic transaction rollback scenarios

## Implementation Flow

### Phase 1: Relay-Server Endpoint
- Add `/create_account_and_register_user` endpoint to relay-server
- Implement server-side contract calling logic
- Test endpoint with mock data

### Phase 2: Function Abstraction
- Create `create_account_and_register_with_relay_server()` function
- Create `create_account_and_register_with_testnet_faucet()` function
- Update main registration logic to use appropriate function

### Phase 3: Rollback Logic Updates
- update preSignedDeleteAccount logic for relay-server flow (simply ignore it)
- Update rollback test scenarios
- Simplify error handling for atomic transactions


## Configuration Examples

### Relay-Server Configuration (Atomic Registration)
```typescript
const config: PasskeyManagerConfig = {
  relayServerUrl: 'https://accounts.example.com',
  useRelayer: true,
  // Uses create_account_and_register_with_relay_server()
};
```

### Testnet Faucet Configuration (Sequential Registration)
```typescript
const config: PasskeyManagerConfig = {
  relayServerUrl: undefined,
  useRelayer: false,
  // Uses create_account_and_register_with_testnet_faucet()
};
```

## Next Steps

1. Implement relay-server `/create_account_and_register_user` endpoint
2. Create function abstractions for both registration flows
3. Update rollback logic
4. Update E2E tests for both flows
5. Test function swapping functionality
6. Update documentation and examples