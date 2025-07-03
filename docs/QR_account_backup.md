# QR Account Backup & Device Addition

## Overview
Enable users to add a second device to their existing NEAR account via QR code scanning. Prioritizes UX simplicity while maintaining security through TouchID/biometric authentication.

## User Flow

### Simple 2-Step Process
```
Device1 (Existing): "Add Device" → TouchID → Show QR [privateKey + accountId]
Device2 (New):      "Scan QR"   → Scan    → TouchID → Account Added ✅
```

**Total time: ~30 seconds**
**User friction: Minimal**

## Technical Implementation

### QR Code Data Structure
```typescript
interface QRBackupData {
  accountId: string;        // NEAR account ID (e.g., "alice.near")
  privateKey: string;       // Ed25519 private key (base58 encoded)
  timestamp?: number;       // Optional expiry timestamp
  version?: string;         // Format version for compatibility
}
```

### Device1 (Export Flow)
```typescript
// 1. Export existing credentials
const exportData = await passkeyManager.exportNearKeypairWithTouchId(accountId);
// Returns: { accountId, publicKey, privateKey }

// 2. Generate QR code
const qrData = JSON.stringify({
  accountId: exportData.accountId,
  privateKey: exportData.privateKey
});
// Display QR code with qrData
```

### Device2 (Import Flow)
```typescript
// 1. Scan QR code and parse
const { accountId, privateKey } = JSON.parse(scannedQrData);

// 2. Add device to account (creates new keypair + AddKey transaction)
const result = await passkeyManager.addDeviceToAccount(privateKey, accountId);

// 3. Broadcast transaction
const transactionResult = await passkeyManager.broadcastTransaction(result);

// 4. Discard imported private key (security)
// privateKey cleared from memory
```

### Core Transaction Logic
The `signAddKeyToDevice` function handles:

1. **Validation**: Verify imported private key belongs to account
2. **Nonce/BlockHash**: Fetch current transaction metadata
3. **New Keypair**: Create TouchID-secured keypair for Device2
4. **AddKey Action**: Build NEAR transaction to add new device
5. **Signing**: Sign transaction with imported private key
6. **Return**: Signed transaction ready for broadcast

```typescript
// Key implementation in WebAuthnManager
async signAddKeyToDevice({
  newDevicePublicKey,    // Device2's new public key
  accountId,             // Account to add device to
  importedPrivateKey,    // Device1's private key (temporary)
  context,               // PasskeyManager context
  // ...
}): Promise<VerifyAndSignTransactionResult>
```

## Security Model

### Security Benefits
✅ **Minimal Exposure**: Private key used once, immediately discarded
✅ **Device Isolation**: Each device gets unique TouchID-secured keypair
✅ **No Persistent Storage**: Imported key never stored on Device2
✅ **Physical Proximity**: QR scanning requires local access
✅ **Biometric Protection**: TouchID required on both devices

### Risk Assessment
**Low Risk Environment**: Both devices physically controlled by same user
- QR code displayed briefly, then cleared
- No network transmission (local QR scanning)
- Private key cleared from memory after single use

### Required TouchID Prompts
- **Device1**: Required to export private key (decrypt existing keypair)
- **Device2**: Required to create new secure keypair (generate PRF for encryption)

**Cannot eliminate Device2 TouchID** - it's essential for:
- Generating PRF output for key encryption
- Creating secure enclave storage
- Maintaining cryptographic security model

## Alternative Approaches Considered

### Rejected: "Device1 Scans Device2" Flow
```
Device2: Create keypair → Export [publicKey + sessionId] → QR Code
Device1: Scan QR → AddKey transaction → Export [accountId + sessionId] → QR Code
Device2: Scan QR → Store authenticator data → Done
```

**Rejected because:**
- ❌ 4 steps vs 2 steps (100% more friction)
- ❌ 2 QR codes vs 1 QR code
- ❌ Back-and-forth complexity
- ❌ Longer completion time
- ⚠️ Only marginal security improvement for trusted device scenario

## Implementation Status

### Completed
✅ Core transaction signing logic (`signAddKeyToDevice`)
✅ Private key validation and nonce fetching
✅ AddKey action creation and transaction signing
✅ Integration with existing WebAuthn/TouchID infrastructure

### Remaining Work
🔲 QR code generation UI (Device1)
🔲 QR code scanning UI (Device2)
🔲 Error handling and user feedback
🔲 Transaction broadcasting integration
🔲 Success/failure state management

## Design Principles

1. **UX First**: Optimize for 99% use case (trusted device addition)
2. **Minimal Friction**: Reduce steps, prompts, and complexity
3. **Security Pragmatism**: Accept minimal risk for major UX improvement
4. **Physical Trust**: Assume both devices controlled by same user
5. **Clean Architecture**: Maintain separation between QR/UI and crypto logic

## Usage Example

```typescript
// Device1: Export flow
const exportButton = await passkeyManager.exportForQR(accountId);
// Shows QR code with account credentials

// Device2: Import flow
const importResult = await passkeyManager.importFromQR(scannedData);
// Adds Device2 to the account, ready for use
```

This approach delivers the smoothest possible multi-device experience while maintaining the security guarantees that make passkey authentication valuable.