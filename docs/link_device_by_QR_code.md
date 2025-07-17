# Link Device by QR Code Implementation Plan

## Overview

Implement a secure device linking system that allows users to add backup devices to their NEAR account using QR code scanning.

## User Flow Summary

1. **Device2 (New Device)**: Generate credentials → Show QR code → Poll chain for AddKey event → Auto-complete registration
2. **Device1 (Primary Device)**: Authorize with TouchID → Scan QR code → Transfer funds and access key → Done

## Architecture Components

### Core Components
```typescript
// New PasskeyManager methods
class PasskeyManager {
  async generateDeviceLinkingQR(accountId: string): Promise<DeviceLinkingQRData>
  async scanAndLinkDevice(qrData: DeviceLinkingQRData): Promise<LinkDeviceResult>
  async completeDeviceLinking(linkingSession: DeviceLinkingSession): Promise<void>
}

// Supporting types
interface DeviceLinkingQRData {
  accountId: string;
  devicePublicKey: string;
  sessionId: string;
  timestamp: number;
}

interface DeviceLinkingSession {
  accountId: string;
  deviceKeypair: KeyPair;
  credential: PublicKeyCredential;
  vrfChallenge: VRFChallenge;
  status: 'waiting' | 'authorized' | 'registered' | 'failed';
}
```

### WebAuthn Integration
```typescript
// WebAuthnManager new methods
class WebAuthnManager {
  async generateDeviceLinkingCredentials(accountId: string): Promise<{
    credential: PublicKeyCredential;
    keypair: KeyPair;
    vrfChallenge: VRFChallenge;
  }>

  async signDeviceLinkingTransaction(
    qrData: DeviceLinkingQRData,
    fundingAmount: string
  ): Promise<SignedTransaction>
}
```

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)

#### 1.1 Data Structures & Types
```typescript
// Add to src/core/types/passkeyManager.ts
export interface DeviceLinkingQRData {
  accountId: string;
  devicePublicKey: string;
  sessionId: string;
  timestamp: number;
  version: string; // For future compatibility
}

export interface DeviceLinkingSession {
  sessionId: string;
  accountId: string;
  deviceKeypair: KeyPair;
  credential: PublicKeyCredential;
  vrfChallenge: VRFChallenge;
  status: DeviceLinkingStatus;
  createdAt: number;
  expiresAt: number;
}

export type DeviceLinkingStatus =
  | 'generating'     // Device2: Generating credentials
  | 'waiting'        // Device2: Waiting for Device1 authorization
  | 'authorizing'    // Device1: Processing authorization
  | 'authorized'     // Device1: AddKey transaction sent
  | 'registering'    // Device2: Calling verify_and_register_user
  | 'completed'      // Success
  | 'failed'         // Error state
  | 'expired';       // Timeout

export interface LinkDeviceResult extends ActionResult {
  devicePublicKey: string;
  transactionId?: string;
  fundingAmount: string;
}
```

#### 1.2 Session Management
```typescript
// Add to src/core/PasskeyManager/deviceLinking.ts
export class DeviceLinkingSessionManager {
  private sessions = new Map<string, DeviceLinkingSession>();

  createSession(accountId: string): DeviceLinkingSession;
  getSession(sessionId: string): DeviceLinkingSession | null;
  updateSessionStatus(sessionId: string, status: DeviceLinkingStatus): void;
  cleanupExpiredSessions(): void;
}
```

#### 1.3 QR Code Generation
```typescript
// Device2: Generate QR data
export async function generateDeviceLinkingQR(
  context: PasskeyManagerContext,
  accountId: string
): Promise<{
  qrData: DeviceLinkingQRData;
  session: DeviceLinkingSession;
}> {
  // 1. Validate account ID
  validateNearAccountId(accountId);

  // 2. Generate VRF challenge
  const vrfChallenge = await generateBootstrapVrfChallenge(context, accountId);

  // 3. Generate WebAuthn credentials (TouchID #1)
  const credential = await context.webAuthnManager.touchIdPrompt
    .generateRegistrationCredentials({
      nearAccountId: accountId,
      challenge: vrfChallenge.outputAs32Bytes(),
    });

  // 4. Derive NEAR keypair
  const keypairResult = await context.webAuthnManager
    .deriveNearKeypairAndEncrypt({
      credential,
      nearAccountId: accountId
    });

  // 5. Create session
  const sessionId = generateSessionId();
  const session: DeviceLinkingSession = {
    sessionId,
    accountId,
    deviceKeypair: KeyPair.fromString(keypairResult.privateKey),
    credential,
    vrfChallenge,
    status: 'waiting',
    createdAt: Date.now(),
    expiresAt: Date.now() + (15 * 60 * 1000) // 15 minute timeout
  };

  // 6. Generate QR data
  const qrData: DeviceLinkingQRData = {
    accountId,
    devicePublicKey: keypairResult.publicKey,
    sessionId,
    timestamp: Date.now(),
    version: '1.0'
  };

  return { qrData, session };
}
```

### Phase 2: Device1 Authorization (Week 2)

#### 2.1 QR Scanning & Validation
```typescript
// Device1: Scan and validate QR
export async function scanAndLinkDevice(
  context: PasskeyManagerContext,
  qrData: DeviceLinkingQRData,
  options?: { fundingAmount?: string }
): Promise<LinkDeviceResult> {

  // 1. Validate QR data
  validateDeviceLinkingQRData(qrData);

  // 2. Check account ownership
  await verifyAccountOwnership(context, qrData.accountId);

  // 3. Create combined AddKey + Transfer transaction
  const fundingAmount = options?.fundingAmount || '0.1'; // Default 0.1 NEAR

  const signedTransaction = await context.webAuthnManager
    .signDeviceLinkingTransaction({
      context,
      accountId: qrData.accountId,
      devicePublicKey: qrData.devicePublicKey,
      fundingAmount: parseNearAmount(fundingAmount)!,
    });

  // 4. Broadcast transaction (TouchID #2)
  const result = await broadcastTransaction(context, signedTransaction, options);

  return {
    success: true,
    accountId: qrData.accountId,
    devicePublicKey: qrData.devicePublicKey,
    transactionId: result.transactionId,
    fundingAmount
  };
}
```

#### 2.2 Combined Transaction Creation
```typescript
// WebAuthnManager method
async signDeviceLinkingTransaction({
  context,
  accountId,
  devicePublicKey,
  fundingAmount
}: {
  context: PasskeyManagerContext;
  accountId: string;
  devicePublicKey: string;
  fundingAmount: string;
}): Promise<SignedTransaction> {

  const publicKey = PublicKey.from(devicePublicKey);

  // Create combined transaction
  const transaction = await context.nearClient.createTransaction({
    receiverId: accountId,
    actions: [
      // Add Device2's public key as full access key
      actionCreators.addKey(
        publicKey,
        AccessKey.fullAccess()
      ),
      // Transfer funding for Device2's operations
      actionCreators.transfer(fundingAmount)
    ]
  });

  // Sign with Device1's credentials (TouchID prompt)
  return await this.signTransaction({
    context,
    accountId,
    transaction,
    prompt: `Authorize new device and transfer ${formatNearAmount(fundingAmount)} NEAR for setup`
  });
}
```

### Phase 3: Device2 Registration (Week 2)

#### 3.1 Blockchain Polling
```typescript
// Device2: Wait for authorization
export async function waitForDeviceAuthorization(
  context: PasskeyManagerContext,
  session: DeviceLinkingSession
): Promise<boolean> {

  const maxAttempts = 45; // 45 attempts = ~90 seconds with exponential backoff
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      // Check if our public key is now an access key
      const accessKeys = await context.nearClient
        .viewAccessKeyList(session.accountId);

      const hasKey = accessKeys.keys.some(key =>
        key.public_key === session.deviceKeypair.getPublicKey().toString()
      );

      if (hasKey) {
        return true; // Authorization detected!
      }

      // Exponential backoff: 2s, 3s, 4.5s, 6.75s, ... max 10s
      const delay = Math.min(2000 * Math.pow(1.5, attempts), 10000);
      await new Promise(resolve => setTimeout(resolve, delay));
      attempts++;

    } catch (error) {
      console.warn(`Polling attempt ${attempts} failed:`, error);
      attempts++;
    }
  }

  throw new Error('Device authorization timeout - please try again');
}
```

#### 3.2 Complete Registration
```typescript
// Device2: Complete registration
export async function completeDeviceLinking(
  context: PasskeyManagerContext,
  session: DeviceLinkingSession
): Promise<void> {

  // 1. Wait for Device1 authorization
  await waitForDeviceAuthorization(context, session);

  // 2. Create NEAR client with Device2's keypair
  const device2Client = new NearClient({
    networkId: context.nearClient.networkId,
    keyStore: new InMemoryKeyStore(),
  });

  // Add Device2's keypair to keystore
  await device2Client.keyStore.setKey(
    context.nearClient.networkId,
    session.accountId,
    session.deviceKeypair
  );

  // 3. Call verify_and_register_user with Device2's credentials
  const registrationData = serializeCredentialWithPRF(session.credential);

  // use signAndSendTransaction, callFunction may be deprecated
  await device2Client.callFunction({
    contractId: context.nearClient.contractId,
    methodName: 'verify_and_register_user',
    args: {
      webauthn_registration: registrationData,
      vrf_challenge_data: session.vrfChallenge,
    },
    gas: '300000000000000',
    attachedDeposit: '0'
  });

  // 4. Store authenticator locally
  await context.webAuthnManager.storeAuthenticator({
    credentialId: session.credential.id,
    credentialPublicKey: new Uint8Array(session.credential.rawId),
    transports: ['internal'],
    name: `Linked Device ${new Date().toISOString()}`,
    nearAccountId: session.accountId,
    registered: new Date().toISOString(),
    syncedAt: new Date().toISOString(),
    vrfPublicKey: session.deviceKeypair.getPublicKey().toString()
  });
}
```

### Phase 4: UI Components (Week 3)

#### 4.1 React Components
```typescript
// src/react/components/DeviceLinking/GenerateQRComponent.tsx
interface GenerateQRProps {
  accountId: string;
  onComplete: (result: LinkDeviceResult) => void;
  onError: (error: Error) => void;
}

export function GenerateQRComponent({ accountId, onComplete, onError }: GenerateQRProps) {
  const [qrData, setQRData] = useState<DeviceLinkingQRData | null>(null);
  const [status, setStatus] = useState<DeviceLinkingStatus>('generating');

  // Implementation with QR display, status updates, polling
}

// src/react/components/DeviceLinking/ScanQRComponent.tsx
interface ScanQRProps {
  onComplete: (result: LinkDeviceResult) => void;
  onError: (error: Error) => void;
}

export function ScanQRComponent({ onComplete, onError }: ScanQRProps) {
  // QR scanner implementation with validation
}
```

#### 4.2 Hook Integration
```typescript
// src/react/hooks/useDeviceLinking.ts
export function useDeviceLinking() {
  const { passkeyManager } = usePasskeyManager();

  const generateQR = useCallback(async (accountId: string) => {
    return await passkeyManager.generateDeviceLinkingQR(accountId);
  }, [passkeyManager]);

  const scanAndLink = useCallback(async (qrData: DeviceLinkingQRData) => {
    return await passkeyManager.scanAndLinkDevice(qrData);
  }, [passkeyManager]);

  const completeLink = useCallback(async (session: DeviceLinkingSession) => {
    return await passkeyManager.completeDeviceLinking(session);
  }, [passkeyManager]);

  return { generateQR, scanAndLink, completeLink };
}
```

### Phase 5: Error Handling & Testing (Week 4)

#### 5.1 Error Scenarios
```typescript
// Error handling for common scenarios
export class DeviceLinkingError extends Error {
  constructor(
    message: string,
    public code: DeviceLinkingErrorCode,
    public phase: 'generation' | 'authorization' | 'registration'
  ) {
    super(message);
  }
}

export enum DeviceLinkingErrorCode {
  INVALID_QR_DATA = 'INVALID_QR_DATA',
  ACCOUNT_NOT_OWNED = 'ACCOUNT_NOT_OWNED',
  AUTHORIZATION_TIMEOUT = 'AUTHORIZATION_TIMEOUT',
  INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
  REGISTRATION_FAILED = 'REGISTRATION_FAILED',
  SESSION_EXPIRED = 'SESSION_EXPIRED'
}
```

#### 5.2 E2E Test Plan
```typescript
// src/__tests__/e2e/device-linking.test.ts
describe('Device Linking E2E', () => {
  test('Complete device linking flow', async () => {
    // Setup: Create Device1 account
    const device1Account = await setupTestAccount();

    // Device2: Generate QR
    const { qrData, session } = await passkeyManager2
      .generateDeviceLinkingQR(device1Account.accountId);

    expect(qrData.accountId).toBe(device1Account.accountId);
    expect(qrData.devicePublicKey).toMatch(/^ed25519:/);

    // Device1: Scan and authorize
    const linkResult = await passkeyManager1
      .scanAndLinkDevice(qrData);

    expect(linkResult.success).toBe(true);
    expect(linkResult.transactionId).toBeDefined();

    // Device2: Complete registration
    await passkeyManager2.completeDeviceLinking(session);

    // Verify: Both devices can now access account
    const device1Auth = await passkeyManager1.getAuthenticatedUser();
    const device2Auth = await passkeyManager2.getAuthenticatedUser();

    expect(device1Auth?.accountId).toBe(device1Account.accountId);
    expect(device2Auth?.accountId).toBe(device1Account.accountId);
  });

  test('Error: Invalid QR data', async () => {
    const invalidQR = { accountId: 'invalid', devicePublicKey: 'bad' };

    await expect(passkeyManager.scanAndLinkDevice(invalidQR))
      .rejects.toThrow(DeviceLinkingError);
  });

  test('Error: Authorization timeout', async () => {
    const { session } = await passkeyManager2.generateDeviceLinkingQR('test.testnet');

    // Don't authorize, just wait for timeout
    await expect(passkeyManager2.completeDeviceLinking(session))
      .rejects.toThrow('authorization timeout');
  });
});
```