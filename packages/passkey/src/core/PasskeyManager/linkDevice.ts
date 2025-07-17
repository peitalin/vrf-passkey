import type { NearClient } from '../NearClient';
import type { ActionOptions, ActionResult, DeviceLinkingOptions } from '../types/passkeyManager';
import type { PasskeyManagerContext } from './index';
import { ActionType } from '../types/actions';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';
import { getLoginState } from './login';
import { executeAction } from './actions';
import type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  DeviceLinkingStatus,
  LinkDeviceResult
} from '../types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
import QRCode from 'qrcode';
import { base64UrlEncode } from '../../utils/encoders';
// jsQR will be dynamically imported when needed

/**
 * Device linking flow class - manages the complete device linking process
 *
 * Usage:
 * ```typescript
 * // Device2: Generate QR and start polling
 * const flow = new LinkDeviceFlow(context, options);
 * const { qrData, qrCodeDataURL } = await flow.generateQR(accountId);
 *
 * // Device1: Scan and authorize
 * const result = await LinkDeviceFlow.scanAndLink(context, options);
 *
 * // Device2: Flow automatically completes when AddKey is detected
 * const state = flow.getState();
 * ```
 */
export class LinkDeviceFlow {
  private context: PasskeyManagerContext;
  private options?: DeviceLinkingOptions;
  private session: DeviceLinkingSession | null = null;
  private phase: 'idle' | 'generating' | 'waiting' | 'registering' | 'complete' | 'error' = 'idle';
  private error?: Error;
  private pollingInterval?: NodeJS.Timeout;
  private lastRpcCallTime = 0;
  private readonly instanceId = Math.random().toString(36).substring(2, 8);

  constructor(context: PasskeyManagerContext, options?: DeviceLinkingOptions) {
    this.context = context;
    this.options = options;
    console.log(`LinkDeviceFlow[${this.instanceId}]: New instance created`);
  }

  /**
   * Device2: Generate QR code and start polling for AddKey transaction
   * No account ID required - Device2 discovers which account it's linked to from contract polling
   */
  async generateQR(): Promise<{ qrData: DeviceLinkingQRData; qrCodeDataURL: string }> {
    try {
      this.phase = 'generating';

      // 1. Generate temporary account ID for VRF challenge (will be replaced with actual account from logs)
      const tempAccountId = 'temp-device-linking.testnet';

      // 2. Generate VRF challenge
      const vrfChallenge = await generateBootstrapVrfChallenge(this.context, tempAccountId);

      // 3. Generate WebAuthn credentials (TouchID #1)
      const credential = await this.context.webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
        nearAccountId: tempAccountId,
        challenge: vrfChallenge.outputAs32Bytes(),
      });

      // 4. Derive NEAR keypair
      const nearKeyResult = await this.context.webAuthnManager.deriveNearKeypairAndEncrypt({
        credential,
        nearAccountId: tempAccountId
      });

      if (!nearKeyResult.success || !nearKeyResult.publicKey) {
        throw new Error('Failed to generate NEAR keypair');
      }

      // 5. Create session (accountId will be updated when discovered from logs)
      this.session = {
        accountId: null, // Will be discovered from contract logs
        nearPublicKey: nearKeyResult.publicKey,
        credential,
        vrfChallenge,
        status: 'waiting',
        createdAt: Date.now(),
        expiresAt: Date.now() + (15 * 60 * 1000) // 15 minute timeout
      };

      // 6. Generate QR data (no account ID needed)
      const qrData: DeviceLinkingQRData = {
        devicePublicKey: nearKeyResult.publicKey,
        timestamp: Date.now(),
        version: '1.0'
      };

      // 7. Create QR code data URL
      const qrDataString = JSON.stringify(qrData);
      const qrCodeDataURL = await generateQRCodeDataURL(qrDataString);

      // 8. Start polling for AddKey transaction
      this.startPolling();
      this.phase = 'waiting';

      this.options?.onEvent?.({
        step: 1,
        phase: 'qr-code-generated',
        status: 'progress',
        timestamp: Date.now(),
        message: 'QR code generated, waiting for Device1 to scan and authorize...'
      });

      return { qrData, qrCodeDataURL };

    } catch (error: any) {
      this.phase = 'error';
      this.error = error;
      throw new DeviceLinkingError(
        `Failed to generate device linking QR: ${error.message}`,
        DeviceLinkingErrorCode.REGISTRATION_FAILED,
        'generation'
      );
    }
  }

  /**
   * Device1: Scan QR code and execute AddKey transaction (static method)
   */
  static async scanAndLink(
    context: PasskeyManagerContext,
    options?: DeviceLinkingOptions
  ): Promise<LinkDeviceResult> {
    const { onEvent, onError } = options || {};

    try {
      onEvent?.({
        step: 1,
        phase: 'scanning',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Scanning QR code...'
      });

      // 1. Scan QR code
      const { scanQRCodeFromCamera } = await import('../../utils/qr-scanner');
      const qrData = await scanQRCodeFromCamera(options?.cameraId, options?.config);

      onEvent?.({
        step: 2,
        phase: 'scanning',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Validating QR data...'
      });

      // 2. Validate QR data
      validateDeviceLinkingQRData(qrData);

      onEvent?.({
        step: 3,
        phase: 'authorization',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Checking Device1 account access...'
      });

      // 3. Get Device1's current account (the account that will receive the new key)
      const device1LoginState = await getLoginState(context);

      if (!device1LoginState.isLoggedIn || !device1LoginState.nearAccountId) {
        throw new Error('Device1 must be logged in to authorize device linking');
      }

      const device1AccountId = device1LoginState.nearAccountId;

      onEvent?.({
        step: 4,
        phase: 'authorization',
        status: 'progress',
        timestamp: Date.now(),
        message: `Adding Device2's key to ${device1AccountId}...`
      });

      // 4. Call contract's add_device_key function instead of direct AddKey
      const fundingAmount = options?.fundingAmount || '0.1'; // Default funding amount

      const actionResult = await executeAction(
        context,
        device1AccountId, // Use Device1's account ID for signing
        {
          type: ActionType.FunctionCall,
          receiverId: context.webAuthnManager.configs.contractId, // Call the contract
          methodName: 'add_device_key',
          args: {
            device_public_key: qrData.devicePublicKey, // Device2's public key from QR
            target_account_id: device1AccountId, // Add key to Device1's account
          },
          gas: '100000000000000', // 100 TGas
          deposit: '0' // No deposit needed for device linking
        },
        {
          onEvent: (event) => {
            // Forward action events as device linking events
            onEvent?.({
              step: 4,
              phase: 'authorization',
              status: event.status,
              timestamp: event.timestamp,
              message: `Device key addition: ${event.message}`
            });
          },
          onError: onError,
          hooks: options?.hooks
        }
      );

      if (!actionResult.success) {
        throw new Error(actionResult.error || 'Device key addition failed');
      }

      onEvent?.({
        step: 5,
        phase: 'registration',
        status: 'success',
        timestamp: Date.now(),
        message: `Device2's key added to ${device1AccountId} successfully!`
      });

      return {
        success: true,
        devicePublicKey: qrData.devicePublicKey,
        transactionId: actionResult.transactionId || 'unknown',
        fundingAmount,
        linkedToAccount: device1AccountId // Include which account the key was added to
      };

    } catch (error: any) {
      const errorMessage = `Failed to scan and link device: ${error.message}`;
      onError?.(new Error(errorMessage));

      throw new DeviceLinkingError(
        errorMessage,
        DeviceLinkingErrorCode.AUTHORIZATION_TIMEOUT,
        'authorization'
      );
    }
  }

  /**
   * Start polling blockchain for AddKey transaction
   */
  private startPolling(): void {
    if (!this.session) return;

    // Always stop any existing polling before starting new one
    this.stopPolling();

    console.log(`LinkDeviceFlow[${this.instanceId}]: Starting polling interval`);
    this.pollingInterval = setInterval(async () => {
      // Double-check we should still be polling (prevents race conditions)
      if (!this.shouldContinuePolling()) {
        this.stopPolling();
        return;
      }

      try {
        const hasNewKey = await this.checkForDeviceKeyAdded();
        if (hasNewKey) await this.handleDeviceKeyFound();
      } catch (error: any) {
        console.error('Polling error:', error);
        // On persistent errors, stop polling to prevent spam
        if (error.message?.includes('429') || error.message?.includes('Too Many Requests')) {
          console.warn('Rate limited - stopping polling');
          this.stopPolling();
        }
      }
    }, 1000);
  }

  private shouldContinuePolling(): boolean {
    if (!this.session || this.phase !== 'waiting') return false;

    if (Date.now() > this.session.expiresAt) {
      this.session.status = 'expired';
      this.phase = 'error';
      this.error = new Error('Session expired');
      return false;
    }

    return true;
  }

  private async handleDeviceKeyFound(): Promise<void> {
    this.session!.status = 'registering';
    this.phase = 'registering';

    this.options?.onEvent?.({
      step: 2,
      phase: 'addkey-detected',
      status: 'progress',
      timestamp: Date.now(),
      message: 'AddKey transaction detected, completing registration...'
    });

    await this.completeRegistration();
  }

  /**
   * Check if device key has been added by polling contract HashMap
   */
  private async checkForDeviceKeyAdded(): Promise<boolean> {
    console.log(`LinkDeviceFlow[${this.instanceId}]: Checking for device key addition`);
    // if (!this.session || Date.now() - this.lastRpcCallTime < 1000) return false;

    try {
      this.lastRpcCallTime = Date.now();

      // Method might not exist on current contract, so let's handle gracefully
      const linkingResult = await this.context.nearClient.view({
        account: this.context.webAuthnManager.configs.contractId,
        method: 'get_device_linking_account',
        args: { device_public_key: this.session!.nearPublicKey }
      });

      if (linkingResult && Array.isArray(linkingResult) && linkingResult.length >= 2) {
        const [linkedAccountId, accessKeyPermission] = linkingResult;
        console.log(`Discovered linked account: ${linkedAccountId} with: ${accessKeyPermission}`);
        this.session!.accountId = linkedAccountId;
        return true;
      }

      return false;
    } catch (error: any) {
      console.error('Error checking for device key addition:', error);
      return false;
    }
  }

  /**
   * Complete device linking with contract call
   */
  private async completeRegistration(): Promise<void> {
    if (!this.session || !this.session.accountId) {
      throw new Error('Session or account ID not available for registration');
    }

    try {
      this.options?.onEvent?.({
        step: 3,
        phase: 'registration',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Calling verify_and_register_user on contract...'
      });

      // Call verify_and_register_user on the contract using Device2's credentials
      const { webAuthnManager } = this.context;

      // Get deterministic VRF public key for the contract call
      const deterministicVrfResult = await webAuthnManager.deriveVrfKeypairFromPrf({
        credential: this.session.credential,
        nearAccountId: this.session.accountId
      });

      if (!deterministicVrfResult.success || !deterministicVrfResult.vrfPublicKey) {
        throw new Error('Failed to derive deterministic VRF keypair for contract registration');
      }

      // Sign and send the contract registration transaction
      const registrationResult = await webAuthnManager.signVerifyAndRegisterUser({
        contractId: webAuthnManager.configs.contractId,
        credential: this.session.credential,
        vrfChallenge: this.session.vrfChallenge,
        deterministicVrfPublicKey: deterministicVrfResult.vrfPublicKey,
        signerAccountId: this.session.accountId,
        nearAccountId: this.session.accountId,
        publicKeyStr: this.session.nearPublicKey,
        nearClient: this.context.nearClient,
        onEvent: (progress) => {
          this.options?.onEvent?.({
            step: 3,
            phase: 'registration',
            status: 'progress',
            timestamp: Date.now(),
            message: `Contract registration: ${progress.message}`
          });
        },
      });

      if (!registrationResult.verified || !registrationResult.signedTransaction) {
        throw new Error('Contract verification failed during device linking');
      }

      // Broadcast the registration transaction
      const transactionResult = await this.context.nearClient.sendTransaction(
        registrationResult.signedTransaction
      );

      // Clean up temporary device linking mapping in the contract
      try {
        await executeAction(
          this.context,
          this.session.accountId,
          {
            type: ActionType.FunctionCall,
            receiverId: this.context.webAuthnManager.configs.contractId,
            methodName: 'cleanup_device_linking',
            args: {
              device_public_key: this.session.nearPublicKey
            },
            deposit: '0'
          },
          {}
        );
      } catch (cleanupError) {
        // Don't fail the whole process if cleanup fails
        console.warn('Failed to clean up device linking mapping:', cleanupError);
      }

      // Store authenticator data locally on Device2
      await this.storeDeviceAuthenticator();

      this.session.status = 'completed';
      this.phase = 'complete';
      this.stopPolling();

      this.options?.onEvent?.({
        step: 3,
        phase: 'registration',
        status: 'success',
        timestamp: Date.now(),
        message: 'Device linking completed successfully!'
      });

    } catch (error: any) {
      this.session.status = 'failed';
      this.phase = 'error';
      this.error = error;
      this.stopPolling();
      throw error;
    }
  }

  /**
   * Store authenticator data locally on Device2
   */
  private async storeDeviceAuthenticator(): Promise<void> {
    if (!this.session || !this.session.accountId) {
      throw new Error('Session or account ID not available for storing authenticator');
    }

    const { webAuthnManager } = this.context;
    const { credential, accountId, nearPublicKey } = this.session;

    // Store user data
    await webAuthnManager.storeUserData({
      nearAccountId: accountId,
      clientNearPublicKey: nearPublicKey,
      lastUpdated: Date.now(),
      prfSupported: true,
      deterministicKey: true,
      passkeyCredential: {
        id: credential.id,
        rawId: base64UrlEncode(new Uint8Array(credential.rawId))
      },
      encryptedVrfKeypair: undefined // Will be populated during login
    });

    // Store authenticator
    await webAuthnManager.storeAuthenticator({
      nearAccountId: accountId,
      credentialId: credential.id,
      credentialPublicKey: new Uint8Array(credential.rawId), // Use rawId as public key identifier
      transports: ['internal'],
      name: `Linked Device ${new Date().toISOString()}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      vrfPublicKey: nearPublicKey
    });
  }

  /**
   * Stop polling - guaranteed to clear any existing interval
   */
  private stopPolling(): void {
    if (this.pollingInterval) {
      console.log(`LinkDeviceFlow[${this.instanceId}]: Stopping polling interval`);
      clearInterval(this.pollingInterval);
      this.pollingInterval = undefined;
    }
  }

  /**
   * Get current flow state
   */
  getState() {
    return {
      phase: this.phase,
      session: this.session,
      error: this.error,
      isWaiting: this.phase === 'waiting',
      isRegistering: this.phase === 'registering',
      isComplete: this.phase === 'complete',
      hasError: this.phase === 'error'
    };
  }

  /**
   * Cancel the flow and cleanup
   */
  cancel(): void {
    console.log(`LinkDeviceFlow[${this.instanceId}]: Cancel called`);
    this.stopPolling();
    this.phase = 'idle';
    this.session = null;
    this.error = undefined;
  }

  /**
   * Reset flow to initial state
   */
  reset(): void {
    this.cancel();
  }
}

// === UTILITY FUNCTIONS ===

async function generateQRCodeDataURL(data: string): Promise<string> {
  return QRCode.toDataURL(data, {
    width: 256,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff'
    },
    errorCorrectionLevel: 'M'
  });
}

export function validateDeviceLinkingQRData(qrData: DeviceLinkingQRData): void {
  if (!qrData.devicePublicKey) {
    throw new DeviceLinkingError(
      'Missing device public key',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization'
    );
  }

  if (!qrData.timestamp) {
    throw new DeviceLinkingError(
      'Missing timestamp',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization'
    );
  }

  // Check timestamp is not too old (max 30 minutes)
  const maxAge = 30 * 60 * 1000; // 30 minutes
  if (Date.now() - qrData.timestamp > maxAge) {
    throw new DeviceLinkingError(
      'QR code expired',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'authorization'
    );
  }

  // Account ID is optional - Device2 discovers it from contract logs
  if (qrData.accountId) {
    validateNearAccountId(qrData.accountId);
  }
}

// === MAIN FUNCTIONS ===

/**
 * Device2: Create a new device linking flow
 */
export function createDeviceLinkingFlow(
  context: PasskeyManagerContext,
  options?: DeviceLinkingOptions
): LinkDeviceFlow {
  return new LinkDeviceFlow(context, options);
}

/**
 * Device1: Scan QR code and execute AddKey transaction
 */
export async function scanAndLinkDevice(
  context: PasskeyManagerContext,
  options?: DeviceLinkingOptions
): Promise<LinkDeviceResult> {
  return LinkDeviceFlow.scanAndLink(context, options);
}

/**
 * Legacy support: Generate QR - now returns a flow instance
 */
export function generateDeviceLinkingQR(
  context: PasskeyManagerContext,
  accountId: string,
  options?: DeviceLinkingOptions
): LinkDeviceFlow {
  const flow = new LinkDeviceFlow(context, options);
  // User must call flow.generateQR(accountId) to actually generate
  return flow;
}
