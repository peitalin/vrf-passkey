import { KeyPair } from '@near-js/crypto';

import type { PasskeyManagerContext } from './index';
import { ActionType } from '../types/actions';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';
import { getNonceBlockHashAndHeight } from './actions';
import { base64UrlEncode } from '../../utils';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';

import type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  StartDeviceLinkingOptionsDevice2
} from '../types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
import QRCode from 'qrcode';
// jsQR will be dynamically imported when needed
import type { ActionParams } from '../types/signer-worker';
import { IndexedDBManager } from '../IndexedDBManager';
import type { EncryptedVRFKeypair } from '../types/vrf-worker';
import type { VRFChallenge } from '../types/webauthn';
import { generateDeviceSpecificUserId } from '../WebAuthnManager/touchIdPrompt';
import { getDeviceLinkingAccountContractCall } from "../rpcCalls";
import { DEFAULT_WAIT_STATUS } from "../types/rpc";


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
  private options: StartDeviceLinkingOptionsDevice2;
  private session: DeviceLinkingSession | null = null;
  private phase: 'idle' | 'generating' | 'waiting' | 'registering' | 'complete' | 'error' = 'idle';
  private error?: Error;
  private pollingInterval?: NodeJS.Timeout;
  private lastRpcCallTime = 0;
  private KEY_POLLING_INTERVAL = 4000;
  private readonly instanceId = Math.random().toString(36).substring(2, 8);

  constructor(context: PasskeyManagerContext, options: StartDeviceLinkingOptionsDevice2) {
    this.context = context;
    this.options = options;
    console.log(`LinkDeviceFlow[${this.instanceId}]: New instance created`);
  }

  /**
   * Device2 (companion device): Generate QR code and start polling for AddKey transaction
   *
   * Supports two flows:
   * - Option E: If accountId provided, generate proper NEAR keypair immediately (faster)
   * - Option F: If no accountId, generate temp NEAR keypair, replace later (seamless UX)
   */
  async generateQR(accountId?: AccountId): Promise<{
    qrData: DeviceLinkingQRData;
    qrCodeDataURL: string
  }> {
    try {
      this.phase = 'generating';

      if (accountId) {
        // === OPTION E: Account ID provided - generate proper keypair immediately ===
        console.log(`LinkDeviceFlow: Option E - Using provided account ID: ${accountId}`);

        // Validate account ID format
        validateNearAccountId(accountId);

        // validate account exists on-chain
        const accountExists = await this.context.nearClient.viewAccount(accountId);
        if (!accountExists) {
          throw new Error(`Account ${accountId} does not exist onchain`);
        }

        // Generate VRF challenge for the real account
        const vrfChallenge = await generateBootstrapVrfChallenge(this.context, accountId);

        // Generate WebAuthn credentials with TouchID (for real account)
        // Note: Device number will be determined later when Device1 creates the mapping
        const credential = await this.context.webAuthnManager.touchIdPrompt.generateRegistrationCredentials({
          nearAccountId: accountId,
          challenge: vrfChallenge.outputAs32Bytes(),
        });

        // Derive NEAR keypair with proper account-specific salt
        const nearKeyResult = await this.context.webAuthnManager.deriveNearKeypairAndEncrypt({
          credential,
          nearAccountId: toAccountId(accountId)
        });

        if (!nearKeyResult.success || !nearKeyResult.publicKey) {
          throw new Error('Failed to generate NEAR keypair for provided account');
        }

        // Create session with real account ID from start
        this.session = {
          accountId: accountId,
          deviceNumber: undefined,
          nearPublicKey: nearKeyResult.publicKey,
          credential,
          vrfChallenge,
          status: 'waiting',
          createdAt: Date.now(),
          expiresAt: Date.now() + (15 * 60 * 1000) // 15 minute timeout
        };

        console.log(`LinkDeviceFlow: Option E - Generated proper NEAR keypair for ${accountId}`);

      } else {
        // === OPTION F: No account ID - generate temporary keypair, replace later ===
        console.log(`LinkDeviceFlow: Option F - No account provided, using temporary keypair approach`);

        const tempAccountId = 'temp-device-linking.testnet';

        // Generate temporary NEAR keypair WITHOUT TouchID/VRF (just for QR generation)
        const tempNearKeyResult = await this.generateTemporaryNearKeypair();

        // Create session with null accountId (will be discovered from polling)
        this.session = {
          accountId: null, // Will be discovered from contract polling
          deviceNumber: undefined, // Will be discovered from contract polling
          nearPublicKey: tempNearKeyResult.publicKey,
          credential: null, // Will be generated later when we know real account
          vrfChallenge: null, // Will be generated later
          status: 'waiting',
          createdAt: Date.now(),
          expiresAt: Date.now() + (15 * 60 * 1000), // 15 minute timeout
          tempPrivateKey: tempNearKeyResult.privateKey // Store temp private key for signing later
        };

        console.log(`LinkDeviceFlow: Option F - Generated temporary NEAR keypair`);
      }

      // Generate QR data (works for both options)
      const qrData: DeviceLinkingQRData = {
        device2PublicKey: this.session.nearPublicKey,
        accountId: this.session.accountId || undefined, // Convert null to undefined for optional field
        timestamp: Date.now(),
        version: '1.0'
      };

      // Create QR code data URL
      const qrDataString = JSON.stringify(qrData);
      const qrCodeDataURL = await generateQRCodeDataURL(qrDataString);

      // Start polling for AddKey transaction
      this.startPolling();
      this.phase = 'waiting';

      const flowType = accountId
        ? 'Option E (provided account)'
        : 'Option F (account discovery)';

      this.options?.onEvent?.({
        step: 1,
        phase: 'qr-code-generated',
        status: 'progress',
        timestamp: Date.now(),
        message: `QR code generated using ${flowType}, waiting for Device1 to scan and authorize...`
      });

      return { qrData, qrCodeDataURL };

    } catch (error: any) {
      this.phase = 'error';
      this.error = error;

      this.options?.onEvent?.({
        step: 0,
        phase: 'error',
        status: 'error',
        timestamp: Date.now(),
        message: error.message,
      });

      throw new DeviceLinkingError(
        `Failed to generate device linking QR: ${error.message}`,
        DeviceLinkingErrorCode.REGISTRATION_FAILED,
        'generation'
      );
    }
  }

  /**
   * Generate temporary NEAR keypair without TouchID/VRF for Option F flow
   * This creates a proper Ed25519 keypair that can be used for the QR code
   */
  private async generateTemporaryNearKeypair(): Promise<{ publicKey: string; privateKey: string }> {
    // Generate a temporary random NEAR Ed25519 keypair
    const keyPair = KeyPair.fromRandom('ed25519');
    const publicKeyNear = keyPair.getPublicKey().toString();
    const privateKeyNear = keyPair.toString();
    console.log(`LinkDeviceFlow: Generated temporary Ed25519 keypair`);
    return {
      publicKey: publicKeyNear,
      privateKey: privateKeyNear
    };
  }

  /**
   * Device2: Start polling blockchain for AddKey transaction
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
    }, this.KEY_POLLING_INTERVAL);
  }

  private shouldContinuePolling(): boolean {
    if (!this.session || this.phase !== 'waiting') return false;

    if (Date.now() > this.session.expiresAt) {
      this.session.status = 'expired';
      this.phase = 'error';
      this.error = new Error('Session expired');

      this.options?.onEvent?.({
        step: 0,
        phase: 'error',
        status: 'error',
        timestamp: Date.now(),
        message: 'Device linking session expired',
      });

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
   * Device2: Check if device key has been added by polling contract HashMap
   */
  private async checkForDeviceKeyAdded(): Promise<boolean> {
    const sessionInfo = `instanceId=${this.instanceId}, publicKey=${this.session?.nearPublicKey?.substring(0, 20)}...`;
    console.log(`LinkDeviceFlow[${sessionInfo}]: Checking for device key addition`);

    if (!this.session?.nearPublicKey) {
      console.error(`LinkDeviceFlow[${sessionInfo}]: No session or public key available for polling`);
      return false;
    }

    try {
      this.lastRpcCallTime = Date.now();
      console.log(`LinkDeviceFlow[${sessionInfo}]: Querying contract ${this.context.webAuthnManager.configs.contractId} for key: ${this.session.nearPublicKey}`);

      const linkingResult = await getDeviceLinkingAccountContractCall(
        this.context.nearClient,
        this.context.webAuthnManager.configs.contractId,
        this.session.nearPublicKey
      );

      this.options?.onEvent?.({
        step: 2,
        phase: 'polling',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Polling contract for linked account...'
      });

      if (linkingResult && Array.isArray(linkingResult) && linkingResult.length >= 2) {
        const [linkedAccountId, deviceNumber] = linkingResult;
        console.log(`LinkDeviceFlow[${sessionInfo}]: SUCCESS! Discovered linked account:`, {
          linkedAccountId,
          deviceNumber,
          timestamp: new Date().toISOString()
        });
        this.session.accountId = linkedAccountId;
        this.session.deviceNumber = deviceNumber; // Store device number for later use

        return true;
      }

      // Log different response types for debugging
      if (linkingResult === null || linkingResult === undefined) {
        console.log(`LinkDeviceFlow[${sessionInfo}]: No mapping found yet (null/undefined response)`);
      } else if (Array.isArray(linkingResult)) {
        if (linkingResult.length < 2) {
          console.log(`LinkDeviceFlow[${sessionInfo}]: Array response but insufficient length:`, linkingResult);
        } else {
          console.log(`LinkDeviceFlow[${sessionInfo}]: Valid array response but failed condition check:`, linkingResult);
        }
      } else {
        console.log(`️LinkDeviceFlow[${sessionInfo}]: Unhandled response type:`, typeof linkingResult, linkingResult);
      }

      return false;
    } catch (error: any) {
      console.error(`LinkDeviceFlow[${sessionInfo}]: Error checking for device key addition:`, {
        error: error.message,
        stack: error.stack,
        name: error.name,
        code: error.code
      });

      return false;
    }
  }

  /**
   * Device2: Complete device linking with local storage
   */
  private async completeRegistration(): Promise<void> {
    if (!this.session || !this.session.accountId) {
      throw new Error('AccountID not available for registration');
    }

    try {
      this.options?.onEvent?.({
        step: 3,
        phase: 'registration',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Storing device authenticator data locally...'
      });

      // First, migrate/generate the VRF credentials for the real account
      // This will generate the credential for Option F flow
      const migrateKeysResult = await this.migrateKeysAndCredentials();

      // Store authenticator data locally on Device2
      // Device1 already handled the contract registration and AddKey transaction
      await this.storeDeviceAuthenticator(migrateKeysResult);

      this.options?.onEvent?.({
        step: 3,
        phase: 'registration',
        status: 'progress',
        timestamp: Date.now(),
        message: 'Cleaning up temporary device linking mapping...'
      });

      this.session.status = 'completed';
      this.phase = 'complete';
      this.stopPolling();

      this.options?.onEvent?.({
        step: 3,
        phase: 'device-linking',
        status: 'success',
        timestamp: Date.now(),
        message: 'Device linking completed successfully!'
      });

      // CHANGE: Auto-login for Device2 after successful device linking
      console.log('LinkDeviceFlow: Starting auto-login attempt...');
      try {
        await this.attemptAutoLogin(migrateKeysResult);
        console.log('LinkDeviceFlow: Auto-login completed successfully');

        // Send additional event after successful auto-login to update React state
        this.options?.onEvent?.({
          step: 4,
          phase: 'device-linking',
          status: 'success',
          timestamp: Date.now(),
          message: 'Auto-login completed - device fully ready!'
        });
      } catch (loginError: any) {
        console.warn('Auto-login failed after device linking:', loginError.message);
        console.warn('Auto-login error details:', loginError);

        this.options?.onEvent?.({
          step: 4,
          phase: 'registration-error',
          status: 'error',
          timestamp: Date.now(),
          message: loginError.message,
        });

        // Don't fail the whole linking process if auto-login fails
      }

    } catch (error: any) {
      this.session.status = 'failed';
      this.phase = 'error';
      this.error = error;
      this.stopPolling();

      this.options?.onEvent?.({
        step: 0,
        phase: 'registration-error',
        status: 'error',
        timestamp: Date.now(),
        message: error.message,
      });

      throw error;
    }
  }

  /**
   * Device2: Attempt auto-login after successful device linking
   */
  private async attemptAutoLogin(migrateKeysResult: {
    encryptedVrfKeypair: EncryptedVRFKeypair;
    vrfPublicKey: string;
    nearPublicKey: string;
    credential: PublicKeyCredential;
    vrfChallenge?: VRFChallenge;
  } | undefined): Promise<void> {
    console.log('LinkDeviceFlow: attemptAutoLogin called with:', {
      hasSession: !!this.session,
      accountId: this.session?.accountId,
      hasCredential: !!this.session?.credential,
      hasMigrateKeysResult: !!migrateKeysResult
    });

    if (!this.session || !this.session.accountId || !this.session.credential || !migrateKeysResult) {
      const missing = [];
      if (!this.session) missing.push('session');
      if (!this.session?.accountId) missing.push('accountId');
      if (!this.session?.credential) missing.push('credential');
      if (!migrateKeysResult) missing.push('migrateKeysResult');
      throw new Error(`Missing required data for auto-login: ${missing.join(', ')}`);
    }

    this.options?.onEvent?.({
      step: 4,
      phase: 'device-linking',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Attempting automatic login...'
    });

    console.log('LinkDeviceFlow: Calling unlockVRFKeypair with:', {
      nearAccountId: this.session.accountId,
      hasEncryptedVrfKeypair: !!migrateKeysResult.encryptedVrfKeypair,
      hasCredential: !!this.session.credential,
      credentialType: this.session.credential?.type,
      hasPrfOutput: !!this.session.credential?.getClientExtensionResults()?.prf?.results?.first
    });

    // Check if credential has PRF output
    const prfOutput = this.session.credential?.getClientExtensionResults()?.prf?.results?.first;
    if (!prfOutput) {
      throw new Error('Credential does not have PRF output - cannot unlock VRF keypair');
    }

    // Unlock VRF keypair for immediate login
    const vrfUnlockResult = await this.context.webAuthnManager.unlockVRFKeypair({
      nearAccountId: this.session.accountId,
      encryptedVrfKeypair: migrateKeysResult.encryptedVrfKeypair,
      credential: this.session.credential,
    });

    console.log('LinkDeviceFlow: VRF unlock result:', vrfUnlockResult);

    if (vrfUnlockResult.success) {
      this.options?.onEvent?.({
        step: 4,
        phase: 'device-linking',
        status: 'success',
        timestamp: Date.now(),
        message: `Successfully logged in to ${this.session.accountId}!`
      });
    } else {
      throw new Error(vrfUnlockResult.error || 'VRF unlock failed');
    }
  }

  /**
   * Device2: Store authenticator data locally on Device2
   */
  private async storeDeviceAuthenticator(migrateKeysResult: {
    encryptedVrfKeypair: EncryptedVRFKeypair;
    vrfPublicKey: string;
    nearPublicKey: string;
    credential: PublicKeyCredential;
    vrfChallenge?: VRFChallenge;
  } | undefined): Promise<void> {
    if (!this.session || !this.session.accountId) {
      throw new Error('Session or account ID not available for storing authenticator');
    }

    try {
      const { webAuthnManager } = this.context;
      const { credential, accountId } = this.session;

      // Now check for credential after migration (should be available for both Option E and F)
      if (!credential) {
        throw new Error('WebAuthn credential not available after VRF migration');
      }

      if (!migrateKeysResult?.encryptedVrfKeypair) {
        throw new Error('VRF credentials not available after migration');
      }

      // Issue 1 Fix: Log device number to debug the issue
      console.log("Device2 authenticator storage - Device Number:", this.session.deviceNumber);
      if (this.session.deviceNumber === undefined || this.session.deviceNumber === null) {
        throw new Error('Device number not available - cannot determine device-specific account ID');
      }

      // Generate device-specific account ID for storage
      const deviceSpecificAccountId = generateDeviceSpecificUserId(accountId, this.session.deviceNumber);
      console.log("Using device number: ", this.session.deviceNumber, " (assigned by contract for this device)");
      console.log(`LinkDeviceFlow: Storing authenticator data for device-specific account: ${deviceSpecificAccountId}`);
      // Store user data for the device-specific account
      await webAuthnManager.storeUserData({
        nearAccountId: accountId, // Use device-specific account ID
        clientNearPublicKey: migrateKeysResult.nearPublicKey,
        lastUpdated: Date.now(),
        prfSupported: true,
        deterministicKey: true,
        passkeyCredential: {
          id: credential.id,
          rawId: base64UrlEncode(new Uint8Array(credential.rawId))
        },
        encryptedVrfKeypair: migrateKeysResult.encryptedVrfKeypair,
        deviceNumber: this.session.deviceNumber // Pass the correct device number from session
      });

      // Store authenticator for the device-specific account
      await webAuthnManager.storeAuthenticator({
        nearAccountId: accountId, // Use device-specific account ID
        credentialId: base64UrlEncode(new Uint8Array(credential.rawId)),
        credentialPublicKey: new Uint8Array(credential.rawId),
        transports: ['internal'],
        name: `Device ${this.session.deviceNumber || 'Unknown'} Passkey for ${accountId.split('.')[0]}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
        vrfPublicKey: migrateKeysResult.vrfPublicKey,
        deviceNumber: this.session.deviceNumber // Pass the correct device number from session
      });

      console.log(`LinkDeviceFlow: Successfully stored authenticator data for account: ${deviceSpecificAccountId}`);

    } catch (error) {
      console.error(`LinkDeviceFlow: Failed to store authenticator data:`, error);
      // Clean up any partial data on failure
      await this.cleanupFailedLinkingAttempt();
      throw error;
    }
  }

  /**
   * Re-derive VRF credentials for the real account ID instead of migrating temp credentials
   * The VRF derivation is account-specific, so we need to re-derive with the real account ID
   *
   * For Option F: Generate WebAuthn credential + derive VRF credentials
   * For Option E: VRF credentials already exist, just ensure they're stored
   */
  private async migrateKeysAndCredentials(): Promise<{
    encryptedVrfKeypair: EncryptedVRFKeypair;
    vrfPublicKey: string;
    nearPublicKey: string;
    credential: PublicKeyCredential;
    vrfChallenge?: VRFChallenge;
  } | undefined> {

    if (!this.session?.accountId) {
      return undefined;
    }
    const realAccountId = this.session.accountId;

    try {
      console.log(`LinkDeviceFlow: Processing VRF credentials for real account: ${realAccountId}`);

      if (!this.session.credential) {
        // === OPTION F: Need to generate WebAuthn credential + derive VRF ===
        console.log(`LinkDeviceFlow: Option F - Generating WebAuthn credential for ${realAccountId}`);

        // Generate VRF challenge for the real account (uses account ID as salt)
        const vrfChallenge = await generateBootstrapVrfChallenge(this.context, realAccountId);

        // Use device number that was discovered during polling
        const deviceNumber = this.session.deviceNumber;
        console.log(`LinkDeviceFlow: Using device number ${deviceNumber} for credential generation`);

        // Generate WebAuthn credentials with TouchID (now that we know the real account)
        const credential = await this.context.webAuthnManager.touchIdPrompt.generateRegistrationCredentialsForLinkDevice({
          nearAccountId: realAccountId, // Use base account ID for consistent PRF salts across devices
          deviceNumber, // Use device number discovered during polling
          challenge: vrfChallenge.outputAs32Bytes(),
        });

        // Store credential and challenge in session for later cleanup
        this.session.credential = credential;
        this.session.vrfChallenge = vrfChallenge;

        // Derive VRF keypair from PRF output for storage
        const vrfDerivationResult = await this.context.webAuthnManager.deriveVrfKeypairFromPrf({
          credential: credential,
          nearAccountId: realAccountId // Use base account ID for PRF salt consistency
        });

        if (!vrfDerivationResult.success || !vrfDerivationResult.encryptedVrfKeypair) {
          throw new Error('Failed to derive VRF keypair from PRF for real account');
        }

        console.log(`LinkDeviceFlow: Option F - Generated proper credentials, implementing 3-step flow`);

        // === STEP 1: Generate NEAR keypair (deterministic, no transaction signing) ===
        // Use base account ID for consistent keypair derivation across devices
        const nearKeyResultStep1 = await this.context.webAuthnManager.deriveNearKeypairAndEncrypt({
          nearAccountId: realAccountId, // Use base account ID for consistency
          credential: credential,
          // No options - just generate the keypair, don't sign registration tx yet
        });

        if (!nearKeyResultStep1.success || !nearKeyResultStep1.publicKey) {
          throw new Error('Failed to derive NEAR keypair in step 1');
        }

        console.log(`LinkDeviceFlow: Step 1 - Generated keypair: ${nearKeyResultStep1.publicKey}`);

        // === STEP 2: Execute Key Replacement Transaction ===
        const {
          nextNonce,
          txBlockHash,
        } = await getNonceBlockHashAndHeight({
          nearClient: this.context.nearClient,
          nearPublicKeyStr: this.session.nearPublicKey, // Use temp key for nonce info
          nearAccountId: realAccountId
        });
        console.log("nextNonce", nextNonce);

        await this.executeKeySwapTransaction(
          nearKeyResultStep1.publicKey,
          nextNonce,
          txBlockHash
        );

        // === STEP 3: Get new key's actual nonce and sign registration transaction ===
        const {
          nextNonce: newKeyNonce,
          txBlockHash: newTxBlockHash,
        } = await getNonceBlockHashAndHeight({
          nearClient: this.context.nearClient,
          nearPublicKeyStr: nearKeyResultStep1.publicKey, // Use NEW key for its actual nonce
          nearAccountId: realAccountId
        });

        // Generate the same keypair again (deterministic) but now with registration transaction
        const nearKeyResultStep3 = await this.context.webAuthnManager.deriveNearKeypairAndEncrypt({
          nearAccountId: realAccountId, // Use base account ID for consistency
          credential: credential,
          options: {
            vrfChallenge: vrfChallenge,
            contractId: this.context.webAuthnManager.configs.contractId,
            nonce: newKeyNonce, // ✅ Use NEW key's actual nonce
            blockHash: newTxBlockHash,
            // Pass the deterministic VRF public key for contract call
            // Note: deviceNumber removed - contract determines this automatically for device linking
            deterministicVrfPublicKey: vrfDerivationResult.vrfPublicKey,
          }
        });

        if (!nearKeyResultStep3.success || !nearKeyResultStep3.signedTransaction) {
          throw new Error('Failed to sign registration transaction in step 3');
        }

        console.log(`LinkDeviceFlow: Step 3 - Generated registration transaction with correct nonce`);

        // === STEP 3: Broadcast Registration Transaction ===
        console.log(`LinkDeviceFlow: Broadcasting Device2 authenticator registration transaction`);
        const registrationTxResult = await this.context.nearClient.sendTransaction(nearKeyResultStep3.signedTransaction);
        console.log(`LinkDeviceFlow: Device2 authenticator registered on-chain:`, registrationTxResult?.transaction?.hash);

        // === OPTION F: Clean up temp account VRF data ===
        // Clean up any temp account VRF data (Option F only)
        if (this.session?.tempPrivateKey) {
          try {
            await IndexedDBManager.nearKeysDB.deleteEncryptedKey('temp-device-linking.testnet');
            console.log(`LinkDeviceFlow: Cleaned up temp VRF credentials`);
          } catch (err) {
            console.warn(`️LinkDeviceFlow: Could not clean up temp VRF credentials:`, err);
          }
        }

        // Return all derived values - no more session state confusion!
        const result = {
          encryptedVrfKeypair: vrfDerivationResult.encryptedVrfKeypair,
          vrfPublicKey: vrfDerivationResult.vrfPublicKey,
          nearPublicKey: nearKeyResultStep1.publicKey,
          credential: credential,
          vrfChallenge: vrfChallenge
        };

        console.log('LinkDeviceFlow: Option F returning result with credential:', {
          hasCredential: !!result.credential,
          credentialType: result.credential?.type,
          hasPrfOutput: !!result.credential?.getClientExtensionResults()?.prf?.results?.first
        });

        return result;

      } else {
        // === OPTION E: Regenerate credential with device number ===
        console.log(`LinkDeviceFlow: Option E - Regenerating credentials with device number for ${realAccountId}`);

        // Generate VRF challenge for the real account
        const vrfChallenge = await generateBootstrapVrfChallenge(this.context, realAccountId);

        // Use device number that was discovered during polling
        const deviceNumber = this.session.deviceNumber;
        console.log(`LinkDeviceFlow: Option E - Using device number ${deviceNumber} for credential regeneration`);

        // Regenerate WebAuthn credentials with proper device number
        const credential = await this.context.webAuthnManager.touchIdPrompt.generateRegistrationCredentialsForLinkDevice({
          nearAccountId: realAccountId, // Use base account ID for consistent PRF salts across devices
          deviceNumber, // Use device number discovered during polling
          challenge: vrfChallenge.outputAs32Bytes(),
        });

        // Store regenerated credential and challenge in session
        this.session.credential = credential;
        this.session.vrfChallenge = vrfChallenge;

        // For Option E, also derive VRF keypair from regenerated credential
        const vrfDerivationResult = await this.context.webAuthnManager.deriveVrfKeypairFromPrf({
          credential: credential,
          nearAccountId: realAccountId // Use base account ID for PRF salt consistency
        });

        if (!vrfDerivationResult.success || !vrfDerivationResult.encryptedVrfKeypair) {
          throw new Error('Failed to derive VRF keypair from PRF for Option E');
        }

        console.log(`LinkDeviceFlow: Option E - VRF credentials properly derived for ${realAccountId}`);

        // Return all derived values - clean and explicit!
        const result = {
          encryptedVrfKeypair: vrfDerivationResult.encryptedVrfKeypair,
          vrfPublicKey: vrfDerivationResult.vrfPublicKey,
          nearPublicKey: this.session.nearPublicKey, // For Option E, use existing NEAR public key
          credential: credential, // Use regenerated credential with device number
          vrfChallenge: vrfChallenge // Use regenerated VRF challenge
        };

        console.log('LinkDeviceFlow: Option E returning result with credential:', {
          hasCredential: !!result.credential,
          credentialType: result.credential?.type,
          hasPrfOutput: !!result.credential?.getClientExtensionResults()?.prf?.results?.first
        });

        return result;
      }

    } catch (error) {
      console.error(`LinkDeviceFlow: Failed to process VRF credentials:`, error);
      throw error;
    }
  }

  /**
   * Execute key replacement transaction for Option F flow
   * Replace temporary key with properly derived key using AddKey + DeleteKey
   */
  private async executeKeySwapTransaction(
    newPublicKey: string,
    nextNonce: string,
    txBlockHash: string
  ): Promise<void> {
    if (!this.session?.tempPrivateKey || !this.session?.accountId) {
      throw new Error('Missing temporary private key or account ID for key replacement');
    }

    const { tempPrivateKey, accountId, nearPublicKey: oldPublicKey } = this.session;

    try {
      console.log(`LinkDeviceFlow: Executing key replacement transaction for ${accountId}`);
      console.log(`   - Old key: ${oldPublicKey}`);
      console.log(`   - New key: ${newPublicKey}`);

      // Build actions: AddKey new + DeleteKey old
      const actions: ActionParams[] = [
        {
          actionType: ActionType.AddKey,
          public_key: newPublicKey,
          access_key: JSON.stringify({
            nonce: 0,
            permission: { FullAccess: {} }
          })
        },
        {
          actionType: ActionType.DeleteKey,
          public_key: oldPublicKey
        }
      ];

      // Use the webAuthnManager to sign with the temporary private key
      const keySwapResult = await this.context.webAuthnManager.signTransactionWithKeyPair({
        nearPrivateKey: tempPrivateKey,
        signerAccountId: accountId,
        receiverId: accountId,
        nonce: nextNonce,
        blockHash: txBlockHash,
        actions
      });

      // Broadcast the transaction
      const txResult = await this.context.nearClient.sendTransaction(
        keySwapResult.signedTransaction,
        DEFAULT_WAIT_STATUS.linkDeviceSwapKey
      );

      console.log(`LinkDeviceFlow: Key replacement transaction successful:`, txResult?.transaction?.hash);

    } catch (error) {
      console.error(`LinkDeviceFlow: Key replacement transaction failed:`, error);
      throw new Error(`Key replacement failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Clean up failed linking attempts - remove any partially stored data
   */
  private async cleanupFailedLinkingAttempt(): Promise<void> {
    if (!this.session) return;

    try {
      const { credential, accountId, nearPublicKey } = this.session;

      console.log(`LinkDeviceFlow: Cleaning up failed linking attempt for ${accountId || 'unknown account'}`);

      // Remove any authenticator data for both base and device-specific accounts (if they were discovered)
      if (accountId && credential) {

        try {
          await IndexedDBManager.clientDB.deleteAllAuthenticatorsForUser(accountId);
          console.log(`LinkDeviceFlow: Removed authenticators for ${accountId}`);
        } catch (err) {
          console.warn(`️LinkDeviceFlow: Could not remove authenticators for ${accountId}:`, err);
        }

        try {
          await IndexedDBManager.clientDB.deleteUser(accountId);
          console.log(`LinkDeviceFlow: Removed user data for ${accountId}`);
        } catch (err) {
          console.warn(`️LinkDeviceFlow: Could not remove user data for ${accountId}:`, err);
        }

        // Remove any VRF credentials for both device-specific and base accounts (in case re-derivation happened)
        try {
          await IndexedDBManager.nearKeysDB.deleteEncryptedKey(accountId);
          console.log(`LinkDeviceFlow: Removed VRF credentials for device-specific account ${accountId}`);
        } catch (err) {
          console.warn(`️LinkDeviceFlow: Could not remove VRF credentials for ${accountId}:`, err);
        }
      }

      // Always clean up temp account VRF data (this is where initial QR generation stores data)
      try {
        await IndexedDBManager.nearKeysDB.deleteEncryptedKey('temp-device-linking.testnet');
        console.log(`LinkDeviceFlow: Removed temp VRF credentials`);
      } catch (err) {
        console.warn(`️LinkDeviceFlow: Could not remove temp VRF credentials:`, err);
      }

    } catch (error) {
      console.error(`LinkDeviceFlow: Error during cleanup:`, error);
    }
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
