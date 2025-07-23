import { TxExecutionStatus } from "@near-js/types";
import type { PasskeyManagerContext } from './index';
import { ActionType } from '../types/actions';
import { validateNearAccountId } from '../../utils/validation';
import { generateBootstrapVrfChallenge } from './registration';
import { getLoginState } from './login';
import { executeAction, getNonceBlockHashAndHeight } from './actions';
import { base64UrlEncode } from '../../utils';
import type { VRFInputData } from '../types/vrf-worker';
import type { AccountId } from '../types/accountIds';
import { toAccountId, validateAccountId } from '../types/accountIds';

import type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  DeviceLinkingStatus,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDeviceLinkingOptionsDevice2
} from '../types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
import QRCode from 'qrcode';
// jsQR will be dynamically imported when needed
import { scanQRCodeFromCamera } from '../../utils/qr-scanner';
import type { ActionParams } from '../types/signer-worker';
import { IndexedDBManager } from '../IndexedDBManager';
import { KeyPair } from '@near-js/crypto';
import type { EncryptedVRFKeypair } from '../types/vrf-worker';
import type { VRFChallenge } from '../types/webauthn';

const TRANSACTION_FINALIZATION_DELAY = 1000;

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
  private options?: StartDeviceLinkingOptionsDevice2;
  private session: DeviceLinkingSession | null = null;
  private phase: 'idle' | 'generating' | 'waiting' | 'registering' | 'complete' | 'error' = 'idle';
  private error?: Error;
  private pollingInterval?: NodeJS.Timeout;
  private lastRpcCallTime = 0;
  private KEY_POLLING_INTERVAL = 4000;
  private readonly instanceId = Math.random().toString(36).substring(2, 8);

  constructor(context: PasskeyManagerContext, options?: StartDeviceLinkingOptionsDevice2) {
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
        devicePublicKey: this.session.nearPublicKey,
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

      // Method might not exist on current contract, so let's handle gracefully
      const linkingResult = await this.context.nearClient.callFunction(
        this.context.webAuthnManager.configs.contractId,
        'get_device_linking_account',
        { device_public_key: this.session.nearPublicKey }
      );

      console.log(`LinkDeviceFlow[${sessionInfo}]: RPC response received:`, {
        result: linkingResult,
        type: typeof linkingResult,
        isArray: Array.isArray(linkingResult),
        length: Array.isArray(linkingResult) ? linkingResult.length : 'N/A'
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
      } else {
        console.log(`️LinkDeviceFlow[${sessionInfo}]: Unhandled response:`, linkingResult);
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
      console.log(">>>>>> Device2 authenticator storage - Device Number:", this.session.deviceNumber);
      if (this.session.deviceNumber === undefined || this.session.deviceNumber === null) {
        console.error(">>>>>> Device number is undefined/null! This should be 2 for device2");
        throw new Error('Device number not available - cannot determine device-specific account ID');
      }

      // Generate device-specific account ID for storage
      const deviceSpecificAccountId = this.generateDeviceSpecificAccountId(accountId, this.session.deviceNumber);
      console.log(">>>>>> deviceSpecificAccountId to REGISTER: ", deviceSpecificAccountId);
      console.log(">>>>>> Using device number: ", this.session.deviceNumber, " (assigned by contract for this device)");

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

        await this.executeKeyReplacementTransaction(
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

        // Wait 2s for transaction to finalize
        await new Promise(resolve => setTimeout(resolve, TRANSACTION_FINALIZATION_DELAY));

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
        return {
          encryptedVrfKeypair: vrfDerivationResult.encryptedVrfKeypair,
          vrfPublicKey: vrfDerivationResult.vrfPublicKey,
          nearPublicKey: nearKeyResultStep1.publicKey,
          credential: credential,
          vrfChallenge: vrfChallenge
        };

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
        return {
          encryptedVrfKeypair: vrfDerivationResult.encryptedVrfKeypair,
          vrfPublicKey: vrfDerivationResult.vrfPublicKey,
          nearPublicKey: this.session.nearPublicKey, // For Option E, use existing NEAR public key
          credential: credential, // Use regenerated credential with device number
          vrfChallenge: vrfChallenge // Use regenerated VRF challenge
        };
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
  private async executeKeyReplacementTransaction(
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
      const result = await this.context.webAuthnManager.signTransactionWithKeyPair({
        nearPrivateKey: tempPrivateKey,
        signerAccountId: accountId,
        receiverId: accountId,
        nonce: nextNonce,
        blockHash: txBlockHash,
        actions
      });

      // Broadcast the transaction
      const txResult = await this.context.nearClient.sendTransaction(
        result.signedTransaction,
        "FINAL" as TxExecutionStatus
      );

      console.log(`LinkDeviceFlow: Key replacement transaction successful:`, txResult?.transaction?.hash);

      // Wait 1s for transaction to finalize
      await new Promise(resolve => setTimeout(resolve, TRANSACTION_FINALIZATION_DELAY));

    } catch (error) {
      console.error(`LinkDeviceFlow: Key replacement transaction failed:`, error);
      throw new Error(`Key replacement failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate device-specific account ID for storage
   * Similar to generateDeviceSpecificUserId but for account storage keys
   */
  private generateDeviceSpecificAccountId(nearAccountId: AccountId, deviceNumber?: number): string {
    // If no device number provided or device number is 0, this is the first device
    if (deviceNumber === undefined || deviceNumber === 0) {
      return nearAccountId;
    }

    // Add device number to account ID
    if (nearAccountId.includes('.')) {
      const parts = nearAccountId.split('.');
      // Insert device number after the first part
      // "serp124.web3-authn-v2.testnet" -> "serp124.1.web3-authn-v2.testnet"
      parts.splice(1, 0, deviceNumber.toString());
      return parts.join('.');
    } else {
      // Fallback for accounts without dots
      return `${nearAccountId}.${deviceNumber}`;
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

/**
 * Device1 (original device): Scan QR code and execute AddKey transaction
 */
export async function scanAndLinkDevice(
  context: PasskeyManagerContext,
  options?: ScanAndLinkDeviceOptionsDevice1
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
    const qrData = await scanQRCodeFromCamera(options?.cameraId, options?.cameraConfigs);

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

    // 4. Execute batched transaction: AddKey + Contract notification
    const fundingAmount = options?.fundingAmount || '0.1'; // Default funding amount

    // Parse the device public key for AddKey action
    const devicePublicKey = qrData.devicePublicKey;
    if (!devicePublicKey.startsWith('ed25519:')) {
      throw new Error('Invalid device public key format');
    }

    // Execute two transactions with one PRF - reuse VRF challenge and credential

    onEvent?.({
      step: 4,
      phase: 'authorization',
      status: 'progress',
      timestamp: Date.now(),
      message: `Performing TouchID authentication for device linking...`
    });

    // Device1 account is already validated above

    const userData = await context.webAuthnManager.getUser(device1AccountId);
    const nearPublicKeyStr = userData?.clientNearPublicKey;
    if (!nearPublicKeyStr) {
      throw new Error('Client NEAR public key not found in user data');
    }
    // Generate VRF challenge once for both transactions
    const {
      accessKeyInfo,
      nextNonce,
      txBlockHeight,
      txBlockHash
    } = await getNonceBlockHashAndHeight({
      nearClient: context.nearClient,
      nearPublicKeyStr: nearPublicKeyStr,
      nearAccountId: device1AccountId
    });

    const nextNextNonce = (BigInt(accessKeyInfo.nonce) + BigInt(2)).toString();

    const vrfInputData: VRFInputData = {
      userId: device1AccountId,
      rpId: window.location.hostname,
      blockHeight: txBlockHeight,
      blockHash: txBlockHash,
      timestamp: Date.now()
    };

    const vrfChallenge = await context.webAuthnManager.generateVrfChallenge(vrfInputData);

    // Single TouchID prompt for both transactions
    const authenticators = await context.webAuthnManager.getAuthenticatorsByUser(device1AccountId);
    const credential = await context.webAuthnManager.touchIdPrompt.getCredentials({
      nearAccountId: device1AccountId,
      challenge: vrfChallenge.outputAs32Bytes(),
      authenticators,
    });

    onEvent?.({
      step: 4,
      phase: 'authorization',
      status: 'progress',
      timestamp: Date.now(),
      message: 'TouchID successful! Signing AddKey transaction...'
    });

    // Sign both transactions with one PRF authentication
    const transactionResults = await context.webAuthnManager.signTransactionsWithActions({
      transactions: [
        // Transaction 1: AddKey - Add Device2's key to Device1's account
        {
          nearAccountId: device1AccountId,
          receiverId: device1AccountId,
          actions: [{
            actionType: ActionType.AddKey,
            public_key: devicePublicKey,
            access_key: JSON.stringify({
              nonce: 0,
              permission: { FullAccess: {} }
            })
          }],
          nonce: nextNonce,
        },
        // Transaction 2: Store mapping in contract
        {
          nearAccountId: device1AccountId,
          receiverId: context.webAuthnManager.configs.contractId,
          actions: [{
            actionType: ActionType.FunctionCall,
            method_name: 'store_device_linking_mapping',
            args: JSON.stringify({
              device_public_key: devicePublicKey,
              target_account_id: device1AccountId,
            }),
            gas: '50000000000000', // 50 TGas for device linking with yield promise cleanup
            deposit: '0'
          }],
          nonce: nextNextNonce,
        }
      ],
      // Common parameters
      blockHash: txBlockHash,
      contractId: context.webAuthnManager.configs.contractId,
      vrfChallenge: vrfChallenge,
      credential: credential,
      nearRpcUrl: context.webAuthnManager.configs.nearRpcUrl,
      onEvent: (progress) => {
        onEvent?.({
          step: 4,
          phase: 'authorization',
          status: 'progress',
          timestamp: Date.now(),
          message: `Contract registration: ${progress.message}`
        })
      }
    });

    if (!transactionResults[0].signedTransaction) {
      throw new Error('AddKey transaction signing failed');
    }

    if (!transactionResults[1].signedTransaction) {
      throw new Error('Contract mapping transaction signing failed');
    }

    // Broadcast both transactions
    const addKeyTxResult = await context.nearClient.sendTransaction(transactionResults[0].signedTransaction);
    const contractTxResult = await context.nearClient.sendTransaction(transactionResults[1].signedTransaction);

    onEvent?.({
      step: 5,
      phase: 'authorization',
      status: 'progress',
      timestamp: Date.now(),
      message: `Both transactions signed and broadcasted successfully!`
    });

    onEvent?.({
      step: 6,
      phase: 'registration',
      status: 'success',
      timestamp: Date.now(),
      message: `Device2's key added to ${device1AccountId} successfully!`
    });

    return {
      success: true,
      devicePublicKey: qrData.devicePublicKey,
      transactionId: addKeyTxResult?.transaction?.hash || contractTxResult?.transaction?.hash || 'unknown',
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
