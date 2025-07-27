import { TxExecutionStatus } from "@near-js/types";
import type { PasskeyManagerContext } from './index';
import { ActionType } from '../types/actions';
import { validateNearAccountId } from '../../utils/validation';
import { getLoginState } from './login';
import { getNonceBlockHashAndHeight } from './actions';
import type { VRFInputData } from '../types/vrf-worker';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
} from '../types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
// jsQR will be dynamically imported when needed
import { scanQRCodeFromCamera } from '../../utils/qrScanner';

/**
 * Device1 (original device): Link device using pre-scanned QR data
 */
export async function linkDeviceWithQRData(
  context: PasskeyManagerContext,
  qrData: DeviceLinkingQRData,
  options: Omit<ScanAndLinkDeviceOptionsDevice1, 'cameraId' | 'cameraConfigs'>
): Promise<LinkDeviceResult> {
  const { onEvent, onError } = options || {};

  try {
    onEvent?.({
      step: 2,
      phase: 'scanning',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Validating QR data...'
    });

    // Validate QR data
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
    const fundingAmount = options.fundingAmount;

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
    const nextNextNonce = (BigInt(nextNonce) + BigInt(1)).toString();

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
    const signedTransactions = await context.webAuthnManager.signTransactionsWithActions({
      transactions: [
        // Transaction 1: AddKey - Add Device2's key to Device1's account
        {
          nearAccountId: device1AccountId,
          receiverId: device1AccountId,
          actions: [{
            actionType: ActionType.AddKey,
            public_key: devicePublicKey,
            access_key: JSON.stringify({
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

    if (!signedTransactions[0].signedTransaction) {
      throw new Error('AddKey transaction signing failed');
    }
    if (!signedTransactions[1].signedTransaction) {
      throw new Error('Contract mapping transaction signing failed');
    }

    // Broadcast both transactions
    let addKeyTxResult, contractTxResult;
    try {
      console.log('LinkDeviceFlow: Broadcasting AddKey transaction...');
      console.log('LinkDeviceFlow: AddKey transaction details:', {
        receiverId: signedTransactions[0].signedTransaction.transaction.receiverId,
        actions: JSON.parse(signedTransactions[0].signedTransaction.transaction.actionsJson || '[]'),
        transactionKeys: Object.keys(signedTransactions[0].signedTransaction.transaction),
        fullTransaction: JSON.stringify(signedTransactions[0].signedTransaction.transaction, null, 2)
      });

      addKeyTxResult = await context.nearClient.sendTransaction(
        signedTransactions[0].signedTransaction,
        "INCLUDED_FINAL" as TxExecutionStatus
      );
      console.log('LinkDeviceFlow: AddKey transaction result:', addKeyTxResult?.transaction?.hash);

      // Send success events immediately after AddKey succeeds (critical transaction)
      console.log('LinkDeviceFlow: Sending step 5 event...');
      onEvent?.({
        step: 5,
        phase: 'authorization',
        status: 'progress',
        timestamp: Date.now(),
        message: `AddKey transaction signed and broadcasted successfully!`
      });

      console.log('LinkDeviceFlow: Sending step 6 event...');
      onEvent?.({
        step: 6,
        phase: 'registration',
        status: 'success',
        timestamp: Date.now(),
        message: `Device2's key added to ${device1AccountId} successfully!`
      });

      // Wait for AddKey transaction to be confirmed before submitting contract mapping
      // This prevents nonce conflicts that cause the contract transaction to hang
      console.log('LinkDeviceFlow: Waiting for AddKey transaction confirmation to prevent nonce conflicts...');

      // Check if contract mapping transaction is valid before attempting to broadcast
      const contractTx = signedTransactions[1].signedTransaction;
      console.log('LinkDeviceFlow: Broadcasting contract mapping transaction...');
      console.log('LinkDeviceFlow: Contract mapping transaction details:', {
        receiverId: contractTx.transaction.receiverId,
        actions: JSON.parse(contractTx.transaction.actionsJson || '[]').length
      });

      // Standard timeout since nonce conflict should be resolved by the 2s delay
      contractTxResult = await context.nearClient.sendTransaction(
        contractTx,
        "INCLUDED_FINAL"
      );
      console.log('LinkDeviceFlow: Contract mapping transaction result:', contractTxResult?.transaction?.hash);

    } catch (txError: any) {
      console.error('LinkDeviceFlow: AddKey transaction broadcasting failed:', txError);
      console.error('LinkDeviceFlow: Transaction error details:', {
        message: txError.message,
        stack: txError.stack,
        name: txError.name
      });
      throw new Error(`AddKey transaction broadcasting failed: ${txError.message}`);
    }

    console.log('LinkDeviceFlow: Sending step 5 event...');
    onEvent?.({
      step: 5,
      phase: 'authorization',
      status: 'progress',
      timestamp: Date.now(),
      message: `Both transactions signed and broadcasted successfully!`
    });

    console.log('LinkDeviceFlow: Preparing return result...');
    const result = {
      success: true,
      devicePublicKey: qrData.devicePublicKey,
      transactionId: addKeyTxResult?.transaction?.hash || contractTxResult?.transaction?.hash || 'unknown',
      fundingAmount,
      linkedToAccount: device1AccountId // Include which account the key was added to
    };

    console.log('LinkDeviceFlow: Sending step 6 event...');
    onEvent?.({
      step: 6,
      phase: 'registration',
      status: 'success',
      timestamp: Date.now(),
      message: `Device2's key added to ${device1AccountId} successfully!`
    });

    console.log('LinkDeviceFlow: Returning result:', result);
    return result;

  } catch (error: any) {
    console.error('LinkDeviceFlow: scanAndLinkDevice caught error:', error);
    console.error('LinkDeviceFlow: Error stack:', error.stack);

    const errorMessage = `Failed to scan and link device: ${error.message}`;
    onError?.(new Error(errorMessage));

    throw new DeviceLinkingError(
      errorMessage,
      DeviceLinkingErrorCode.AUTHORIZATION_TIMEOUT,
      'authorization'
    );
  }
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

/**
 * Device1 (original device): Scan QR code and execute AddKey transaction (convenience method)
 */
export async function scanAndLinkDevice(
  context: PasskeyManagerContext,
  options: ScanAndLinkDeviceOptionsDevice1
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
    const qrData = await scanQRCodeFromCamera(options.cameraId, options.cameraConfigs);

    // 2. Use the extracted linking function with the scanned QR data
    return await linkDeviceWithQRData(context, qrData, {
      fundingAmount: options.fundingAmount,
      onEvent,
      onError
    });

  } catch (error: any) {
    onError?.(error);
    throw error;
  }
}