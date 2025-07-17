import { useState } from 'react'
import { usePasskeyContext } from '@web3authn/passkey/react'
import toast from 'react-hot-toast'
import type { LastTxDetails } from '../types'

// Import the improved QRCodeScanner from the SDK
import { QRCodeScanner } from '@web3authn/passkey/react'

export function LinkDeviceScanQR() {
  const {
    loginState: {
      isLoggedIn,
      nearPublicKey,
      nearAccountId
    },
  } = usePasskeyContext();

  const [isSecureContext] = useState(() => window.isSecureContext);
  const [deviceLinkingState, setDeviceLinkingState] = useState<{
    mode: 'idle' | 'device1';
    isProcessing: boolean;
    showScanner: boolean;
  }>({ mode: 'idle', isProcessing: false, showScanner: false });

  // Device linking handlers
  const onLinkDeviceAsDevice1 = async () => {
    if (!isLoggedIn) {
      toast.error('Please login first to scan and link devices');
      return;
    }

    setDeviceLinkingState({ mode: 'device1', isProcessing: false, showScanner: true });
  };

  const handleDeviceLinked = (result: any) => {
    toast.success(`Device linked successfully to ${result.linkedToAccount}!`);
    setDeviceLinkingState({ mode: 'idle', isProcessing: false, showScanner: false });
  };

  const handleError = (error: Error) => {
    console.error('Device linking error:', error);
    toast.error(`Device linking failed: ${error.message}`);
    setDeviceLinkingState({ mode: 'idle', isProcessing: false, showScanner: false });
  };

  const onCancelDeviceLinking = () => {
    setDeviceLinkingState({ mode: 'idle', isProcessing: false, showScanner: false });
    toast.dismiss();
  };

  return (
    <>
      <div className="link-device-container-root">
        <div className="passkey-container">
          {deviceLinkingState.mode === 'idle' && (
            <div className="device-linking-section">
              <div className="auth-buttons">
                <button
                  onClick={onLinkDeviceAsDevice1}
                  className="action-button"
                  disabled={!isSecureContext || deviceLinkingState.isProcessing}
                >
                  Scan QR (Device1)
                </button>
              </div>
              <p className="device-linking-help">
                Device1: Scan a QR code to add Device2's key to your account<br/>
                Device2: Generate a QR code for Device1 to scan
              </p>
            </div>
          )}
        </div>
      </div>

      <QRCodeScanner
        isOpen={deviceLinkingState.showScanner}
        autoLink={true}
        fundingAmount="0.1"
        onDeviceLinked={handleDeviceLinked}
        onError={handleError}
        onClose={onCancelDeviceLinking}
      />
    </>
  );
}