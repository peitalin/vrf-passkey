import React, { useCallback } from 'react';
import type { DeviceLinkingQRData, LinkDeviceResult } from '../../core/types/linkDevice';
import type { DeviceLinkingEvent } from '../../core/types/passkeyManager';
import { useQRCamera } from '../hooks/useQRCamera';
import { useDeviceLinking } from '../hooks/useDeviceLinking';
import { useQRFileUpload } from '../hooks/useQRFileUpload';

export interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: DeviceLinkingQRData) => void;
  onDeviceLinked?: (result: LinkDeviceResult) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: DeviceLinkingEvent) => void;
  fundingAmount?: string;
  isOpen?: boolean;
  cameraId?: string;
  className?: string;
  style?: React.CSSProperties;
  showCamera?: boolean;
  showFileUpload?: boolean;
}

export const QRCodeScanner: React.FC<QRCodeScannerProps> = ({
  onQRCodeScanned,
  onDeviceLinked,
  onError,
  onClose,
  onEvent,
  fundingAmount = '0.05', // 0.05 NEAR
  isOpen = true,
  cameraId,
  className,
  style,
  showCamera = true,
  showFileUpload = false,
}) => {
  // Initialize device linking hook
  const { linkDevice } = useDeviceLinking({
    onDeviceLinked,
    onError,
    onClose,
    onEvent,
    fundingAmount
  });

  // Handle QR detection from camera
  const handleCameraQRDetected = useCallback(async (qrData: DeviceLinkingQRData) => {
    onQRCodeScanned?.(qrData);
    await linkDevice(qrData, 'camera');
  }, [onQRCodeScanned, linkDevice]);

  // Handle QR detection from file upload
  const handleFileQRDetected = useCallback(async (qrData: DeviceLinkingQRData) => {
    onQRCodeScanned?.(qrData);
    await linkDevice(qrData, 'file');
  }, [onQRCodeScanned, linkDevice]);

  // Always initialize both hooks (avoid conditional hook calls)
  const qrCamera = useQRCamera({
    onQRDetected: handleCameraQRDetected,
    onError,
    isOpen: showCamera ? isOpen : false, // Only active when camera should be shown
    cameraId
  });

  const fileUpload = useQRFileUpload({
    onQRDetected: handleFileQRDetected,
    onError
  });

  // Handle close with camera cleanup
  const handleClose = useCallback(() => {
    qrCamera.stopScanning();
        onClose?.();
  }, [qrCamera.stopScanning, onClose]);

  // Enhanced file upload that stops camera first
  const handleFileUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    // Stop camera scanning first to avoid conflicts
    if (qrCamera.isScanning) {
      qrCamera.stopScanning();
    }

    // Reset any camera errors
    qrCamera.setError(null);

    // Handle the file upload
    await fileUpload.handleFileUpload(event);
  }, [qrCamera, fileUpload.handleFileUpload]);

  const SCAN_TIMEOUT_MS = 60000; // 60 seconds timeout

  // Don't render if not open
  if (!isOpen) return null;

  // Determine processing state from camera or file upload
  const isProcessing = qrCamera.isProcessing || fileUpload.isProcessing;

  // Modal UI with centered design
  return (
    <div className={`qr-scanner-modal ${className || ''}`} style={style}>
      {qrCamera.error ? (
        <div className="qr-scanner-error-container">
          <div className="qr-scanner-error-message">
            <p>{qrCamera.error}</p>
            <button onClick={() => qrCamera.setError(null)} className="qr-scanner-error-button">
              Try Again
            </button>
            <button onClick={handleClose} className="qr-scanner-error-button">
              Close
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* Camera scanning mode - only show if camera mode is enabled */}
          {showCamera && qrCamera.scanMode === 'auto' && (
            <>
              <div className="qr-scanner-camera-container">
                <video
                  ref={qrCamera.videoRef}
                  className="qr-scanner-video"
                  style={{
                    transform: qrCamera.isFrontCamera ? 'scaleX(-1)' : 'none' // Flip front cameras horizontally
                  }}
                  playsInline
                  autoPlay
                  muted
                />
                <canvas ref={qrCamera.canvasRef} className="qr-scanner-canvas" />

                {/* Scanner overlay */}
                <div className="qr-scanner-overlay">
                  <div className="qr-scanner-box">
                    {/* Corner indicators */}
                    <div className="qr-scanner-corner-top-left" />
                    <div className="qr-scanner-corner-top-right" />
                    <div className="qr-scanner-corner-bottom-left" />
                    <div className="qr-scanner-corner-bottom-right" />
                  </div>
                </div>
              </div>

              <div className="qr-scanner-instructions">
                <p>Position the QR code within the frame</p>
                <p className="qr-scanner-sub-instruction">
                  {isProcessing ? 'Processing QR code...' : 'The camera will automatically scan when a QR code is detected'}
                </p>
                {qrCamera.isScanning && (
                  <p className="qr-scanner-sub-instruction qr-scanner-sub-instruction--small">
                    Timeout: {Math.ceil((SCAN_TIMEOUT_MS - (Date.now())) / 1000)}s remaining
                  </p>
                )}
              </div>

              {/* Camera controls */}
              {qrCamera.cameras.length > 1 && (
                <div className="qr-scanner-camera-controls">
                  <select
                    value={qrCamera.selectedCamera}
                    onChange={(e) => qrCamera.handleCameraChange(e.target.value)}
                    className="qr-scanner-camera-selector"
                  >
                    {qrCamera.cameras.map(camera => (
                      <option key={camera.deviceId} value={camera.deviceId}>
                        {camera.label || `Camera ${camera.deviceId.substring(0, 8)}...`}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </>
          )}

          {/* File upload only mode - show instructions when camera is not available */}
          {!showCamera && showFileUpload && (
            <div className="qr-scanner-instructions">
              <p>Upload QR Code Image</p>
              <p className="qr-scanner-sub-instruction">
                Click the upload button below to select a QR code image from your device
              </p>
            </div>
          )}

          {/* Mode controls - only show available modes */}
          {(showCamera || showFileUpload) && (
            <div className="qr-scanner-mode-controls">
              {showCamera && (
            <button
                  onClick={() => qrCamera.setScanMode('auto')}
                  className={qrCamera.scanMode === 'auto'
                    ? 'qr-scanner-mode-button--active'
                    : 'qr-scanner-mode-button'
                  }
            >
              Camera
            </button>
              )}
              {showFileUpload && (
            <button
                  onClick={() => { qrCamera.setScanMode('file'); fileUpload.fileInputRef.current?.click(); }}
                  className="qr-scanner-mode-button"
              disabled={isProcessing}
            >
              Upload
            </button>
              )}
          </div>
          )}

          {/* Hidden file input - only include if file upload is enabled */}
          {showFileUpload && (
          <input
            type="file"
            accept="image/*"
            onChange={handleFileUpload}
              ref={fileUpload.fileInputRef}
            style={{ display: 'none' }}
          />
          )}
        </>
      )}

      {/* Close button */}
      <button onClick={handleClose} className="qr-scanner-close">
        ✕
      </button>
    </div>
  );
};

export default QRCodeScanner;