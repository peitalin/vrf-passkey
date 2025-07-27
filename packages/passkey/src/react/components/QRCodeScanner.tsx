import React, { useCallback } from 'react';
import type { DeviceLinkingQRData, LinkDeviceResult } from '../../core/types/linkDevice';
import type { DeviceLinkingSSEEvent } from '../../core/types/passkeyManager';
import { useQRCamera } from '../hooks/useQRCamera';
import { useDeviceLinking } from '../hooks/useDeviceLinking';
import { useQRFileUpload } from '../hooks/useQRFileUpload';

export interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: DeviceLinkingQRData) => void;
  onDeviceLinked?: (result: LinkDeviceResult) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: DeviceLinkingSSEEvent) => void;
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
  showFileUpload = true,
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
    <div style={{ ...modalStyles.modal, ...style }} className={className}>
      {qrCamera.error ? (
        <div style={modalStyles.errorContainer}>
          <div style={modalStyles.errorMessage}>
            <p>{qrCamera.error}</p>
            <button onClick={() => qrCamera.setError(null)} style={modalStyles.errorButton}>
              Try Again
            </button>
            <button onClick={handleClose} style={modalStyles.errorButton}>
              Close
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* Camera scanning mode - only show if camera mode is enabled */}
          {showCamera && qrCamera.scanMode === 'auto' && (
            <>
              <div style={modalStyles.cameraContainer}>
                <video
                  ref={qrCamera.videoRef}
                  style={{
                    ...modalStyles.video,
                    transform: qrCamera.isFrontCamera ? 'scaleX(-1)' : 'none' // Flip front cameras horizontally
                  }}
                  playsInline
                  autoPlay
                  muted
                />
                <canvas ref={qrCamera.canvasRef} style={modalStyles.canvas} />

                {/* Scanner overlay */}
                <div style={modalStyles.scannerOverlay}>
                  <div style={modalStyles.scannerBox}>
                    {/* Corner indicators */}
                    <div style={modalStyles.cornerTopLeft} />
                    <div style={modalStyles.cornerTopRight} />
                    <div style={modalStyles.cornerBottomLeft} />
                    <div style={modalStyles.cornerBottomRight} />
                  </div>
                </div>
              </div>

              <div style={modalStyles.instructions}>
                <p>Position the QR code within the frame</p>
                <p style={modalStyles.subInstruction}>
                  {isProcessing ? 'Processing QR code...' : 'The camera will automatically scan when a QR code is detected'}
                </p>
                {qrCamera.isScanning && (
                  <p style={{ ...modalStyles.subInstruction, fontSize: '12px', opacity: 0.7 }}>
                    Timeout: {Math.ceil((SCAN_TIMEOUT_MS - (Date.now())) / 1000)}s remaining
                  </p>
                )}
              </div>

              {/* Camera controls */}
              {qrCamera.cameras.length > 1 && (
                <div style={modalStyles.cameraControls}>
                  <select
                    value={qrCamera.selectedCamera}
                    onChange={(e) => qrCamera.handleCameraChange(e.target.value)}
                    style={modalStyles.cameraSelector}
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
            <div style={modalStyles.instructions}>
              <p>Upload QR Code Image</p>
              <p style={modalStyles.subInstruction}>
                Click the upload button below to select a QR code image from your device
              </p>
            </div>
          )}

          {/* Mode controls - only show available modes */}
          {(showCamera || showFileUpload) && (
            <div style={modalStyles.modeControls}>
              {showCamera && (
                <button
                  onClick={() => qrCamera.setScanMode('auto')}
                  style={qrCamera.scanMode === 'auto' ? modalStyles.modeButtonActive : modalStyles.modeButton}
                >
                  Camera
                </button>
              )}
              {showFileUpload && (
                <button
                  onClick={() => { qrCamera.setScanMode('file'); fileUpload.fileInputRef.current?.click(); }}
                  style={modalStyles.modeButton}
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
      <button onClick={handleClose} style={modalStyles.close}>
        ✕
      </button>
    </div>
  );
};

// Modal styles for centered UI
const modalStyles: Record<string, React.CSSProperties> = {
  modal: {
    position: 'fixed',
    inset: 0,
    backgroundColor: 'rgba(0,0,0,0.8)',
    zIndex: 9999,
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    flexDirection: 'column',
    // Safe area insets for mobile notch devices
    paddingTop: 'max(env(safe-area-inset-top), 20px)',
    paddingBottom: 'max(env(safe-area-inset-bottom), 20px)',
    paddingLeft: 'max(env(safe-area-inset-left), 20px)',
    paddingRight: 'max(env(safe-area-inset-right), 20px)',
  },
  cameraContainer: {
    position: 'relative',
    display: 'inline-block',
  },
  video: {
    width: '400px',
    height: '400px',
    objectFit: 'cover', // Crop to square format
    objectPosition: 'center center', // Center the crop properly
    borderRadius: '12px',
    display: 'block',
    margin: '0 auto', // Center the video element itself
    transform: 'translateX(0)', // Ensure no horizontal offset
  },
  canvas: {
    display: 'none',
  },
  scannerOverlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    pointerEvents: 'none',
  },
  scannerBox: {
    width: '394px',
    height: '394px',
    border: '2px solid rgba(74, 222, 128, 0.6)',
    borderRadius: 10,
    position: 'relative',
    background: 'transparent',
    boxShadow: '0 0 15px rgba(74, 222, 128, 0.4)',
  },
  cornerTopLeft: {
    position: 'absolute',
    top: -6,
    left: -6,
    width: 20,
    height: 20,
    borderTop: '3px solid #4ade80',
    borderLeft: '3px solid #4ade80',
    borderTopLeftRadius: 4,
  },
  cornerTopRight: {
    position: 'absolute',
    top: -6,
    right: -6,
    width: 20,
    height: 20,
    borderTop: '3px solid #4ade80',
    borderRight: '3px solid #4ade80',
    borderTopRightRadius: 4,
  },
  cornerBottomLeft: {
    position: 'absolute',
    bottom: -6,
    left: -6,
    width: 20,
    height: 20,
    borderBottom: '3px solid #4ade80',
    borderLeft: '3px solid #4ade80',
    borderBottomLeftRadius: 4,
  },
  cornerBottomRight: {
    position: 'absolute',
    bottom: -6,
    right: -6,
    width: 20,
    height: 20,
    borderBottom: '3px solid #4ade80',
    borderRight: '3px solid #4ade80',
    borderBottomRightRadius: 4,
  },
  instructions: {
    marginTop: '24px',
    color: 'white',
    textAlign: 'center',
    fontSize: '16px',
    fontWeight: '500',
    textShadow: '0 2px 4px rgba(0,0,0,0.8)',
    maxWidth: '400px',
  },
  subInstruction: {
    fontSize: '13px',
    fontWeight: '400',
    opacity: 0.7,
    marginTop: '8px',
    lineHeight: '1.4',
  },
  cameraControls: {
    marginTop: '16px',
    display: 'flex',
    justifyContent: 'center',
  },
  cameraSelector: {
    backgroundColor: 'rgba(0,0,0,0.7)',
    color: 'white',
    border: '1px solid rgba(74, 222, 128, 0.5)',
    borderRadius: '6px',
    padding: '6px 10px',
    fontSize: '13px',
    backdropFilter: 'blur(10px)',
    maxWidth: '200px',
  },
  modeControls: {
    marginTop: '20px',
    display: 'flex',
    gap: '10px',
    justifyContent: 'center',
  },
  modeButton: {
    backgroundColor: 'rgba(0,0,0,0.7)',
    color: 'white',
    border: '1px solid rgba(255,255,255,0.3)',
    borderRadius: '6px',
    padding: '8px 14px',
    fontSize: '13px',
    cursor: 'pointer',
    backdropFilter: 'blur(10px)',
    transition: 'all 0.2s ease',
    minWidth: '80px',
  },
  modeButtonActive: {
    backgroundColor: 'rgba(74, 222, 128, 0.2)',
    color: 'white',
    border: '1px solid #4ade80',
    borderRadius: '6px',
    padding: '8px 14px',
    fontSize: '13px',
    cursor: 'pointer',
    backdropFilter: 'blur(10px)',
    transition: 'all 0.2s ease',
    minWidth: '80px',
  },
  close: {
    position: 'absolute',
    top: '20px',
    right: '20px',
    background: 'rgba(0,0,0,0.7)',
    color: 'white',
    border: 'none',
    borderRadius: '50%',
    width: 36,
    height: 36,
    fontSize: 18,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 10,
    transition: 'all 0.2s ease',
    backdropFilter: 'blur(10px)',
  },
  errorContainer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '300px',
    padding: '20px',
  },
  errorMessage: {
    backgroundColor: 'rgba(239, 68, 68, 0.95)',
    color: 'white',
    padding: '20px',
    borderRadius: '12px',
    textAlign: 'center',
    maxWidth: '300px',
    backdropFilter: 'blur(10px)',
    boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
  },
  errorButton: {
    marginTop: '12px',
    marginLeft: '6px',
    marginRight: '6px',
    padding: '8px 16px',
    backgroundColor: 'white',
    color: '#ef4444',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: '500',
    fontSize: '14px',
    transition: 'all 0.2s ease',
  }
};

export default QRCodeScanner;