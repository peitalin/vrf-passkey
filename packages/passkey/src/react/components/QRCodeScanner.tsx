import React, { useEffect, useRef, useState } from 'react';
import { usePasskeyContext } from '../context';
import type { DeviceLinkingQRData, LinkDeviceResult } from '../../core/types/linkDevice';
import { validateDeviceLinkingQRData } from '../../core/PasskeyManager/linkDevice';


interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: DeviceLinkingQRData) => void;
  onDeviceLinked?: (result: LinkDeviceResult) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  autoLink?: boolean;
  fundingAmount?: string;
  isOpen?: boolean;
  cameraId?: string;
  className?: string;
  style?: React.CSSProperties;
}

export const QRCodeScanner: React.FC<QRCodeScannerProps> = ({
  onQRCodeScanned,
  onDeviceLinked,
  onError,
  onClose,
  autoLink = true,
  fundingAmount = '0.1',
  isOpen = true,
  cameraId,
  className,
  style
}) => {
  const { passkeyManager } = usePasskeyContext();
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const animationRef = useRef<number | undefined>(undefined);

  const [isScanning, setIsScanning] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [cameras, setCameras] = useState<MediaDeviceInfo[]>([]);
  const [selectedCamera, setSelectedCamera] = useState<string>(cameraId || '');
  const [scanMode, setScanMode] = useState<'camera' | 'file' | 'auto'>('auto');
  const [isFrontCamera, setIsFrontCamera] = useState<boolean>(false);

  // Use refs to avoid closure issues
  const isScanningRef = useRef(false);
  const scanStartTimeRef = useRef<number>(0);
  const SCAN_TIMEOUT_MS = 60000; // 60 seconds timeout

  // Initialize camera devices
  useEffect(() => {
    const loadCameras = async () => {
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoDevices = devices.filter(device => device.kind === 'videoinput');
        setCameras(videoDevices);

        if (videoDevices.length > 0 && !selectedCamera) {
          // Prefer back camera if available - check multiple patterns
          const backCamera = videoDevices.find(device => {
            const label = device.label.toLowerCase();
            return label.includes('back') ||
                   label.includes('rear') ||
                   label.includes('environment') ||
                   label.includes('main') ||
                   (label.includes('camera') && label.includes('0')) || // Often camera 0 is rear
                   label.includes('facing back');
          });

          // If no clear back camera, avoid cameras with "front", "user", "selfie"
          const nonFrontCamera = backCamera || videoDevices.find(device => {
            const label = device.label.toLowerCase();
            return !label.includes('front') &&
                   !label.includes('user') &&
                   !label.includes('selfie') &&
                   !label.includes('facetime');
          });

          setSelectedCamera(nonFrontCamera?.deviceId || videoDevices[0].deviceId);

          // Detect if the selected camera is a front camera
          const selectedCameraDevice = nonFrontCamera || videoDevices[0];
          const isUsingFrontCamera = selectedCameraDevice && (() => {
            const label = selectedCameraDevice.label.toLowerCase();
            return label.includes('front') ||
                   label.includes('user') ||
                   label.includes('selfie') ||
                   label.includes('facetime') ||
                   label.includes('facing front');
          })();

          setIsFrontCamera(!!isUsingFrontCamera);
        }
      } catch (err) {
        console.error('Failed to enumerate cameras:', err);
      }
    };

    loadCameras();
  }, [selectedCamera]);

  // Monitor isScanning state changes
  useEffect(() => {
    // Keep ref in sync with state
    isScanningRef.current = isScanning;
  }, [isScanning]);

  // Auto-start scanning when modal opens
  useEffect(() => {
    if (isOpen && scanMode === 'auto') {
      startScanning();
    } else if (!isOpen) {
      stopScanning();
    }

    return () => {
      stopScanning();
    };
  }, [isOpen, scanMode]);

  // Handle camera permission and start scanning
  const startScanning = async () => {
    try {
      setError(null);

      const constraints: MediaStreamConstraints = {
        video: {
          deviceId: selectedCamera || undefined,
          width: { ideal: 720, min: 480 },
          height: { ideal: 720, min: 480 },
          aspectRatio: { ideal: 1.0 }, // Square aspect ratio to match display
          facingMode: selectedCamera ? undefined : 'environment'
        }
      };
      console.log('QRCodeScanner: Camera constraints:', constraints);
      const mediaStream = await navigator.mediaDevices.getUserMedia(constraints);
      setStream(mediaStream);

      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
        await videoRef.current.play();
      }

      // Set scanning to true AFTER video is ready and BEFORE starting the scan loop
      setIsScanning(true);
      isScanningRef.current = true;
      scanStartTimeRef.current = Date.now();

      // Start automatic QR scanning with improved frame detection
      setTimeout(() => {
        // Use requestAnimationFrame to start the scanning loop
        const startScanLoop = () => {
          requestAnimationFrame(scanFrame);
        };
        startScanLoop();
      }, 500);

    } catch (err: any) {
      setError(`Camera access denied: ${err.message}`);
      onError?.(err);
      setIsScanning(false);
      isScanningRef.current = false;
    }
  };

  const scanFrame = async () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;

    if (!video || !canvas || !isOpen || !isScanningRef.current) {
      console.log('QRCodeScanner: scanFrame conditions not met - stopping scan loop');
      return;
    }

    // Check for scanning timeout
    const elapsedTime = Date.now() - scanStartTimeRef.current;
    if (elapsedTime > SCAN_TIMEOUT_MS) {
      setIsScanning(false);
      isScanningRef.current = false;
      setError('QR scanning timeout - no valid QR code found within 60 seconds. Please ensure the QR code is clearly visible and try again.');
      onError?.(new Error('QR scanning timeout after 60 seconds'));
      return;
    }

    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) {
      console.log('QRCodeScanner: No canvas context available');
      return;
    }

    // Only scan if video has loaded and has dimensions
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      try {
        // Dynamic import of jsQR for code splitting
        const { default: jsQR } = await import('jsqr');
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert"
        });

        if (code) {
          setIsScanning(false);
          isScanningRef.current = false;
          await handleQRDetected(code.data);
          return;
        }
      } catch (err) {
        console.error('QRCodeScanner: QR scanning error:', err);
      }
    }

    // Throttle to ~10 FPS to reduce CPU usage
    if (isScanningRef.current && isOpen) {
      animationRef.current = requestAnimationFrame(scanFrame);
    }
  };

  const handleQRDetected = async (qrData: string) => {
    console.log('QRCodeScanner: QR detected -', { length: qrData.length, preview: qrData.substring(0, 100) });
    try {
      setIsProcessing(true);

      // Parse and validate QR data
      const parsedQRData = parseAndValidateQRData(qrData);
      console.log('QRCodeScanner: Valid QR data -', {
        devicePublicKey: parsedQRData.devicePublicKey,
        accountId: parsedQRData.accountId,
        timestamp: new Date(parsedQRData.timestamp || 0).toISOString()
      });

      // Notify callback
      onQRCodeScanned?.(parsedQRData);

      // Handle auto-linking if enabled
      if (autoLink) {
        try {
          console.log('QRCodeScanner: Starting device linking...');
          console.log('QRCodeScanner: About to call scanAndLinkDevice...');

          const result = await passkeyManager.scanAndLinkDevice({
            cameraId: selectedCamera,
            fundingAmount,
            onEvent: (event) => console.log('QRCodeScanner: Linking event -', event.phase, event.message),
            onError: (error) => {
              console.error('QRCodeScanner: Linking error -', error.message);
              setError(error.message);
              onError?.(error);
            }
          });

          console.log('QRCodeScanner: scanAndLinkDevice returned successfully');
          console.log('QRCodeScanner: Device linking completed successfully -', { success: !!result, result });
          onDeviceLinked?.(result);
        } catch (linkingError: any) {
          console.error('QRCodeScanner: Device linking failed -', linkingError.message);
          console.error('QRCodeScanner: Device linking error details:', linkingError);
          setError(linkingError.message || 'Failed to link device');
          onError?.(linkingError);
        }
      } else {
        console.log('QRCodeScanner: Manual mode - QR scanning complete');
      }
    } catch (err: any) {
      console.error('QRCodeScanner: Processing failed -', err.message);
      setError(err.message || 'Failed to process QR code');
      onError?.(err);
    } finally {
      // Always stop scanning and close after QR detection and processing, regardless of success/failure
      console.log('QRCodeScanner: Finally block - cleaning up camera and closing scanner...');
      stopScanning();
      console.log('QRCodeScanner: Calling onClose callback...');
      if (onClose) {
        onClose();
      } else {
        console.warn('QRCodeScanner: No onClose callback provided');
      }
      setIsProcessing(false);
    }
  };

  const parseAndValidateQRData = (qrData: string): DeviceLinkingQRData => {
    // Parse JSON
    let parsedData: DeviceLinkingQRData;
    try {
      parsedData = JSON.parse(qrData);
    } catch {
      // Detect common non-JSON formats
      if (qrData.startsWith('http')) {
        throw new Error('QR code contains a URL, not device linking data');
      }
      if (qrData.includes('ed25519:')) {
        throw new Error('QR code contains a NEAR key, not device linking data');
      }
      throw new Error('Invalid QR code format - expected JSON device linking data');
    }

    // Validate required fields
    const missing = [];
    if (!parsedData.devicePublicKey) missing.push('devicePublicKey');
    if (!parsedData.timestamp) missing.push('timestamp');
    if (missing.length > 0) {
      throw new Error(`Invalid device linking QR code: Missing ${missing.join(', ')}`);
    }

    return parsedData;
  };

  const stopScanning = () => {
    console.log('QRCodeScanner: stopScanning called - cleaning up camera...');

    // Reset state
    setIsScanning(false);
    isScanningRef.current = false;
    scanStartTimeRef.current = 0;

    // Cancel animation and cleanup video
    if (animationRef.current) {
      console.log('QRCodeScanner: Cancelling animation frame');
      cancelAnimationFrame(animationRef.current);
      animationRef.current = undefined;
    }

    if (videoRef.current) {
      console.log('QRCodeScanner: Cleaning up video element');
      videoRef.current.pause();
      videoRef.current.srcObject = null;
      videoRef.current.load();
    }

    // Stop camera tracks and cleanup
    if (stream) {
      console.log('QRCodeScanner: Stopping camera tracks');
      stream.getTracks().forEach(track => {
        if (track.readyState === 'live') {
          console.log('QRCodeScanner: Stopping track:', track.kind, track.label);
          track.stop();
        }
        track.onended = track.onmute = track.onunmute = null;
      });
      setStream(null);
    }

    // Optional garbage collection hint
    window.gc?.();
    console.log('QRCodeScanner: Cleanup complete');
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {

    const file = event.target.files?.[0];
    if (!file) return;
    isScanning && stopScanning(); // Stop camera scanning to prevent camera conflicts

    console.log('QRCodeScanner: File upload -', { name: file.name, type: file.type, size: file.size });

    try {
      setIsProcessing(true);
      setError(null);

      // Dynamic import of qr-scanner for lazy loading
      const { scanQRCodeFromFile } = await import('../../utils/qr-scanner');
      const parsedQRData = await scanQRCodeFromFile(file);

      console.log('QRCodeScanner: Valid file QR -', {
        devicePublicKey: parsedQRData.devicePublicKey,
        accountId: parsedQRData.accountId
      });

      onQRCodeScanned?.(parsedQRData);

      // Handle auto-linking if enabled
      if (autoLink) {
        const result = await passkeyManager.scanAndLinkDevice({
          cameraId: selectedCamera,
          fundingAmount,
          onEvent: (event) => console.log('QRCodeScanner: File linking event -', event.phase),
          onError: (error) => {
            console.error('QRCodeScanner: File linking error -', error.message);
            setError(error.message);
            onError?.(error);
          }
        });

        console.log('QRCodeScanner: File linking completed -', { success: !!result });
        onDeviceLinked?.(result);
        stopScanning();
        onClose?.();
      } else {
        console.log('QRCodeScanner: Manual mode - file processing complete');
      }

    } catch (err: any) {
      console.error('QRCodeScanner: File processing failed -', err.message);
      setError(err.message || 'Failed to scan QR code from file');
      onError?.(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCameraChange = (deviceId: string) => {
    setSelectedCamera(deviceId);

    // Detect if the new camera is a front camera
    const selectedCameraDevice = cameras.find(camera => camera.deviceId === deviceId);
    if (selectedCameraDevice) {
      const label = selectedCameraDevice.label.toLowerCase();
      const isNewCameraFront = label.includes('front')
                            || label.includes('user')
                            || label.includes('selfie')
                            || label.includes('facetime')
                            || label.includes('facing front');
      setIsFrontCamera(isNewCameraFront);
    }

    if (isScanning) {
      stopScanning();
      // Restart with new camera
      setTimeout(startScanning, 100);
    }
  };

  const handleClose = () => {
    stopScanning();
    onClose?.();
  };

  // Don't render if not open
  if (!isOpen) return null;

  // Modal UI with centered design
  return (
    <div style={{ ...modalStyles.modal, ...style }} className={className}>
      {error ? (
        <div style={modalStyles.errorContainer}>
          <div style={modalStyles.errorMessage}>
            <p>{error}</p>
            <button onClick={() => setError(null)} style={modalStyles.errorButton}>
              Try Again
            </button>
            <button onClick={handleClose} style={modalStyles.errorButton}>
              Close
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* Camera scanning mode */}
          {scanMode === 'auto' && (
            <>
              <div style={modalStyles.cameraContainer}>
                <video
                  ref={videoRef}
                  style={{
                    ...modalStyles.video,
                    transform: isFrontCamera ? 'scaleX(-1)' : 'none' // Flip front cameras horizontally
                  }}
                  playsInline
                  autoPlay
                  muted
                />
                <canvas ref={canvasRef} style={modalStyles.canvas} />

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
                {isScanning && (
                  <p style={{ ...modalStyles.subInstruction, fontSize: '12px', opacity: 0.7 }}>
                    Timeout: {Math.ceil((SCAN_TIMEOUT_MS - (Date.now() - scanStartTimeRef.current)) / 1000)}s remaining
                  </p>
                )}
              </div>

              {/* Camera controls */}
              {cameras.length > 1 && (
                <div style={modalStyles.cameraControls}>
                  <select
                    value={selectedCamera}
                    onChange={(e) => handleCameraChange(e.target.value)}
                    style={modalStyles.cameraSelector}
                  >
                    {cameras.map(camera => (
                      <option key={camera.deviceId} value={camera.deviceId}>
                        {camera.label || `Camera ${camera.deviceId.substring(0, 8)}...`}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </>
          )}

          {/* Alternative scan modes */}
          <div style={modalStyles.modeControls}>
            <button
              onClick={() => setScanMode('auto')}
              style={scanMode === 'auto' ? modalStyles.modeButtonActive : modalStyles.modeButton}
            >
              Camera
            </button>
            <button
              onClick={() => { setScanMode('file'); fileInputRef.current?.click(); }}
              style={modalStyles.modeButton}
              disabled={isProcessing}
            >
              Upload
            </button>
          </div>

          {/* Hidden file input */}
          <input
            type="file"
            accept="image/*"
            onChange={handleFileUpload}
            ref={fileInputRef}
            style={{ display: 'none' }}
          />
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