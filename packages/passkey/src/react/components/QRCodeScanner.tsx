import React, { useEffect, useRef, useState } from 'react';
import { usePasskeyContext } from '../context';
import type { DeviceLinkingQRData, LinkDeviceResult } from '../../core/types/linkDevice';
import { LinkDeviceFlow, validateDeviceLinkingQRData } from '../../core/PasskeyManager/linkDevice';


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

  // Use refs to avoid closure issues
  const isScanningRef = useRef(false);

  // Initialize camera devices
  useEffect(() => {
    const loadCameras = async () => {
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoDevices = devices.filter(device => device.kind === 'videoinput');
        setCameras(videoDevices);

        if (videoDevices.length > 0 && !selectedCamera) {
          // Prefer back camera if available
          const backCamera = videoDevices.find(device =>
            device.label.toLowerCase().includes('back') ||
            device.label.toLowerCase().includes('rear') ||
            device.label.toLowerCase().includes('environment')
          );
          setSelectedCamera(backCamera?.deviceId || videoDevices[0].deviceId);
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
    if (isScanning) {
      console.log('📹 QRCodeScanner: Scanning started');
    }
  }, [isScanning]);

  // Auto-start scanning when modal opens
  useEffect(() => {
    console.log('QRCodeScanner: Modal state changed:', { isOpen, scanMode });

    if (isOpen && scanMode === 'auto') {
      console.log('QRCodeScanner: Starting camera scanning...');
      startScanning();
    } else if (!isOpen) {
      console.log('QRCodeScanner: Modal closed, stopping scanning...');
      stopScanning();
    }

    return () => {
      stopScanning();
    };
  }, [isOpen, scanMode]);

  // Handle camera permission and start scanning
  const startScanning = async () => {
    console.log('QRCodeScanner: Requesting camera access...');

    try {
      setError(null);

      const constraints: MediaStreamConstraints = {
        video: {
          deviceId: selectedCamera || undefined,
          width: { ideal: 1280 },
          height: { ideal: 720 },
          facingMode: selectedCamera ? undefined : 'environment'
        }
      };

      console.log('QRCodeScanner: Camera constraints:', constraints);
      const mediaStream = await navigator.mediaDevices.getUserMedia(constraints);
      console.log('QRCodeScanner: Camera access granted, stream obtained');
      setStream(mediaStream);

      if (videoRef.current) {
        console.log('QRCodeScanner: Setting video source and starting playback...');
        videoRef.current.srcObject = mediaStream;
        await videoRef.current.play();
        console.log('QRCodeScanner: Video playback started');
      }

      // Set scanning to true AFTER video is ready and BEFORE starting the scan loop
      console.log('QRCodeScanner: Setting isScanning to true...');
      setIsScanning(true);
      isScanningRef.current = true;

      // Start automatic QR scanning with improved frame detection
      console.log('QRCodeScanner: Starting frame scanning in 500ms...');
      setTimeout(() => {
        console.log('QRCodeScanner: Timeout reached, starting scan loop...');
        // Use requestAnimationFrame to start the scanning loop
        const startScanLoop = () => {
          console.log('QRCodeScanner: Starting scan loop frame...');
          requestAnimationFrame(scanFrame);
        };
        startScanLoop();
      }, 500);

    } catch (err: any) {
      console.error('QRCodeScanner: Camera access error:', err);
      setError(`Camera access denied: ${err.message}`);
      onError?.(err);
      setIsScanning(false);
      isScanningRef.current = false;
    }
  };

  const scanFrame = async () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;

    // Reduced logging - only log every 60 frames (~6 seconds)
    if (Math.random() < 0.016) {
      console.log('QRCodeScanner: Scanning active...', {
        hasVideo: !!video,
        hasCanvas: !!canvas,
        isOpen,
        isScanning: isScanningRef.current
      });
    }

    if (!video || !canvas || !isOpen || !isScanningRef.current) {
      console.log('QRCodeScanner: scanFrame conditions not met - stopping scan loop');
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

      // Only log frame details occasionally
      if (Math.random() < 0.01) {
        console.log('📷 QRCodeScanner: Scanning frame:', {
          videoWidth: video.videoWidth,
          videoHeight: video.videoHeight,
          readyState: video.readyState
        });
      }

      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      try {
        // Dynamic import of jsQR for code splitting
        const { default: jsQR } = await import('jsqr');
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert"
        });

        if (code) {
          console.log('QRCodeScanner: QR code detected!');
          console.log('QRCodeScanner: Raw QR data:', code.data);
          console.log('QRCodeScanner: QR location:', code.location);
          setIsScanning(false);
          isScanningRef.current = false;
          await handleQRDetected(code.data);
          return;
        } else {
          // Very infrequent scanning status log
          if (Math.random() < 0.005) {
            console.log('📷 QRCodeScanner: Scanning... (no QR detected)');
          }
        }
      } catch (err) {
        console.error('QRCodeScanner: QR scanning error:', err);
      }
    } else {
      console.log('QRCodeScanner: Video not ready:', {
        readyState: video.readyState,
        HAVE_ENOUGH_DATA: video.HAVE_ENOUGH_DATA
      });
    }

    // Throttle to ~10 FPS to reduce CPU usage
    if (isScanningRef.current && isOpen) {
      animationRef.current = requestAnimationFrame(scanFrame);
    } else {
      console.log('QRCodeScanner: Not continuing scan loop, isScanning:', isScanningRef.current, 'isOpen:', isOpen);
    }
  };

  const handleQRDetected = async (qrData: string) => {
    console.log('QRCodeScanner: QR code detected!');
    console.log('QRCodeScanner: Raw data length:', qrData.length);
    console.log('QRCodeScanner: Raw QR data (first 200 chars):', qrData.substring(0, 200));
    console.log('QRCodeScanner: Full raw QR data:', qrData);

    try {
      setIsProcessing(true);

      // Parse the QR data
      let parsedQRData: DeviceLinkingQRData;
      try {
        console.log('QRCodeScanner: Attempting to parse QR data as JSON...');
        parsedQRData = JSON.parse(qrData);
        console.log('QRCodeScanner: Successfully parsed QR data:', parsedQRData);

        // Extract and log key components
        console.log('QRCodeScanner: Extracted data components:');
        console.log('  - Device Public Key:', parsedQRData.devicePublicKey);
        console.log('  - Account ID:', parsedQRData.accountId || 'NOT PROVIDED');
        console.log('  - Timestamp:', parsedQRData.timestamp, new Date(parsedQRData.timestamp || 0).toISOString());
        console.log('  - Version:', parsedQRData.version || 'NOT PROVIDED');

      } catch (error) {
        console.error('QRCodeScanner: Failed to parse QR data as JSON:', error);
        console.log('QRCodeScanner: Attempting to parse as other formats...');

        // Try to detect if it's a different format
        if (qrData.startsWith('http')) {
          console.log('QRCodeScanner: Detected URL format:', qrData);
          throw new Error('QR code contains a URL, not device linking data');
        } else if (qrData.includes('ed25519:')) {
          console.log('QRCodeScanner: Detected NEAR key format:', qrData);
          throw new Error('QR code contains a NEAR key, not device linking data');
        } else {
          console.log('QRCodeScanner: Unknown QR format, raw content:', qrData);
          throw new Error('Invalid QR code format - expected JSON device linking data');
        }
      }

      // Validate the QR data structure
      console.log('QRCodeScanner: Validating QR data structure...');

      const validationErrors = [];
      if (!parsedQRData.devicePublicKey) validationErrors.push('Missing devicePublicKey');
      if (!parsedQRData.timestamp) validationErrors.push('Missing timestamp');

      if (validationErrors.length > 0) {
        console.error('QRCodeScanner: Invalid QR data structure:', {
          errors: validationErrors,
          hasDevicePublicKey: !!parsedQRData.devicePublicKey,
          hasTimestamp: !!parsedQRData.timestamp,
          hasAccountId: !!parsedQRData.accountId,
          parsedQRData
        });
        throw new Error(`Invalid device linking QR code: ${validationErrors.join(', ')}`);
      }

      console.log('✅ QRCodeScanner: QR data validation passed');
      console.log('✅ QRCodeScanner: Valid device linking QR detected with public key:', parsedQRData.devicePublicKey);

      // Callback for manual handling
      console.log('QRCodeScanner: Calling onQRCodeScanned callback...');
      onQRCodeScanned?.(parsedQRData);

      if (autoLink) {
        console.log('QRCodeScanner: Auto-linking enabled, starting device linking...');
        // Use the scanAndLinkDevice method for automatic linking
        const result = await passkeyManager.scanAndLinkDevice({
          cameraId: selectedCamera,
          fundingAmount,
          onEvent: (event: any) => {
            console.log('QRCodeScanner: Device linking event:', event);
          },
          onError: (error: any) => {
            console.error('❌ QRCodeScanner: Device linking error:', error);
            setError(error.message);
            onError?.(error);
          }
        });

        console.log('✅ QRCodeScanner: Device linking completed:', result);
        onDeviceLinked?.(result);
        console.log('QRCodeScanner: Closing scanner...');
        onClose?.();
      } else {
        console.log('QRCodeScanner: Auto-linking disabled, QR scanning complete');
      }

    } catch (err: any) {
      console.error('❌ QRCodeScanner: Error processing QR code:', err);
      setError(err.message || 'Failed to process QR code');
      onError?.(err);
    } finally {
      setIsProcessing(false);
      console.log('QRCodeScanner: Processing complete');
    }
  };

  const stopScanning = () => {
    console.log('QRCodeScanner: Stopping camera and cleaning up...');
    setIsScanning(false);
    isScanningRef.current = false;

    // Cancel animation frame first to stop scanning loop
    if (animationRef.current) {
      console.log('QRCodeScanner: Canceling animation frame...');
      cancelAnimationFrame(animationRef.current);
      animationRef.current = undefined;
    }

    // Stop video element and clear source
    if (videoRef.current) {
      console.log('QRCodeScanner: Pausing video and clearing source...');
      videoRef.current.pause();
      videoRef.current.srcObject = null;
      // Force load to release the stream
      videoRef.current.load();
    }

    // Stop all camera tracks with enhanced cleanup
    if (stream) {
      console.log('QRCodeScanner: Stopping camera tracks...');
      const tracks = stream.getTracks();
      tracks.forEach((track, index) => {
        console.log(`QRCodeScanner: Stopping track ${index}:`, track.kind, track.readyState, track.label);
        if (track.readyState === 'live') {
          track.stop();
          console.log(`✅ QRCodeScanner: Track ${index} stopped, new state:`, track.readyState);
        }
      });

      // Additional cleanup - remove all track listeners
      tracks.forEach(track => {
        track.onended = null;
        track.onmute = null;
        track.onunmute = null;
      });

      setStream(null);
      console.log('✅ QRCodeScanner: All camera tracks stopped and stream cleared');
    }

    // Force garbage collection hint (browsers may ignore this)
    if (window.gc) {
      try {
        window.gc();
        console.log('QRCodeScanner: Garbage collection requested');
      } catch (e) {
        // Ignore - gc not available in production
      }
    }

    console.log('✅ QRCodeScanner: Camera cleanup complete');
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      console.log('QRCodeScanner: No file selected');
      return;
    }

    console.log('QRCodeScanner: File selected for upload:', file.name, file.type, file.size);

    // Stop camera scanning immediately to prevent conflicts
    if (isScanning) {
      console.log('QRCodeScanner: Stopping camera before file processing...');
      stopScanning();
    }

    try {
      setIsProcessing(true);
      setError(null);

      // Always scan file directly first
      console.log('QRCodeScanner: Scanning QR from uploaded file...');
      const { scanQRCodeFromFile } = await import('../../utils/qr-scanner');
      const qrData = await scanQRCodeFromFile(file);
      console.log('✅ QRCodeScanner: Successfully scanned QR from file:', qrData);

      // Validate the QR data
      validateDeviceLinkingQRData(qrData);
      console.log('✅ QRCodeScanner: QR data validation passed');

      // Callback for manual handling
      onQRCodeScanned?.(qrData);

            if (autoLink) {
        console.log('QRCodeScanner: Auto-linking mode - performing device linking...');

        // For auto-linking with file upload, we need to handle this manually since
        // scanAndLinkDevice is designed for camera scanning only
        // TODO: This would require implementing device linking with pre-scanned QR data
        // For now, just report the QR data and ask user to use camera mode for auto-linking
        console.log('️QRCodeScanner: Auto-linking with file upload not yet supported');
        setError('Auto-linking with file upload is not yet supported. Please use camera mode for auto-linking, or scan manually.');
        onError?.(new Error('Auto-linking with file upload not supported'));
      } else {
        console.log('QRCodeScanner: Manual QR scanning mode - file processing complete');
      }

    } catch (err: any) {
      console.error('❌ QRCodeScanner: Error processing file upload:', err);
      setError(err.message || 'Failed to scan QR code from file');
      onError?.(err);
    } finally {
      setIsProcessing(false);
      console.log('QRCodeScanner: File upload processing complete');
    }
  };

  const handleCameraChange = (deviceId: string) => {
    setSelectedCamera(deviceId);
    if (isScanning) {
      stopScanning();
      // Restart with new camera
      setTimeout(startScanning, 100);
    }
  };

  const handleClose = () => {
    console.log('❌ QRCodeScanner: Close button clicked, cleaning up...');
    stopScanning();
    console.log('❌ QRCodeScanner: Calling onClose callback...');
    onClose?.();
    console.log('✅ QRCodeScanner: Close handling complete');
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
                  style={modalStyles.video}
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
    objectFit: 'cover',
    borderRadius: '12px',
    display: 'block',
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