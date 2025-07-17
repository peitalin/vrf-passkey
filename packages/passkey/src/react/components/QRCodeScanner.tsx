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
      setIsScanning(true);

      const constraints: MediaStreamConstraints = {
        video: {
          deviceId: selectedCamera || undefined,
          width: { ideal: 1280 },
          height: { ideal: 720 },
          facingMode: selectedCamera ? undefined : 'environment'
        }
      };

      const mediaStream = await navigator.mediaDevices.getUserMedia(constraints);
      setStream(mediaStream);

      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
        await videoRef.current.play();
      }

      // Start automatic QR scanning with improved frame detection
      setTimeout(() => {
        requestAnimationFrame(scanFrame);
      }, 500);

    } catch (err: any) {
      setError(`Camera access denied: ${err.message}`);
      onError?.(err);
      setIsScanning(false);
    }
  };

  const scanFrame = async () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas || !isOpen || !isScanning) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Only scan if video has loaded and has dimensions
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      try {
        // Dynamic import of jsQR for code splitting
        const { default: jsQR } = await import('jsqr');
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code) {
          setIsScanning(false);
          await handleQRDetected(code.data);
          return;
        }
      } catch (err) {
        console.error('QR scanning error:', err);
      }
    }

    // Throttle to ~10 FPS to reduce CPU usage
    animationRef.current = requestAnimationFrame(scanFrame);
  };

  const handleQRDetected = async (qrData: string) => {
    try {
      setIsProcessing(true);

      // Parse the QR data
      let parsedQRData: DeviceLinkingQRData;
      try {
        parsedQRData = JSON.parse(qrData);
      } catch (error) {
        throw new Error('Invalid QR code format');
      }

      // Validate the QR data structure
      if (!parsedQRData.devicePublicKey || !parsedQRData.timestamp) {
        throw new Error('Invalid device linking QR code');
      }

      // Callback for manual handling
      onQRCodeScanned?.(parsedQRData);

      if (autoLink) {
        // Use the scanAndLinkDevice method for automatic linking
        const result = await passkeyManager.scanAndLinkDevice({
          cameraId: selectedCamera,
          fundingAmount,
          onEvent: (event: any) => {
            console.log('Device linking event:', event);
          },
          onError: (error: any) => {
            console.error('Device linking error:', error);
            setError(error.message);
            onError?.(error);
          }
        });

        onDeviceLinked?.(result);
        onClose?.();
      }

    } catch (err: any) {
      setError(err.message || 'Failed to process QR code');
      onError?.(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const stopScanning = () => {
    setIsScanning(false);
    if (stream) {
      stream.getTracks().forEach(track => track.stop());
      setStream(null);
    }

    if (animationRef.current) {
      cancelAnimationFrame(animationRef.current);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      setIsProcessing(true);
      setError(null);

      if (autoLink) {
        // Use the scanAndLinkDevice method that handles QR scanning internally
        const result = await passkeyManager.scanAndLinkDevice({
          fundingAmount,
          onEvent: (event: any) => {
            console.log('Device linking event:', event);
          },
          onError: (error: any) => {
            console.error('Device linking error:', error);
            setError(error.message);
            onError?.(error);
          }
        });

        onDeviceLinked?.(result);
        onClose?.();
      } else {
        // Manual QR scanning without auto-linking
        const { scanQRCodeFromFile } = await import('../../utils/qr-scanner');
        const qrData = await scanQRCodeFromFile(file);
        onQRCodeScanned?.(qrData);
      }

    } catch (err: any) {
      setError(err.message || 'Failed to scan QR code from file');
      onError?.(err);
    } finally {
      setIsProcessing(false);
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
    width: '200px',
    height: '200px',
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
    width: '194px',
    height: '194px',
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
    maxWidth: '300px',
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