import { useEffect, useRef, useState, useCallback } from 'react';
import { getOptimalCameraFacingMode } from '../deviceDetection';
import type { DeviceLinkingQRData } from '@/index';

export interface UseQRCameraOptions {
  onQRDetected?: (qrData: DeviceLinkingQRData) => void;
  onError?: (error: Error) => void;
  isOpen?: boolean;
  cameraId?: string;
}

export interface UseQRCameraReturn {
  // State
  isScanning: boolean;
  isProcessing: boolean;
  error: string | null;
  cameras: MediaDeviceInfo[];
  selectedCamera: string;
  scanMode: 'camera' | 'file' | 'auto';
  isFrontCamera: boolean;

  // Refs for UI
  videoRef: React.RefObject<HTMLVideoElement>;
  canvasRef: React.RefObject<HTMLCanvasElement>;

  // Controls
  startScanning: () => Promise<void>;
  stopScanning: () => void;
  handleCameraChange: (deviceId: string) => void;
  setScanMode: (mode: 'camera' | 'file' | 'auto') => void;
  setError: (error: string | null) => void;

  // Utilities
  getOptimalFacingMode: () => 'user' | 'environment';
}

export const useQRCamera = (options: UseQRCameraOptions): UseQRCameraReturn => {
  const {
    onQRDetected,
    onError,
    isOpen = true,
    cameraId
  } = options;

  // Refs
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number | undefined>(undefined);
  const isScanningRef = useRef(false);
  const scanStartTimeRef = useRef<number>(0);

  // State
  const [isScanning, setIsScanning] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [cameras, setCameras] = useState<MediaDeviceInfo[]>([]);
  const [selectedCamera, setSelectedCamera] = useState<string>(cameraId || '');
  const [scanMode, setScanMode] = useState<'camera' | 'file' | 'auto'>('auto');
  const [isFrontCamera, setIsFrontCamera] = useState<boolean>(false);

  const SCAN_TIMEOUT_MS = 60000; // 60 seconds timeout

  // Use imported device detection utility
  const getOptimalFacingMode = useCallback(() => getOptimalCameraFacingMode(), []);

    // Initialize camera devices
  useEffect(() => {
    const loadCameras = async () => {
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoDevices = devices.filter(device => device.kind === 'videoinput');
        setCameras(videoDevices);

        if (videoDevices.length > 0 && !selectedCamera) {
          // Default to first camera
          setSelectedCamera(videoDevices[0].deviceId);
          setIsFrontCamera(false); // We'll detect this when stream starts
        }
      } catch (error) {
        console.error('Error enumerating cameras:', error);
        setError('Failed to access camera devices');
      }
    };

    loadCameras();
  }, [selectedCamera]);

  // Monitor isScanning state changes
  useEffect(() => {
    isScanningRef.current = isScanning;
  }, [isScanning]);

  // Auto-start scanning when modal opens
  useEffect(() => {
    if (isOpen && scanMode === 'auto') {
      startScanning();
    } else if (!isOpen) {
      stopScanning();
    }

    return () => { stopScanning(); };
  }, [isOpen, scanMode]);

  // Parse and validate QR data
  const parseAndValidateQRData = useCallback((qrData: string): DeviceLinkingQRData => {
    let parsedData: DeviceLinkingQRData;
    try {
      parsedData = JSON.parse(qrData);
    } catch {
      if (qrData.startsWith('http')) {
        throw new Error('QR code contains a URL, not device linking data');
      }
      if (qrData.includes('ed25519:')) {
        throw new Error('QR code contains a NEAR key, not device linking data');
      }
      throw new Error('Invalid QR code format - expected JSON device linking data');
    }

    const missing = [];
    if (!parsedData.device2PublicKey) missing.push('devicePublicKey');
    if (!parsedData.timestamp) missing.push('timestamp');
    if (missing.length > 0) {
      throw new Error(`Invalid device linking QR code: Missing ${missing.join(', ')}`);
    }

    return parsedData;
  }, []);

  // Handle QR detection from camera
  const handleQRDetected = useCallback(async (qrData: string) => {
    console.log('useQRCamera: QR detected -', { length: qrData.length, preview: qrData.substring(0, 100) });

    try {
      setIsProcessing(true);

      const parsedQRData = parseAndValidateQRData(qrData);
      console.log('useQRCamera: Valid QR data -', {
        devicePublicKey: parsedQRData.device2PublicKey,
        accountId: parsedQRData.accountId,
        timestamp: new Date(parsedQRData.timestamp || 0).toISOString()
      });

      onQRDetected?.(parsedQRData);

    } catch (err: any) {
      console.error('useQRCamera: QR processing failed -', err.message);
      setError(err.message || 'Failed to process QR code');
      onError?.(err);
    } finally {
      console.log('useQRCamera: QR detection complete - stopping scanning...');
      setIsProcessing(false);
      stopScanning();
    }
  }, [parseAndValidateQRData, onQRDetected, onError]);

  // Frame scanning logic
  const scanFrame = useCallback(async () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;

    if (!video || !canvas || !isOpen || !isScanningRef.current) {
      console.log('useQRCamera: scanFrame conditions not met - stopping scan loop');
      return;
    }

    // Check for scanning timeout
    const elapsedTime = Date.now() - scanStartTimeRef.current;
    if (elapsedTime > SCAN_TIMEOUT_MS) {
      setIsScanning(false);
      isScanningRef.current = false;
      setError(`QR scanning timeout - no valid QR code found within ${SCAN_TIMEOUT_MS / 1000} seconds. Please ensure the QR code is clearly visible and try again.`);
      onError?.(new Error(`QR scanning timeout after ${SCAN_TIMEOUT_MS / 1000} seconds`));
      return;
    }

    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) {
      console.log('useQRCamera: No canvas context available');
      return;
    }

    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      try {
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
        console.error('useQRCamera: QR scanning error:', err);
      }
    }

    if (isScanningRef.current && isOpen) {
      animationRef.current = requestAnimationFrame(scanFrame);
    }
  }, [isOpen, handleQRDetected, onError]);

  // Start scanning function
  const startScanning = useCallback(async () => {
    try {
      setError(null);

      const constraints: MediaStreamConstraints = {
        video: {
          deviceId: selectedCamera || undefined,
          width: { ideal: 720, min: 480 },
          height: { ideal: 720, min: 480 },
          aspectRatio: { ideal: 1.0 },
          facingMode: selectedCamera ? undefined : getOptimalFacingMode()
        }
      };

      console.log('useQRCamera: Camera constraints:', constraints);
      const mediaStream = await navigator.mediaDevices.getUserMedia(constraints);
      setStream(mediaStream);

      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
        await videoRef.current.play();
      }

      // Detect camera facing mode from actual stream settings
      const videoTrack = mediaStream.getVideoTracks()[0];
      if (videoTrack) {
        const settings = videoTrack.getSettings();
        setIsFrontCamera(settings.facingMode === 'user');
      }

      setIsScanning(true);
      isScanningRef.current = true;
      scanStartTimeRef.current = Date.now();

      setTimeout(() => {
        requestAnimationFrame(scanFrame);
      }, 500);

    } catch (err: any) {
      setError(`Camera access denied: ${err.message}`);
      onError?.(err);
      setIsScanning(false);
      isScanningRef.current = false;
    }
  }, [selectedCamera, scanFrame, onError]);

  // Stop scanning function
  const stopScanning = useCallback(() => {
    console.log('useQRCamera: stopScanning called - cleaning up camera...');

    setIsScanning(false);
    isScanningRef.current = false;
    scanStartTimeRef.current = 0;

    if (animationRef.current) {
      console.log('useQRCamera: Cancelling animation frame');
      cancelAnimationFrame(animationRef.current);
      animationRef.current = undefined;
    }

    if (videoRef.current) {
      console.log('useQRCamera: Cleaning up video element');
      videoRef.current.pause();
      videoRef.current.srcObject = null;
      videoRef.current.load();
    }

    if (stream) {
      console.log('useQRCamera: Stopping camera tracks');
      stream.getTracks().forEach(track => {
        if (track.readyState === 'live') {
          console.log('useQRCamera: Stopping track:', track.kind, track.label);
          track.stop();
        }
        track.onended = track.onmute = track.onunmute = null;
      });
      setStream(null);
    }

    window.gc?.();
    console.log('useQRCamera: Cleanup complete');
  }, [stream]);



  // Handle camera change
  const handleCameraChange = useCallback((deviceId: string) => {
    setSelectedCamera(deviceId);

    const selectedCameraDevice = cameras.find(camera => camera.deviceId === deviceId);
    if (selectedCameraDevice) {
      const label = selectedCameraDevice.label.toLowerCase();
      const isNewCameraFront = label.includes('front') ||
                              label.includes('user') ||
                              label.includes('selfie') ||
                              label.includes('facetime') ||
                              label.includes('facing front');
      setIsFrontCamera(isNewCameraFront);
    }

    if (isScanning) {
      stopScanning();
      setTimeout(startScanning, 100);
    }
  }, [cameras, isScanning, stopScanning, startScanning]);

    return {
    // State
    isScanning,
    isProcessing,
    error,
    cameras,
    selectedCamera,
    scanMode,
    isFrontCamera,

    // Refs
    videoRef,
    canvasRef,

    // Controls
    startScanning,
    stopScanning,
    handleCameraChange,
    setScanMode,
    setError,

    // Utilities
    getOptimalFacingMode,
  };
};