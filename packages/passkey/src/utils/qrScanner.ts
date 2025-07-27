import type { DeviceLinkingQRData } from '../core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../core/types/linkDevice';
import { validateDeviceLinkingQRData } from '../core/PasskeyManager/scanDevice';

/**
 * QR Scanner utility with lazy loading
 * This module lazy loads the jsQR library only when scanning is needed
 */

type JsQR = (data: Uint8ClampedArray, width: number, height: number, options?: any) => any;
const SCAN_TIMEOUT_MS = 60000; // 60 seconds

/**
 * Scan QR code from camera with lazy loading
 */
export async function scanQRCodeFromCamera(
  cameraId?: string,
  cameraConfigs?: {
    facingMode?: 'user' | 'environment';
    width?: number;
    height?: number;
  }
): Promise<DeviceLinkingQRData> {
  let stream: MediaStream | null = null;
  let scanning = true;
  const scanStartTime = Date.now();

  const cleanup = () => {
    scanning = false;
    stream?.getTracks().forEach(track => track.stop());
  };

  try {
    const jsQR = await loadJsQR();

    // Setup camera stream
    const constraints: MediaStreamConstraints = {
      video: {
        facingMode: cameraConfigs?.facingMode || 'environment',
        width: cameraConfigs?.width || 640,
        height: cameraConfigs?.height || 480,
        ...(cameraId && { deviceId: { exact: cameraId } })
      }
    };

    stream = await navigator.mediaDevices.getUserMedia(constraints);

    // Setup video element
    const video = document.createElement('video');
    video.srcObject = stream;
    video.playsInline = true;
    video.muted = true;

    await new Promise<void>((resolve, reject) => {
      video.onloadedmetadata = () => video.play().then(resolve).catch(reject);
      video.onerror = reject;
    });

    // Setup canvas for frame capture
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) throw createQRError('Unable to get canvas 2D context');

    // Scanning loop
    return new Promise<DeviceLinkingQRData>((resolve, reject) => {
      const scanFrame = () => {
        if (!scanning) return;

        // Check timeout
        if (Date.now() - scanStartTime > SCAN_TIMEOUT_MS) {
          cleanup();
          reject(new DeviceLinkingError(
            'QR scanning timeout - no valid QR code found within 60 seconds. Please ensure the QR code is clearly visible and try again.',
            DeviceLinkingErrorCode.SESSION_EXPIRED,
            'authorization'
          ));
          return;
        }

        // Process frame
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);

          if (code) {
            cleanup();
            try {
              resolve(parseAndValidateQR(code.data));
              return;
            } catch (error) {
              reject(error);
              return;
            }
          }
        }

        requestAnimationFrame(scanFrame);
      };

      scanFrame();
    });

  } catch (error: any) {
    cleanup();
    throw createQRError(`Camera access failed: ${error.message}`);
  }
}

/**
 * Scan QR code from file with lazy loading
 */
export async function scanQRCodeFromFile(file: File): Promise<DeviceLinkingQRData> {
  const jsQR = await loadJsQR();

  // Setup canvas
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  if (!ctx) throw createQRError('Unable to get canvas 2D context');

  // Load and process image
  const dataUrl = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result) {
        resolve(e.target.result as string);
      } else {
        reject(createQRError('Failed to read file'));
      }
    };
    reader.onerror = () => reject(createQRError('Failed to read file'));
    reader.readAsDataURL(file);
  });

  // Process image
  const img = await new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(createQRError('Failed to load image file'));
    image.src = dataUrl;
  });

  // Scan QR code
  canvas.width = img.width;
  canvas.height = img.height;
  ctx.drawImage(img, 0, 0);

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(imageData.data, imageData.width, imageData.height);

  if (!code) {
    throw createQRError('No QR code found in image');
  }

  return parseAndValidateQR(code.data);
}

// ===========================
// PRIVATE HELPER FUNCTIONS
// ===========================

/**
 * Lazy load jsQR library
 */
async function loadJsQR(): Promise<JsQR> {
  const { default: jsQR } = await import('jsqr');
  return jsQR;
}

function createQRError(message: string): DeviceLinkingError {
  return new DeviceLinkingError(message, DeviceLinkingErrorCode.INVALID_QR_DATA, 'authorization');
}

function parseAndValidateQR(qrCodeData: string): DeviceLinkingQRData {
  try {
    const qrData = JSON.parse(qrCodeData) as DeviceLinkingQRData;
    validateDeviceLinkingQRData(qrData);
    return qrData;
  } catch (error: any) {
    throw createQRError(`Invalid QR code data: ${error.message}`);
  }
}