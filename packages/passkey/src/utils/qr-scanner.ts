/**
 * QR Scanner utility with lazy loading
 * This module lazy loads the jsQR library only when scanning is needed
 */

import type { DeviceLinkingQRData } from '../core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../core/types/linkDevice';
import { validateDeviceLinkingQRData } from '../core/PasskeyManager/linkDevice';

// Lazy import type for jsQR
type JsQR = (data: Uint8ClampedArray, width: number, height: number, options?: any) => any;

/**
 * Lazy load jsQR library
 */
async function loadJsQR(): Promise<JsQR> {
  const { default: jsQR } = await import('jsqr');
  return jsQR;
}

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
  return new Promise(async (resolve, reject) => {
    let stream: MediaStream | null = null;
    let scanning = true;
    let jsQR: JsQR | null = null;
    const SCAN_TIMEOUT_MS = 60000; // 60 seconds timeout
    const scanStartTime = Date.now();

    const cleanup = () => {
      scanning = false;
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
      }
    };

    try {
      // Load jsQR library
      jsQR = await loadJsQR();

      // Get camera stream
      const constraints: MediaStreamConstraints = {
        video: {
          facingMode: cameraConfigs?.facingMode || 'environment',
          width: cameraConfigs?.width || 640,
          height: cameraConfigs?.height || 480,
          ...(cameraId && { deviceId: { exact: cameraId } })
        }
      };

      stream = await navigator.mediaDevices.getUserMedia(constraints);

      // Create video element
      const video = document.createElement('video');
      video.srcObject = stream;
      video.playsInline = true;
      video.muted = true;

      await new Promise<void>((resolveVideo, rejectVideo) => {
        video.onloadedmetadata = () => {
          video.play()
            .then(() => resolveVideo())
            .catch(rejectVideo);
        };
        video.onerror = rejectVideo;
      });

      // Create canvas for frame capture
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');

      if (!ctx) {
        throw new Error('Unable to get canvas 2D context');
      }

      const scanFrame = () => {
        if (!scanning || !jsQR) return;

        // Check for scanning timeout
        const elapsedTime = Date.now() - scanStartTime;
        if (elapsedTime > SCAN_TIMEOUT_MS) {
          cleanup();
          reject(new DeviceLinkingError(
            'QR scanning timeout - no valid QR code found within 60 seconds. Please ensure the QR code is clearly visible and try again.',
            DeviceLinkingErrorCode.SESSION_EXPIRED,
            'authorization'
          ));
          return;
        }

        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);

          if (code) {
            cleanup();
            try {
              const qrData = JSON.parse(code.data) as DeviceLinkingQRData;
              validateDeviceLinkingQRData(qrData);
              resolve(qrData);
              return;
            } catch (error: any) {
              reject(new DeviceLinkingError(
                `Invalid QR code data: ${error.message}`,
                DeviceLinkingErrorCode.INVALID_QR_DATA,
                'authorization'
              ));
              return;
            }
          }
        }

        requestAnimationFrame(scanFrame);
      };

      scanFrame();

    } catch (error: any) {
      cleanup();
      reject(new DeviceLinkingError(
        `Camera access failed: ${error.message}`,
        DeviceLinkingErrorCode.INVALID_QR_DATA,
        'authorization'
      ));
    }
  });
}

/**
 * Scan QR code from file with lazy loading
 */
export async function scanQRCodeFromFile(file: File): Promise<DeviceLinkingQRData> {
  return new Promise(async (resolve, reject) => {
    try {
      // Load jsQR library
      const jsQR = await loadJsQR();

      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');

      if (!ctx) {
        reject(new DeviceLinkingError(
          'Unable to get canvas 2D context',
          DeviceLinkingErrorCode.INVALID_QR_DATA,
          'authorization'
        ));
        return;
      }

      const img = new Image();

      img.onload = () => {
        try {
          canvas.width = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);

          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);

          if (code) {
            try {
              const qrData = JSON.parse(code.data) as DeviceLinkingQRData;
              validateDeviceLinkingQRData(qrData);
              resolve(qrData);
            } catch (error: any) {
              reject(new DeviceLinkingError(
                `Invalid QR code data: ${error.message}`,
                DeviceLinkingErrorCode.INVALID_QR_DATA,
                'authorization'
              ));
            }
          } else {
            reject(new DeviceLinkingError(
              'No QR code found in image',
              DeviceLinkingErrorCode.INVALID_QR_DATA,
              'authorization'
            ));
          }
        } catch (error: any) {
          reject(new DeviceLinkingError(
            `Failed to process image: ${error.message}`,
            DeviceLinkingErrorCode.INVALID_QR_DATA,
            'authorization'
          ));
        }
      };

      img.onerror = () => {
        reject(new DeviceLinkingError(
          'Failed to load image file',
          DeviceLinkingErrorCode.INVALID_QR_DATA,
          'authorization'
        ));
      };

      // Convert file to data URL
      const reader = new FileReader();
      reader.onload = (e) => {
        if (e.target?.result) {
          img.src = e.target.result as string;
        } else {
          reject(new DeviceLinkingError(
            'Failed to read file',
            DeviceLinkingErrorCode.INVALID_QR_DATA,
            'authorization'
          ));
        }
      };

      reader.onerror = () => {
        reject(new DeviceLinkingError(
          'Failed to read file',
          DeviceLinkingErrorCode.INVALID_QR_DATA,
          'authorization'
        ));
      };

      reader.readAsDataURL(file);

    } catch (error: any) {
      reject(new DeviceLinkingError(
        `Failed to initialize QR scanner: ${error.message}`,
        DeviceLinkingErrorCode.INVALID_QR_DATA,
        'authorization'
      ));
    }
  });
}