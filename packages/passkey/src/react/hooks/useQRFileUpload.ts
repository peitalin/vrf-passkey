import { useRef, useCallback } from 'react';
import type { DeviceLinkingQRData } from '../../core/types/linkDevice';

export interface UseQRFileUploadOptions {
  onQRDetected?: (qrData: DeviceLinkingQRData) => void;
  onError?: (error: Error) => void;
}

export interface UseQRFileUploadReturn {
  fileInputRef: React.RefObject<HTMLInputElement>;
  handleFileUpload: (event: React.ChangeEvent<HTMLInputElement>) => Promise<void>;
  isProcessing: boolean;
}

export const useQRFileUpload = (options: UseQRFileUploadOptions): UseQRFileUploadReturn => {
  const { onQRDetected, onError } = options;

  const fileInputRef = useRef<HTMLInputElement>(null);
  const isProcessingRef = useRef(false);

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
    if (!parsedData.devicePublicKey) missing.push('devicePublicKey');
    if (!parsedData.timestamp) missing.push('timestamp');
    if (missing.length > 0) {
      throw new Error(`Invalid device linking QR code: Missing ${missing.join(', ')}`);
    }

    return parsedData;
  }, []);

  // Handle file upload
  const handleFileUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    console.log('useQRFileUpload: File upload -', { name: file.name, type: file.type, size: file.size });

    try {
      isProcessingRef.current = true;

      const { scanQRCodeFromFile } = await import('../../utils/qrScanner');
      const parsedQRData = await scanQRCodeFromFile(file);

      console.log('useQRFileUpload: Valid file QR -', {
        devicePublicKey: parsedQRData.devicePublicKey,
        accountId: parsedQRData.accountId
      });

      onQRDetected?.(parsedQRData);

    } catch (err: any) {
      console.error('useQRFileUpload: File processing failed -', err.message);
      onError?.(err);
    } finally {
      isProcessingRef.current = false;
    }
  }, [onQRDetected, onError]);

  return {
    fileInputRef,
    handleFileUpload,
    isProcessing: isProcessingRef.current,
  };
};