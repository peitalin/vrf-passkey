import React from 'react';
import type { DeviceLinkingQRData, LinkDeviceResult } from '../../core/types/linkDevice';

// Lazy load the QRCodeScanner component
const QRCodeScannerComponent = React.lazy(() => import('./QRCodeScanner'));

// Props interface (re-exported for convenience)
export interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: DeviceLinkingQRData) => void;
  onDeviceLinked?: (result: LinkDeviceResult) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  autoLink?: boolean;
  fundingAmount?: string;
  isOpen?: boolean;
  cameraId?: string;
  cameraConfigs?: {
    facingMode?: 'user' | 'environment';
    width?: number;
    height?: number;
  };
  className?: string;
  style?: React.CSSProperties;
}

// Lazy wrapper with Suspense
export const QRCodeScanner: React.FC<QRCodeScannerProps> = (props) => {
  return (
    <React.Suspense
      fallback={
        <div style={{
          padding: '2rem',
          textAlign: 'center',
          border: '2px solid #ddd',
          borderRadius: '8px',
          minHeight: '200px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          Loading QR Scanner...
        </div>
      }
    >
      <QRCodeScannerComponent {...props} />
    </React.Suspense>
  );
};

export default QRCodeScanner;