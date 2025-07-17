import React from 'react';

// Lazy load the QRCodeScanner component
const QRCodeScannerComponent = React.lazy(() => import('./QRCodeScanner'));

// Props interface (re-exported for convenience)
export interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: any) => void;
  onDeviceLinked?: (result: any) => void;
  onError?: (error: Error) => void;
  autoLink?: boolean;
  fundingAmount?: string;
  cameraId?: string;
  config?: {
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