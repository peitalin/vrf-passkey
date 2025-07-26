import React from 'react';
import type { QRCodeScannerProps } from './QRCodeScanner';

// Lazy load the QRCodeScanner component
const QRCodeScannerComponent = React.lazy(() => import('./QRCodeScanner'));

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