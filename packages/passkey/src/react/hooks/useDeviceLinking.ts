import { useRef, useCallback } from 'react';
import { usePasskeyContext } from '../context';
import type { DeviceLinkingQRData, LinkDeviceResult } from '../../core/types/linkDevice';
import type { DeviceLinkingSSEEvent } from '../../core/types/passkeyManager';

export interface UseDeviceLinkingOptions {
  onDeviceLinked?: (result: LinkDeviceResult) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: DeviceLinkingSSEEvent) => void;
  fundingAmount?: string;
}

export interface UseDeviceLinkingReturn {
  linkDevice: (qrData: DeviceLinkingQRData, source: 'camera' | 'file') => Promise<void>;
}

export const useDeviceLinking = (options: UseDeviceLinkingOptions): UseDeviceLinkingReturn => {
  const { passkeyManager } = usePasskeyContext();
  const {
    onDeviceLinked,
    onError,
    onClose,
    onEvent,
    fundingAmount = '0.1'
  } = options;

  const hasClosedEarlyRef = useRef(false);

  // Use refs for callbacks to avoid dependency changes
  const callbacksRef = useRef({
    onDeviceLinked,
    onError,
    onClose,
    onEvent
  });

  // Update refs when callbacks change
  callbacksRef.current = {
    onDeviceLinked,
    onError,
    onClose,
    onEvent
  };

  // Handle device linking with early close logic
  const linkDevice = useCallback(async (qrData: DeviceLinkingQRData, source: 'camera' | 'file') => {
    const { onDeviceLinked, onError, onClose, onEvent } = callbacksRef.current;

    try {
      console.log(`useDeviceLinking: Starting device linking from ${source}...`);
      hasClosedEarlyRef.current = false; // Reset for this linking attempt

      const result = await passkeyManager.linkDeviceWithQRData(qrData, {
        fundingAmount,
        onEvent: (event: any) => {
          onEvent?.(event);
          console.log(`useDeviceLinking: ${source} linking event -`, event.phase, event.message);

          // Close scanner immediately after QR validation succeeds
          switch (event.step) {
            case 3:
              if (event.phase === 'authorization' && event.status === 'progress') {
                console.log('useDeviceLinking: QR validation complete - closing scanner while linking continues...');
                hasClosedEarlyRef.current = true;
                onClose?.();
              }
              break;
          }
        },
        onError: (error: any) => {
          console.error(`useDeviceLinking: ${source} linking error -`, error.message);
          onError?.(error);
        }
      });

      console.log(`useDeviceLinking: ${source} linking completed -`, { success: !!result });
      onDeviceLinked?.(result);

    } catch (linkingError: any) {
      console.error(`useDeviceLinking: ${source} linking failed -`, linkingError.message);
      onError?.(linkingError);

      // Close scanner on error if it hasn't been closed early
      if (!hasClosedEarlyRef.current) {
        console.log('useDeviceLinking: Closing scanner due to linking error...');
        onClose?.();
      }
    }
  }, [fundingAmount, passkeyManager]);

  return {
    linkDevice,
  };
};