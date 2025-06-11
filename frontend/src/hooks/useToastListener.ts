import { useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  toastEmitter,
  type ToastEvent
} from '@web3authn/passkey';

/**
 * Hook to listen to SDK toast events and display them using react-hot-toast
 */
export const useToastListener = () => {
  useEffect(() => {
    const handleToastEvent = (event: ToastEvent & { id: string }) => {
      const { type, message, id, options } = event;

      switch (type) {
        case 'loading':
          if (message) {
            toast.loading(message, {
              id,
              duration: options?.duration,
              style: options?.style
            });
          }
          break;

        case 'success':
          if (message) {
            toast.success(message, {
              id,
              duration: options?.duration,
              style: options?.style
            });
          }
          break;

        case 'error':
          if (message) {
            toast.error(message, {
              id,
              duration: options?.duration,
              style: options?.style
            });
          }
          break;

        case 'dismiss':
          toast.dismiss(id);
          break;

        default:
          console.warn('Unknown toast event type:', type);
      }
    };

    // Start listening to toast events
    const cleanup = toastEmitter.onToast(handleToastEvent);

    // Cleanup listener on unmount
    return cleanup;
  }, []);
};