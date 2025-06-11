import { useEffect } from 'react';
import toast from 'react-hot-toast';
import { authEventEmitter, type AuthEvent } from '@web3authn/passkey';

/**
 * Hook to listen to Web3Authn SDK events and display them using react-hot-toast
 */
export const useWeb3AuthnEventListener = () => {
  useEffect(() => {
    const handleAuthEvent = (event: AuthEvent & { id: string }) => {
      const { type, message, id, options } = event;

      // Log every event for debugging
      console.log('🔔 Web3Authn Event:', {
        type,
        message,
        id,
        options,
        timestamp: new Date().toISOString()
      });

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
          console.warn('⚠️ Unknown toast event type:', type, event);
      }
    };

    console.log('📡 Starting Web3Authn event listener...');

    // Start listening to toast events
    const cleanup = authEventEmitter.onAuthEvent(handleAuthEvent);

    // Cleanup listener on unmount
    return () => {
      console.log('🛑 Stopping Web3Authn event listener...');
      cleanup();
    };
  }, []);
};