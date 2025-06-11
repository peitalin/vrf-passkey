// Example: Using the Toast Event Emitter with different toast libraries

import { authEventEmitter } from '@web3authn/passkey';

// === Example 1: Using with react-hot-toast ===
import toast from 'react-hot-toast';

function setupReactHotToast() {
  return authEventEmitter.onToast((event) => {
    const { type, message, id, options } = event;

    switch (type) {
      case 'loading':
        toast.loading(message, { id, ...options });
        break;
      case 'success':
        toast.success(message, { id, ...options });
        break;
      case 'error':
        toast.error(message, { id, ...options });
        break;
      case 'dismiss':
        toast.dismiss(id);
        break;
    }
  });
}

// === Example 2: Using with react-toastify ===
import { toast as toastify } from 'react-toastify';

function setupReactToastify() {
  return authEventEmitter.onToast((event) => {
    const { type, message, id, options } = event;

    switch (type) {
      case 'loading':
        toastify.info(message, { toastId: id, autoClose: false });
        break;
      case 'success':
        toastify.success(message, { toastId: id, ...options });
        break;
      case 'error':
        toastify.error(message, { toastId: id, ...options });
        break;
      case 'dismiss':
        toastify.dismiss(id);
        break;
    }
  });
}

// === Example 3: Custom toast implementation ===
function setupCustomToast() {
  return authEventEmitter.onToast((event) => {
    const { type, message, id, options } = event;

    console.log(`[CUSTOM TOAST] ${type.toUpperCase()}: ${message}`, { id, options });

    // Implement your own toast logic here
    // Could be a custom modal, notification system, etc.
  });
}

// === Usage in React component ===
function useToastListener() {
  useEffect(() => {
    // Choose your preferred toast library setup
    const cleanup = setupReactHotToast();

    return cleanup; // Cleanup listener on unmount
  }, []);
}

// === Testing the emitter directly ===
function testToastEmitter() {
  // Test loading toast
  const loadingId = authEventEmitter.loading('Processing...', {
    style: { background: '#3498db', color: 'white' }
  });

  setTimeout(() => {
    // Update to success
    authEventEmitter.success('Success!', {
      id: loadingId,
      style: { background: '#2ecc71', color: 'white' }
    });
  }, 2000);

  // Test error toast
  authEventEmitter.error('Something went wrong!', {
    duration: 5000,
    style: { background: '#e74c3c', color: 'white' }
  });
}