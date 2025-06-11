# Auth Event Emitting System

The `@web3authn/passkey` SDK uses an event-based toast notification system that allows developers to integrate with any toast library of their choice.

## Basic Usage

### 1. Import the Auth Event Emitter

```typescript
import { authEventEmitter, AuthEvent } from '@web3authn/passkey';
```

### 2. Listen to Toast Events

```typescript
import { useEffect } from 'react';
import toast from 'react-hot-toast'; // or your preferred library

function useToastListener() {
  useEffect(() => {
    const cleanup = authEventEmitter.onAuthEvent((event: AuthEvent & { id: string }) => {
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

    return cleanup; // Important: cleanup on unmount
  }, []);
}
```

### 3. Use in Your App

```typescript
function App() {
  useToastListener(); // Add this to your root component

  return (
    <PasskeyProvider>
      {/* Your toast library's Toaster component */}
      <Toaster />
      {/* Your app content */}
    </PasskeyProvider>
  );
}
```

## Auth Event Types

```typescript
interface AuthEvent {
  type: 'loading' | 'success' | 'error' | 'dismiss';
  message?: string;
  id?: string;
  options?: {
    duration?: number;
    style?: {
      background?: string;
      color?: string;
    };
  };
}
```

### Event Types

- **`loading`**: Shows a loading/spinner toast
- **`success`**: Shows a success toast (often updates a previous loading toast)
- **`error`**: Shows an error toast
- **`dismiss`**: Dismisses a specific toast by ID

## Integration Examples

### With react-hot-toast

```typescript
import toast from 'react-hot-toast';
import { authEventEmitter } from '@web3authn/passkey';

const cleanup = authEventEmitter.onAuthEvent((event) => {
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
```

### With react-toastify

```typescript
import { toast } from 'react-toastify';
import { authEventEmitter } from '@web3authn/passkey';

const cleanup = authEventEmitter.onAuthEvent((event) => {
  const { type, message, id, options } = event;

  switch (type) {
    case 'loading':
      toast.info(message, { toastId: id, autoClose: false });
      break;
    case 'success':
      toast.success(message, { toastId: id, ...options });
      break;
    case 'error':
      toast.error(message, { toastId: id, ...options });
      break;
    case 'dismiss':
      toast.dismiss(id);
      break;
  }
});
```

### Custom Implementation

```typescript
import { authEventEmitter } from '@web3authn/passkey';

const cleanup = authEventEmitter.onAuthEvent((event) => {
  const { type, message, id, options } = event;

  // Your custom toast implementation
  console.log(`Toast [${type}]: ${message}`, { id, options });

  // Could trigger your own modal system, notifications, etc.
  showCustomNotification(type, message, options);
});
```

## Advanced Usage

### Manual Toast Triggering

You can also manually trigger toasts using the emitter:

```typescript
import { authEventEmitter } from '@web3authn/passkey';

// Show loading toast
const loadingId = authEventEmitter.loading('Processing transaction...', {
  style: { background: '#3498db', color: 'white' }
});

// Later, update to success
authEventEmitter.success('Transaction completed!', {
  id: loadingId,
  style: { background: '#2ecc71', color: 'white' }
});

// Or show an error
authEventEmitter.error('Transaction failed', {
  duration: 5000,
  style: { background: '#e74c3c', color: 'white' }
});

// Dismiss specific toast
authEventEmitter.dismiss(loadingId);
```

### Rate Limiting

The toast emitter automatically handles rate limiting to prevent toast spam:

- Maximum of 3 concurrent toasts by default
- Automatically dismisses oldest toasts when limit is exceeded
- Each toast gets a unique ID for tracking
