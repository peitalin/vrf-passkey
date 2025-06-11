# Toast Event System

The `@web3authn/passkey` SDK uses an event-based toast notification system that allows developers to integrate with any toast library of their choice, eliminating React instance conflicts and providing maximum flexibility.

## Why Event-Based Toasts?

- **Framework Agnostic**: No direct dependency on specific toast libraries
- **No React Conflicts**: Eliminates React instance duplication issues
- **Developer Choice**: Use any toast library (react-hot-toast, react-toastify, custom implementations)
- **Smaller Bundle**: Reduced SDK dependencies
- **Better Architecture**: Clean separation of concerns

## Basic Usage

### 1. Import the Toast Emitter

```typescript
import { toastEmitter, ToastEvent } from '@web3authn/passkey';
```

### 2. Listen to Toast Events

```typescript
import { useEffect } from 'react';
import toast from 'react-hot-toast'; // or your preferred library

function useToastListener() {
  useEffect(() => {
    const cleanup = toastEmitter.onToast((event: ToastEvent & { id: string }) => {
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

## Toast Event Types

### ToastEvent Interface

```typescript
interface ToastEvent {
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
import { toastEmitter } from '@web3authn/passkey';

const cleanup = toastEmitter.onToast((event) => {
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
import { toastEmitter } from '@web3authn/passkey';

const cleanup = toastEmitter.onToast((event) => {
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
import { toastEmitter } from '@web3authn/passkey';

const cleanup = toastEmitter.onToast((event) => {
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
import { toastEmitter } from '@web3authn/passkey';

// Show loading toast
const loadingId = toastEmitter.loading('Processing transaction...', {
  style: { background: '#3498db', color: 'white' }
});

// Later, update to success
toastEmitter.success('Transaction completed!', {
  id: loadingId,
  style: { background: '#2ecc71', color: 'white' }
});

// Or show an error
toastEmitter.error('Transaction failed', {
  duration: 5000,
  style: { background: '#e74c3c', color: 'white' }
});

// Dismiss specific toast
toastEmitter.dismiss(loadingId);
```

### Rate Limiting

The toast emitter automatically handles rate limiting to prevent toast spam:

- Maximum of 3 concurrent toasts by default
- Automatically dismisses oldest toasts when limit is exceeded
- Each toast gets a unique ID for tracking

## Migration Guide

### From Direct Toast Usage

**Before (with direct dependency):**

```typescript
import toast from 'react-hot-toast';

function MyComponent() {
  const handleAction = () => {
    toast.loading('Processing...');
    // ... action logic
    toast.success('Done!');
  };
}
```

**After (with event system):**

```typescript
// In your root component
function App() {
  useToastListener(); // Add this once
  return <MyComponent />;
}

// In your component - SDK handles toasts automatically
function MyComponent() {
  const { registerPasskey } = usePasskeyContext();

  const handleAction = () => {
    // SDK will emit toast events automatically
    registerPasskey('username');
  };
}
```

## Benefits

1. **No More React Instance Conflicts**: The SDK no longer bundles React dependencies for toasts
2. **Choose Your Library**: Use any toast library or build your own
3. **Consistent API**: All SDK operations emit standardized toast events
4. **Better Performance**: Smaller bundle size, fewer dependencies
5. **Future Proof**: Easy to switch toast libraries without changing SDK code

## Best Practices

1. **Set up the listener once** in your root component
2. **Always return the cleanup function** from `useEffect`
3. **Handle all event types** to ensure complete toast coverage
4. **Use consistent styling** across your application
5. **Test with your chosen toast library** to ensure proper integration

This event-based approach provides a much cleaner architecture while maintaining all the functionality you expect from the passkey registration and authentication flows.