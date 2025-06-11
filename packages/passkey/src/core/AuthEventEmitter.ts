// === AUTH EVENT EMITTER ===

export interface AuthEvent {
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

export class AuthEventEmitter {
  private activeToasts = new Set<string>();
  private maxConcurrentToasts = 3;
  private listeners: Array<(event: AuthEvent & { id: string }) => void> = [];

  /**
   * Generate a unique ID for auth events
   */
  private generateId(): string {
    return `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Emit a auth event
   */
  private emit(event: AuthEvent): string {
    const id = event.id || this.generateId();
    const eventWithId = { ...event, id };

    console.log('🔥 AuthEventEmitter.emit() called:', {
      type: event.type,
      message: event.message,
      id: id,
      listenerCount: this.listeners.length
    });

    // Call all registered listeners
    this.listeners.forEach((listener, index) => {
      try {
        console.log(`📞 Calling listener ${index + 1}/${this.listeners.length}`);
        listener(eventWithId);
        console.log(`✅ Listener ${index + 1} executed successfully`);
      } catch (error) {
        console.error(`❌ Error in listener ${index + 1}:`, error);
      }
    });

    if (event.type !== 'dismiss') {
      this.activeToasts.add(id);

      // Auto-cleanup for rate limiting
      if (this.activeToasts.size > this.maxConcurrentToasts) {
        const [oldestToast] = this.activeToasts;
        this.dismiss(oldestToast);
      }
    } else {
      this.activeToasts.delete(id);
    }

    return id;
  }

  /**
   * Show loading auth event
   */
  loading(message: string, options?: AuthEvent['options']): string {
    console.log('🔄 AuthEventEmitter.loading() called:', message);
    return this.emit({
      type: 'loading',
      message,
      options
    });
  }

  /**
   * Show success auth event
   */
  success(message: string, options?: AuthEvent['options'] & { id?: string }): string {
    console.log('✅ AuthEventEmitter.success() called:', message);
    const id = options?.id;
    return this.emit({
      type: 'success',
      message,
      options: {
        duration: options?.duration,
        style: options?.style
      },
      id
    });
  }

  /**
   * Show error toast
   */
  error(message: string, options?: AuthEvent['options'] & { id?: string }): string {
    console.log('❌ AuthEventEmitter.error() called:', message);
    const id = options?.id;
    return this.emit({
      type: 'error',
      message,
      options: {
        duration: options?.duration,
        style: options?.style
      },
      id
    });
  }

  /**
   * Dismiss a toast
   */
  dismiss(id: string): void {
    console.log('🗑️ AuthEventEmitter.dismiss() called:', id);
    this.emit({
      type: 'dismiss',
      id
    });
  }

  /**
   * Listen for auth events
   */
  onAuthEvent(callback: (event: AuthEvent & { id: string }) => void): () => void {
    console.log('👂 AuthEventEmitter.onAuthEvent() called - registering listener');

    // Add callback to listeners array
    this.listeners.push(callback);
    console.log(`📡 Listener registered. Total listeners: ${this.listeners.length}`);

    // Test immediately
    setTimeout(() => {
      console.log('🧪 Testing with a dummy event...');
      callback({ type: 'loading', message: 'Test event', id: 'test-123' });
    }, 50);

    // Return cleanup function
    return () => {
      console.log('🛑 Removing event listener');
      const index = this.listeners.indexOf(callback);
      if (index > -1) {
        this.listeners.splice(index, 1);
        console.log(`🛑 Listener removed. Remaining listeners: ${this.listeners.length}`);
      }
    };
  }
}

// Export singleton instance
export const authEventEmitter = new AuthEventEmitter();

// Add some debugging for the singleton
console.log('🎪 AuthEventEmitter singleton created:', authEventEmitter);