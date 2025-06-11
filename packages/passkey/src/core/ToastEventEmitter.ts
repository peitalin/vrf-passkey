// === TOAST EVENT EMITTER ===

export interface ToastEvent {
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

export class ToastEventEmitter extends EventTarget {
  private activeToasts = new Set<string>();
  private maxConcurrentToasts = 3;

  /**
   * Generate a unique ID for toast messages
   */
  private generateId(): string {
    return `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Emit a toast event
   */
  private emit(event: ToastEvent): string {
    const id = event.id || this.generateId();
    const toastEvent = new CustomEvent('toast', {
      detail: { ...event, id }
    });

    this.dispatchEvent(toastEvent);

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
   * Show loading toast
   */
  loading(message: string, options?: ToastEvent['options']): string {
    return this.emit({
      type: 'loading',
      message,
      options
    });
  }

  /**
   * Show success toast
   */
  success(message: string, options?: ToastEvent['options'] & { id?: string }): string {
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
  error(message: string, options?: ToastEvent['options'] & { id?: string }): string {
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
    this.emit({
      type: 'dismiss',
      id
    });
  }

  /**
   * Listen for toast events
   */
  onToast(callback: (event: ToastEvent & { id: string }) => void): () => void {
    const handler = (event: CustomEvent) => {
      callback(event.detail);
    };

    this.addEventListener('toast', handler as EventListener);

    // Return cleanup function
    return () => {
      this.removeEventListener('toast', handler as EventListener);
    };
  }
}

// Export singleton instance
export const toastEmitter = new ToastEventEmitter();