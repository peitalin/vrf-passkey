import toast from 'react-hot-toast';
import { MAX_CONCURRENT_TOASTS } from '../../../config';
import type { ToastOptions, ManagedToast } from '../types';

// Toast queue management to limit concurrent toasts
const activeToasts = new Set<string>();

export const useToastManager = (): ManagedToast => {
  const managedToast: ManagedToast = {
    loading: (message: string, options: ToastOptions = {}): string => {
      if (activeToasts.size >= MAX_CONCURRENT_TOASTS) {
        // Dismiss oldest toast to make room
        const [oldestToast] = activeToasts;
        toast.dismiss(oldestToast);
        activeToasts.delete(oldestToast);
      }
      const id = toast.loading(message, options);
      activeToasts.add(id);
      return id;
    },

    success: (message: string, options: ToastOptions = {}): string => {
      if (options.id) {
        // Update existing toast
        activeToasts.delete(options.id);
        const newId = toast.success(message, options);
        activeToasts.add(newId);
        return newId;
      } else {
        // New toast
        if (activeToasts.size >= MAX_CONCURRENT_TOASTS) {
          const [oldestToast] = activeToasts;
          toast.dismiss(oldestToast);
          activeToasts.delete(oldestToast);
        }
        const id = toast.success(message, options);
        activeToasts.add(id);
        return id;
      }
    },

    error: (message: string, options: ToastOptions = {}): string => {
      if (activeToasts.size >= MAX_CONCURRENT_TOASTS) {
        const [oldestToast] = activeToasts;
        toast.dismiss(oldestToast);
        activeToasts.delete(oldestToast);
      }
      const id = toast.error(message, options);
      activeToasts.add(id);
      return id;
    },

    dismiss: (id: string): void => {
      toast.dismiss(id);
      activeToasts.delete(id);
    }
  };

  return managedToast;
};