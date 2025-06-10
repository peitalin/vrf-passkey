import { useState, useEffect } from 'react';
import { indexDBManager } from '../../../services/IndexDBManager';
import type { OptimisticAuthOptions, OptimisticAuthHook } from '../types';

const OPTIMISTIC_AUTH_KEY = 'optimisticAuth';

export const useOptimisticAuth = (
  options: OptimisticAuthOptions = {}
): OptimisticAuthHook => {
  const { currentUser } = options;
  const [optimisticAuth, setOptimisticAuthState] = useState<boolean>(true);

  // Load initial setting
  useEffect(() => {
    const loadOptimisticAuth = async (): Promise<void> => {
      if (currentUser) {
        // Load from user preferences if logged in
        const user = await indexDBManager.getUser(currentUser);
        setOptimisticAuthState(user?.preferences?.optimisticAuth ?? true);
      } else {
        // Load from app state if not logged in
        const saved = await indexDBManager.getAppState<boolean>(OPTIMISTIC_AUTH_KEY);
        setOptimisticAuthState(saved ?? true);
      }
    };

    loadOptimisticAuth();
  }, [currentUser]);

  // Sync when currentUser changes
  useEffect(() => {
    if (currentUser) {
      const syncFromUser = async (): Promise<void> => {
        const user = await indexDBManager.getUser(currentUser);
        if (user?.preferences?.optimisticAuth !== undefined) {
          setOptimisticAuthState(user.preferences.optimisticAuth);
        }
      };
      syncFromUser();
    }
  }, [currentUser]);

  const setOptimisticAuth = (value: boolean): void => {
    setOptimisticAuthState(value);

    // Persist the setting
    if (currentUser) {
      // Store in user preferences
      indexDBManager.updatePreferences(currentUser, { optimisticAuth: value });
    } else {
      // Store in app state
      indexDBManager.setAppState(OPTIMISTIC_AUTH_KEY, value);
    }
  };

  return {
    optimisticAuth,
    setOptimisticAuth,
  };
};