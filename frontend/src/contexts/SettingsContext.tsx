import React, { createContext, useContext, useState, useEffect } from 'react';
import { ClientUserManager } from '../services/ClientUserManager';

interface SettingsContextType {
  useOptimisticAuth: boolean;
  setUseOptimisticAuth: (value: boolean) => void;
  currentUser: string | null;
  setCurrentUser: (nearAccountId: string | null) => void;
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

export const useSettings = (): SettingsContextType => {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
};

interface SettingsProviderProps {
  children: React.ReactNode;
}

export const SettingsProvider: React.FC<SettingsProviderProps> = ({ children }) => {
  // Get the current user from ClientUserManager
  const [currentUser, setCurrentUserState] = useState<string | null>(() => {
    const lastUser = ClientUserManager.getLastUser();
    return lastUser?.nearAccountId || null;
  });

  // Get optimistic auth setting from current user's preferences
  const [useOptimisticAuth, setUseOptimisticAuthState] = useState(() => {
    if (currentUser) {
      const user = ClientUserManager.getUser(currentUser);
      return user?.preferences?.useOptimisticAuth ?? true; // Default to Fast mode for better UX
    }
    // Fallback to old localStorage method for backwards compatibility
    const saved = localStorage.getItem('useOptimisticAuth');
    return saved ? JSON.parse(saved) : true; // Default to Fast mode for new users
  });

  // Update user preferences when optimistic auth setting changes
  const setUseOptimisticAuth = (value: boolean) => {
    setUseOptimisticAuthState(value);

    if (currentUser) {
      // Store in user preferences
      ClientUserManager.updatePreferences(currentUser, { useOptimisticAuth: value });
    } else {
      // Fallback to localStorage for backwards compatibility
      localStorage.setItem('useOptimisticAuth', JSON.stringify(value));
    }
  };

  // Update current user and reload preferences
  const setCurrentUser = (nearAccountId: string | null) => {
    setCurrentUserState(nearAccountId);

    if (nearAccountId) {
      const user = ClientUserManager.getUser(nearAccountId);
      if (user?.preferences?.useOptimisticAuth !== undefined) {
        setUseOptimisticAuthState(user.preferences.useOptimisticAuth);
      }
    }
  };

  // Sync with ClientUserManager when currentUser changes
  useEffect(() => {
    if (currentUser) {
      const user = ClientUserManager.getUser(currentUser);
      if (user && user.preferences?.useOptimisticAuth !== useOptimisticAuth) {
        setUseOptimisticAuthState(user.preferences.useOptimisticAuth ?? true); // Default to Fast mode
      }
    }
  }, [currentUser]);

  return (
    <SettingsContext.Provider value={{
      useOptimisticAuth,
      setUseOptimisticAuth,
      currentUser,
      setCurrentUser
    }}>
      {children}
    </SettingsContext.Provider>
  );
};