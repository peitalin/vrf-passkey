import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { webAuthnManager } from '../../security/WebAuthnManager';
import { indexDBManager } from '../../services/IndexDBManager';
import { useOptimisticAuth } from './hooks/useOptimisticAuth';
import { useGreetingService } from './hooks/useNearGreetingService';
import { usePasskeyRegistration } from './hooks/usePasskeyRegistration';
import { usePasskeyLogin } from './hooks/usePasskeyLogin';
import { usePasskeyActions } from './hooks/usePasskeyActions';
import type {
  PasskeyContextType,
  PasskeyContextProviderProps
} from './types';

const PasskeyContext = createContext<PasskeyContextType | undefined>(undefined);

export const PasskeyContextProvider: React.FC<PasskeyContextProviderProps> = ({ children }) => {
  // State management
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [nearPublicKey, setNearPublicKey] = useState<string | null>(null);
  const [nearAccountId, setNearAccountId] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentGreeting, setCurrentGreeting] = useState<string | null>(null);

  // Use the extracted optimistic auth hook, passing current user for proper persistence
  const { optimisticAuth, setOptimisticAuth } = useOptimisticAuth({
    currentUser: nearAccountId
  });

  // Utility function
  const setUsernameState = (name: string) => {
    setUsername(name);
  };

  // Current user management (moved from SettingsContext)
  const setCurrentUser = (nearAccountId: string | null) => {
    // This is now managed internally - nearAccountId is the source of truth
    // The useOptimisticAuth hook will react to changes in nearAccountId
  };

  // Custom hooks
  const { fetchCurrentGreeting } = useGreetingService(setCurrentGreeting, setIsProcessing);

  const { registerPasskey } = usePasskeyRegistration(
    isProcessing,
    setIsProcessing,
    setIsLoggedIn,
    setUsername,
    setNearAccountId,
    setNearPublicKey,
    optimisticAuth
  );

  const { loginPasskey } = usePasskeyLogin(
    username,
    optimisticAuth,
    setIsProcessing,
    setIsLoggedIn,
    setUsername,
    setNearAccountId,
    setNearPublicKey,
  );

  const { executeDirectActionViaWorker } = usePasskeyActions(
    isLoggedIn,
    username,
    nearAccountId,
    optimisticAuth,
    setIsProcessing,
    fetchCurrentGreeting
  );

  // Logout function
  const logoutPasskey = () => {
    setIsLoggedIn(false);
    setUsername(null);
    setNearPublicKey(null);
    setCurrentGreeting(null);
    setNearAccountId(null);
  };

  // Load user data on mount
  useEffect(() => {
    const loadUserData = async () => {
      try {
        // Get the last user from IndexDBManager
        const lastUser = await indexDBManager.getLastUser();
        if (lastUser) {
          setUsername(lastUser.username);
          setNearAccountId(lastUser.nearAccountId);

          // Update last login time
          await indexDBManager.updateLastLogin(lastUser.nearAccountId);

          // Load the client-managed NEAR public key from WebAuthnManager
          try {
            const webAuthnUserData = await webAuthnManager.getUserData(lastUser.username);
            if (webAuthnUserData?.clientNearPublicKey) {
              setNearPublicKey(webAuthnUserData.clientNearPublicKey);
              console.log('Loaded client-managed NEAR public key from WebAuthnManager:', webAuthnUserData.clientNearPublicKey);
            } else {
              console.log('No client-managed NEAR public key found in WebAuthnManager for:', lastUser.username);
              setNearPublicKey(null);
            }
          } catch (webAuthnDataError) {
            console.warn('Failed to load WebAuthn user data, setting nearPublicKey to null:', webAuthnDataError);
            setNearPublicKey(null);
          }

          console.log('Loaded user data from IndexDBManager:', {
            username: lastUser.username,
            nearAccountId: lastUser.nearAccountId,
            registeredAt: new Date(lastUser.registeredAt).toISOString(),
          });
        } else {
          console.log('No previous user found in IndexDBManager');
        }
      } catch (error) {
        console.error('Error loading user data from IndexDBManager:', error);
      }
    };

    loadUserData();
  }, []);

  // Fetch greeting when logged in
  useEffect(() => {
    if (isLoggedIn && !isProcessing) {
      // Only fetch if not already processing to prevent race conditions
      fetchCurrentGreeting();
    }
  }, [isLoggedIn]); // Removed fetchCurrentGreeting from deps - only trigger when login status changes

  const value: PasskeyContextType = {
    isLoggedIn,
    username,
    nearPublicKey,
    nearAccountId,
    isProcessing,
    currentGreeting,
    setUsernameState,
    registerPasskey,
    loginPasskey,
    logoutPasskey,
    executeDirectActionViaWorker,
    fetchCurrentGreeting,
    optimisticAuth,
    setOptimisticAuth,
  };

  return <PasskeyContext.Provider value={value}>{children}</PasskeyContext.Provider>;
};

export const usePasskeyContext = () => {
  const context = useContext(PasskeyContext);
  if (context === undefined) {
    throw new Error('usePasskeyContext must be used within a PasskeyContextProvider');
  }
  return context;
};

// Re-export types for convenience
export type {
  PasskeyContextType,
  ExecuteActionCallbacks,
  RegistrationResult,
  LoginResult,
  GreetingResult
} from './types';