import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { indexDBManager } from '../../core/IndexDBManager';
import { PasskeyManager } from '../../core/PasskeyManager';
import { useOptimisticAuth } from '../hooks/useOptimisticAuth';
import { useNearRpcProvider } from '../hooks/useNearRpcProvider';
import type {
  PasskeyContextType,
  PasskeyContextProviderProps,
  LoginState,
  RegistrationResult,
  LoginOptions,
  LoginResult,
  RegistrationOptions,
  ExecuteActionCallbacks
} from '../types';

const PasskeyContext = createContext<PasskeyContextType | undefined>(undefined);

export const PasskeyProvider: React.FC<PasskeyContextProviderProps> = ({
  children,
  config: userConfig
}) => {

  const [loginState, setLoginState] = useState<LoginState>({
    isLoggedIn: false,
    username: null,
    nearAccountId: null,
    nearPublicKey: null,
  });

  // Get NEAR RPC provider
  const { getNearRpcProvider } = useNearRpcProvider();

  // Initialize PasskeyManager with configuration
  const [passkeyManager] = useState(() => {
    const defaultConfig = {
      serverUrl: 'http://localhost:3001', // Default for development
      nearNetwork: 'testnet' as const,
      relayerAccount: 'webauthn-contract.testnet',
      optimisticAuth: true,
    };

    const finalConfig = { ...defaultConfig, ...userConfig };
    return new PasskeyManager(finalConfig, getNearRpcProvider());
  });

  // Use optimistic auth hook
  const { optimisticAuth, setOptimisticAuth } = useOptimisticAuth({
    currentUser: loginState.nearAccountId
  });

  // Simple logout that only manages React state
  const logout = useCallback(() => {
    setLoginState({
      isLoggedIn: false,
      username: null,
      nearAccountId: null,
      nearPublicKey: null,
    });
  }, [loginState]);

  const loginPasskey = async (username: string, options: LoginOptions) => {
    const result: LoginResult = await passkeyManager.loginPasskey(username, {
      optimisticAuth: optimisticAuth,
      onEvent: (event) => {
        if (event.type === 'loginCompleted') {
          setLoginState({
            isLoggedIn: true,
            username: event.data.username,
            nearAccountId: event.data.nearAccountId || null,
            nearPublicKey: event.data.publicKey || null,
          });
        }
        options.onEvent?.(event);
      },
      onError: (error) => {
        logout();
        options.onError?.(error);
      }
    });

    return result
  }

  const registerPasskey = async (username: string, options: RegistrationOptions) => {
    const result: RegistrationResult = await passkeyManager.registerPasskey(username, {
      optimisticAuth: optimisticAuth,
      onEvent: (event) => {
        if (event.phase === 'user-ready') {
          setLoginState({
            isLoggedIn: true,
            username: event.username,
            nearAccountId: event.nearAccountId || null,
            nearPublicKey: event.clientNearPublicKey || null,
          });
        }
        options.onEvent?.(event);
      },
      onError: (error) => {
        logout();
        options.onError?.(error);
      }
    });

    return result;
  }

  // Load user data on mount
  useEffect(() => {
    const loadUserData = async () => {
      try {
        const lastUser = await indexDBManager.getLastUser();
        if (lastUser) {
          setLoginState({
            ...loginState,
            username: lastUser.username,
            nearAccountId: lastUser.nearAccountId,
          });
          await indexDBManager.updateLastLogin(lastUser.nearAccountId);

          // Load client-managed NEAR public key
          try {
            const webAuthnManager = passkeyManager.getWebAuthnManager();
            const webAuthnUserData = await webAuthnManager.getUserData(lastUser.username);
            if (webAuthnUserData?.clientNearPublicKey) {
              setLoginState({
                ...loginState,
                nearPublicKey: webAuthnUserData.clientNearPublicKey,
              });
              console.log('Loaded client-managed NEAR public key:', webAuthnUserData.clientNearPublicKey);
            } else {
              console.log('No client-managed NEAR public key found for:', lastUser.username);
              setLoginState({ ...loginState, nearPublicKey: null });
            }
          } catch (webAuthnDataError) {
            console.warn('Failed to load WebAuthn user data:', webAuthnDataError);
            setLoginState({ ...loginState, nearPublicKey: null });
          }
          // console.log('Loaded user data:', {
          //   username: lastUser.username,
          //   nearAccountId: lastUser.nearAccountId,
          //   registeredAt: new Date(lastUser.registeredAt).toISOString(),
          // });
        }
      } catch (error) {
        console.error('Error loading user data:', error);
      }
    };

    loadUserData();
  }, [passkeyManager]);

  const value: PasskeyContextType = {
    // State
    loginState,
    // Simple utility functions
    logout,
    loginPasskey,
    registerPasskey,
    // Settings
    optimisticAuth,
    setOptimisticAuth,
    // Core PasskeyManager instance - provides ALL functionality
    passkeyManager,
    // Legacy compatibility
    webAuthnManager: passkeyManager.getWebAuthnManager(),
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
} from '../types';