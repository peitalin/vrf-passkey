import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { indexDBManager } from '../../core/IndexDBManager';
import { PasskeyManager } from '../../core/PasskeyManager';
import { useOptimisticAuth } from '../hooks/useOptimisticAuth';
import { useNearRpcProvider } from '../hooks/useNearRpcProvider';
import { useAccountInput } from '../hooks/useAccountInput';
import type {
  PasskeyContextType,
  PasskeyContextProviderProps,
  LoginState,
  AccountInputState,
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

  // Authentication state (actual login status)
  const [loginState, setLoginState] = useState<LoginState>({
    isLoggedIn: false,
    nearAccountId: null,
    nearPublicKey: null,
  });

  // UI input state (separate from authentication state)
  const [accountInputState, setAccountInputState] = useState<AccountInputState>({
    inputUsername: '',
    lastLoggedInUsername: '',
    lastLoggedInDomain: '',
    targetAccountId: '',
    displayPostfix: '',
    isUsingExistingAccount: false,
    accountExists: false,
    indexDBAccounts: []
  });

  // Get NEAR RPC provider
  const { getNearRpcProvider } = useNearRpcProvider();

  // Store the initial optimisticAuth value from config
  const [initialOptimisticAuth] = useState(() => userConfig?.optimisticAuth ?? false);

  // Initialize PasskeyManager with configuration
  const [passkeyManager] = useState(() => {
    const defaultConfig = {
      nearNetwork: 'testnet' as const,
      relayerAccount: 'webauthn-contract.testnet',
    };

    // Only add serverUrl if explicitly provided
    const finalConfig = { ...defaultConfig, ...userConfig };

    // If no serverUrl is provided, enable serverless mode by omitting it
    console.log('PasskeyProvider config: ', finalConfig);

    return new PasskeyManager(finalConfig, getNearRpcProvider());
  });

  // Use optimistic auth hook
  const { optimisticAuth, setOptimisticAuth } = useOptimisticAuth({
    currentUser: loginState.nearAccountId,
    initialValue: initialOptimisticAuth
  });

  // Use account input hook
  const accountInputHook = useAccountInput({
    passkeyManager,
    relayerAccount: passkeyManager.getConfig().relayerAccount,
    optimisticAuth,
    currentNearAccountId: loginState.nearAccountId,
    isLoggedIn: loginState.isLoggedIn
  });

  // Sync account input hook state with account input state
  useEffect(() => {
    setAccountInputState({
      inputUsername: accountInputHook.inputUsername,
      lastLoggedInUsername: accountInputHook.lastLoggedInUsername,
      lastLoggedInDomain: accountInputHook.lastLoggedInDomain,
      targetAccountId: accountInputHook.targetAccountId,
      displayPostfix: accountInputHook.displayPostfix,
      isUsingExistingAccount: accountInputHook.isUsingExistingAccount,
      accountExists: accountInputHook.accountExists,
      indexDBAccounts: accountInputHook.indexDBAccounts
    });
  }, [
    accountInputHook.inputUsername,
    accountInputHook.lastLoggedInUsername,
    accountInputHook.lastLoggedInDomain,
    accountInputHook.targetAccountId,
    accountInputHook.displayPostfix,
    accountInputHook.isUsingExistingAccount,
    accountInputHook.accountExists,
    accountInputHook.indexDBAccounts
  ]);

  // Simple logout that only manages React state
  const logout = useCallback(() => {
    setLoginState(prevState => ({
      ...prevState,
      isLoggedIn: false,
      nearAccountId: null,
      nearPublicKey: null,
    }));
  }, []);

  const loginPasskey = async (nearAccountId: string, options: LoginOptions) => {
    const result: LoginResult = await passkeyManager.loginPasskey(nearAccountId, {
      optimisticAuth: optimisticAuth,
      onEvent: (event) => {
        if (event.type === 'loginCompleted') {
          setLoginState(prevState => ({
            ...prevState,
            isLoggedIn: true,
            nearAccountId: event.data.nearAccountId || null,
            nearPublicKey: event.data.publicKey || null,
          }));
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

  const registerPasskey = async (nearAccountId: string, options: RegistrationOptions) => {
    const result: RegistrationResult = await passkeyManager.registerPasskey(nearAccountId, {
      optimisticAuth: optimisticAuth,
      onEvent: (event) => {
        if (event.phase === 'user-ready') {
          setLoginState(prevState => ({
            ...prevState,
            isLoggedIn: true,
            nearAccountId: event.nearAccountId || null,
            nearPublicKey: event.clientNearPublicKey || null,
          }));
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
          setLoginState(prevState => ({
            ...prevState,
            nearAccountId: lastUser.nearAccountId,
          }));
          await indexDBManager.updateLastLogin(lastUser.nearAccountId);

          // Load client-managed NEAR public key
          try {
            const webAuthnManager = passkeyManager.getWebAuthnManager();
            const webAuthnUserData = await webAuthnManager.getUserData(lastUser.nearAccountId);
            if (webAuthnUserData?.clientNearPublicKey) {
              setLoginState(prevState => ({
                ...prevState,
                nearPublicKey: webAuthnUserData.clientNearPublicKey || null,
              }));
              console.log('Loaded client-managed NEAR public key:', webAuthnUserData.clientNearPublicKey);
            } else {
              console.log('No client-managed NEAR public key found for:', lastUser.nearAccountId);
              setLoginState(prevState => ({ ...prevState, nearPublicKey: null }));
            }
          } catch (webAuthnDataError) {
            console.warn('Failed to load WebAuthn user data:', webAuthnDataError);
            setLoginState(prevState => ({ ...prevState, nearPublicKey: null }));
          }
        }
      } catch (error) {
        console.error('Error loading user data:', error);
      }
    };

    loadUserData();
  }, [passkeyManager]);

  const value: PasskeyContextType = {
    // Authentication state (actual state from contract/backend)
    loginState,
    // UI input state (form/input tracking)
    accountInputState,
    // Simple utility functions
    logout,
    loginPasskey,
    registerPasskey,
    // Settings
    optimisticAuth,
    setOptimisticAuth,
    // Account input management
    setInputUsername: accountInputHook.setInputUsername,
    refreshAccountData: accountInputHook.refreshAccountData,
    // Core PasskeyManager instance - provides ALL functionality
    passkeyManager,
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