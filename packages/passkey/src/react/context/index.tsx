import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
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
  // Note: isLoggedIn is true ONLY when VRF worker has private key in memory (vrfActive = true)
  // This means the user can generate VRF challenges without additional TouchID prompts
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
      relayerAccount: 'web3-authn.testnet',
      contractId: 'web3-authn.testnet'
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
  const logout = useCallback(async () => {
    try {
      // Clear VRF session when user logs out
      await passkeyManager.getVRFManager().logout();
    } catch (error) {
      console.warn('VRF logout warning:', error);
    }

    setLoginState(prevState => ({
      ...prevState,
      isLoggedIn: false,
      nearAccountId: null,
      nearPublicKey: null,
    }));
  }, [passkeyManager]);

  const loginPasskey = async (nearAccountId: string, options: LoginOptions) => {
    const result: LoginResult = await passkeyManager.loginPasskey(nearAccountId, {
      optimisticAuth: optimisticAuth,
      onEvent: async (event) => {
        if (event.type === 'loginCompleted') {
          // Check VRF status to determine if user is truly logged in
          const currentLoginState = await passkeyManager.getLoginState(nearAccountId);
          const isVRFLoggedIn = currentLoginState.vrfActive;

          setLoginState(prevState => ({
            ...prevState,
            isLoggedIn: isVRFLoggedIn,  // Only logged in if VRF is active
            nearAccountId: event.data.nearAccountId || null,
            nearPublicKey: event.data.publicKey || null,
          }));

          console.log('Login completed - VRF status:', {
            vrfActive: currentLoginState.vrfActive,
            isLoggedIn: isVRFLoggedIn
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

  const registerPasskey = async (nearAccountId: string, options: RegistrationOptions) => {
    const result: RegistrationResult = await passkeyManager.registerPasskey(nearAccountId, {
      optimisticAuth: optimisticAuth,
      onEvent: async (event) => {
        if (event.phase === 'registration-complete' && event.status === 'success') {
          // Check VRF status to determine if user is truly logged in after registration
          const currentLoginState = await passkeyManager.getLoginState(nearAccountId);
          const isVRFLoggedIn = currentLoginState.vrfActive;

          setLoginState(prevState => ({
            ...prevState,
            isLoggedIn: isVRFLoggedIn,  // Only logged in if VRF is active
            nearAccountId: nearAccountId,
            nearPublicKey: currentLoginState.publicKey || null,
          }));

          console.log('Registration completed - VRF status:', {
            vrfActive: currentLoginState.vrfActive,
            isLoggedIn: isVRFLoggedIn,
            nearAccountId: nearAccountId,
            publicKey: currentLoginState.publicKey
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
        // Use the new consolidated getLoginState function
        const loginState = await passkeyManager.getLoginState();

        if (loginState.nearAccountId) {
          // User is only logged in if VRF worker has private key in memory
          const isVRFLoggedIn = loginState.vrfActive;

          setLoginState(prevState => ({
            ...prevState,
            nearAccountId: loginState.nearAccountId,
            nearPublicKey: loginState.publicKey,
            isLoggedIn: isVRFLoggedIn  // Only logged in if VRF is active
          }));

          console.log('Loaded login state:', {
            nearAccountId: loginState.nearAccountId,
            publicKey: loginState.publicKey,
            isLoggedIn: isVRFLoggedIn,
            vrfActive: loginState.vrfActive,
            hasUserData: !!loginState.userData
          });
        } else {
          console.log('No user data found');
        }
      } catch (error) {
        console.error('Error loading login state:', error);
      }
    };

    loadUserData();
  }, [passkeyManager]);

  const value: PasskeyContextType = {
    // UI acccount name input state (form/input tracking)
    accountInputState,
    // Simple login/register functions
    logout,
    loginPasskey,
    registerPasskey,
    // Authentication state (actual state from contract/backend)
    getLoginState: (nearAccountId?: string) => passkeyManager.getLoginState(nearAccountId),
    loginState,
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