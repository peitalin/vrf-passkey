import React, { createContext, useState, useContext, useEffect, useCallback, useMemo, useRef } from 'react';
import { PasskeyManager } from '../../core/PasskeyManager';
import { useNearClient } from '../hooks/useNearClient';
import { useAccountInput } from '../hooks/useAccountInput';
import { useRelayer } from '../hooks/useRelayer';
import type {
  PasskeyContextType,
  PasskeyContextProviderProps,
  LoginState,
  AccountInputState,
  RegistrationResult,
  LoginOptions,
  LoginResult,
  RegistrationOptions,
} from '../types';

const PasskeyContext = createContext<PasskeyContextType | undefined>(undefined);

// Global singleton to prevent multiple PasskeyManager instances in StrictMode
let globalPasskeyManager: PasskeyManager | null = null;
let globalConfig: any = null;

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

  // Get the minimal NEAR RPC provider
  const nearClient = useNearClient();

  // Initialize PasskeyManager with singleton pattern to prevent double initialization in StrictMode
  const passkeyManager = useMemo(() => {
    const defaultConfig = {
      nearNetwork: 'testnet' as const,
      relayerAccount: 'web3-authn.testnet',
      contractId: 'web3-authn.testnet',
      nearRpcUrl: 'https://rpc.testnet.near.org'
    };

    const finalConfig = { ...defaultConfig, ...userConfig };

    // Check if we already have a global instance with the same config
    const configChanged = JSON.stringify(globalConfig) !== JSON.stringify(finalConfig);

    if (!globalPasskeyManager || configChanged) {
      console.log('PasskeyProvider: Creating new PasskeyManager instance with config:', finalConfig);
      globalPasskeyManager = new PasskeyManager(finalConfig, nearClient);
      globalConfig = finalConfig;
    } else {
      console.log('PasskeyProvider: Reusing existing PasskeyManager instance');
    }

    return globalPasskeyManager;
  }, [userConfig, nearClient]);

  // Use relayer hook
  const relayerHook = useRelayer({
    initialValue: userConfig?.initialUseRelayer ?? false
  });

  // Use account input hook
  const accountInputHook = useAccountInput({
    passkeyManager,
    relayerAccount: passkeyManager.configs.relayerAccount,
    useRelayer: relayerHook.useRelayer,
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
      await passkeyManager.logoutAndClearVrfSession();
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
      onEvent: async (event) => {
        if (event.phase === 'login-complete' && event.status === 'success') {
          // Check VRF status to determine if user is truly logged in
          const currentLoginState = await passkeyManager.getLoginState(nearAccountId);
          const isVRFLoggedIn = currentLoginState.vrfActive;

          setLoginState(prevState => ({
            ...prevState,
            isLoggedIn: isVRFLoggedIn,  // Only logged in if VRF is active
            nearAccountId: event.nearAccountId || null,
            nearPublicKey: event.clientNearPublicKey || null,
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
    // Account input management
    setInputUsername: accountInputHook.setInputUsername,
    refreshAccountData: accountInputHook.refreshAccountData,
    // Relayer management
    useRelayer: relayerHook.useRelayer,
    setUseRelayer: relayerHook.setUseRelayer,
    toggleRelayer: relayerHook.toggleRelayer,
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