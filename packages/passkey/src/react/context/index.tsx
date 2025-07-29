import {
  createContext,
  useState,
  useContext,
  useEffect,
  useCallback,
  useMemo,
} from 'react';
import { PasskeyManager, AccountRecoveryFlow } from '../../core/PasskeyManager';
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
  ActionOptions,
  StartDeviceLinkingOptionsDevice2,
  ScanAndLinkDeviceOptionsDevice1,
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
      relayerAccount: 'web3-authn-v2.testnet',
      contractId: 'web3-authn-v2.testnet',
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
      console.debug('PasskeyProvider: Reusing existing PasskeyManager instance');
    }

    return globalPasskeyManager;
  }, [userConfig]);

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
      ...options,
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
      ...options,
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

  const recoverAccountWithAccountId = async (
    accountId: string,
    options?: ActionOptions,
    reuseCredential?: PublicKeyCredential
  ) => {
    const result = await passkeyManager.recoverAccountWithAccountId(accountId, options, reuseCredential);

    // Update login state if recovery was successful and includes login state
    if (result.success && result.loginState) {
      setLoginState(prevState => ({
        ...prevState,
        isLoggedIn: result.loginState!.isLoggedIn,
        nearAccountId: accountId,
        nearPublicKey: result.publicKey || null,
      }));

      console.log('Recovery completed - Login state updated:', {
        accountId,
        isLoggedIn: result.loginState.isLoggedIn,
        vrfActive: result.loginState.vrfActive,
        publicKey: result.publicKey
      });
    }

    return result;
  }

  const startAccountRecoveryFlow = (options?: ActionOptions): AccountRecoveryFlow => {
    return passkeyManager.startAccountRecoveryFlow(options);
  }

  /**
   * Device2: Start device linking flow
   * @param options - DeviceLinkingOptionsDevice2
   * @returns LinkDeviceFlow
   */
  const startDeviceLinkingFlow = (options?: StartDeviceLinkingOptionsDevice2) => {
    return passkeyManager.startDeviceLinkingFlow({
      ...options,
      onEvent: (event) => {
        // Call original event handler
        options?.onEvent?.(event);

        console.log('Device linking event received:', { phase: event.phase, status: event.status, message: event.message });

        // Update React state when auto-login completes successfully
        if (event.phase === 'device-linking' && event.status === 'success') {
          console.log('Device linking auto-login completed - refreshing login state...');
          // Refresh login state to update React context after successful auto-login
          refreshLoginState()
        }
      }
    });
  }

  /**
   * Device1: Scan QR code and execute AddKey transaction
   * @param options - DeviceLinkingOptionsDevice1
   * @returns LinkDeviceResult
   */
  const scanAndLinkDevice = async (options: ScanAndLinkDeviceOptionsDevice1) => {
    return await passkeyManager.scanAndLinkDevice(options);
  }

  // Function to manually refresh login state
    const refreshLoginState = useCallback(async (nearAccountId?: string) => {
      try {
      const loginState = await passkeyManager.getLoginState(nearAccountId);

        if (loginState.nearAccountId) {
          // User is only logged in if VRF worker has private key in memory
          const isVRFLoggedIn = loginState.vrfActive;

          setLoginState(prevState => ({
            ...prevState,
            nearAccountId: loginState.nearAccountId,
            nearPublicKey: loginState.publicKey,
            isLoggedIn: isVRFLoggedIn  // Only logged in if VRF is active
          }));

        console.log('Refreshed login state:', {
            nearAccountId: loginState.nearAccountId,
            publicKey: loginState.publicKey,
            isLoggedIn: isVRFLoggedIn,
            vrfActive: loginState.vrfActive,
            hasUserData: !!loginState.userData
          });
        }
      } catch (error) {
      console.error('Error refreshing login state:', error);
      }
  }, [passkeyManager]);

  // Load user data on mount
  useEffect(() => {
    refreshLoginState();
  }, [refreshLoginState]);

  const value: PasskeyContextType = {
    // UI acccount name input state (form/input tracking)
    accountInputState,
    // Account input management
    setInputUsername: accountInputHook.setInputUsername,
    refreshAccountData: accountInputHook.refreshAccountData,
    useRelayer: relayerHook.useRelayer,
    setUseRelayer: relayerHook.setUseRelayer,
    toggleRelayer: relayerHook.toggleRelayer,

    // Simple login/register functions
    logout,                      // Clears VRF session (logs out)
    loginPasskey,
    registerPasskey,

    // Account recovery functions
    recoverAccountWithAccountId, // Recover account with accountID and TouchId
    startAccountRecoveryFlow,    // Create account recovery flow to discover accounts onchain, and recover accounts
    startDeviceLinkingFlow,     // Create device linking flow for Whatsapp-style QR scan + device linking
    scanAndLinkDevice,           // Scan QR and link device (Device1 side)

    // Authentication state (actual state from contract/backend)
    getLoginState: (nearAccountId?: string) => passkeyManager.getLoginState(nearAccountId),
    refreshLoginState,           // Manually refresh login state
    loginState,

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