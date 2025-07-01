'use strict';

var jsxRuntime = require('../node_modules/.pnpm/react@18.3.1/node_modules/react/jsx-runtime.js');
var require$$0 = require('react');
var index = require('../src/core/PasskeyManager/index.js');
var useNearRpcProvider = require('../hooks/useNearRpcProvider.js');
var useAccountInput = require('../hooks/useAccountInput.js');
var useRelayer = require('../hooks/useRelayer.js');

const PasskeyContext = require$$0.createContext(undefined);
const PasskeyProvider = ({ children, config: userConfig }) => {
    // Authentication state (actual login status)
    // Note: isLoggedIn is true ONLY when VRF worker has private key in memory (vrfActive = true)
    // This means the user can generate VRF challenges without additional TouchID prompts
    const [loginState, setLoginState] = require$$0.useState({
        isLoggedIn: false,
        nearAccountId: null,
        nearPublicKey: null,
    });
    // UI input state (separate from authentication state)
    const [accountInputState, setAccountInputState] = require$$0.useState({
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
    const { getNearRpcProvider } = useNearRpcProvider.useNearRpcProvider();
    // Initialize PasskeyManager with configuration
    const [passkeyManager] = require$$0.useState(() => {
        const defaultConfig = {
            nearNetwork: 'testnet',
            relayerAccount: 'web3-authn.testnet',
            contractId: 'web3-authn.testnet',
            nearRpcUrl: 'https://rpc.testnet.near.org'
        };
        const finalConfig = { ...defaultConfig, ...userConfig };
        console.log('PasskeyProvider config: ', finalConfig);
        return new index.PasskeyManager(finalConfig, getNearRpcProvider());
    });
    // Use relayer hook
    const relayerHook = useRelayer.useRelayer({
        initialValue: userConfig?.relayerOptions?.initialUseRelayer ?? false
    });
    // Use account input hook
    const accountInputHook = useAccountInput.useAccountInput({
        passkeyManager,
        relayerAccount: passkeyManager.configs.relayerAccount,
        useRelayer: relayerHook.useRelayer,
        currentNearAccountId: loginState.nearAccountId,
        isLoggedIn: loginState.isLoggedIn
    });
    // Sync account input hook state with account input state
    require$$0.useEffect(() => {
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
    const logout = require$$0.useCallback(async () => {
        try {
            // Clear VRF session when user logs out
            await passkeyManager.logoutAndClearVrfSession();
        }
        catch (error) {
            console.warn('VRF logout warning:', error);
        }
        setLoginState(prevState => ({
            ...prevState,
            isLoggedIn: false,
            nearAccountId: null,
            nearPublicKey: null,
        }));
    }, [passkeyManager]);
    const loginPasskey = async (nearAccountId, options) => {
        const result = await passkeyManager.loginPasskey(nearAccountId, {
            onEvent: async (event) => {
                if (event.phase === 'login-complete' && event.status === 'success') {
                    // Check VRF status to determine if user is truly logged in
                    const currentLoginState = await passkeyManager.getLoginState(nearAccountId);
                    const isVRFLoggedIn = currentLoginState.vrfActive;
                    setLoginState(prevState => ({
                        ...prevState,
                        isLoggedIn: isVRFLoggedIn, // Only logged in if VRF is active
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
        return result;
    };
    const registerPasskey = async (nearAccountId, options) => {
        const result = await passkeyManager.registerPasskey(nearAccountId, {
            onEvent: async (event) => {
                if (event.phase === 'registration-complete' && event.status === 'success') {
                    // Check VRF status to determine if user is truly logged in after registration
                    const currentLoginState = await passkeyManager.getLoginState(nearAccountId);
                    const isVRFLoggedIn = currentLoginState.vrfActive;
                    setLoginState(prevState => ({
                        ...prevState,
                        isLoggedIn: isVRFLoggedIn, // Only logged in if VRF is active
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
    };
    // Load user data on mount
    require$$0.useEffect(() => {
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
                        isLoggedIn: isVRFLoggedIn // Only logged in if VRF is active
                    }));
                    console.log('Loaded login state:', {
                        nearAccountId: loginState.nearAccountId,
                        publicKey: loginState.publicKey,
                        isLoggedIn: isVRFLoggedIn,
                        vrfActive: loginState.vrfActive,
                        hasUserData: !!loginState.userData
                    });
                }
                else {
                    console.log('No user data found');
                }
            }
            catch (error) {
                console.error('Error loading login state:', error);
            }
        };
        loadUserData();
    }, [passkeyManager]);
    const value = {
        // UI acccount name input state (form/input tracking)
        accountInputState,
        // Simple login/register functions
        logout,
        loginPasskey,
        registerPasskey,
        // Authentication state (actual state from contract/backend)
        getLoginState: (nearAccountId) => passkeyManager.getLoginState(nearAccountId),
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
    return jsxRuntime.jsxRuntimeExports.jsx(PasskeyContext.Provider, { value: value, children: children });
};
const usePasskeyContext = () => {
    const context = require$$0.useContext(PasskeyContext);
    if (context === undefined) {
        throw new Error('usePasskeyContext must be used within a PasskeyContextProvider');
    }
    return context;
};

exports.PasskeyProvider = PasskeyProvider;
exports.usePasskeyContext = usePasskeyContext;
//# sourceMappingURL=index.js.map
