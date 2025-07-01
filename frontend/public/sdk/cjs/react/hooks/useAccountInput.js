'use strict';

var require$$0 = require('react');

function useAccountInput({ passkeyManager, relayerAccount, useRelayer, currentNearAccountId, isLoggedIn }) {
    const [state, setState] = require$$0.useState({
        inputUsername: '',
        lastLoggedInUsername: '',
        lastLoggedInDomain: '',
        targetAccountId: '',
        displayPostfix: '',
        isUsingExistingAccount: false,
        accountExists: false,
        indexDBAccounts: []
    });
    // Load IndexDB accounts and determine account info
    const refreshAccountData = require$$0.useCallback(async () => {
        try {
            const { accountIds, lastUsedAccountId } = await passkeyManager.getRecentLogins();
            let lastUsername = '';
            let lastDomain = '';
            if (lastUsedAccountId) {
                const parts = lastUsedAccountId.split('.');
                lastUsername = parts[0];
                lastDomain = `.${parts.slice(1).join('.')}`;
            }
            setState(prevState => ({
                ...prevState,
                indexDBAccounts: accountIds,
                lastLoggedInUsername: lastUsername,
                lastLoggedInDomain: lastDomain
            }));
        }
        catch (error) {
            console.warn('Error loading account data:', error);
        }
    }, [passkeyManager]);
    // Update derived state when inputs change
    const updateDerivedState = require$$0.useCallback((username, accounts) => {
        if (!username.trim()) {
            setState(prevState => ({
                ...prevState,
                targetAccountId: '',
                displayPostfix: '',
                isUsingExistingAccount: false,
                accountExists: false
            }));
            return;
        }
        // Check if username matches any existing account in IndexDB
        const existingAccount = accounts.find(accountId => accountId.split('.')[0].toLowerCase() === username.toLowerCase());
        let targetAccountId;
        let displayPostfix;
        let isUsingExistingAccount;
        if (existingAccount) {
            // Use existing account's full ID
            targetAccountId = existingAccount;
            const parts = existingAccount.split('.');
            displayPostfix = `.${parts.slice(1).join('.')}`;
            isUsingExistingAccount = true;
        }
        else {
            // New account: use relayer or testnet based on useRelayer setting
            const postfix = useRelayer ? relayerAccount : 'testnet';
            targetAccountId = `${username}.${postfix}`;
            displayPostfix = `.${postfix}`;
            isUsingExistingAccount = false;
        }
        setState(prevState => ({
            ...prevState,
            targetAccountId,
            displayPostfix,
            isUsingExistingAccount
        }));
        // Check if account has credentials
        checkAccountExists(targetAccountId);
    }, [useRelayer, relayerAccount, passkeyManager]);
    // Check if account has passkey credentials
    const checkAccountExists = require$$0.useCallback(async (accountId) => {
        if (!accountId) {
            setState(prevState => ({ ...prevState, accountExists: false }));
            return;
        }
        try {
            const hasCredential = await passkeyManager.hasPasskeyCredential(accountId);
            setState(prevState => ({ ...prevState, accountExists: hasCredential }));
        }
        catch (error) {
            console.warn('Error checking credentials:', error);
            setState(prevState => ({ ...prevState, accountExists: false }));
        }
    }, [passkeyManager]);
    // Handle username input changes
    const setInputUsername = require$$0.useCallback((username) => {
        setState(prevState => ({ ...prevState, inputUsername: username }));
        updateDerivedState(username, state.indexDBAccounts);
    }, [state.indexDBAccounts, updateDerivedState]);
    // onInitialMount: Load last logged in user and prefill
    require$$0.useEffect(() => {
        const initializeAccountInput = async () => {
            await refreshAccountData();
            if (isLoggedIn && currentNearAccountId) {
                // User is logged in, show their username
                const username = currentNearAccountId.split('.')[0];
                setState(prevState => ({ ...prevState, inputUsername: username }));
            }
            else {
                // No logged-in user, try to get last used account
                const { lastUsedAccountId } = await passkeyManager.getRecentLogins();
                if (lastUsedAccountId) {
                    const username = lastUsedAccountId.split('.')[0];
                    setState(prevState => ({ ...prevState, inputUsername: username }));
                }
            }
        };
        initializeAccountInput();
    }, [passkeyManager, isLoggedIn, currentNearAccountId, passkeyManager]);
    // onLogout: Reset to last used account
    require$$0.useEffect(() => {
        const handleLogoutReset = async () => {
            // Only reset if user just logged out (isLoggedIn is false but we had a nearAccountId before)
            if (!isLoggedIn && !currentNearAccountId) {
                try {
                    const { lastUsedAccountId } = await passkeyManager.getRecentLogins();
                    if (lastUsedAccountId) {
                        const username = lastUsedAccountId.split('.')[0];
                        setState(prevState => ({ ...prevState, inputUsername: username }));
                    }
                }
                catch (error) {
                    console.warn('Error resetting username after logout:', error);
                }
            }
        };
        handleLogoutReset();
    }, [isLoggedIn, currentNearAccountId, passkeyManager]);
    // Update derived state when dependencies change
    require$$0.useEffect(() => {
        updateDerivedState(state.inputUsername, state.indexDBAccounts);
    }, [state.inputUsername, state.indexDBAccounts, updateDerivedState]);
    return {
        ...state,
        setInputUsername,
        refreshAccountData
    };
}

exports.useAccountInput = useAccountInput;
//# sourceMappingURL=useAccountInput.js.map
