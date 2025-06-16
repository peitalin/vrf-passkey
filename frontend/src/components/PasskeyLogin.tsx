import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { usePasskeyContext } from '@web3authn/passkey/react'
import { Toggle } from './Toggle'
import { GreetingMenu } from './GreetingMenu'
import toast from 'react-hot-toast'
import type {
  RegistrationSSEEvent,
  LoginEvent
} from '@web3authn/passkey/react'

export function PasskeyLogin() {
  const {
    loginState: {
      isLoggedIn,
      nearPublicKey,
      nearAccountId
    },
    logout,
    loginPasskey,
    registerPasskey,
    optimisticAuth,
    setOptimisticAuth,
    passkeyManager,
  } = usePasskeyContext();

  const [localUsernameInput, setLocalUsernameInput] = useState('');
  const [isPasskeyRegisteredForLocalInput, setIsPasskeyRegisteredForLocalInput] = useState(false);
  const [domain, setDomain] = useState(() => optimisticAuth ? 'webauthn-contract.testnet' : 'testnet');
  const [isSecureContext] = useState(() => window.isSecureContext);

  // Store the full account ID from storage to preserve the correct domain
  const [storedAccountId, setStoredAccountId] = useState<string | null>(null);

  // Store account found by live search as user types
  const [liveSearchedAccount, setLiveSearchedAccount] = useState<string | null>(null);

  const usernameInputRef = useRef<HTMLInputElement>(null);
  const postfixRef = useRef<HTMLSpanElement>(null);

  const handleAuthModeToggle = useCallback((checked: boolean) => {
    setOptimisticAuth(checked);

    // Update domain for new accounts (when no stored account or username doesn't match stored account)
    const inputUsername = localUsernameInput.trim();
    if (!storedAccountId || (storedAccountId && storedAccountId.split('.')[0] !== inputUsername)) {
      const newDomain = checked ? 'webauthn-contract.testnet' : 'testnet';
      setDomain(newDomain);
    }
    // If stored account exists and username matches, keep the stored account's domain
  }, [setOptimisticAuth, localUsernameInput, storedAccountId]);

  const webAuthnManager = useMemo(() => passkeyManager.getWebAuthnManager(), [passkeyManager]);
  const accountName = useMemo(() => nearAccountId?.split('.')?.[0], [nearAccountId]);

  // Function to search for existing accounts by username
  const searchAccountsByUsername = useCallback(async (username: string): Promise<string | null> => {
    if (!username.trim()) return null;

    try {
      // Access IndexDBManager through the existing webAuthnManager/passkeyManager
      // Since we already have access to the manager instances, we can get all users
      const allUsersData = await webAuthnManager.getAllUserData();

      // Find account that matches the username
      const matchingUser = allUsersData.find(user => {
        const userUsername = user.nearAccountId.split('.')[0];
        return userUsername.toLowerCase() === username.toLowerCase();
      });

      return matchingUser ? matchingUser.nearAccountId : null;
    } catch (error) {
      console.warn('Error searching for accounts by username:', error);
      return null;
    }
  }, [webAuthnManager]);

  // Dynamic postfix based on live searched account, stored account, or current domain
  const dynamicPostfix = useMemo(() => {
    const inputUsername = localUsernameInput.trim();

    // Priority 1: Live searched account (as user types)
    if (liveSearchedAccount && inputUsername && liveSearchedAccount.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) {
      const domain = liveSearchedAccount.split('.').slice(1).join('.');
      return `.${domain}`;
    }

    // Priority 2: Stored account from initial load
    if (storedAccountId && inputUsername && storedAccountId.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) {
      const domain = storedAccountId.split('.').slice(1).join('.');
      return `.${domain}`;
    }

    // Priority 3: Fall back to current domain for new accounts
    return `.${domain}`;
  }, [liveSearchedAccount, storedAccountId, domain, localUsernameInput]);

  // Check if we're showing an existing account domain (either live searched or stored)
  const isUsingExistingAccountDomain = useMemo(() => {
    const inputUsername = localUsernameInput.trim();
    return (liveSearchedAccount && inputUsername && liveSearchedAccount.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) ||
           (storedAccountId && inputUsername && storedAccountId.split('.')[0].toLowerCase() === inputUsername.toLowerCase());
  }, [liveSearchedAccount, storedAccountId, localUsernameInput]);

  // Only auto-populate when input is empty when nearAccountId first loads
  useEffect(() => {
    const loadUserData = async () => {
      if (accountName && nearAccountId) {
        // User is logged in, show their username and preserve their account ID
        setLocalUsernameInput(accountName);
        setStoredAccountId(nearAccountId);

        // Extract and set the correct domain from the logged-in account
        const accountDomain = nearAccountId.split('.').slice(1).join('.');
        setDomain(accountDomain);

        const hasCredential = await webAuthnManager.hasPasskeyCredential(nearAccountId);
        setIsPasskeyRegisteredForLocalInput(hasCredential);
      } else {
        // No logged-in user, try to show last used username and preserve domain
        const prevAccountId = await webAuthnManager.getLastUsedNearAccountId();
        if (prevAccountId) {
          // Extract username and preserve full account ID
          const username = prevAccountId.split('.')[0];
          setLocalUsernameInput(username);
          setStoredAccountId(prevAccountId);

          // Extract and set the correct domain from stored account
          const storedDomain = prevAccountId.split('.').slice(1).join('.');
          setDomain(storedDomain);

          const hasCredential = await webAuthnManager.hasPasskeyCredential(prevAccountId);
          setIsPasskeyRegisteredForLocalInput(hasCredential);
        } else {
          // No stored account, clear stored account ID
          setStoredAccountId(null);
        }
      }
    };

    loadUserData();
  }, [accountName, nearAccountId, webAuthnManager]);

  // Update postfix position when username changes
  useEffect(() => {
    if (usernameInputRef.current && postfixRef.current) {
      const input = usernameInputRef.current;
      const postfix = postfixRef.current;

      if (localUsernameInput.length > 0) {
        // Show postfix and position it
        postfix.style.visibility = 'visible';

        // Create a temporary element to measure text width
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        if (context) {
          const computedStyle = window.getComputedStyle(input);
          context.font = `${computedStyle.fontWeight} ${computedStyle.fontSize} ${computedStyle.fontFamily}`;

          const textWidth = context.measureText(localUsernameInput).width;
          const inputPaddingLeft = parseFloat(computedStyle.paddingLeft) || 0;

          // Position postfix right after the text
          postfix.style.left = `${inputPaddingLeft + textWidth + 2}px`; // +2px for small gap
        }
      } else {
        // Hide postfix when no text
        postfix.style.visibility = 'hidden';
      }
    }
  }, [localUsernameInput]);

  const handleLocalUsernameChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const newUsername = e.target.value;
    setLocalUsernameInput(newUsername);

    if (newUsername.trim()) {
      // Search for existing accounts with this username
      const foundAccount = await searchAccountsByUsername(newUsername.trim());
      setLiveSearchedAccount(foundAccount);

      // Determine which account to check credentials for
      let accountToCheck: string;
      if (foundAccount) {
        // Found existing account, use it
        accountToCheck = foundAccount;
      } else if (storedAccountId && storedAccountId.split('.')[0].toLowerCase() === newUsername.trim().toLowerCase()) {
        // Username matches stored account but wasn't found in search (shouldn't happen)
        accountToCheck = storedAccountId;
      } else {
        // No existing account, construct new account ID with current domain
        accountToCheck = `${newUsername.trim()}.${domain}`;
      }

      // Check credentials for the determined account
      const hasCredential = await webAuthnManager.hasPasskeyCredential(accountToCheck);
      setIsPasskeyRegisteredForLocalInput(hasCredential);

      // Clear stored account ID if username doesn't match it
      if (storedAccountId && storedAccountId.split('.')[0].toLowerCase() !== newUsername.trim().toLowerCase()) {
        setStoredAccountId(null);
      }
    } else {
      // Empty username - clear everything
      setIsPasskeyRegisteredForLocalInput(false);
      setLiveSearchedAccount(null);
      setStoredAccountId(null);
    }
  };

  const onRegister = async () => {
    if (!localUsernameInput.trim()) {
      return;
    }

    const inputUsername = localUsernameInput.trim();

    // For registration, check if username matches any existing account
    // Priority: live searched account > stored account > new account
    let newAccountId: string;
    if (liveSearchedAccount && liveSearchedAccount.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) {
      // Username matches live searched account - this should not happen since register button
      // should be disabled, but handle gracefully
      newAccountId = liveSearchedAccount;
      console.log('Attempting to re-register live searched account:', newAccountId);
    } else if (storedAccountId && storedAccountId.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) {
      // Username matches stored account - this should not happen since register button
      // should be disabled, but handle gracefully
      newAccountId = storedAccountId;
      console.log('Attempting to re-register stored account:', newAccountId);
    } else {
      // New registration with current domain
      newAccountId = `${inputUsername}.${domain}`;
      console.log('Registering new account:', newAccountId);
    }

    console.log('newAccountId', newAccountId);
    try {
      const result = await registerPasskey(newAccountId, {
        optimisticAuth,
        onEvent: (event: RegistrationSSEEvent) => {
          switch (event.phase) {
            case 'webauthn-verification':
              if (event.status === 'progress') {
                toast.loading('Starting registration...', { id: 'registration' });
              }
              break;
            case 'user-ready':
              if (event.status === 'success') {
                toast.success(`Welcome ${event.nearAccountId}! Registration complete!`, { id: 'registration' });
              }
              break;
            case 'registration-complete':
              if (event.status === 'success') {
                toast.success('Registration completed successfully!', { id: 'registration' });
              }
              break;
            case 'registration-error':
              toast.error(event.error || 'Registration failed', { id: 'registration' });
              break;
            default:
              if (event.status === 'progress') {
                toast.loading(event.message || 'Processing...', { id: 'registration' });
              }
          }
        },
      });

      if (result.success) {
        // Registration successful - update stored account ID and live search
        if (result.nearAccountId) {
          setStoredAccountId(result.nearAccountId);
          setLiveSearchedAccount(result.nearAccountId);
          // Update domain to match the registered account
          const registeredDomain = result.nearAccountId.split('.').slice(1).join('.');
          setDomain(registeredDomain);
        }
      }
    } catch (error: any) {
      console.error('Registration error:', error);
    }
  };

  const onLogin = async () => {
    const inputUsername = localUsernameInput.trim();

    // Determine which account ID to use with priority order:
    // 1. Live searched account (from typing search)
    // 2. Stored account (from initial load)
    // 3. Constructed account ID (for new accounts)
    let accountId: string;

    if (liveSearchedAccount && liveSearchedAccount.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) {
      accountId = liveSearchedAccount;
      console.log('Using live searched account ID:', accountId);
    } else if (storedAccountId && storedAccountId.split('.')[0].toLowerCase() === inputUsername.toLowerCase()) {
      accountId = storedAccountId;
      console.log('Using stored account ID:', accountId);
    } else {
      // Username was changed or no existing account, construct new account ID
      accountId = `${inputUsername}.${domain}`;
      console.log('Constructing new account ID:', accountId);
    }

    console.log('login with accountId', accountId);
    const result = await loginPasskey(accountId, {
      optimisticAuth,
      onEvent: (event: LoginEvent) => {
        switch (event.type) {
          case 'loginStarted':
            toast.loading(`Logging in ${event.data.nearAccountId ? ' as ' + event.data.nearAccountId : ''}...`, { id: 'login' });
            break;
          case 'loginProgress':
            toast.loading(event.data.message, { id: 'login' });
            break;
          case 'loginCompleted':
            toast.success(`Logged in as ${event.data.nearAccountId}!`, { id: 'login' });
            break;
          case 'loginFailed':
            toast.error(event.data.error, { id: 'login' });
            break;
        }
      }
    });

    if (result.success) {
      // Login successful
    }
  };

  if (!isSecureContext) {
    return (
      <div className="passkey-container">
        <h3>Passkey Authentication</h3>
        <div className="security-warning">
          <p>⚠️ Warning: Passkey operations require a secure context (HTTPS or localhost).</p>
          <p>Please ensure your development server is running on HTTPS or access via localhost.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="passkey-container-root">
      <div className="passkey-container">
        {!isLoggedIn ? (
          <>
            <h2>Passkey Login</h2>
            <p className="caption">Authenticate onchain with Passkeys</p>
          </>
        ) : (
          <>
            <h2>Welcome, {accountName}</h2>
            <p className="caption">Send NEAR transactions with Passkeys</p>
          </>
        )}
        {!isLoggedIn ? (
          <>
            <div className="input-wrapper">
              <div className="username-input-container">
                <input
                  ref={usernameInputRef}
                  type="text"
                  value={localUsernameInput}
                  onChange={handleLocalUsernameChange}
                  placeholder="Enter username for passkey"
                  className="styled-input username-input"
                />
                <span
                  ref={postfixRef}
                  className={`account-postfix ${isUsingExistingAccountDomain ? 'stored-account' : ''}`}
                  title={isUsingExistingAccountDomain ? 'Using existing account domain' : 'New account domain'}
                >
                  {dynamicPostfix}
                  {isUsingExistingAccountDomain && <span className="stored-indicator">●</span>}
                </span>
              </div>
              {isPasskeyRegisteredForLocalInput && localUsernameInput && (
                <div className="account-exists-badge">
                  account exists
                </div>
              )}
            </div>

            <Toggle
              checked={optimisticAuth}
              onChange={handleAuthModeToggle}
              label={optimisticAuth ? 'Fast Signing' : 'Contract Signing'}
              tooltip={optimisticAuth
                ? 'Fast transaction signing with optimistic response'
                : 'Contract signed Passkey authentication (slower)'
              }
              className="auth-mode-toggle"
              size="small"
              textPosition="left"
            />

            <div className="auth-buttons">
              <button onClick={onRegister}
                className={`action-button ${!isPasskeyRegisteredForLocalInput ? 'primary' : ''}`}
                disabled={!localUsernameInput || !isSecureContext || isPasskeyRegisteredForLocalInput}>
                Register Passkey
              </button>
              <button onClick={onLogin}
                className={`action-button ${isPasskeyRegisteredForLocalInput ? 'primary' : ''}`}
                disabled={!localUsernameInput || !isPasskeyRegisteredForLocalInput}
              >
                Login with Passkey
              </button>
            </div>
          </>
        ) : (
          <>
            {nearPublicKey ? (
              <GreetingMenu />
            ) : (
              <div className="info-box">
                <p>✅ Passkey registered successfully!</p>
                <p>Server-derived NEAR public key not available for greeting functionality.</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}