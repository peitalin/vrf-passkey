import { useState, useEffect, useCallback, useRef } from 'react'
import { usePasskeyContext } from '@web3authn/passkey/react'
import { Toggle } from './Toggle'
import { GreetingMenu } from './GreetingMenu'
import toast from 'react-hot-toast'
import type {
  RegistrationSSEEvent,
  LoginEvent
} from '@web3authn/passkey/react'
import {
  NEAR_ACCOUNT_POSTFIX
} from '../config'

export function PasskeyLogin() {
  const {
    loginState: {
    isLoggedIn,
    username,
    nearPublicKey,
      nearAccountId
    },
    logout,
    loginPasskey,
    registerPasskey,
    optimisticAuth,
    setOptimisticAuth,
    webAuthnManager,
  } = usePasskeyContext();

  const [localUsernameInput, setLocalUsernameInput] = useState('');
  const [isPasskeyRegisteredForLocalInput, setIsPasskeyRegisteredForLocalInput] = useState(false);
  const [isSecureContext] = useState(() => window.isSecureContext);
  const [hasManuallyClearedInput, setHasManuallyClearedInput] = useState(false);
  const [isLoggedInOptimistic, setIsLoggedInOptimistic] = useState(false);

  const usernameInputRef = useRef<HTMLInputElement>(null);
  const postfixRef = useRef<HTMLSpanElement>(null);

  // Handle auth mode toggle without affecting username input
  const handleAuthModeToggle = useCallback((checked: boolean) => {
    // Preserve the current username input value
    const preservedUsername = localUsernameInput;

    // Update the auth mode
    setOptimisticAuth(checked);

    // Ensure username is preserved after state update
    if (preservedUsername && preservedUsername !== localUsernameInput) {
      // Use requestAnimationFrame to ensure state update happens after re-render
      requestAnimationFrame(() => {
        setLocalUsernameInput(preservedUsername);
      });
    }
  }, [localUsernameInput, setOptimisticAuth]);

  // Prevent username from being overwritten by useEffect when auth mode changes
  const authModeToggleRef = useRef(false);
  const handleAuthModeToggleWithRef = useCallback((checked: boolean) => {
    authModeToggleRef.current = true;
    handleAuthModeToggle(checked);
    // Reset the flag after a short delay
    setTimeout(() => {
      authModeToggleRef.current = false;
    }, 100);
  }, [handleAuthModeToggle]);

  useEffect(() => {
    const loadUserData = async () => {
      // Don't overwrite username if user is actively toggling auth mode
      if (hasManuallyClearedInput || authModeToggleRef.current) return;

      if (username) {
        setLocalUsernameInput(username);
        const hasCredential = await webAuthnManager.hasPasskeyCredential(username);
        setIsPasskeyRegisteredForLocalInput(hasCredential);
      } else {
        const prevUsername = await webAuthnManager.getLastUsedUsername();
        if (prevUsername) {
          setLocalUsernameInput(prevUsername);
          const hasCredential = await webAuthnManager.hasPasskeyCredential(prevUsername);
          setIsPasskeyRegisteredForLocalInput(hasCredential);
        }
      }
    };

    loadUserData();
  }, [username, hasManuallyClearedInput]);

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

    if (newUsername) {
      setHasManuallyClearedInput(false); // User is typing, not clearing
      const hasCredential = await webAuthnManager.hasPasskeyCredential(newUsername);
      setIsPasskeyRegisteredForLocalInput(hasCredential);
    } else {
      setHasManuallyClearedInput(true); // User has cleared the input
      setIsPasskeyRegisteredForLocalInput(false);
    }
  };

  const onRegister = async () => {
    if (!localUsernameInput.trim()) {
      return;
    }
    try {
      const result = await registerPasskey(localUsernameInput.trim(), {
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
                toast.success(`Welcome ${event.username}! Registration complete!`, { id: 'registration' });
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
        // Registration successful
      }
    } catch (error: any) {
      console.error('Registration error:', error);
    }
  };

  const onLogin = async () => {
    const userToAttemptLogin = localUsernameInput.trim();
    const result = await loginPasskey(userToAttemptLogin || undefined, {
      optimisticAuth,
      onEvent: (event: LoginEvent) => {
        switch (event.type) {
          case 'loginStarted':
            toast.loading(`Logging in${event.data.username ? ' as ' + event.data.username : ''}...`, { id: 'login' });
            break;
          case 'loginProgress':
            toast.loading(event.data.message, { id: 'login' });
            break;
          case 'loginCompleted':
            toast.success(`Logged in as ${event.data.username}!`, { id: 'login' });
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
            <h2>Welcome, {username}</h2>
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
                <span ref={postfixRef} className="account-postfix">{NEAR_ACCOUNT_POSTFIX}</span>
              </div>
              {isPasskeyRegisteredForLocalInput && localUsernameInput && (
                <div className="account-exists-badge">
                  account exists
                </div>
              )}
            </div>

            <Toggle
              checked={optimisticAuth}
              onChange={handleAuthModeToggleWithRef}
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