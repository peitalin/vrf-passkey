import { useState, useCallback, useRef, useMemo } from 'react'
import { usePasskeyContext } from '@web3authn/passkey/react'
import { Toggle } from './Toggle'
import { GreetingMenu } from './GreetingMenu'
import { usePostfixPosition } from '../hooks/usePostfixPosition'
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
    accountInputState: {
      inputUsername,
      targetAccountId,
      displayPostfix,
      isUsingExistingAccount,
      accountExists
    },
    loginPasskey,
    registerPasskey,
    optimisticAuth,
    setOptimisticAuth,
    setInputUsername,
  } = usePasskeyContext();

  const [isSecureContext] = useState(() => window.isSecureContext);

  const usernameInputRef = useRef<HTMLInputElement>(null);
  const postfixRef = useRef<HTMLSpanElement>(null);

  const accountName = useMemo(() => nearAccountId?.split('.')?.[0], [nearAccountId]);

  // Use the postfix positioning hook
  usePostfixPosition({
    inputRef: usernameInputRef,
    postfixRef: postfixRef,
    inputValue: inputUsername
  });

  const handleAuthModeToggle = useCallback((checked: boolean) => {
    setOptimisticAuth(checked);
  }, [setOptimisticAuth]);

  const handleLocalUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInputUsername(e.target.value);
  };

  const onRegister = async () => {
    if (!targetAccountId) {
      return;
    }

    console.log('Registering account:', targetAccountId);
    try {
      const result = await registerPasskey(targetAccountId, {
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

      if (result.success && result.nearAccountId) {
        // Registration successful - the context will handle updating account data
      }
    } catch (error: any) {
      console.error('Registration error:', error);
    }
  };

  const onLogin = async () => {
    if (!targetAccountId) {
      return;
    }

    console.log('Logging in with account:', targetAccountId);
    const result = await loginPasskey(targetAccountId, {
      optimisticAuth,
      onEvent: (event: LoginEvent) => {
        switch (event.type) {
          case 'loginStarted':
            toast.loading(`Logging in as ${targetAccountId}...`, { id: 'login' });
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
                  value={inputUsername}
                  onChange={handleLocalUsernameChange}
                  placeholder="Enter username for passkey"
                  className="styled-input username-input"
                />
                <span
                  ref={postfixRef}
                  className={`account-postfix ${isUsingExistingAccount ? 'stored-account' : ''}`}
                  title={isUsingExistingAccount ? 'Using existing account domain' : 'New account domain'}
                >
                  {displayPostfix}
                  {isUsingExistingAccount && <span className="stored-indicator">●</span>}
                </span>
              </div>
              {accountExists && inputUsername && (
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
                className={`action-button ${!accountExists ? 'primary' : ''}`}
                disabled={!inputUsername || !isSecureContext || accountExists}>
                Register Passkey
              </button>
              <button onClick={onLogin}
                className={`action-button ${accountExists ? 'primary' : ''}`}
                disabled={!inputUsername || !accountExists}
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

            {/* VRF WebAuthn Experimental Section */}
            <div className="vrf-section" style={{ marginTop: '2rem', padding: '1rem', border: '2px dashed #8B5CF6', borderRadius: '8px', backgroundColor: '#F8FAFC' }}>
              <h3 style={{ color: '#7C3AED', marginBottom: '0.5rem' }}>🔐 VRF WebAuthn (Experimental)</h3>
              <p style={{ fontSize: '0.875rem', color: '#64748B', marginBottom: '1rem' }}>
                Test Verifiable Random Function authentication using WebAuthn PRF extension.
              </p>

              <div style={{ display: 'flex', gap: '0.5rem', flexDirection: 'column' }}>
                <button
                  onClick={async () => {
                    try {
                      toast.loading('Starting VRF Registration...', { id: 'vrf-register' });

                      // Get the passkey manager from context
                      const passkeyManager = (window as any).passkeyManager;
                      if (!passkeyManager) {
                        throw new Error('PasskeyManager not available');
                      }

                      const result = await passkeyManager.vrfRegistrationWithContract(
                        nearAccountId || 'alice.testnet'
                      );

                      console.log('VRF Registration:', result);

                      if (result.success) {
                        toast.success('VRF Registration successful!', { id: 'vrf-register' });
                      } else {
                        toast.error(`VRF Registration failed: ${result.error}`, { id: 'vrf-register' });
                      }
                    } catch (error: any) {
                      console.error('VRF Registration error:', error);
                      toast.error(`VRF Registration failed: ${error.message}`, { id: 'vrf-register' });
                    }
                  }}
                  style={{
                    padding: '0.5rem 1rem',
                    backgroundColor: '#8B5CF6',
                    color: 'white',
                    border: 'none',
                    borderRadius: '6px',
                    fontSize: '0.875rem',
                    cursor: 'pointer'
                  }}
                >
                  VRF Register ({nearAccountId})
                </button>

                <button
                  onClick={async () => {
                    try {
                      toast.loading('Starting VRF Authentication...', { id: 'vrf-auth' });

                      // Get the passkey manager from context
                      const passkeyManager = (window as any).passkeyManager;
                      if (!passkeyManager) {
                        throw new Error('PasskeyManager not available');
                      }

                      const result = await passkeyManager.vrfAuthenticationWithContract(
                        nearAccountId || 'alice.testnet'
                      );

                      console.log('VRF Authentication:', result);

                      if (result.success) {
                        toast.success('VRF Authentication successful!', { id: 'vrf-auth' });
                      } else {
                        toast.error(`VRF Authentication failed: ${result.error}`, { id: 'vrf-auth' });
                      }
                    } catch (error: any) {
                      console.error('VRF Authentication error:', error);
                      toast.error(`VRF Authentication failed: ${error.message}`, { id: 'vrf-auth' });
                    }
                  }}
                  style={{
                    padding: '0.5rem 1rem',
                    backgroundColor: '#7C3AED',
                    color: 'white',
                    border: 'none',
                    borderRadius: '6px',
                    fontSize: '0.875rem',
                    cursor: 'pointer'
                  }}
                >
                  VRF Authenticate ({nearAccountId})
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}