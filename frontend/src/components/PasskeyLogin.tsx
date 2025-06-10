import { useState, useEffect, useCallback, useRef } from 'react'
import { usePasskeyContext } from '../contexts/PasskeyContext'
import toast from 'react-hot-toast'
import { ActionType, type SerializableActionArgs } from '../types'
import { RefreshIcon } from './icons/RefreshIcon'
import { webAuthnManager } from '../security/WebAuthnManager'
import { shortenString } from '../utils/strings'
import { Toggle } from './Toggle'
import {
  WEBAUTHN_CONTRACT_ID,
  MUTED_GREEN,
  MUTED_BLUE,
  MUTED_ORANGE,
  TOAST_TEXT_COLOR,
  NEAR_ACCOUNT_POSTFIX,
  NEAR_EXPLORER_BASE_URL
} from '../config'

interface LastTxDetails {
  id: string;
  link: string;
  message?: string; // Optional: if you want to store the greeting set
}

export function PasskeyLogin() {
  const {
    isLoggedIn,
    username,
    nearPublicKey,
    isProcessing,
    currentGreeting,
    setUsernameState,
    registerPasskey,
    loginPasskey,
    executeDirectActionViaWorker,
    fetchCurrentGreeting,
    logoutPasskey,
    optimisticAuth,
    setOptimisticAuth,
  } = usePasskeyContext();

  const [localUsernameInput, setLocalUsernameInput] = useState('');
  const [isPasskeyRegisteredForLocalInput, setIsPasskeyRegisteredForLocalInput] = useState(false);
  const [customGreetingInput, setCustomGreetingInput] = useState('Hello from Passkey App!');
  const [isSecureContext] = useState(() => window.isSecureContext);
  const [lastTxDetails, setLastTxDetails] = useState<LastTxDetails | null>(null);
  const [hasManuallyClearedInput, setHasManuallyClearedInput] = useState(false);
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
  }, [username, hasManuallyClearedInput]); // Removed optimisticAuth from dependencies

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
    setUsernameState(newUsername); // Keep context in sync if needed, or remove if only local state matters

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
      toast.error('Please enter a username to register.');
      return;
    }

    try {
      // Use the context registerPasskey which now handles SSE and all toast notifications
      const result = await registerPasskey(localUsernameInput.trim());

      // The PasskeyContext handles all step-by-step toast notifications
      // We only need to handle final error states here since success is handled by SSE
      if (!result.success) {
        toast.error(result.error || 'Registration failed.');
      }

      setLastTxDetails(null);
    } catch (error: any) {
      console.error('Registration error:', error);
      toast.error(`Registration failed: ${error.message}`);
    }
  };

  const onLogin = async () => {
    const userToAttemptLogin = localUsernameInput.trim();
    const toastId = toast.loading(
      `Attempting login${userToAttemptLogin ? ' for ' + userToAttemptLogin : ' (discoverable passkey)'}...`,
      { style: { background: MUTED_BLUE, color: TOAST_TEXT_COLOR } }
    );
    const result = await loginPasskey(userToAttemptLogin || undefined);
    if (result.success) {
      toast.success(
        `Logged in as ${result.loggedInUsername || userToAttemptLogin}!`,
        { id: toastId, style: { background: MUTED_GREEN, color: TOAST_TEXT_COLOR } }
      );
      setLastTxDetails(null);
    } else {
      toast.error(result.error || 'Login failed.', { id: toastId });
    }
  };

  const onFetchGreeting = async () => {
    const toastId = toast.loading(
      'Refreshing greeting...',
      { style: { background: MUTED_BLUE, color: TOAST_TEXT_COLOR } }
    );
    const result = await fetchCurrentGreeting();
    if (result.success) {
      toast.success(
        'Greeting refreshed!',
        { id: toastId, style: { background: MUTED_GREEN, color: TOAST_TEXT_COLOR } }
      );
    } else {
      toast.error(result.error || "Failed to refresh greeting", { id: toastId });
    }
  };

  const onExecuteDirectAction = async () => {
    if (!customGreetingInput.trim()) {
      toast.error("Please enter a greeting message.");
      return;
    }
    if (!username) {
      toast.error("Cannot execute action: User not logged in.");
      return;
    }

    const newGreetingMessage = `${customGreetingInput.trim()} [updated: ${new Date().toLocaleTimeString()}]`;

    const actionToExecute: SerializableActionArgs = {
      action_type: ActionType.FunctionCall,
      receiver_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'set_greeting',
      args: JSON.stringify({ greeting: newGreetingMessage }),
      gas: "30000000000000",
      deposit: "0",
    };

    let toastId = '';
    setLastTxDetails(null);

    await executeDirectActionViaWorker(actionToExecute, {
      optimisticAuth: optimisticAuth, // Use greeting-specific auth mode
      beforeDispatch: () => {
        toastId = toast.loading(
          optimisticAuth ? 'Dispatching Set Greeting (Fast)... ' : 'Dispatching Set Greeting (via Contract)... ',
          { style: { background: MUTED_BLUE, color: TOAST_TEXT_COLOR } }
        );
      },
      afterDispatch: (success, data) => {
        if (success && data?.transaction_outcome?.id) {
          const txId = data.transaction_outcome.id;
          const txLink = `${NEAR_EXPLORER_BASE_URL}/txns/${txId}`;
          const shortTxId = shortenString(txId, 10, 6);
          const greetingSet = newGreetingMessage;
          const successMessage = `Set Greeting to "${greetingSet}" successful!`;

          setLastTxDetails({
            id: txId,
            link: txLink,
            message: `${greetingSet}`
          });

          const successContent = (
            <span>
              {successMessage} Tx: <a href={txLink} target="_blank" rel="noopener noreferrer" className="toast-tx-link">{shortTxId}</a>.
            </span>
          );
          toast.success(successContent, {
            id: toastId,
            duration: 8000,
            style: { background: MUTED_GREEN, color: TOAST_TEXT_COLOR }
          });
        } else if (success) {
          toast.success(`Direct Action successful! (No TxID found in response)`, { id: toastId, duration: 6000, style: { background: MUTED_GREEN, color: TOAST_TEXT_COLOR } });
          setLastTxDetails({ id: 'N/A', link: '#', message: 'Success, no TxID in response' });
        } else {
          toast.error(data?.error || 'Direct Action failed.', { id: toastId });
          setLastTxDetails({ id: 'N/A', link: '#', message: `Failed: ${data?.error || 'Unknown error'}` });
        }
      }
    });
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
              <button onClick={onRegister} className={`action-button ${!isPasskeyRegisteredForLocalInput ? 'primary' : ''}`}
                disabled={!localUsernameInput || !isSecureContext || isPasskeyRegisteredForLocalInput || isProcessing}>
                Register Passkey
              </button>
              <button onClick={onLogin} className={`action-button ${isPasskeyRegisteredForLocalInput ? 'primary' : ''}`}
                disabled={!localUsernameInput || !isPasskeyRegisteredForLocalInput || isProcessing}>
                {localUsernameInput ? 'Login with Passkey' : 'Login (enter username or try discoverable)'}
              </button>
              {!localUsernameInput && (
                <button onClick={() => loginPasskey()} className="action-button"
                        disabled={isProcessing}>
                  Login with Passkey
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            {nearPublicKey ? (
              <div className="greeting-controls-box">
                <div className="webauthn-contract-link">Onchain message on <a href={`${NEAR_EXPLORER_BASE_URL}/address/webauthn-contract.testnet`} target="_blank" rel="noopener noreferrer">{WEBAUTHN_CONTRACT_ID}</a>:</div>
                <div className="on-chain-greeting-box">
                  <button onClick={onFetchGreeting} disabled={isProcessing} title="Refresh Greeting" className="refresh-icon-button">
                    <RefreshIcon size={22} color={MUTED_GREEN}/>
                  </button>
                  <p><strong>{currentGreeting || "..."}</strong></p>
                </div>

                {lastTxDetails && lastTxDetails.id !== 'N/A' && (
                  <div className="last-tx-display">
                    <span>Transaction ID: </span>
                    <a href={lastTxDetails.link} target="_blank" rel="noopener noreferrer"
                      title={lastTxDetails.id}
                      className="tx-link"
                    >
                      {shortenString(lastTxDetails.id, 10, 6)}
                    </a>
                  </div>
                )}

                <Toggle
                  checked={optimisticAuth}
                  onChange={setOptimisticAuth}
                  label={optimisticAuth ? 'Fast Signing' : 'Contract Signing'}
                  tooltip={optimisticAuth
                    ? 'Fast transaction signing with optimistic response'
                    : 'Contract signed Passkey authentication (slower)'
                  }
                  className="greeting-auth-mode-toggle"
                  size="small"
                />

                <div className="greeting-input-group">
                  <input
                    type="text"
                    value={customGreetingInput}
                    onChange={(e) => setCustomGreetingInput(e.target.value)}
                    placeholder="Enter new greeting"
                    className="styled-input" /* Keep styled-input for consistency, greeting-input-group handles layout */
                  />
                  <button
                    onClick={onExecuteDirectAction}
                    className="action-button"
                    disabled={isProcessing || !customGreetingInput.trim()}
                  >
                    {isProcessing ? 'Processing...' : 'Set New Greeting'}
                  </button>
                </div>
              </div>
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