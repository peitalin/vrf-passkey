import { useState, useEffect } from 'react'
import { usePasskeyContext } from '../contexts/PasskeyContext'
import { useSettings } from '../contexts/SettingsContext'
import toast from 'react-hot-toast'
import { ActionType, type SerializableActionArgs } from '../types'
import { RefreshIcon } from './RefreshIcon'
import { webAuthnManager } from '../security/WebAuthnManager'
import { shortenString } from '../utils/strings'
import { WEBAUTHN_CONTRACT_ID } from '../config'


interface LastTxDetails {
  id: string;
  link: string;
  message?: string; // Optional: if you want to store the greeting set
}

export function PasskeyLogin() {
  const {
    isLoggedIn,
    username,
    serverDerivedNearPK,
    isProcessing,
    currentGreeting,
    setUsernameState,
    registerPasskey,
    loginPasskey,
    executeDirectActionViaWorker,
    fetchCurrentGreeting,
    logoutPasskey,
  } = usePasskeyContext();

  const { useOptimisticAuth, setUseOptimisticAuth } = useSettings();

  const [localUsernameInput, setLocalUsernameInput] = useState('');
  const [isPasskeyRegisteredForLocalInput, setIsPasskeyRegisteredForLocalInput] = useState(false);
  const [customGreetingInput, setCustomGreetingInput] = useState('Hello from Passkey App!');
  const [isSecureContext] = useState(() => window.isSecureContext);
  const [lastTxDetails, setLastTxDetails] = useState<LastTxDetails | null>(null);
  const [hasManuallyClearedInput, setHasManuallyClearedInput] = useState(false);

  useEffect(() => {
    const loadUserData = async () => {
      if (hasManuallyClearedInput) return; // Don't override manual clearing

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
    const toastId = toast.loading('Registering passkey...', { style: { background: '#2196F3', color: 'white' } });
    const result = await registerPasskey(localUsernameInput.trim());
    if (result.success) {
      let successMessage = `Registered and logged in as ${localUsernameInput.trim()}!`;
      let toastDuration = 6000;

      if (result.nearAccountId && result.clientNearPublicKey) {
        successMessage += `\nAccount ID: ${result.nearAccountId}\nClient PK: ${shortenString(result.clientNearPublicKey, 10, 10)}`;
        toastDuration = 8000; // Longer duration if more info
      }

      if (result.transactionId) {
        const txLink = `https://testnet.nearblocks.io/txns/${result.transactionId}`;
        const shortTxId = shortenString(result.transactionId, 10, 6);
        const successContent = (
          <span>
            {successMessage.split('\n').map((line, i) => (<span key={i}>{line}<br/></span>))}
            Tx: <a href={txLink} target="_blank" rel="noopener noreferrer" className="toast-tx-link">{shortTxId}</a>
          </span>
        );
        toast.success(successContent, {
          id: toastId,
          duration: toastDuration, // Use updated duration
          style: { background: '#4CAF50', color: 'white' }
        });
      } else {
        // If no transactionId, but we have accountId and PK, still show them
        const successContentNoTx = (
            <span>
                {successMessage.split('\n').map((line, i) => (<span key={i}>{line}<br/></span>))}
            </span>
        );
        toast.success(successContentNoTx, {
            id: toastId,
            duration: toastDuration, // Use updated duration
            style: { background: '#4CAF50', color: 'white' }
        });
      }
      setLastTxDetails(null);
    } else {
      toast.error(result.error || 'Registration failed.', { id: toastId });
    }
  };

  const onLogin = async () => {
    const userToAttemptLogin = localUsernameInput.trim();
    const toastId = toast.loading(
      `Attempting login${userToAttemptLogin ? ' for ' + userToAttemptLogin : ' (discoverable passkey)'}...`,
      { style: { background: '#2196F3', color: 'white' } }
    );
    const result = await loginPasskey(userToAttemptLogin || undefined);
    if (result.success) {
      toast.success(`Logged in as ${result.loggedInUsername || userToAttemptLogin}!`, { id: toastId, style: { background: '#4CAF50', color: 'white' } });
      setLastTxDetails(null);
    } else {
      toast.error(result.error || 'Login failed.', { id: toastId });
    }
  };

  const onFetchGreeting = async () => {
    const toastId = toast.loading('Refreshing greeting...', { style: { background: '#2196F3', color: 'white' } });
    const result = await fetchCurrentGreeting();
    if (result.success) {
      toast.success('Greeting refreshed!', { id: toastId, style: { background: '#2196F3', color: 'white' } });
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

    const newGreetingMessage = `${customGreetingInput.trim()} (updated: ${new Date().toLocaleTimeString()})`;

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

    await executeDirectActionViaWorker(
      actionToExecute,
      {
        beforeDispatch: () => {
          toastId = toast.loading('Dispatching Set Greeting (Direct Action)... ', { style: { background: '#2196F3', color: 'white' } });
        },
        afterDispatch: (success, data) => {
          if (success && data?.transaction_outcome?.id) {
            const txId = data.transaction_outcome.id;
            const txLink = `https://testnet.nearblocks.io/txns/${txId}`;
            const shortTxId = shortenString(txId, 10, 6);
            const greetingSet = newGreetingMessage;
            const successMessage = `Set Greeting to "${greetingSet}" (Direct) successful!`;

            setLastTxDetails({
              id: txId,
              link: txLink,
              message: `Set to: "${greetingSet}"`
            });

            const successContent = (
              <span>
                {successMessage} Tx: <a href={txLink} target="_blank" rel="noopener noreferrer" className="toast-tx-link">{shortTxId}</a>.
              </span>
            );
            toast.success(successContent, {
              id: toastId,
              duration: 8000,
              style: { background: '#4CAF50', color: 'white' }
            });
          } else if (success) {
            toast.success(`Direct Action successful! (No TxID found in response)`, { id: toastId, duration: 6000, style: { background: '#4CAF50', color: 'white' } });
            setLastTxDetails({ id: 'N/A', link: '#', message: 'Success, no TxID in response' });
          } else {
            toast.error(data?.error || 'Direct Action failed.', { id: toastId });
            setLastTxDetails({ id: 'N/A', link: '#', message: `Failed: ${data?.error || 'Unknown error'}` });
          }
        }
      }
    );
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
    <div className="passkey-container">
      <h3>Passkey Authentication with NEAR</h3>
      {!isLoggedIn ? (
        <>
          <div>
            <input
              type="text"
              value={localUsernameInput}
              onChange={handleLocalUsernameChange}
              placeholder="Enter username for passkey"
              className="styled-input"
            />
          </div>

          <div className="auth-mode-toggle">
            <label className="toggle-label">
              <input
                type="checkbox"
                checked={useOptimisticAuth}
                onChange={(e) => setUseOptimisticAuth(e.target.checked)}
                className="toggle-checkbox"
              />
              <span className="toggle-slider"></span>
              <span className="toggle-text">
                {useOptimisticAuth ? 'Fast Auth (Optimistic)' : 'Secure Auth (Contract Sync)'}
              </span>
            </label>
            <div className="auth-mode-description">
              {useOptimisticAuth
                ? 'Immediate response with background contract update'
                : 'Wait for contract verification before response'
              }
            </div>
          </div>

          <div className="auth-buttons">
            <button onClick={onRegister} className="action-button"
              disabled={!localUsernameInput || !isSecureContext || isPasskeyRegisteredForLocalInput || isProcessing}>
              Register Passkey
            </button>
            <button onClick={onLogin} className="action-button"
              disabled={(!localUsernameInput && isPasskeyRegisteredForLocalInput && !isProcessing) ? false : (!localUsernameInput || isProcessing)}>
              {localUsernameInput ? 'Login with Passkey' : 'Login (enter username or try discoverable)'}
            </button>
            {!localUsernameInput && (
              <button onClick={() => loginPasskey()} className="action-button"
                      disabled={isProcessing || isPasskeyRegisteredForLocalInput}>
                Login with Discoverable Passkey
              </button>
            )}
          </div>
          {isPasskeyRegisteredForLocalInput && localUsernameInput && <p style={{fontSize: '0.8em'}}>Passkey registered for '{localUsernameInput}'. Try Login.</p>}
        </>
      ) : (
        <>
          <div className="user-info-box">
            <h4>Logged in as: {username}</h4>
            <button onClick={logoutPasskey} className="action-button logout-button">
              Logout
            </button>
          </div>

          {serverDerivedNearPK ? (
            <div className="greeting-controls-box">
              <h4>Manage Greeting on {WEBAUTHN_CONTRACT_ID}</h4>

              <button onClick={onFetchGreeting} disabled={isProcessing} title="Refresh Greeting" className="refresh-icon-button">
                <RefreshIcon size={22} />
              </button>

              {currentGreeting && (
                <div className="on-chain-greeting-box">
                  <p><strong>On-Chain Greeting:</strong></p>
                  <p>"{currentGreeting}"</p>
                </div>
              )}

              {lastTxDetails && lastTxDetails.id !== 'N/A' && (
                <div className="last-tx-display">
                  <span>Last Set Greeting Tx: </span>
                  <a href={lastTxDetails.link} target="_blank" rel="noopener noreferrer" title={lastTxDetails.id} className="tx-link">
                    {shortenString(lastTxDetails.id, 10, 6)}
                  </a>
                  {lastTxDetails.message && <span className="tx-message">{lastTxDetails.message}</span>}
                </div>
              )}

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
                  className="action-button" /* Keep action-button for base styling */
                  disabled={isProcessing || !customGreetingInput.trim()}
                >
                  {isProcessing ? 'Processing...' : 'Set New Greeting (Direct)'}
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
  );
}