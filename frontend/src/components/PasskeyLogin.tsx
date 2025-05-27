import { useState, useEffect } from 'react'
import { usePasskeyContext } from '../contexts/PasskeyContext'
import toast from 'react-hot-toast'
import { ActionType, type SerializableActionArgs } from '../types'
import { RefreshIcon } from './RefreshIcon'

const HELLO_NEAR_CONTRACT_ID = 'cyan-loong.testnet'

// Helper to shorten strings like TxIDs or PKs
const shortenString = (str: string | null | undefined, headChars = 6, tailChars = 4) => {
  if (!str) return '';
  if (str.length <= headChars + tailChars + 2) return str; // If already short or has a prefix like "ed25519:"
  const prefixIndex = str.indexOf(':');
  if (prefixIndex > -1 && prefixIndex < headChars) { // Handle prefixes like ed25519:
    return `${str.substring(0, prefixIndex + 1 + headChars)}...${str.substring(str.length - tailChars)}`;
  }
  return `${str.substring(0, headChars)}...${str.substring(str.length - tailChars)}`;
};

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
    executeServerAction,
    fetchCurrentGreeting,
    logoutPasskey,
  } = usePasskeyContext();

  const [localUsernameInput, setLocalUsernameInput] = useState('');
  const [isPasskeyRegisteredForLocalInput, setIsPasskeyRegisteredForLocalInput] = useState(false);
  const [customGreetingInput, setCustomGreetingInput] = useState('Hello from Passkey App!');
  const [isSecureContext] = useState(() => window.isSecureContext);
  const [lastTxDetails, setLastTxDetails] = useState<LastTxDetails | null>(null);

  useEffect(() => {
    if (username) {
      setLocalUsernameInput(username);
      if (localStorage.getItem(`passkeyCredential_${username}`)) {
        setIsPasskeyRegisteredForLocalInput(true);
      }
    } else {
      const prevUsername = localStorage.getItem('prevPasskeyUsername');
      if (prevUsername) {
        setLocalUsernameInput(prevUsername);
        if (localStorage.getItem(`passkeyCredential_${prevUsername}`)) {
          setIsPasskeyRegisteredForLocalInput(true);
        }
      }
    }
  }, [username]);

  const handleLocalUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newUsername = e.target.value;
    setLocalUsernameInput(newUsername);
    setUsernameState(newUsername);
    if (localStorage.getItem(`passkeyCredential_${newUsername}`)) {
      setIsPasskeyRegisteredForLocalInput(true);
    } else {
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
      toast.success(`Registered and logged in as ${localUsernameInput.trim()}!`, { id: toastId, style: { background: '#4CAF50', color: 'white' } });
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

  const onExecuteAction = async () => {
    if (!customGreetingInput.trim()) {
      toast.error("Please enter a greeting message.");
      return;
    }
    if (!username) {
      toast.error("Cannot execute action: User not logged in.");
      return;
    }

    const actionToExecute: SerializableActionArgs = {
      action_type: ActionType.FunctionCall,
      receiver_id: HELLO_NEAR_CONTRACT_ID,
      method_name: 'set_greeting',
      gas: "30000000000000",
      deposit: "0",
    };

    let toastId = '';
    setLastTxDetails(null);

    await executeServerAction(
      actionToExecute,
      username,
      customGreetingInput,
      {
        beforeDispatch: () => {
          toastId = toast.loading('Dispatching Set Greeting action...', { style: { background: '#2196F3', color: 'white' } });
        },
        afterDispatch: (success, data) => {
          if (success && data?.transactionId) {
            const txLink = `https://testnet.nearblocks.io/txns/${data.transactionId}`;
            const shortTxId = shortenString(data.transactionId, 10, 6);
            const greetingSet = (actionToExecute.method_name === 'set_greeting') ? customGreetingInput.trim() : null;
            const successMessage = `Set Greeting to "${greetingSet}" successful!`;

            setLastTxDetails({
              id: data.transactionId,
              link: txLink,
              message: greetingSet ? `Set to: "${greetingSet}"` : undefined
            });

            const successContent = (
              <span>
                {successMessage} Tx: <a href={txLink} target="_blank" rel="noopener noreferrer" className="toast-tx-link">{shortTxId}</a>.
                Result: {data?.successValue || '(No value)'}
              </span>
            );
            toast.success(successContent, {
              id: toastId,
              duration: 8000,
              style: { background: '#4CAF50', color: 'white' }
            });
          } else if (success) {
            toast.success(`Action successful! ${data?.successValue || '(No value)'}`, { id: toastId, duration: 6000, style: { background: '#4CAF50', color: 'white' } });
            setLastTxDetails({ id: 'N/A', link: '#', message: data?.successValue || 'Success, no TxID' });
          } else {
            toast.error(data?.error || 'Action failed.', { id: toastId });
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
          {serverDerivedNearPK && (
            <div className="greeting-controls-box">
              <h4>Manage Greeting on {HELLO_NEAR_CONTRACT_ID}</h4>

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
                  onClick={onExecuteAction}
                  className="action-button" /* Keep action-button for base styling */
                  disabled={isProcessing || !customGreetingInput.trim()}
                >
                  {isProcessing ? 'Processing...' : 'Set New Greeting'}
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}