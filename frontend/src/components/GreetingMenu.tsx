import { useState, useCallback, useEffect } from 'react';
import { usePasskeyContext } from '@web3authn/passkey/react';
import { RefreshIcon } from './icons/RefreshIcon';
import { Toggle } from './Toggle';
import { shortenString } from '../utils/strings';
import { useSetGreeting } from '../hooks/useSetGreeting';
import toast from 'react-hot-toast';
import type { ActionEvent } from '@web3authn/passkey/react';
import type { SerializableActionArgs } from '../types';
import { ActionType } from '../types';
import {
  WEBAUTHN_CONTRACT_ID,
  MUTED_GREEN,
  NEAR_EXPLORER_BASE_URL
} from '../config';

interface LastTxDetails {
  id: string;
  link: string;
  message?: string;
}

export function GreetingMenu() {
  const {
    loginState: { isLoggedIn, nearAccountId },
    passkeyManager,
  } = usePasskeyContext();

  const [greetingInput, setGreetingInput] = useState('Hello from Passkey App!');
  const [lastTxDetails, setLastTxDetails] = useState<LastTxDetails | null>(null);

  const {
    onchainGreeting,
    isLoading,
    fetchGreeting,
    error
  } = useSetGreeting();

  // Automatically fetch greeting when component mounts
  useEffect(() => {
    if (isLoggedIn && !isLoading) {
      fetchGreeting();
    }
  }, []);

  const handleRefreshGreeting = useCallback(async () => {
    await fetchGreeting();
  }, [fetchGreeting]);

  const handleSetGreeting = useCallback(async () => {
    if (!greetingInput.trim() || !isLoggedIn) {
      return;
    }

    const newGreetingMessage = `${greetingInput.trim()} [updated: ${new Date().toLocaleTimeString()}]`;

    const actionToExecute: SerializableActionArgs = {
      action_type: ActionType.FunctionCall,
      receiver_id: WEBAUTHN_CONTRACT_ID,
      method_name: 'set_greeting',
      args: JSON.stringify({ greeting: newGreetingMessage }),
      gas: "30000000000000",
      deposit: "0",
    };

    setLastTxDetails(null);

    await passkeyManager.executeAction(nearAccountId, actionToExecute, {
      onEvent: (event: ActionEvent) => {
        switch (event.type) {
          case 'actionStarted':
            toast.loading('Processing transaction...', { id: 'action' });
            break;
          case 'actionProgress':
            toast.loading(event.data.message, { id: 'action' });
            break;
          case 'actionCompleted':
            toast.success('Transaction completed successfully!', { id: 'action' });
            // Refresh greeting after successful update
            fetchGreeting();
            break;
          case 'actionFailed':
            toast.error(`Transaction failed: ${event.data.error}`, { id: 'action' });
            break;
        }
      },
      hooks: {
        afterCall: (success: boolean, result?: any) => {
          if (success) {
            // Reset greeting input on any successful transaction
            setGreetingInput("");
          }

          if (success && result?.transactionId) {
            const txId = result.transactionId;
            const txLink = `${NEAR_EXPLORER_BASE_URL}/txns/${txId}`;

            setLastTxDetails({
              id: txId,
              link: txLink,
              message: newGreetingMessage
            });
          } else if (success) {
            setLastTxDetails({ id: 'N/A', link: '#', message: 'Success, no TxID in response' });
          } else {
            setLastTxDetails({ id: 'N/A', link: '#', message: `Failed: ${result?.error || 'Unknown error'}` });
          }
        }
      }
    });
  }, [greetingInput, isLoggedIn, nearAccountId, passkeyManager, fetchGreeting]);

  if (!isLoggedIn) {
    return null;
  }

  return (
    <div className="passkey-container-root">
      <div className="passkey-container">

        <h2>Welcome, {nearAccountId}</h2>
        <p className="caption">Send NEAR transactions with Passkeys</p>

        <div className="greeting-controls-box">
          <div className="webauthn-contract-link">
            Onchain message on&nbsp;
            <a href={`${NEAR_EXPLORER_BASE_URL}/address/${WEBAUTHN_CONTRACT_ID}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {WEBAUTHN_CONTRACT_ID}
            </a>:
          </div>

          <div className="on-chain-greeting-box">
            <button
              onClick={handleRefreshGreeting}
              disabled={isLoading}
              title="Refresh Greeting"
              className="refresh-icon-button"
            >
              <RefreshIcon size={22} color={MUTED_GREEN}/>
            </button>
            <p><strong>{onchainGreeting || "..."}</strong></p>
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

          <div className="greeting-input-group">
            <input
              type="text"
              value={greetingInput}
              onChange={(e) => setGreetingInput(e.target.value)}
              placeholder="Enter new greeting"
              className="styled-input"
            />
            <button
              onClick={handleSetGreeting}
              className="action-button"
              disabled={isLoading || !greetingInput.trim()}
            >
              {isLoading ? 'Processing...' : 'Set New Greeting'}
            </button>
          </div>

          {error && (
            <div className="error-message">
              Error: {error}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}