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

  // NEAR transfer state
  const [transferRecipient, setTransferRecipient] = useState('');
  const [transferAmount, setTransferAmount] = useState('');

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

  const handleSendNear = useCallback(async () => {
    if (!transferRecipient.trim() || !transferAmount.trim() || !isLoggedIn) {
      return;
    }

    // Validate amount is a positive number
    const amount = parseFloat(transferAmount);
    if (isNaN(amount) || amount <= 0) {
      toast.error('Please enter a valid amount greater than 0');
      return;
    }

    // Validate recipient account ID format (basic validation)
    const recipient = transferRecipient.trim();
    if (!recipient.includes('.') || recipient.length < 2) {
      toast.error('Please enter a valid NEAR account ID (e.g., recipient.testnet)');
      return;
    }

    // Convert NEAR to yoctoNEAR (1 NEAR = 10^24 yoctoNEAR)
    // Use string manipulation to avoid scientific notation like "1e+24"
    const nearStr = amount.toString();
    const parts = nearStr.split('.');
    const wholePart = parts[0] || '0';
    const fracPart = (parts[1] || '').padEnd(24, '0').slice(0, 24);
    const yoctoAmount = wholePart + fracPart;

    const transferAction: SerializableActionArgs = {
      action_type: ActionType.Transfer,
      receiver_id: recipient,
      amount: yoctoAmount,
    };

    setLastTxDetails(null);

    await passkeyManager.executeAction(nearAccountId, transferAction, {
      onEvent: (event: ActionEvent) => {
        switch (event.type) {
          case 'actionStarted':
            toast.loading('Processing NEAR transfer...', { id: 'transfer' });
            break;
          case 'actionProgress':
            toast.loading(event.data.message, { id: 'transfer' });
            break;
          case 'actionCompleted':
            toast.success(`Successfully sent ${amount} NEAR to ${recipient}!`, { id: 'transfer' });
            break;
          case 'actionFailed':
            toast.error(`Transfer failed: ${event.data.error}`, { id: 'transfer' });
            break;
        }
      },
      hooks: {
        afterCall: (success: boolean, result?: any) => {
          if (success) {
            // Reset transfer inputs on successful transaction
            setTransferRecipient("");
            setTransferAmount("");
          }

          if (success && result?.transactionId) {
            const txId = result.transactionId;
            const txLink = `${NEAR_EXPLORER_BASE_URL}/txns/${txId}`;

            setLastTxDetails({
              id: txId,
              link: txLink,
              message: `Sent ${amount} NEAR to ${recipient}`
            });
          } else if (success) {
            setLastTxDetails({
              id: 'N/A',
              link: '#',
              message: `Transfer successful: ${amount} NEAR to ${recipient}`
            });
          } else {
            setLastTxDetails({
              id: 'N/A',
              link: '#',
              message: `Transfer failed: ${result?.error || 'Unknown error'}`
            });
          }
        }
      }
    });
  }, [transferRecipient, transferAmount, isLoggedIn, nearAccountId, passkeyManager]);

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

          <div className="transfer-section">
            <h3>Send NEAR</h3>
            <div className="transfer-input-group">
              <input
                type="text"
                value={transferRecipient}
                onChange={(e) => setTransferRecipient(e.target.value)}
                placeholder="Recipient account (e.g., alice.testnet)"
                className="styled-input"
              />
              <input
                type="number"
                value={transferAmount}
                onChange={(e) => setTransferAmount(e.target.value)}
                placeholder="Amount in NEAR"
                className="styled-input"
                min="0"
                step="0.01"
              />
              <button
                onClick={handleSendNear}
                className="action-button"
                disabled={isLoading || !transferRecipient.trim() || !transferAmount.trim()}
              >
                {isLoading ? 'Processing...' : 'Send NEAR'}
              </button>
            </div>
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