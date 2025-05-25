import { useState, useEffect, useCallback } from 'react'
import { SERVER_URL } from '../config'
import { bufferEncode, bufferDecode, publicKeyCredentialToJSON } from '../utils'
import type { ServerRegistrationOptions, ServerAuthenticationOptions } from '../types'

export function PasskeyLogin() {
  const [username, setUsername] = useState('')
  const [isPasskeyRegistered, setIsPasskeyRegistered] = useState(false)
  const [isPasskeyLoggedIn, setIsPasskeyLoggedIn] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [isSecureContext, setIsSecureContext] = useState(() => window.isSecureContext);
  const [serverDerivedNearPK, setServerDerivedNearPK] = useState<string | null | undefined>(null);

  useEffect(() => {
    const prevUsername = localStorage.getItem('prevPasskeyUsername');
    if (prevUsername) {
      setUsername(prevUsername);
      if (localStorage.getItem(`passkeyCredential_${prevUsername}`)) {
        setIsPasskeyRegistered(true);
      }
    }
  }, []);

  const handlePasskeyRegister = async () => {
    if (!username) {
      setStatusMessage('Username is required to register a passkey.');
      return;
    }
    if (!isSecureContext) {
      setStatusMessage('Passkey operations require a secure context (HTTPS or localhost).');
      return;
    }
    setStatusMessage(`Starting passkey registration for ${username}...`);
    localStorage.setItem('prevPasskeyUsername', username);

    try {
      const regOptionsResponse = await fetch(`${SERVER_URL}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });

      if (!regOptionsResponse.ok) {
        const errorData = await regOptionsResponse.json().catch(() => ({ error: 'Failed to fetch registration options' }));
        throw new Error(errorData.error || `Server responded with ${regOptionsResponse.status}`);
      }
      const options: ServerRegistrationOptions = await regOptionsResponse.json();
      const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: bufferDecode(options.challenge),
        user: {
          ...options.user,
          id: new TextEncoder().encode(options.user.id),
        },
        excludeCredentials: options.excludeCredentials?.map(cred => ({
          ...cred,
          id: bufferDecode(cred.id),
          transports: cred.transports as AuthenticatorTransport[] | undefined,
        })),
        authenticatorSelection: options.authenticatorSelection || {
          residentKey: "required",
          userVerification: "preferred",
        },
      };
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
      }) as PublicKeyCredential | null;

      if (!credential || !(credential.response instanceof AuthenticatorAttestationResponse)) {
        setStatusMessage('Passkey registration cancelled or failed at browser level (no attestation response).');
        return;
      }

      const attestationResponseJSON = publicKeyCredentialToJSON(credential);
      const verificationResponse = await fetch(`${SERVER_URL}/verify-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, attestationResponse: attestationResponseJSON }),
      });
      const verificationData = await verificationResponse.json();
      if (verificationResponse.ok && verificationData.verified) {
        localStorage.setItem(`passkeyCredential_${username}`, JSON.stringify({
          id: credential.id,
          rawId: bufferEncode(credential.rawId),
        }));
        setIsPasskeyRegistered(true);
        setIsPasskeyLoggedIn(true);
        setStatusMessage(`Passkey registered for ${username}!`);
      } else {
        throw new Error(verificationData.error || 'Passkey verification failed on server.');
      }
    } catch (error) {
      console.error('Passkey registration error:', error);
      let errorMessage = "Registration failed";
      if (error instanceof Error) errorMessage += `: ${error.message}`;
      else errorMessage += `: ${String(error)}`;
      setStatusMessage(errorMessage);
      setIsPasskeyRegistered(false);
      setIsPasskeyLoggedIn(false);
    }
  };

  const handlePasskeyLogin = useCallback(async () => {
    if (!isSecureContext) {
      setStatusMessage('Passkey operations require a secure context (HTTPS or localhost).');
      return;
    }
    setStatusMessage('Attempting passkey login...');

    try {
      const authOptionsResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(username ? { username } : {}),
      });
      if (!authOptionsResponse.ok) {
        const errorData = await authOptionsResponse.json().catch(() => ({ error: 'Failed to fetch authentication options' }));
        throw new Error(errorData.error || `Server responded with ${authOptionsResponse.status}`);
      }
      const options: ServerAuthenticationOptions = await authOptionsResponse.json();
      const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge: bufferDecode(options.challenge),
        rpId: options.rpId,
        allowCredentials: options.allowCredentials?.map(cred => ({
          ...cred,
          id: bufferDecode(cred.id),
          transports: cred.transports as AuthenticatorTransport[] | undefined,
        })),
        userVerification: options.userVerification || "preferred",
        timeout: options.timeout || 60000,
      };
      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
      }) as PublicKeyCredential | null;
      if (!assertion) {
        setStatusMessage('Passkey login cancelled or no assertion received from browser.');
        setIsPasskeyLoggedIn(false);
        return;
      }
      const assertionResponseJSON = publicKeyCredentialToJSON(assertion);
      const verificationResponse = await fetch(`${SERVER_URL}/verify-authentication`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertionResponseJSON),
      });
      const verificationData = await verificationResponse.json();
      if (verificationResponse.ok && verificationData.verified) {
        const loggedInUsername = verificationData.username;
        const derivedPkFromServer = verificationData.derivedNearPublicKey;

        if (!loggedInUsername) {
          throw new Error("Server did not return a username on successful login.");
        }
        setUsername(loggedInUsername);
        setIsPasskeyLoggedIn(true);
        setServerDerivedNearPK(derivedPkFromServer);
        setStatusMessage(`Successfully logged in as ${loggedInUsername} with your passkey! Server-derived NEAR PK: ${derivedPkFromServer || 'Not provided'}`);
        localStorage.setItem('prevPasskeyUsername', loggedInUsername);
      } else {
        setIsPasskeyLoggedIn(false);
        throw new Error(verificationData.error || 'Passkey authentication failed on server.');
      }
    } catch (loginError) {
      console.error('Passkey login error:', loginError);
      setIsPasskeyLoggedIn(false);
      let displayMessage = "Login failed";
      if (loginError instanceof Error) {
        displayMessage += `: ${loginError.message}`;
        if (loginError.name === 'NotAllowedError') {
          displayMessage = 'Passkey operation not allowed or cancelled. Check browser/security settings or if a passkey exists for the username.';
        }
      } else {
        displayMessage += `: ${String(loginError)}`;
      }
      setStatusMessage(displayMessage);
    }
  }, [username, isSecureContext, setStatusMessage, setUsername, setIsPasskeyLoggedIn]);

  const handlePasskeyLogout = useCallback(async () => {
    setIsPasskeyLoggedIn(false);
    setServerDerivedNearPK(null);
    setStatusMessage('Logged out successfully from Passkey.');
  }, [setIsPasskeyLoggedIn, setStatusMessage]);

  const handleMockServerAction = () => {
    if (!serverDerivedNearPK) {
      const errorMessage = 'Cannot perform mock server action: No server-derived NEAR PK available.';
      setStatusMessage(errorMessage);
      alert(errorMessage);
      console.warn('Mock server action attempted, but no serverDerivedNearPK is set.');
      return;
    }

    const randomNumber = Math.floor(Math.random() * 1000000);
    const mockTransactionId = `mock-tx-${Date.now()}-${randomNumber}`;

    const mockActionDetails = {
      transactionId: mockTransactionId,
      action: 'transfer',
      params: { to: 'bob.near', amount: '1 NEAR', memo: `Order #${randomNumber}` },
      authorizedByPasskeyLinkedNearPK: serverDerivedNearPK,
      timestamp: new Date().toISOString(),
    };

    console.log('Simulating server-authorized action with details:', mockActionDetails);
    alert(`Simulating server-authorized action with details: ${JSON.stringify(mockActionDetails)}`);
    setStatusMessage(`Mock server action initiated. Server would use NEAR PK: ${serverDerivedNearPK} to authorize this. Check console.`);
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

  if (isPasskeyLoggedIn) {
    return (
      <div className="passkey-container">
        <h3>Passkey Authenticated</h3>
        <p>Welcome, {username}!</p>
        <p>Your passkey is ready.</p>
        {serverDerivedNearPK && (
          <div className="near-key-info" style={{margin: '1rem 0', padding: '0.5rem', border: '1px solid #eee', fontSize: '0.9em'}}>
            <p>Server-Derived NEAR Public Key: <strong>{serverDerivedNearPK}</strong></p>
            <button
              onClick={handleMockServerAction}
              className="action-button"
              style={{backgroundColor: '#ffc107', color: 'black', marginTop: '0.5rem'}}
            >
              Mock Server-Authorized Action
            </button>
          </div>
        )}
        <button onClick={handlePasskeyLogout} className="action-button">Logout with Passkey</button>
        {statusMessage && <p className="status-message">{statusMessage}</p>}
      </div>
    );
  } else {
    return (
      <div className="passkey-container">
        <h3>Passkey Authentication with NEAR</h3>
        <div>
          <input
            type="text"
            value={username}
            onChange={(e) => {
              const newUsername = e.target.value;
              setUsername(newUsername);
              if (localStorage.getItem(`passkeyCredential_${newUsername}`)) {
                setIsPasskeyRegistered(true);
              } else {
                setIsPasskeyRegistered(false);
              }
            }}
            placeholder="Enter username for passkey"
            className="styled-input"
          />
        </div>
        <div className="auth-buttons">
          <button onClick={handlePasskeyRegister} className="action-button"
            disabled={!username || !isSecureContext || isPasskeyRegistered}>
            Register Passkey
          </button>
          <button onClick={handlePasskeyLogin} className="action-button"
            disabled={!username || !isPasskeyRegistered}>
            Login with Passkey
          </button>
        </div>
        {isPasskeyRegistered && <p style={{fontSize: '0.8em'}}>Passkey registered for '{username}'. Try Login.</p>}

        {statusMessage && <p className="status-message" style={{marginTop: '1rem'}}>{statusMessage}</p>}
      </div>
    );
  }
}