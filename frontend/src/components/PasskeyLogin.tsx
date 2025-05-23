import { useState, useEffect } from 'react'
import { SERVER_URL } from '../config'
import { bufferEncode, bufferDecode, publicKeyCredentialToJSON } from '../utils'
import type { ServerRegistrationOptions, ServerAuthenticationOptions } from '../types'



export function PasskeyLogin() {
  const [username, setUsername] = useState('')
  const [isPasskeyRegistered, setIsPasskeyRegistered] = useState(false)
  const [isPasskeyLoggedIn, setIsPasskeyLoggedIn] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [isSecureContext, setIsSecureContext] = useState(() => window.isSecureContext);

  useEffect(() => {
    // Check for a previously entered username to pre-fill, if any. This doesn't imply registration.
    const prevUsername = localStorage.getItem('prevPasskeyUsername');
    if (prevUsername) {
      setUsername(prevUsername);
      // Optionally, check if this username has a registered passkey to set setIsPasskeyRegistered
      // This local check is just a UI hint. Server is the source of truth.
      if (localStorage.getItem(`passkeyCredential_${prevUsername}`)) {
          setIsPasskeyRegistered(true);
      }
    }
  }, [])

  const handlePasskeyRegister = async () => {
    if (!username) {
      setStatusMessage('Please enter a username to register.');
      return;
    }
    if (!isSecureContext) {
      setStatusMessage('Passkey operations require a secure context (HTTPS or localhost).');
      return;
    }
    setStatusMessage('Starting passkey registration...');
    localStorage.setItem('prevPasskeyUsername', username);

    try {
      // 1. Get registration options from server
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

      // Convert relevant fields from base64url to ArrayBuffer for the WebAuthn API
      const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: bufferDecode(options.challenge),
        user: {
          ...options.user,
          id: bufferDecode(options.user.id), // Server sends user.id as base64url
        },
        // Decode excludeCredentials if present
        excludeCredentials: options.excludeCredentials?.map(cred => ({
          ...cred,
          id: bufferDecode(cred.id),
          transports: cred.transports as AuthenticatorTransport[] | undefined,
           // Cast to satisfy type, assumes server sends valid transports
        })),
        // Ensure authenticatorSelection is correctly structured if provided
        authenticatorSelection: options.authenticatorSelection || {
            residentKey: "required", // Default to residentKey required for passkeys
            userVerification: "preferred",
        },
      };

      console.log("Registration options from server:", options);
      console.log("Parsed options for navigator.credentials.create:", publicKeyCredentialCreationOptions);


      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
      }) as PublicKeyCredential | null;

      if (!credential) {
        setStatusMessage('Passkey registration cancelled or failed at browser level.');
        return;
      }

      // 2. Send attestation response to server for verification
      const attestationResponseJSON = publicKeyCredentialToJSON(credential);
      console.log("Sending to /verify-registration:", { username, attestationResponse: attestationResponseJSON });

      const verificationResponse = await fetch(`${SERVER_URL}/verify-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, attestationResponse: attestationResponseJSON }),
      });

      const verificationData = await verificationResponse.json();

      if (verificationResponse.ok && verificationData.verified) {
        // Store a marker that this browser knows about a passkey for this user
        // This is mainly for UX, server is the source of truth.
        localStorage.setItem(`passkeyCredential_${username}`, JSON.stringify({
           id: credential.id, // Store original ID (base64url string from credential)
           rawId: bufferEncode(credential.rawId), // Store rawId as base64url
        }));

        setIsPasskeyRegistered(true);
        setIsPasskeyLoggedIn(true); // Auto-login after registration
        setStatusMessage(`Passkey registered successfully for ${username}! You are now logged in.`);
        console.log("Registration Succeeded on Server:", verificationData);
      } else {
        throw new Error(verificationData.error || 'Passkey verification failed on server.');
      }

    } catch (error) {
      console.error('Passkey registration error:', error);
      let errorMessage = "Registration failed";
      if (error instanceof Error) errorMessage += `: ${error.message}`;
      else errorMessage += `: ${String(error)}`;
      setStatusMessage(errorMessage);
      setIsPasskeyRegistered(false); // Ensure state reflects failure
      setIsPasskeyLoggedIn(false);
    }
  };

  const handlePasskeyLogin = async () => {
    if (!isSecureContext) {
      setStatusMessage('Passkey operations require a secure context (HTTPS or localhost).');
      return;
    }
    setStatusMessage('Attempting passkey login...');

    try {
      // 1. Get authentication options from server
      // Pass username if available, server can use it as a hint or for non-discoverable credentials
      const authOptionsResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(username ? { username } : {}), // Send username if available
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
          transports: cred.transports as AuthenticatorTransport[] | undefined, // Cast to satisfy type
        })),
        userVerification: options.userVerification || "preferred",
        timeout: options.timeout || 60000,
      };

      console.log("Authentication options from server:", options);
      console.log("Parsed options for navigator.credentials.get:", publicKeyCredentialRequestOptions);

      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
      }) as PublicKeyCredential | null;

      if (!assertion) {
        setStatusMessage('Passkey login cancelled or no assertion received from browser.');
        setIsPasskeyLoggedIn(false);
        return;
      }

      // 2. Send assertion to server for verification
      const assertionResponseJSON = publicKeyCredentialToJSON(assertion);
      console.log("Sending to /verify-authentication:", assertionResponseJSON);

      const verificationResponse = await fetch(`${SERVER_URL}/verify-authentication`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertionResponseJSON), // Server expects the full AssertionResponseJSON
      });

      const verificationData = await verificationResponse.json();

      if (verificationResponse.ok && verificationData.verified) {
        const loggedInUsername = verificationData.username; // Server should return username
        if (!loggedInUsername) {
            throw new Error("Server did not return a username on successful login.");
        }
        setUsername(loggedInUsername); // Update username from server
        setIsPasskeyLoggedIn(true);
        setStatusMessage(`Successfully logged in as ${loggedInUsername} with your passkey!`);
        localStorage.setItem('prevPasskeyUsername', loggedInUsername); // Remember for next visit

        console.log("Login Succeeded on Server:", verificationData);
      } else {
        setIsPasskeyLoggedIn(false);
        throw new Error(verificationData.error || 'Passkey authentication failed on server.');
      }

    } catch (error) {
      console.error('Passkey login error:', error);
      setIsPasskeyLoggedIn(false);
      let errorMessage = "Login failed";
      if (error instanceof Error) errorMessage += `: ${error.message}`;
      else errorMessage += `: ${String(error)}`;

      if (errorMessage.toLowerCase().includes("aborted") || errorMessage.toLowerCase().includes("cancelled")) {
          setStatusMessage("Passkey login cancelled by user.");
      } else if (errorMessage.toLowerCase().includes("notallowederror")) {
          setStatusMessage("Passkey operation not allowed. This might be due to security settings, or no matching passkeys found for the request.");
      } else if (errorMessage.toLowerCase().includes("failed to fetch") || errorMessage.toLowerCase().includes("server responded with")){
          setStatusMessage(`Login failed: Could not connect to server or server error. (${error.message})`);
      } else {
          setStatusMessage(errorMessage);
      }
    }
  };

  const handlePasskeyLogout = () => {
    setIsPasskeyLoggedIn(false);
    setStatusMessage('Logged out successfully.');
    // Optionally clear the username input: setUsername('');
    // Or keep localStorage.getItem('prevPasskeyUsername') for next login hint
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
        <button onClick={handlePasskeyLogout} className="action-button">Logout with Passkey</button>
        {statusMessage && <p className="status-message">{statusMessage}</p>}
      </div>
    );
  } else {
  return (
    <div className="passkey-container">
      <h3>Passkey Authentication</h3>
        <div>
          <input
            type="text"
            value={username}
            onChange={(e) => {
                setUsername(e.target.value);
                // If user types, we can't be sure if a passkey is registered for this specific name yet
                // until they try to register or login.
                // We can optimistically set isPasskeyRegistered if we find a credential for this username.
                if (localStorage.getItem(`passkeyCredential_${e.target.value}`)) {
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
        <button
            onClick={handlePasskeyRegister}
            className="action-button"
          >
            Register with Passkey
        </button>

        <button
            onClick={handlePasskeyLogin}
            className="action-button"
            disabled={!username}
            // Consider disabling if username is empty and no passkeys are generally known to exist,
            // but for discoverable credentials, username input is less critical for login initiation.
        >
          Login with Passkey
        </button>
      </div>

        {statusMessage && <p className="status-message">{statusMessage}</p>}

      <div className="debug-info">
          <p>Passkey known for '{username}' in browser storage: {isPasskeyRegistered ? 'Yes' : 'No'}</p>
      </div>
    </div>
    );
  }
}
