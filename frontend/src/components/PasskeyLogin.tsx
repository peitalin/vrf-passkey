import { useState, useEffect, useCallback } from 'react'
import { SERVER_URL } from '../config'
import { bufferEncode, bufferDecode, publicKeyCredentialToJSON } from '../utils'
import type { ServerRegistrationOptions, ServerAuthenticationOptions } from '../types'
import { nearService } from '../near'


export function PasskeyLogin() {
  const [username, setUsername] = useState('')
  const [isPasskeyRegistered, setIsPasskeyRegistered] = useState(false)
  const [isPasskeyLoggedIn, setIsPasskeyLoggedIn] = useState(false)
  const [statusMessage, setStatusMessage] = useState('')
  const [isSecureContext, setIsSecureContext] = useState(() => window.isSecureContext);

  // State for NEAR keys
  const [nearPublicKey, setNearPublicKey] = useState<string | null>(null);
  const [nearSecretKey, setNearSecretKey] = useState<string | null>(null); // WARNING: Storing secret keys in state/localStorage is insecure for production

  useEffect(() => {
    const prevUsername = localStorage.getItem('prevPasskeyUsername');
    if (prevUsername) {
      setUsername(prevUsername);
      if (localStorage.getItem(`passkeyCredential_${prevUsername}`)) {
        setIsPasskeyRegistered(true);
        // If user was previously logged in & passkey exists, try to load their NEAR keys
        const storedNearPK = localStorage.getItem(`nearPublicKey_${prevUsername}`);
        const storedNearSK = localStorage.getItem(`nearSecretKey_${prevUsername}`); // WARNING: Insecure
        if (storedNearPK) setNearPublicKey(storedNearPK);
        if (storedNearSK) setNearSecretKey(storedNearSK);
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

    let generatedNearKeys: { publicKey: string; secretKey: string } | null = null;
    try {
      generatedNearKeys = nearService.generateSeedPhrase();
      setNearPublicKey(generatedNearKeys.publicKey);
      setNearSecretKey(generatedNearKeys.secretKey); // WARNING: Insecure
      setStatusMessage(`Generated NEAR key pair for ${username}. Public Key: ${generatedNearKeys.publicKey}. Proceeding with passkey registration...`);
    } catch (keyError) {
      console.error("Error generating NEAR key pair:", keyError);
      setStatusMessage(`Failed to generate NEAR key pair: ${keyError instanceof Error ? keyError.message : String(keyError)}. Passkey registration aborted.`);
      return;
    }

    try {
      const regOptionsResponse = await fetch(`${SERVER_URL}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Send the generated NEAR public key as the username for the passkey, or associate it differently on your server
        body: JSON.stringify({ username /* or generatedNearKeys.publicKey if server expects that */ }),
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
          // The user ID for WebAuthn should be stable. If `username` can change, this might be an issue.
          // It's often derived from an immutable user ID from your backend.
          // For now, using the `username` from input, which we also use for localStorage keying.
          id: bufferDecode(options.user.id), // Server provides this, derived from username
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
        setNearPublicKey(null); // Clear keys if passkey reg fails
        setNearSecretKey(null);
        return;
      }

      const attestationResponseJSON = publicKeyCredentialToJSON(credential);
      const verificationResponse = await fetch(`${SERVER_URL}/verify-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Send username and attestation. Server should associate this with the user (and implicitly the NEAR keys if username is the link)
        body: JSON.stringify({ username, attestationResponse: attestationResponseJSON }),
      });
      const verificationData = await verificationResponse.json();
      if (verificationResponse.ok && verificationData.verified) {
        localStorage.setItem(`passkeyCredential_${username}`, JSON.stringify({
          id: credential.id,
          rawId: bufferEncode(credential.rawId),
        }));
        // Store NEAR keys in localStorage, associated with the username
        if (generatedNearKeys) {
            localStorage.setItem(`nearPublicKey_${username}`, generatedNearKeys.publicKey);
            localStorage.setItem(`nearSecretKey_${username}`, generatedNearKeys.secretKey); // WARNING: Insecure
        }
        setIsPasskeyRegistered(true);
        setIsPasskeyLoggedIn(true);
        // setUsername(username); // username is already set
        setStatusMessage(`Passkey registered for ${username} and linked with generated NEAR keys!`);
      } else {
        setNearPublicKey(null); // Clear keys if verification fails
        setNearSecretKey(null);
        localStorage.removeItem(`nearPublicKey_${username}`);
        localStorage.removeItem(`nearSecretKey_${username}`);
        throw new Error(verificationData.error || 'Passkey verification failed on server.');
      }
    } catch (error) {
      console.error('Passkey registration error:', error);
      setNearPublicKey(null); // Clear keys on any error during this block
      setNearSecretKey(null);
      localStorage.removeItem(`nearPublicKey_${username}`);
      localStorage.removeItem(`nearSecretKey_${username}`);
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
    setNearPublicKey(null); // Clear any existing keys before attempting login
    setNearSecretKey(null);
    try {
      const authOptionsResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(username ? { username } : {}), // Server should respond based on discoverable credentials if username is not sent
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
        if (!loggedInUsername) {
          throw new Error("Server did not return a username on successful login.");
        }
        setUsername(loggedInUsername); // Update username to what server verified
        setIsPasskeyLoggedIn(true);
        setStatusMessage(`Successfully logged in as ${loggedInUsername} with your passkey!`);
        localStorage.setItem('prevPasskeyUsername', loggedInUsername);

        // Retrieve NEAR keys from localStorage for the loggedInUsername
        const storedNearPK = localStorage.getItem(`nearPublicKey_${loggedInUsername}`);
        const storedNearSK = localStorage.getItem(`nearSecretKey_${loggedInUsername}`); // WARNING: Insecure
        if (storedNearPK) {
          setNearPublicKey(storedNearPK);
        } else {
          setStatusMessage(prev => prev + " (No NEAR Public Key found for this user. Was it registered?)");
        }
        if (storedNearSK) {
          setNearSecretKey(storedNearSK);
        } else {
          // No need to double message if PK is also missing
          if(storedNearPK) setStatusMessage(prev => prev + " (No NEAR Secret Key found. Cannot sign transactions.)");
        }

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
    setNearPublicKey(null); // Clear NEAR keys on logout
    setNearSecretKey(null);
    setStatusMessage('Logged out successfully from Passkey.');
    // Optionally, clear keys from localStorage too, but user might want them if they log back in
    // localStorage.removeItem(`nearPublicKey_${username}`);
    // localStorage.removeItem(`nearSecretKey_${username}`);
  }, [setIsPasskeyLoggedIn, setStatusMessage]);

  const handleSignNearTransaction = () => {
    if (!nearSecretKey) {
        setStatusMessage("Cannot sign: NEAR secret key not available.");
        return;
    }
    // Placeholder for actual NEAR transaction signing logic using nearSecretKey
    // This would involve using @near-js libraries to construct and sign a transaction.
    // For now, we'll just simulate it.
    setStatusMessage(`Simulating signing a NEAR transaction with Secret Key: ${nearSecretKey.substring(0,15)}...`);
    console.log("Simulating signing with NEAR Secret Key:", nearSecretKey);
    // In a real scenario:
    // 1. Create a KeyPair from secretKey: `KeyPair.fromString(nearSecretKey)`
    // 2. Get/create a Connection object (provider + signer with this KeyPair)
    // 3. Create an Account object using this connection and the associated nearPublicKey (or accountId derived from it)
    // 4. Construct transaction actions
    // 5. Call account.signAndSendTransaction(...)
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
        {nearPublicKey && (
          <div className="near-key-info" style={{margin: '1rem 0', padding: '0.5rem', border: '1px solid #eee', fontSize: '0.9em'}}>
            <p>Associated NEAR Public Key: {nearPublicKey}</p>
            {/* <p>Associated NEAR Secret Key: {nearSecretKey ? `${nearSecretKey.substring(0,15)}... (INSECURE - for demo only)` : 'Not available'}</p> */}
            {nearSecretKey &&
                <button onClick={handleSignNearTransaction} className="action-button" style={{backgroundColor: '#ffc107', color: 'black', marginTop: '0.5rem'}}>
                    Sign Dummy NEAR Transaction
                </button>
            }
          </div>
        )}
        <button onClick={handlePasskeyLogout} className="action-button">Logout with Passkey</button>
        {statusMessage && <p className="status-message">{statusMessage}</p>}
      </div>
    );
  } else {
    return (
      <div className="passkey-container">
        <h3>Passkey Authentication with NEAR Key Generation</h3>
        <div>
          <input
            type="text"
            value={username}
            onChange={(e) => {
              const newUsername = e.target.value;
              setUsername(newUsername);
              if (localStorage.getItem(`passkeyCredential_${newUsername}`)) {
                setIsPasskeyRegistered(true);
                 // Try to load keys if username changes and passkey exists for new username
                const storedNearPK = localStorage.getItem(`nearPublicKey_${newUsername}`);
                const storedNearSK = localStorage.getItem(`nearSecretKey_${newUsername}`);
                setNearPublicKey(storedNearPK);
                setNearSecretKey(storedNearSK);
              } else {
                setIsPasskeyRegistered(false);
                setNearPublicKey(null);
                setNearSecretKey(null);
              }
            }}
            placeholder="Enter username for passkey & NEAR account"
            className="styled-input"
          />
        </div>
        <div className="auth-buttons">
          <button onClick={handlePasskeyRegister} className="action-button"
            disabled={!username || isPasskeyRegistered}>
            {isPasskeyRegistered && username ? `Passkey Registered` : `Register Passkey & Gen NEAR Keys`}
          </button>
          <button onClick={handlePasskeyLogin} className="action-button"
            disabled={!username || !isPasskeyRegistered}>
            Login with Passkey
          </button>
        </div>
        {isPasskeyRegistered && <p style={{fontSize: '0.8em'}}>Passkey registered for '{username}'. Try Login.</p>}

        {statusMessage && <p className="status-message" style={{marginTop: '1rem'}}>{statusMessage}</p>}

        <div className="debug-info" style={{marginTop: '1rem'}}>
          <p>Username: {username}</p>
          <p>Passkey Registered for '{username}': {isPasskeyRegistered ? 'Yes' : 'No'}</p>
          <p>Passkey Logged In: {isPasskeyLoggedIn ? 'Yes' : 'No'}</p>
          <p>Generated/Loaded NEAR Public Key: {nearPublicKey || 'No'}</p>
          <p>Generated/Loaded NEAR Secret Key: {nearSecretKey ? 'Available (INSECURE - for demo)' : 'No'}</p>
        </div>
      </div>
    );
  }
}