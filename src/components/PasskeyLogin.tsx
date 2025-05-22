import { useState, useEffect } from 'react'
import { useAccount, useConnect, useDisconnect, useSignMessage } from 'wagmi'
import { porto } from 'porto/wagmi'
import { Porto } from 'porto'
import { keccak256, toUtf8Bytes } from 'ethers/lib/utils'

export function PasskeyLogin() {
  const { address, isConnected } = useAccount()
  const { connect } = useConnect()
  const { disconnect } = useDisconnect()
  const { signMessage } = useSignMessage()
  const [message, setMessage] = useState('')
  const [signature, setSignature] = useState('')
  const [digestHash, setDigestHash] = useState('')
  const [isSigningUp, setIsSigningUp] = useState(false)
  const [isSecureContext, setIsSecureContext] = useState(() => window.isSecureContext)
  const [portoInstance, setPortoInstance] = useState<any>(null)

  // Initialize Porto instance
  useEffect(() => {
    try {
      const porto = Porto.create({
        debug: true, // Enable debugging
        name: 'Passkey Example App',
        url: window.location.origin,
        description: 'An example app demonstrating Porto passkey authentication',
      })

      console.log('Porto instance created:', porto)
      setPortoInstance(porto)
    } catch (error) {
      console.error('Failed to create Porto instance:', error)
    }
  }, [])

  // Function to handle passkey signup with Wagmi
  const handleWagmiSignup = async () => {
    try {
      console.log('Starting wagmi signup process')
      setIsSigningUp(true)

      // Create the Porto connector with debug logging
      const portoConnector = porto({
        options: {
          createAccount: true, // Force creation of a new account
          name: 'My Passkey App',
          url: window.location.origin,
          description: 'Sign up with a new passkey',
          debug: true, // Enable debug logging
        }
      })

      console.log('Porto connector created:', portoConnector)

      // Connect using the Porto connector
      console.log('Calling connect...')
      await connect({ connector: portoConnector })

      console.log('Connected successfully')
      setMessage('Passkey created successfully!')
    } catch (error) {
      console.error('Signup error:', error)
      setMessage(`Signup failed: ${error instanceof Error ? error.message : String(error)}`)
    } finally {
      setIsSigningUp(false)
    }
  }

  // Function to handle passkey login
  const handleLogin = async () => {
    try {
      console.log('Starting login process')

      // Create the Porto connector with debug logging
      const portoConnector = porto({
        options: {
          createAccount: false, // Use existing account
          name: 'My Passkey App',
          url: window.location.origin,
          description: 'Login with your passkey',
          debug: true, // Enable debug logging
        }
      })

      console.log('Porto connector created:', portoConnector)

      // Connect using the Porto connector
      console.log('Calling connect...')
      await connect({ connector: portoConnector })

      console.log('Connected successfully')
      setMessage('Logged in successfully!')
    } catch (error) {
      console.error('Login error:', error)
      setMessage(`Login failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // Function to create and sign a digest hash
  const signDigestHash = async () => {
    if (!address) return

    try {
      // Create a sample message to sign
      const messageToSign = `Hello, this is a test message signed at ${new Date().toISOString()}`

      // Create digest hash (keccak256 hash of the message)
      const hash = keccak256(toUtf8Bytes(messageToSign))
      setDigestHash(hash)

      // Sign the message using wagmi's useSignMessage hook
      const signResult = await signMessage({ message: messageToSign })

      if (signResult) {
        setSignature(signResult)
        setMessage('Message signed successfully!')
      }
    } catch (error) {
      console.error('Signing error:', error)
      setMessage(`Signing failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  if (isConnected) {
    return (
      <div className="passkey-container">
        <h2>Passkey Authentication</h2>
        <div className="account-info">
          <p><strong>Connected Address:</strong> {address}</p>
          <button onClick={() => disconnect()} className="disconnect-button">Disconnect</button>
        </div>

        <div className="sign-section">
          <h3>Sign Message</h3>
          <button onClick={signDigestHash} className="sign-button">Create and Sign Hash</button>

          {digestHash && (
            <div className="hash-display">
              <h4>Digest Hash:</h4>
              <p className="hash-value">{digestHash}</p>
            </div>
          )}

          {signature && (
            <div className="signature-display">
              <h4>Signature:</h4>
              <p className="signature-value">{signature}</p>
            </div>
          )}
        </div>

        {message && <p className="status-message">{message}</p>}
      </div>
    )
  }

  return (
    <div className="passkey-container">
      <h2>Passkey Authentication</h2>

      {!isSecureContext && (
        <div className="security-warning">
          <p>⚠️ Warning: You are not in a secure context (HTTPS).</p>
          <p>WebAuthn/Passkeys require HTTPS or localhost to function properly.</p>
          <p>Porto will attempt to use a popup fallback, but for the best experience use HTTPS.</p>
        </div>
      )}

      <div className="auth-buttons">

        <button
          onClick={() => {
            console.log('Wagmi Signup button clicked');
            handleWagmiSignup();
          }}
          disabled={isSigningUp}
          className="signup-button"
        >
          {isSigningUp ? 'Creating Passkey...' : 'Sign Up with Passkey (Wagmi)'}
        </button>

        <button
          onClick={() => {
            console.log('Login button clicked');
            handleLogin();
          }}
          className="login-button"
        >
          Login with Passkey
        </button>
      </div>

      {message && <p className="status-message">{message}</p>}

      <div className="debug-info">
        <p>Running in secure context: {isSecureContext ? 'Yes' : 'No'}</p>
        <p>Porto instance initialized: {portoInstance ? 'Yes' : 'No'}</p>
      </div>
    </div>
  )
}