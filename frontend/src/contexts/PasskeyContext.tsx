import React, { createContext, useState, useContext, useCallback, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { bufferEncode, bufferDecode, publicKeyCredentialToJSON } from '../utils';
import { type ServerAuthenticationOptions, type SerializableActionArgs } from '../types';
import { getTestnetRpcProvider, view } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import { webAuthnManager } from '../security/WebAuthnManager';
import bs58 from 'bs58';
import {
  SERVER_URL,
  RPC_NODE_URL,
  DEFAULT_GAS_STRING,
  RELAYER_ACCOUNT_ID,
  WEBAUTHN_CONTRACT_ID
} from '../config';



let frontendRpcProvider: Provider;

// Helper to convert ArrayBuffer to string (UTF-8)
function bufferSourceToString(bs: ArrayBuffer | ArrayBufferView): string {
    return new TextDecoder().decode(bs);
}

// PLACEHOLDER: Securely derive encryption key from attestation response
async function deriveEncryptionKeyFromAttestation(attestationResponse: AuthenticatorAttestationResponse): Promise<CryptoKey> {
  console.warn('MAIN_THREAD: Using insecure key derivation from attestation for demo. IMPLEMENT SECURE KDF.');
  const clientDataJSONStr = bufferSourceToString(attestationResponse.clientDataJSON);
  const clientData = JSON.parse(clientDataJSONStr);
  const challenge = clientData.challenge;
  const encoder = new TextEncoder();
  const simplisticInputForKeyMaterial = encoder.encode(challenge.slice(0, 16) + "_ENCRYPTION_SALT_DEMO_MAIN_THREAD");

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    simplisticInputForKeyMaterial,
    { name: "PBKDF2" },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: encoder.encode('main-thread-encryption-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// PLACEHOLDER: Securely encrypt data
async function encryptNearPrivateKeyWithDerivedKey(privateKeyString: string, encryptionKey: CryptoKey): Promise<{ encryptedData: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommended IV size
  const encodedPrivateKey = new TextEncoder().encode(privateKeyString);
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    encryptionKey,
    encodedPrivateKey
  );
  return {
    encryptedData: bufferEncode(encryptedBuffer), // Using your existing bufferEncode (base64url)
    iv: bufferEncode(iv.buffer), // Store IV as base64url
  };
}

// 1. Define Context State and Value Types
interface PasskeyState {
  isLoggedIn: boolean;
  username: string | null;
  serverDerivedNearPK: string | null;
  derpAccountId: string | null;
  isProcessing: boolean;
  statusMessage: string | null;
  currentGreeting: string | null;
}

// Define types for callbacks
export interface ExecuteActionCallbacks {
  beforeDispatch?: () => void;
  afterDispatch?: (success: boolean, data?: any) => void;
}

interface PasskeyContextType extends PasskeyState {
  setUsernameState: (username: string) => void;
  setDerpAccountIdState: (accountId: string) => void;
  registerPasskey: (username: string) => Promise<{ success: boolean; error?: string; clientNearPublicKey?: string | null; derpAccountId?: string | null; transactionId?: string | null }>;
  loginPasskey: (username?: string) => Promise<{ success: boolean; error?: string; loggedInUsername?: string; clientNearPublicKey?: string | null; derpAccountId?: string | null }>;
  logoutPasskey: () => void;
  executeDelegateActionViaServer: (
    actionToExecute: SerializableActionArgs,
    currentUsername: string,
    customGreeting?: string,
    callbacks?: ExecuteActionCallbacks
  ) => Promise<void>;
  executeDirectActionViaWorker: (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ) => Promise<void>;
  fetchCurrentGreeting: () => Promise<{ success: boolean; greeting?: string; error?: string }>;
}

// 2. Create Context
const PasskeyContext = createContext<PasskeyContextType | undefined>(undefined);

// 3. Create Context Provider Component
interface PasskeyContextProviderProps {
  children: ReactNode;
}

export const PasskeyContextProvider: React.FC<PasskeyContextProviderProps> = ({ children }) => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [serverDerivedNearPK, setServerDerivedNearPK] = useState<string | null>(null);
  const [derpAccountId, setDerpAccountId] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [currentGreeting, setCurrentGreeting] = useState<string | null>(null);


  const getRpcProvider = () => {
    if (!frontendRpcProvider) {
      frontendRpcProvider = getTestnetRpcProvider();
    }
    return frontendRpcProvider;
  };

  const setUsernameState = (name: string) => {
    setUsername(name);
  };
  const setDerpAccountIdState = (accountId: string) => {
    setDerpAccountId(accountId);
  };

  const fetchCurrentGreeting = useCallback(async () => {
    setIsProcessing(true);
    try {
      const provider = getRpcProvider();
      const result = await view({
        account: WEBAUTHN_CONTRACT_ID,
        method: 'get_greeting',
        args: {},
        deps: { rpcProvider: provider }
      });
      setCurrentGreeting(result as string);
      setIsProcessing(false);
      return { success: true, greeting: result as string };
    } catch (err: any) {
      console.error("Error fetching greeting directly:", err);
      setCurrentGreeting("Error fetching greeting.");
      setIsProcessing(false);
      return { success: false, error: err.message || 'Failed to fetch greeting.' };
    }
  }, []);

  useEffect(() => {
    const loadUserData = async () => {
      try {
        const lastUsername = await webAuthnManager.getLastUsedUsername();
        if (lastUsername) {
          setUsername(lastUsername);
          const userData = await webAuthnManager.getUserData(lastUsername);
          if (userData?.derpAccountId) {
            setDerpAccountId(userData.derpAccountId);
          }
        }
      } catch (error) {
        console.error('Error loading user data:', error);
      }
    };

    loadUserData();
  }, []);

  useEffect(() => {
    if (isLoggedIn) {
      fetchCurrentGreeting();
    }
  }, [isLoggedIn, fetchCurrentGreeting]);

  const registerPasskey = useCallback(async (currentUsername: string): Promise<{ success: boolean; error?: string; clientNearPublicKey?: string | null; derpAccountId?: string | null; transactionId?: string | null }> => {
    if (!currentUsername) {
      return { success: false, error: 'Username is required for registration.' };
    }
    if (!window.isSecureContext) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost).' };
    }
    setIsProcessing(true);
    setStatusMessage('Registering passkey...');

    try {
      // Step 1: WebAuthn credential creation & PRF (if applicable)
      // This now also returns the yieldResumeId needed for contract yield-resume.
      const { credential, prfEnabled, yieldResumeId: registrationyieldResumeId } = await webAuthnManager.registerWithPrf(currentUsername);
      const attestationForServer = publicKeyCredentialToJSON(credential);

      // Step 2: Client-side key generation/management using PRF output (if prfEnabled)
      // This part is crucial and would involve the wasm_worker via webAuthnManager
      let clientManagedPublicKey: string | null = null;
      const userDerpAccountIdToUse = `${currentUsername.toLowerCase().replace(/[^a-z0-9_\-]/g, '').substring(0, 32)}.${RELAYER_ACCOUNT_ID}`;

      if (prfEnabled) {
        const extensionResults = credential.getClientExtensionResults();
        const registrationPrfOutput = (extensionResults as any).prf?.results?.first;
        if (registrationPrfOutput) {
          // Call the WebAuthnManager method that uses PRF to generate/encrypt key
          // This method should return the public key string.
          const prfRegistrationResult = await webAuthnManager.secureRegistrationWithPrf(
            currentUsername,
            registrationPrfOutput,
            { derpAccountId: userDerpAccountIdToUse },
            undefined, // challengeId not directly needed here as registerWithPrf handles it
            true // Skip challenge validation as WebAuthn ceremony just completed
          );
          if (prfRegistrationResult.success) {
            clientManagedPublicKey = prfRegistrationResult.publicKey;
            console.log('PasskeyContext: Client-managed public key obtained/generated:', clientManagedPublicKey);
          } else {
            throw new Error('Client-side key generation/encryption with PRF failed.');
          }
        } else {
            // This case (PRF enabled but no output from registration) might require a second authN to get PRF output.
            // For simplicity, we assume PRF output is available from registration for this flow now.
            // Or, handle the two-touch ID prompt as discussed previously if necessary.
            console.warn("PRF was enabled, but no PRF output directly from registration. Key derivation might need separate authN.");
            // Fallback or error if direct PRF output not available and key is essential
            throw new Error("PRF output not available from registration, cannot derive client key this way.");
        }
      } else {
        // Handle non-PRF flow or throw error if PRF is mandatory
        throw new Error("PRF is required for this registration flow but not enabled/supported by authenticator.");
      }

      if (!clientManagedPublicKey) {
        throw new Error("Failed to obtain client-managed public key.");
      }

      // Step 3: Prepare payload for server's /verify-registration
      const verifyPayload: any = {
        username: currentUsername,
        attestationResponse: attestationForServer,
      };

      // Conditionally add yieldResumeId to the payload if using contract method
      if (!registrationyieldResumeId) {
        console.error('PasskeyContext: yieldResumeId is required for contract method verification but was not returned from registerWithPrf.');
        throw new Error('yieldResumeId is required for contract method verification but was not obtained during WebAuthn ceremony.');
      }
      verifyPayload.yieldResumeId = registrationyieldResumeId;
      console.log('PasskeyContext: Sending yieldResumeId to /verify-registration:', registrationyieldResumeId);

      // Step 4: Call server to verify WebAuthn attestation and store authenticator
      const verifyResponse = await fetch(`${SERVER_URL}/verify-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(verifyPayload),
      });
      const serverVerifyData = await verifyResponse.json();

      if (!verifyResponse.ok || !serverVerifyData.verified) {
        throw new Error(serverVerifyData.error || 'Passkey verification failed by server.');
      }
      console.log(`Server WebAuthn verification successful. DERP Account: ${userDerpAccountIdToUse}`);

      // Step 5: (Optional but recommended) Associate client public key with DERP account on-chain via server
      // This step makes the client-managed key an authorized key for the DERP account.
      let associationTransactionId: string | null = null;
      try {
        const associatePkResponse = await fetch(`${SERVER_URL}/api/associate-account-pk`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: currentUsername,
            derpAccountId: userDerpAccountIdToUse,
            clientNearPublicKey: clientManagedPublicKey
          }),
        });
        const associatePkData = await associatePkResponse.json();
        if (!associatePkResponse.ok || !associatePkData.success) {
          throw new Error(associatePkData.error || 'Failed to associate client NEAR PK with DERP account.');
        }
        associationTransactionId = associatePkData.transactionId || associatePkData.txId || null;
        console.log('Client PK associated with DERP account. Tx:', associationTransactionId);
      } catch (assocError: any) {
        console.warn('Failed to associate client PK with DERP account:', assocError.message);
        // Decide if this is a fatal error for registration or just a warning
      }

      // Step 6: Store user data locally (including client-managed key)
      await webAuthnManager.storeUserData({
          username: currentUsername,
          derpAccountId: userDerpAccountIdToUse,
          clientNearPublicKey: clientManagedPublicKey,
          passkeyCredential: { id: credential.id, rawId: bufferEncode(credential.rawId) },
          prfSupported: prfEnabled,
          lastUpdated: Date.now(),
      });

      // Step 7: Update React context state
      setIsLoggedIn(true);
      setUsername(currentUsername);
      setDerpAccountId(userDerpAccountIdToUse);
      setServerDerivedNearPK(clientManagedPublicKey); // Use the client-managed key for UI state
      setStatusMessage('Passkey registered, verified, and key managed successfully!');
      setIsProcessing(false);
      return {
          success: true,
          derpAccountId: userDerpAccountIdToUse,
          clientNearPublicKey: clientManagedPublicKey,
          transactionId: associationTransactionId
      };

    } catch (err: any) {
      console.error('Registration error in PasskeyContext:', err.message, err.stack);
      setStatusMessage(`Registration Error: ${err.message}`);
      setIsProcessing(false);
      return { success: false, error: err.message };
    }
  }, [setIsProcessing, setStatusMessage, setIsLoggedIn, setUsername, setDerpAccountId, setServerDerivedNearPK]);

  const loginPasskey = useCallback(async (currentUsername?: string): Promise<{ success: boolean; error?: string; loggedInUsername?: string; clientNearPublicKey?: string | null; derpAccountId?: string | null }> => {
    const userToLogin = currentUsername || username;
    if (!userToLogin) {
      return { success: false, error: 'Username is required for login.' };
    }
    if (!window.isSecureContext) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost).' };
    }
    setIsProcessing(true);
    setStatusMessage('Attempting passkey login...');

    try {
      const authOptionsResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userToLogin ? { username: userToLogin } : {}),
      });
      if (!authOptionsResponse.ok) {
        const errorData = await authOptionsResponse.json().catch(() => ({ error: 'Failed to fetch auth options' }));
        throw new Error(errorData.error || `Server error ${authOptionsResponse.status}`);
      }
      const options: ServerAuthenticationOptions & { derpAccountId?: string } = await authOptionsResponse.json();

      const pkRequestOpts: PublicKeyCredentialRequestOptions = {
        challenge: bufferDecode(options.challenge),
        rpId: options.rpId,
        allowCredentials: options.allowCredentials?.map(c => ({ ...c, id: bufferDecode(c.id) })),
        userVerification: options.userVerification || "preferred",
        timeout: options.timeout || 60000,
      };
      const assertion = await navigator.credentials.get({ publicKey: pkRequestOpts }) as PublicKeyCredential | null;
      if (!assertion) throw new Error('Passkey login cancelled or no assertion.');

      const assertionJSON = publicKeyCredentialToJSON(assertion);
      const verifyResponse = await fetch(`${SERVER_URL}/verify-authentication`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(assertionJSON),
      });
      const serverVerifyData = await verifyResponse.json();

      if (verifyResponse.ok && serverVerifyData.verified) {
        const loggedInUsername = serverVerifyData.username;
        if (!loggedInUsername) throw new Error("Login successful but server didn't return username.");

        // Fetch comprehensive user data from local storage, which should include the clientNearPublicKey
        const localUserData = await webAuthnManager.getUserData(loggedInUsername);

        setIsLoggedIn(true);
        setUsername(loggedInUsername);
        setDerpAccountId(serverVerifyData.derpAccountId || localUserData?.derpAccountId);

        // Set the UI-driving public key state from the locally stored clientNearPublicKey
        if (localUserData?.clientNearPublicKey) {
          setServerDerivedNearPK(localUserData.clientNearPublicKey);
          console.log(`Login successful for ${loggedInUsername}. Client-managed PK set from local store: ${localUserData.clientNearPublicKey}`);
        } else {
          setServerDerivedNearPK(null); // Explicitly set to null if not found
          console.warn(`User ${loggedInUsername} logged in, but no clientNearPublicKey found in local storage. Greeting functionality may be limited.`);
        }

        setStatusMessage('Login successful.');
        setIsProcessing(false);
        return {
          success: true,
          loggedInUsername,
          clientNearPublicKey: localUserData?.clientNearPublicKey || null,
          derpAccountId: serverVerifyData.derpAccountId || localUserData?.derpAccountId
        };
      } else {
        throw new Error(serverVerifyData.error || 'Passkey authentication failed by server.');
      }
    } catch (err: any) {
      console.error('Login error in PasskeyContext:', err.message, err.stack);
      setStatusMessage(`Login Error: ${err.message}`);
      setIsProcessing(false);
      return { success: false, error: err.message };
    }
  }, [username, setIsProcessing, setStatusMessage, setIsLoggedIn, setUsername, setDerpAccountId, setServerDerivedNearPK]);

  const logoutPasskey = useCallback(() => {
    setIsLoggedIn(false);
    setUsername(null);
    setServerDerivedNearPK(null);
    setCurrentGreeting(null);
    setDerpAccountId(null);
    setStatusMessage('Logged out.');
  }, [setStatusMessage]);

  const executeDelegateActionViaServer = useCallback(async (
    actionToExecute: SerializableActionArgs,
    currentUsernameForAction: string,
    customGreeting?: string,
    callbacks?: ExecuteActionCallbacks
  ) => {
    callbacks?.beforeDispatch?.();
    setIsProcessing(true);
    setStatusMessage('Executing server action...');
    let success = false;
    let responseData: any = null;

    if (!isLoggedIn || !currentUsernameForAction) {
      setStatusMessage('User not logged in for action.');
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: "User not logged in for action." });
      return;
    }

    let finalAction = { ...actionToExecute };
    if (actionToExecute.method_name === 'set_greeting' && customGreeting !== undefined) {
        const newGreetingMessage = `${customGreeting.trim()} (updated: ${new Date().toLocaleTimeString()})`;
        finalAction.args = JSON.stringify({ greeting: newGreetingMessage });
    }

    try {
      const chalResp = await fetch(`${SERVER_URL}/api/action-challenge`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUsernameForAction, actionDetails: finalAction })
      });
      if (!chalResp.ok) {
        const errData = await chalResp.json().catch(() => ({}));
        responseData = errData;
        throw new Error(errData.error || `Challenge request failed: ${chalResp.statusText}`);
      }
      const chalOpts = await chalResp.json();
      const assertion = await navigator.credentials.get({ publicKey: {
        challenge: bufferDecode(chalOpts.challenge),
        rpId: chalOpts.rpId,
        allowCredentials: chalOpts.allowCredentials.map((c: any) => ({...c, id: bufferDecode(c.id)})),
        userVerification: chalOpts.userVerification, timeout: chalOpts.timeout
      }}) as PublicKeyCredential | null;
      if (!assertion) throw new Error('Action confirmation cancelled.');

      const passkeyAssert = publicKeyCredentialToJSON(assertion);
      const execResp = await fetch(`${SERVER_URL}/api/execute-delegate-action`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUsernameForAction, passkeyAssertion: passkeyAssert, actionToExecute: finalAction })
      });
      responseData = await execResp.json();
      if (execResp.ok && responseData.success) {
        if (finalAction.method_name === 'set_greeting') await fetchCurrentGreeting();
        success = true;
        setStatusMessage('Server action successful.');
      } else {
        throw new Error(responseData.error || 'Action execution failed on server.');
      }
    } catch (err: any) {
      console.error('Execute action error:', err);
      setStatusMessage(`Server Action Error: ${err.message}`);
      responseData = responseData || { error: err.message };
    } finally {
      setIsProcessing(false);
      callbacks?.afterDispatch?.(success, responseData);
    }
  }, [isLoggedIn, fetchCurrentGreeting, setStatusMessage]);

  const executeDirectActionViaWorker = useCallback(async (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ) => {
    callbacks?.beforeDispatch?.();
    setIsProcessing(true);
    setStatusMessage('Processing direct action...');
    console.log('[Direct Action] Initiating...', { serializableActionForContract });

    if (!isLoggedIn || !username || !derpAccountId) {
      const errorMsg = 'User not logged in or DERP account ID not set for direct action.';
      console.error('[Direct Action] Error:', errorMsg, { isLoggedIn, username, derpAccountId });
      setStatusMessage(errorMsg);
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: errorMsg });
      return;
    }
    console.log('[Direct Action] User state validated:', { isLoggedIn, username, derpAccountId });

    try {
      // Check if user has PRF support
      const userData = await webAuthnManager.getUserData(username);
      const usesPrf = userData?.prfSupported === true;

      if (!usesPrf) {
        throw new Error('This application requires PRF support. Please use a PRF-capable authenticator.');
      }

      console.log('[Direct Action] User has PRF support, using PRF-based signing');

      // Authenticate with PRF to get PRF output
      const { credential: passkeyAssertion, prfOutput } = await webAuthnManager.authenticateWithPrf(username, 'signing');

      if (!passkeyAssertion || !prfOutput) {
        throw new Error('PRF authentication failed or no PRF output');
      }

      const { options, challengeId } = await webAuthnManager.getAuthenticationOptions(username);

      const provider = getRpcProvider();
      console.log('[Direct Action] Fetching user data for public key...');
      const publicKeyStr = userData?.clientNearPublicKey;
      if (!publicKeyStr) {
        console.error('[Direct Action] Client NEAR public key not found in user data for user:', username);
        throw new Error('Client NEAR public key not found in user data');
      }
      console.log('[Direct Action] Client NEAR public key found:', publicKeyStr);

      console.log('[Direct Action] Fetching access key info for:', derpAccountId, publicKeyStr);
      const accessKeyInfo = await provider.query({
        request_type: 'view_access_key',
        finality: 'final',
        account_id: derpAccountId,
        public_key: publicKeyStr,
      });
      console.log('[Direct Action] Access key info received:', accessKeyInfo);

      const nonce = (accessKeyInfo as any).nonce + 1;
      console.log('[Direct Action] Fetching latest block info...');
      const blockInfo = await provider.block({ finality: 'final' });
      const blockHashString = blockInfo.header.hash;
      const blockHashBytes = Array.from(bs58.decode(blockHashString));
      console.log('[Direct Action] Nonce and blockHash (base58) ready:', { nonce, blockHashString });

      console.log('[Direct Action] Calling secureTransactionSigningWithPrf...');
      const signingPayload = {
        derpAccountId,
        receiverId: serializableActionForContract.receiver_id,
        contractMethodName: serializableActionForContract.method_name,
        contractArgs: JSON.parse(serializableActionForContract.args),
        gasAmount: serializableActionForContract.gas || DEFAULT_GAS_STRING,
        depositAmount: serializableActionForContract.deposit || "0",
        nonce: nonce.toString(),
        blockHashBytes: blockHashBytes,
      };

      const signingResult = await webAuthnManager.secureTransactionSigningWithPrf(
        username,
        prfOutput,
        signingPayload,
        challengeId
      );
      console.log('[Direct Action] PRF-based secure transaction signing result:', signingResult);

      // Continue with transaction broadcast...
      setStatusMessage('Transaction signed. Sending to network...');
      const signedTransactionBorsh = new Uint8Array(signingResult.signedTransactionBorsh);
      console.log('[Direct Action] Broadcasting transaction to RPC node:', RPC_NODE_URL);

      const rpcResponse = await fetch(RPC_NODE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 'some_id',
          method: 'broadcast_tx_commit',
          params: [Buffer.from(signedTransactionBorsh).toString('base64')]
        })
      });

      const result = await rpcResponse.json();
      console.log('[Direct Action] RPC response JSON:', result);
      if (result.error) {
        console.error('[Direct Action] RPC error:', result.error);
        throw new Error(result.error.data?.message || result.error.message || 'RPC error');
      }

      console.log("[Direct Action] Transaction sent successfully:", result);
      setStatusMessage('Direct action successful!');

      if (serializableActionForContract.method_name === 'set_greeting') {
        console.log('[Direct Action] Action was set_greeting, fetching new greeting...');
        await fetchCurrentGreeting();
      }

      setIsProcessing(false);
      callbacks?.afterDispatch?.(true, result.result);
      console.log('[Direct Action] Completed successfully.');

    } catch (error: any) {
      console.error('[Direct Action] Error during execution:', error);
      setStatusMessage(`Error: ${error.message}`);
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: error.message });
    }
  }, [isLoggedIn, username, derpAccountId, fetchCurrentGreeting, setStatusMessage, setIsProcessing]);

  const value = {
    isLoggedIn,
    username,
    serverDerivedNearPK,
    derpAccountId,
    isProcessing,
    statusMessage,
    currentGreeting,
    setUsernameState,
    setDerpAccountIdState,
    registerPasskey,
    loginPasskey,
    logoutPasskey,
    executeDelegateActionViaServer,
    executeDirectActionViaWorker,
    fetchCurrentGreeting,
  };

  return <PasskeyContext.Provider value={value}>{children}</PasskeyContext.Provider>;
};

// 4. Create Custom Hook to use Context
export const usePasskeyContext = () => {
  const context = useContext(PasskeyContext);
  if (context === undefined) {
    throw new Error('usePasskeyContext must be used within a PasskeyContextProvider');
  }
  return context;
};