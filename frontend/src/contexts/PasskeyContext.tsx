import React, { createContext, useState, useContext, useCallback, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { SERVER_URL } from '../config';
import { bufferEncode, bufferDecode, publicKeyCredentialToJSON } from '../utils';
import { ActionType, type ServerRegistrationOptions, type ServerAuthenticationOptions, type SerializableActionArgs } from '../types';
import { getTestnetRpcProvider, view } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import { Near, Account, KeyPair, keyStores } from 'near-api-js';
import { webAuthnManager } from '../security/WebAuthnManager';

import {
  RPC_NODE_URL,
  PASSKEY_CONTROLLER_CONTRACT_ID,
  DEFAULT_GAS_STRING,
  HELLO_NEAR_CONTRACT_ID
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
  registerPasskey: (username: string) => Promise<{ success: boolean; error?: string; derivedNearPublicKey?: string | null; derpAccountId?: string | null; transactionId?: string | null }>;
  loginPasskey: (username?: string) => Promise<{ success: boolean; error?: string; loggedInUsername?: string; derivedNearPublicKey?: string | null; derpAccountId?: string | null }>;
  logoutPasskey: () => void;
  executeServerAction: (
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

  // Remove the persistent worker reference - we'll create new workers on demand
  // const passkeyCryptoWorkerRef = useRef<Worker | null>(null);

  // Remove the worker initialization useEffect since we'll create workers on demand
  // useEffect(() => { ... }, []);


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
        account: HELLO_NEAR_CONTRACT_ID,
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

  const registerPasskey = useCallback(async (currentUsername: string): Promise<{ success: boolean; error?: string; derivedNearPublicKey?: string | null; derpAccountId?: string | null; transactionId?: string | null }> => {
    if (!currentUsername) {
      return { success: false, error: 'Username is required for registration.', derivedNearPublicKey: null, derpAccountId: null, transactionId: null };
    }
    if (!window.isSecureContext || !crypto.subtle || !crypto.getRandomValues) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost) and Web Crypto API.', derivedNearPublicKey: null, derpAccountId: null, transactionId: null };
    }
    setIsProcessing(true);

    // Store username in IndexedDB
    await webAuthnManager.storeUserData({
      username: currentUsername,
      lastUpdated: Date.now()
    });

    setStatusMessage('Registering passkey...');

    let userDerpAccountIdToUse: string | null = null;
    let generatedNearPublicKeyForChain: string | null = null;
    let serverWebAuthnVerifyData: any = null;
    let tempCredentialStore: PublicKeyCredential | null = null;
    let challengeId: string | null = null;

    try {
      // Get registration options from server via WebAuthnManager
      const {
        options,
        challengeId
      } = await webAuthnManager.getRegistrationOptions(currentUsername);
      userDerpAccountIdToUse = options.derpAccountId || `${currentUsername.toLowerCase().replace(/[^a-z0-9]/g, '')}.passkeyfactory.testnet`;

      const pkCreationOpts: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: bufferDecode(options.challenge), // Use server challenge
        user: { ...options.user, id: new TextEncoder().encode(options.user.id) },
        excludeCredentials: options.excludeCredentials?.map(c => ({ ...c, id: bufferDecode(c.id) })),
        authenticatorSelection: options.authenticatorSelection || { residentKey: "required", userVerification: "preferred" },
      };

      const credential = await navigator.credentials.create({ publicKey: pkCreationOpts }) as PublicKeyCredential | null;
      if (!credential || !(credential.response instanceof AuthenticatorAttestationResponse)) {
        throw new Error('Passkey creation cancelled or failed in browser.');
      }
      tempCredentialStore = credential;
      const attestationForServer = publicKeyCredentialToJSON(credential);

      const verifyResponse = await fetch(`${SERVER_URL}/verify-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUsername, attestationResponse: attestationForServer }),
      });
      serverWebAuthnVerifyData = await verifyResponse.json();

      if (verifyResponse.ok && serverWebAuthnVerifyData.verified) {
        if (serverWebAuthnVerifyData.derpAccountId) {
            userDerpAccountIdToUse = serverWebAuthnVerifyData.derpAccountId;
        }

        // Check if encrypted key already exists
        const hasExistingKey = await webAuthnManager.hasEncryptedKey(userDerpAccountIdToUse!);

        if (!hasExistingKey) {
          console.log(`No existing encrypted key found for ${userDerpAccountIdToUse}. Will generate new key in secure worker.`);
          setStatusMessage(`Generating new NEAR key pair securely...`);

          // Use WebAuthnManager for secure registration (key generation happens in WASM)
          const registrationResult = await webAuthnManager.secureRegistration(
            publicKeyCredentialToJSON(credential),
            {
              derpAccountId: userDerpAccountIdToUse!,
            },
            challengeId
          );

          if (registrationResult.success) {
            // Get the generated public key from the registration result
            generatedNearPublicKeyForChain = registrationResult.publicKey;

            setStatusMessage('NEAR key generated and encrypted securely. Associating with account on server...');
            console.log('Encrypted key stored for', userDerpAccountIdToUse, 'with public key:', generatedNearPublicKeyForChain);

            try {
              const associatePkResponse = await fetch(`${SERVER_URL}/api/associate-account-pk`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  username: currentUsername,
                  derpAccountId: userDerpAccountIdToUse!,
                  clientNearPublicKey: generatedNearPublicKeyForChain!
                }),
              });
              const associatePkData = await associatePkResponse.json();

              console.log('Associate PK API response:', associatePkData);

              if (associatePkResponse.ok && associatePkData.success) {
                // Check for various possible transaction ID field names
                const transactionId = associatePkData.transactionId ||
                                    associatePkData.txId ||
                                    associatePkData.transaction_id ||
                                    associatePkData.txHash ||
                                    associatePkData.transaction_hash ||
                                    associatePkData.tx_hash ||
                                    null;

                console.log('Extracted transaction ID:', transactionId);

                setStatusMessage('Passkey registered, local key encrypted, and NEAR PK associated on-chain.');
                setDerpAccountId(userDerpAccountIdToUse!);

                // Store user data in IndexedDB
                await webAuthnManager.storeUserData({
                  username: currentUsername,
                  derpAccountId: userDerpAccountIdToUse!,
                  clientNearPublicKey: generatedNearPublicKeyForChain!,
                  passkeyCredential: tempCredentialStore ? {
                    id: tempCredentialStore.id,
                    rawId: bufferEncode(tempCredentialStore.rawId)
                  } : undefined,
                  lastUpdated: Date.now()
                });

                setIsLoggedIn(true);
                setUsername(currentUsername);
                setServerDerivedNearPK(serverWebAuthnVerifyData.derivedNearPublicKey || generatedNearPublicKeyForChain);
                setIsProcessing(false);
                return { success: true, derivedNearPublicKey: serverWebAuthnVerifyData.derivedNearPublicKey, derpAccountId: userDerpAccountIdToUse, transactionId: transactionId };
              } else {
                throw new Error(associatePkData.error || 'Failed to associate client NEAR PK with server.');
              }
            } catch (associationError: any) {
              console.error('Error associating client NEAR PK:', associationError);
              setStatusMessage(`Error associating NEAR PK: ${associationError.message}`);
              setIsProcessing(false);
              return { success: false, error: associationError.message, derivedNearPublicKey: null, derpAccountId: null, transactionId: null };
            }
          } else {
            throw new Error('Secure registration failed');
          }
        } else {
          setStatusMessage('Passkey registered. Existing local NEAR key found.');
          setDerpAccountId(userDerpAccountIdToUse!);

          // Get existing user data to retrieve the client public key
          const existingUserData = await webAuthnManager.getUserData(currentUsername);
          const existingClientPublicKey = existingUserData?.clientNearPublicKey;

          // Store user data in IndexedDB
          await webAuthnManager.storeUserData({
            username: currentUsername,
            derpAccountId: userDerpAccountIdToUse!,
            clientNearPublicKey: existingClientPublicKey,
            passkeyCredential: tempCredentialStore ? {
              id: tempCredentialStore.id,
              rawId: bufferEncode(tempCredentialStore.rawId)
            } : undefined,
            lastUpdated: Date.now()
          });

          setIsLoggedIn(true);
          setUsername(currentUsername);
          setServerDerivedNearPK(serverWebAuthnVerifyData.derivedNearPublicKey || existingClientPublicKey);
          setIsProcessing(false);
          return { success: true, derivedNearPublicKey: serverWebAuthnVerifyData.derivedNearPublicKey, derpAccountId: userDerpAccountIdToUse, transactionId: null };
        }
      } else {
        throw new Error(serverWebAuthnVerifyData.error || 'Passkey verification failed by server.');
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      setStatusMessage(`Registration Error: ${err.message}`);
      setIsProcessing(false);
      return { success: false, error: err.message, derivedNearPublicKey: null, derpAccountId: null, transactionId: null };
    }
  }, [setDerpAccountId, setUsername, setIsLoggedIn, setServerDerivedNearPK, setStatusMessage, setIsProcessing]);

  const loginPasskey = useCallback(async (currentUsername?: string): Promise<{ success: boolean; error?: string; loggedInUsername?: string; derivedNearPublicKey?: string | null; derpAccountId?: string | null }> => {
    const userToLogin = currentUsername || username;
    if (!userToLogin) {
      return { success: false, error: 'Username might be needed for login.', loggedInUsername: null, derivedNearPublicKey: null, derpAccountId: null };
    }
    if (!window.isSecureContext) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost).', loggedInUsername: null, derivedNearPublicKey: null, derpAccountId: null };
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
      const verifyData = await verifyResponse.json();

      if (verifyResponse.ok && verifyData.verified) {
        const loggedInUser = verifyData.username;
        if (!loggedInUser) throw new Error("Login successful but server didn't return username.");
        setUsername(loggedInUser);
        setIsLoggedIn(true);
        setServerDerivedNearPK(verifyData.derivedNearPublicKey);

        // Get existing user data or create new
        let userData = await webAuthnManager.getUserData(loggedInUser);
        const userDerpAccountIdFromLogin = verifyData.derpAccountId || options.derpAccountId || userData?.derpAccountId || `${bufferEncode(assertion.rawId).toLowerCase().substring(0,32)}.passkeyfactory.testnet`;

        setDerpAccountId(userDerpAccountIdFromLogin);

        // Update user data in IndexedDB
        await webAuthnManager.storeUserData({
          username: loggedInUser,
          derpAccountId: userDerpAccountIdFromLogin,
          clientNearPublicKey: userData?.clientNearPublicKey || verifyData.clientManagedNearPublicKey,
          passkeyCredential: userData?.passkeyCredential,
          lastUpdated: Date.now()
        });

        if (verifyData.clientManagedNearPublicKey) {
            console.log("Logged in. Server knows client-managed PK:", verifyData.clientManagedNearPublicKey, "for derp ID:", userDerpAccountIdFromLogin);
        } else {
            const hasEncryptedKey = await webAuthnManager.hasEncryptedKey(userDerpAccountIdFromLogin);
            if (hasEncryptedKey) {
                console.log("Logged in. Found local encrypted key for derp ID:", userDerpAccountIdFromLogin, "but server did not return an associated clientManagedNearPublicKey.");
            }
        }

        setStatusMessage('Login successful.');
        setIsProcessing(false);
        return { success: true, loggedInUsername: loggedInUser, derivedNearPublicKey: verifyData.derivedNearPublicKey, derpAccountId: userDerpAccountIdFromLogin };
      } else {
        throw new Error(verifyData.error || 'Passkey authentication failed by server.');
      }
    } catch (err: any) {
      console.error('Login error:', err);
      setStatusMessage(`Login Error: ${err.message}`);
      setIsProcessing(false);
      return { success: false, error: err.message, loggedInUsername: null, derivedNearPublicKey: null, derpAccountId: null };
    }
  }, [username, setDerpAccountId, setUsername, setIsLoggedIn, setServerDerivedNearPK, setStatusMessage]);

  const logoutPasskey = useCallback(() => {
    setIsLoggedIn(false);
    setUsername(null);
    setServerDerivedNearPK(null);
    setCurrentGreeting(null);
    setDerpAccountId(null);
    setStatusMessage('Logged out.');
  }, [setStatusMessage]);

  const executeServerAction = useCallback(async (
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
      const execResp = await fetch(`${SERVER_URL}/api/execute-action`, {
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

    if (!isLoggedIn || !username || !derpAccountId) {
      setStatusMessage('User not logged in or DERP account ID not set.');
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: "User not logged in or DERP account ID missing for direct action." });
      return;
    }

    try {
      // Get authentication options from server via WebAuthnManager
      const { options, challengeId } = await webAuthnManager.getAuthenticationOptions(username);

      const pkRequestOpts: PublicKeyCredentialRequestOptions = {
        challenge: bufferDecode(options.challenge), // Use server challenge
        rpId: options.rpId,
        allowCredentials: options.allowCredentials?.map(c => ({ ...c, id: bufferDecode(c.id) })),
        userVerification: options.userVerification || "required",
        timeout: options.timeout || 60000,
      };
      const passkeyAssertion = await navigator.credentials.get({ publicKey: pkRequestOpts }) as PublicKeyCredential | null;
      if (!passkeyAssertion || !(passkeyAssertion.response instanceof AuthenticatorAssertionResponse)) {
        throw new Error('Passkey authentication cancelled or failed for action.');
      }

      // Get access key info for nonce and block hash
      const provider = getRpcProvider();

      // Get client NEAR public key from IndexedDB
      const userData = await webAuthnManager.getUserData(username);
      const publicKeyStr = userData?.clientNearPublicKey;
      if (!publicKeyStr) {
        throw new Error('Client NEAR public key not found in user data');
      }

      const accessKeyInfo = await provider.query({
        request_type: 'view_access_key',
        finality: 'final',
        account_id: derpAccountId,
        public_key: publicKeyStr,
      });

      const nonce = (accessKeyInfo as any).nonce + 1;
      const blockInfo = await provider.block({ finality: 'final' });
      const blockHash = blockInfo.header.hash;

      // Use WebAuthnManager for secure transaction signing
      const signingResult = await webAuthnManager.secureTransactionSigning(
        publicKeyCredentialToJSON(passkeyAssertion),
        {
          derpAccountId,
          receiverId: PASSKEY_CONTROLLER_CONTRACT_ID,
          contractMethodName: "execute_direct_actions",
          contractArgs: { action_to_execute: serializableActionForContract },
          gasAmount: DEFAULT_GAS_STRING,
          depositAmount: "0",
          nonce: nonce.toString(),
          blockHash: blockHash,
        },
        challengeId
      );

      setStatusMessage('Transaction signed. Sending to network...');

      const signedTransactionBorsh = new Uint8Array(signingResult.signedTransactionBorsh);

      // Send transaction using fetch directly to the RPC endpoint
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
      if (result.error) {
        throw new Error(result.error.message || 'RPC error');
      }

      console.log("Direct action transaction sent:", result);
      setStatusMessage('Direct action successful!');

      // If it was a set_greeting action, fetch the new greeting
      if (serializableActionForContract.method_name === 'set_greeting') {
        await fetchCurrentGreeting();
      }

      setIsProcessing(false);
      callbacks?.afterDispatch?.(true, result.result);

    } catch (error: any) {
      console.error('Execute direct action error:', error);
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
    executeServerAction,
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