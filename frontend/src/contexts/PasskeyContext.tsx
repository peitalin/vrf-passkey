import React, { createContext, useState, useContext, useCallback, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { SERVER_URL } from '../config';
import { bufferEncode, bufferDecode, publicKeyCredentialToJSON } from '../utils';
import { ActionType, type ServerRegistrationOptions, type ServerAuthenticationOptions, type SerializableActionArgs } from '../types';
import { getTestnetRpcProvider, view } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import { Near, Account, KeyPair, keyStores } from 'near-api-js';

// Configuration (replace with your actual values or from a config file)
const NEAR_NETWORK_ID = 'testnet';
const RPC_NODE_URL = 'https://rpc.testnet.near.org';
const PASSKEY_CONTROLLER_CONTRACT_ID = 'passkey-controller.testnet';
const DEFAULT_GAS_STRING = "300000000000000"; // Gas as a string for flexibility, convert to BigInt when needed

const HELLO_NEAR_CONTRACT_ID = 'cyan-loong.testnet';
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
  registerPasskey: (username: string) => Promise<{ success: boolean; error?: string; derivedNearPublicKey?: string | null; derpAccountId?: string | null }>;
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
  const [username, setUsername] = useState<string | null>(null);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [serverDerivedNearPK, setServerDerivedNearPK] = useState<string | null>(null);
  const [derpAccountId, setDerpAccountId] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string | null>('Context loaded.');
  const [currentGreeting, setCurrentGreeting] = useState<string | null>(null);

  const passkeyCryptoWorkerRef = useRef<Worker | null>(null);

  // Initialize Worker
  useEffect(() => {
    if (typeof window !== 'undefined' && !passkeyCryptoWorkerRef.current) {
        passkeyCryptoWorkerRef.current = new Worker(new URL('../passkeyCrypto.worker.ts', import.meta.url), { type: 'module' });
        console.log("PasskeyCryptoWorker initialized.");
        // Optional: Initial ready message from worker
        passkeyCryptoWorkerRef.current.onmessage = (event: MessageEvent) => {
            if (event.data.type === 'WORKER_READY') {
                console.log("Worker reported ready.");
                setStatusMessage("Crypto worker ready.");
            } else if (event.data.type === 'CRYPTO_ERROR') {
                console.error("Worker crypto init error:", event.data.payload.error);
                setStatusMessage(`Worker Init Error: ${event.data.payload.error}`);
            }
        };
        passkeyCryptoWorkerRef.current.onerror = (errEvent: ErrorEvent) => {
            console.error("Worker failed to initialize or unhandled error. Full event:", errEvent);
            const errorMessage = errEvent.message || `Worker error at ${errEvent.filename}:${errEvent.lineno}. Check browser console & network tab for worker script loading issues. Ensure correct MIME type.`;
            setStatusMessage(`Worker Failed: ${errorMessage}`);
        };
    }
    return () => {
      passkeyCryptoWorkerRef.current?.terminate();
      passkeyCryptoWorkerRef.current = null;
      console.log("PasskeyCryptoWorker terminated.");
    };
  }, []);

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
    const prevUsername = localStorage.getItem('prevPasskeyUsername');
    const prevDerpAccountId = localStorage.getItem('derpAccountId');
    if (prevUsername) {
      setUsername(prevUsername);
    }
    if (prevDerpAccountId) {
      setDerpAccountId(prevDerpAccountId);
    }
  }, []);

  useEffect(() => {
    if (isLoggedIn) {
      fetchCurrentGreeting();
    }
  }, [isLoggedIn, fetchCurrentGreeting]);

  const registerPasskey = useCallback(async (currentUsername: string): Promise<{ success: boolean; error?: string; derivedNearPublicKey?: string | null; derpAccountId?: string | null }> => {
    if (!currentUsername) {
      return { success: false, error: 'Username is required for registration.', derivedNearPublicKey: null, derpAccountId: null };
    }
    if (!window.isSecureContext || !crypto.subtle || !crypto.getRandomValues) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost) and Web Crypto API.', derivedNearPublicKey: null, derpAccountId: null };
    }
    if (!passkeyCryptoWorkerRef.current) {
      setStatusMessage('Crypto worker not initialized for registration.');
      return { success: false, error: 'Crypto worker not initialized.', derivedNearPublicKey: null, derpAccountId: null };
    }
    setIsProcessing(true);
    localStorage.setItem('prevPasskeyUsername', currentUsername);
    setStatusMessage('Registering passkey...');

    let userDerpAccountIdToUse: string | null = null;
    let generatedNearPublicKeyForChain: string | null = null;
    let serverWebAuthnVerifyData: any = null;
    let tempCredentialStore: PublicKeyCredential | null = null; // To store credential for use in Promise

    try {
      const regOptionsResponse = await fetch(`${SERVER_URL}/generate-registration-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUsername }),
      });
      if (!regOptionsResponse.ok) {
        const errorData = await regOptionsResponse.json().catch(() => ({ error: 'Failed to fetch reg options' }));
        throw new Error(errorData.error || `Server error ${regOptionsResponse.status}`);
      }
      const options: ServerRegistrationOptions & { derpAccountId?: string } = await regOptionsResponse.json();
      userDerpAccountIdToUse = options.derpAccountId || `${currentUsername.toLowerCase().replace(/[^a-z0-9]/g, '')}.passkeyfactory.testnet`;

      const pkCreationOpts: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: bufferDecode(options.challenge),
        user: { ...options.user, id: new TextEncoder().encode(options.user.id) },
        excludeCredentials: options.excludeCredentials?.map(c => ({ ...c, id: bufferDecode(c.id) })),
        authenticatorSelection: options.authenticatorSelection || { residentKey: "required", userVerification: "preferred" },
      };
      const credential = await navigator.credentials.create({ publicKey: pkCreationOpts }) as PublicKeyCredential | null;
      if (!credential || !(credential.response instanceof AuthenticatorAttestationResponse)) {
        throw new Error('Passkey creation cancelled or failed in browser.');
      }
      tempCredentialStore = credential; // Store for later use in promise
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

        if (!localStorage.getItem(`encrypted_near_key_${userDerpAccountIdToUse!}`)) {
          const newNearKeyPair = KeyPair.fromRandom('ed25519');
          const nearPrivateKeyString = newNearKeyPair.toString();
          generatedNearPublicKeyForChain = newNearKeyPair.getPublicKey().toString();

          console.log(`Client generated NEAR PK for ${userDerpAccountIdToUse}: ${generatedNearPublicKeyForChain}. Will attempt on-chain registration.`);
          setStatusMessage(`Client NEAR PK: ${generatedNearPublicKeyForChain}. Contacting crypto worker for encryption...`);

          passkeyCryptoWorkerRef.current.postMessage({
            type: 'ENCRYPT_PRIVATE_KEY',
            payload: {
              passkeyAttestationResponse: publicKeyCredentialToJSON(credential),
              nearPrivateKeyString: nearPrivateKeyString,
              derpAccountId: userDerpAccountIdToUse!,
            }
          });

          // This Promise now correctly wraps the entire async flow including worker and server call
          return new Promise(async (resolve, reject) => {
            if (!passkeyCryptoWorkerRef.current) {
              setIsProcessing(false);
              return reject({ success: false, error: "Worker became unavailable.", derivedNearPublicKey: null, derpAccountId: null });
            }

            const specificMessageHandler = async (event: MessageEvent) => {
                if (passkeyCryptoWorkerRef.current) {
                    passkeyCryptoWorkerRef.current.onmessage = null;
                    passkeyCryptoWorkerRef.current.onerror = null;
                }
                const { type: workerMsgType, payload: workerPayload } = event.data;
                if (workerMsgType === 'ENCRYPTION_SUCCESS') {
                    setStatusMessage('Local NEAR key encrypted and stored. Associating with account on server...');
                    console.log('Encrypted key stored for', userDerpAccountIdToUse);

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
                        if (associatePkResponse.ok && associatePkData.success) {
                            setStatusMessage('Passkey registered, local key encrypted, and NEAR PK associated on-chain.');
                            setDerpAccountId(userDerpAccountIdToUse!);
                            localStorage.setItem('derpAccountId', userDerpAccountIdToUse!);
                            // Store the client NEAR public key for later use
                            localStorage.setItem(`client_near_pk_${userDerpAccountIdToUse!}`, generatedNearPublicKeyForChain!);
                            setIsLoggedIn(true);
                            setUsername(currentUsername);
                            setServerDerivedNearPK(serverWebAuthnVerifyData.derivedNearPublicKey);
                            if (tempCredentialStore) { // Use stored credential
                                localStorage.setItem(`passkeyCredential_${currentUsername}`, JSON.stringify({ id: tempCredentialStore.id, rawId: bufferEncode(tempCredentialStore.rawId) }));
                            }
                            setIsProcessing(false);
                            resolve({ success: true, derivedNearPublicKey: serverWebAuthnVerifyData.derivedNearPublicKey, derpAccountId: userDerpAccountIdToUse });
                        } else {
                            throw new Error(associatePkData.error || 'Failed to associate client NEAR PK with server.');
                        }
                    } catch (associationError: any) {
                        console.error('Error associating client NEAR PK:', associationError);
                        setStatusMessage(`Error associating NEAR PK: ${associationError.message}`);
                        setIsProcessing(false);
                        reject({ success: false, error: associationError.message, derivedNearPublicKey: null, derpAccountId: null });
                    }
                } else if (workerMsgType === 'ENCRYPTION_FAILURE' || workerMsgType === 'CRYPTO_ERROR' || workerMsgType === 'ERROR') {
                    console.error('WORKER: Encryption failed or crypto error:', workerPayload.error);
                    setStatusMessage(`Encryption Error: ${workerPayload.error}`);
                    setIsProcessing(false);
                    reject({ success: false, error: workerPayload.error, derivedNearPublicKey: null, derpAccountId: null });
                }
            };
            const specificErrorHandler = (errEvent: ErrorEvent) => {
                if (passkeyCryptoWorkerRef.current) {
                    passkeyCryptoWorkerRef.current.onmessage = null;
                    passkeyCryptoWorkerRef.current.onerror = null;
                }
                console.error("Worker error during encryption setup:", errEvent);
                setStatusMessage(`Worker Error: ${errEvent.message}`);
                setIsProcessing(false);
                reject({ success: false, error: errEvent.message, derivedNearPublicKey: null, derpAccountId: null });
            };
            passkeyCryptoWorkerRef.current.onmessage = specificMessageHandler;
            passkeyCryptoWorkerRef.current.onerror = specificErrorHandler;
          });
        } else {
          setStatusMessage('Passkey registered. Existing local NEAR key found.');
          // If key already exists, we still need to set the main user states
          setDerpAccountId(userDerpAccountIdToUse!);
          localStorage.setItem('derpAccountId', userDerpAccountIdToUse!);
        setIsLoggedIn(true);
          setUsername(currentUsername);
          setServerDerivedNearPK(serverWebAuthnVerifyData.derivedNearPublicKey);
          if (tempCredentialStore) { // Use stored credential
            localStorage.setItem(`passkeyCredential_${currentUsername}`, JSON.stringify({ id: tempCredentialStore.id, rawId: bufferEncode(tempCredentialStore.rawId) }));
          }
        setIsProcessing(false);
          return { success: true, derivedNearPublicKey: serverWebAuthnVerifyData.derivedNearPublicKey, derpAccountId: userDerpAccountIdToUse };
        }
      } else {
        throw new Error(serverWebAuthnVerifyData.error || 'Passkey verification failed by server.');
      }
    } catch (err: any) {
      console.error('Registration error:', err);
      setStatusMessage(`Registration Error: ${err.message}`);
      setIsProcessing(false);
      return { success: false, error: err.message, derivedNearPublicKey: null, derpAccountId: null };
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

        const userDerpAccountIdFromLogin = verifyData.derpAccountId || options.derpAccountId || localStorage.getItem('derpAccountId') || `${bufferEncode(assertion.rawId).toLowerCase().substring(0,32)}.passkeyfactory.testnet`;
        setDerpAccountId(userDerpAccountIdFromLogin);
        localStorage.setItem('prevPasskeyUsername', loggedInUser);
        if (userDerpAccountIdFromLogin) localStorage.setItem('derpAccountId', userDerpAccountIdFromLogin);

        if (verifyData.clientManagedNearPublicKey) {
            console.log("Logged in. Server knows client-managed PK:", verifyData.clientManagedNearPublicKey, "for derp ID:", userDerpAccountIdFromLogin);
        } else if (localStorage.getItem(`encrypted_near_key_${userDerpAccountIdFromLogin}`)){
            console.log("Logged in. Found local encrypted key for derp ID:", userDerpAccountIdFromLogin, "but server did not return an associated clientManagedNearPublicKey.");
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

    if (!passkeyCryptoWorkerRef.current) {
        setStatusMessage('Crypto worker not initialized.');
        setIsProcessing(false);
        callbacks?.afterDispatch?.(false, { error: "Crypto worker not initialized for direct action." });
        return;
    }

    try {
      const passkeyChallenge = new Uint8Array(32);
      crypto.getRandomValues(passkeyChallenge);

      const pkRequestOpts: PublicKeyCredentialRequestOptions = {
        challenge: passkeyChallenge,
        userVerification: "required",
        timeout: 60000,
      };
      const passkeyAssertion = await navigator.credentials.get({ publicKey: pkRequestOpts }) as PublicKeyCredential | null;
      if (!passkeyAssertion || !(passkeyAssertion.response instanceof AuthenticatorAssertionResponse)) {
        throw new Error('Passkey authentication cancelled or failed for action.');
      }

      // Get access key info for nonce and block hash
      const provider = getRpcProvider();
      const publicKeyStr = localStorage.getItem(`client_near_pk_${derpAccountId}`);
      if (!publicKeyStr) {
        throw new Error('Client NEAR public key not found in localStorage');
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

      passkeyCryptoWorkerRef.current.postMessage({
        type: 'DECRYPT_AND_SIGN_TRANSACTION',
        payload: {
          derpAccountId,
          passkeyAssertionResponse: publicKeyCredentialToJSON(passkeyAssertion),
          receiverId: PASSKEY_CONTROLLER_CONTRACT_ID,
          contractMethodName: "execute_direct_actions",
          contractArgs: { action_to_execute: serializableActionForContract },
          gasAmount: DEFAULT_GAS_STRING,
          depositAmount: "0",
          nonce: nonce.toString(),
          blockHash: blockHash,
        }
      });

      const handleWorkerResponse = async (event: MessageEvent) => {
        if (passkeyCryptoWorkerRef.current) {
            passkeyCryptoWorkerRef.current.onmessage = null;
            passkeyCryptoWorkerRef.current.onerror = null;
        }

        const { type: workerMsgType, payload: workerPayload } = event.data;

        if (workerMsgType === 'SIGNATURE_SUCCESS') {
          setStatusMessage('Transaction signed. Sending to network...');

          try {
            const signedTransactionBorsh = new Uint8Array(workerPayload.signedTransactionBorsh);

            // Send transaction using fetch directly to the RPC endpoint
            const rpcResponse = await fetch(RPC_NODE_URL, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                jsonrpc: '2.0',
                id: 'dontcare',
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

          } catch (sendError: any) {
            console.error("Error sending transaction:", sendError);
            setStatusMessage(`Transaction Error: ${sendError.message}`);
            setIsProcessing(false);
            callbacks?.afterDispatch?.(false, { error: sendError.message });
          }

        } else if (workerMsgType === 'SIGNATURE_FAILURE' || workerMsgType === 'ERROR') {
          console.error('WORKER: Signing failed:', workerPayload.error);
          setStatusMessage(`Signing Error: ${workerPayload.error}`);
          setIsProcessing(false);
          callbacks?.afterDispatch?.(false, { error: workerPayload.error });
        }
      };

      const handleWorkerError = (errEvent: ErrorEvent) => {
        if (passkeyCryptoWorkerRef.current) {
            passkeyCryptoWorkerRef.current.onmessage = null;
            passkeyCryptoWorkerRef.current.onerror = null;
        }
        console.error("Worker error:", errEvent);
        setStatusMessage(`Worker Error: ${errEvent.message}`);
        setIsProcessing(false);
        callbacks?.afterDispatch?.(false, { error: errEvent.message });
      };

      if (passkeyCryptoWorkerRef.current) {
        passkeyCryptoWorkerRef.current.onmessage = handleWorkerResponse;
        passkeyCryptoWorkerRef.current.onerror = handleWorkerError;
      }

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