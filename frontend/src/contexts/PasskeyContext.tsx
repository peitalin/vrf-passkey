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
  WEBAUTHN_CONTRACT_ID,
  MAX_CONCURRENT_TOASTS,
  MUTED_GREEN,
  MUTED_BLUE,
  MUTED_ORANGE
} from '../config';
import { useSettings } from './SettingsContext';
import { ClientUserManager } from '../services/ClientUserManager';
import toast from 'react-hot-toast';

// Toast queue management to limit concurrent toasts
const activeToasts = new Set<string>();


const managedToast = {
  loading: (message: string, options: any = {}) => {
    if (activeToasts.size >= MAX_CONCURRENT_TOASTS) {
      // Dismiss oldest toast to make room
      const [oldestToast] = activeToasts;
      toast.dismiss(oldestToast);
      activeToasts.delete(oldestToast);
    }
    const id = toast.loading(message, options);
    activeToasts.add(id);
    return id;
  },
  success: (message: string, options: any = {}) => {
    if (options.id) {
      // Update existing toast
      activeToasts.delete(options.id);
      const newId = toast.success(message, options);
      activeToasts.add(newId);
      return newId;
    } else {
      // New toast
      if (activeToasts.size >= MAX_CONCURRENT_TOASTS) {
        const [oldestToast] = activeToasts;
        toast.dismiss(oldestToast);
        activeToasts.delete(oldestToast);
      }
      const id = toast.success(message, options);
      activeToasts.add(id);
      return id;
    }
  },
  error: (message: string, options: any = {}) => {
    if (activeToasts.size >= MAX_CONCURRENT_TOASTS) {
      const [oldestToast] = activeToasts;
      toast.dismiss(oldestToast);
      activeToasts.delete(oldestToast);
    }
    const id = toast.error(message, options);
    activeToasts.add(id);
    return id;
  },
  dismiss: (id: string) => {
    toast.dismiss(id);
    activeToasts.delete(id);
  }
};


let frontendRpcProvider: Provider;

interface PasskeyState {
  isLoggedIn: boolean;
  username: string | null;
  nearPublicKey: string | null;
  nearAccountId: string | null;
  isProcessing: boolean;
  currentGreeting: string | null;
}

export interface ExecuteActionCallbacks {
  beforeDispatch?: () => void;
  afterDispatch?: (success: boolean, data?: any) => void;
  optimisticAuth?: boolean; // Override the global setting for this action
}

interface PasskeyContextType extends PasskeyState {
  setUsernameState: (username: string) => void;
  registerPasskey: (username: string) => Promise<{ success: boolean; error?: string; clientNearPublicKey?: string | null; nearAccountId?: string | null; transactionId?: string | null }>;
  loginPasskey: (username?: string) => Promise<{ success: boolean; error?: string; loggedInUsername?: string; clientNearPublicKey?: string | null; nearAccountId?: string | null }>;
  logoutPasskey: () => void;
  executeDirectActionViaWorker: (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ) => Promise<void>;
  fetchCurrentGreeting: () => Promise<{ success: boolean; greeting?: string; error?: string }>;
  optimisticAuth: boolean;
  setOptimisticAuth: (value: boolean) => void;
}

const PasskeyContext = createContext<PasskeyContextType | undefined>(undefined);

interface PasskeyContextProviderProps {
  children: ReactNode;
}

export const PasskeyContextProvider: React.FC<PasskeyContextProviderProps> = ({ children }) => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState<string | null>(null);
  const [nearPublicKey, setNearPublicKey] = useState<string | null>(null);
  const [nearAccountId, setNearAccountId] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentGreeting, setCurrentGreeting] = useState<string | null>(null);

  const { optimisticAuth, setOptimisticAuth, setCurrentUser } = useSettings();

  const getRpcProvider = () => {
    if (!frontendRpcProvider) {
      frontendRpcProvider = getTestnetRpcProvider();
    }
    return frontendRpcProvider;
  };

  const setUsernameState = (name: string) => {
    setUsername(name);
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
        // Get the last user from ClientUserManager
        const lastUser = ClientUserManager.getLastUser();
        if (lastUser) {
          setUsername(lastUser.username);
          setNearAccountId(lastUser.nearAccountId);
          setCurrentUser(lastUser.nearAccountId);

          // Update last login time
          ClientUserManager.updateLastLogin(lastUser.nearAccountId);

          // Also load the client-managed NEAR public key from WebAuthnManager
          try {
            const webAuthnUserData = await webAuthnManager.getUserData(lastUser.username);
            if (webAuthnUserData?.clientNearPublicKey) {
              setNearPublicKey(webAuthnUserData.clientNearPublicKey);
              console.log('Loaded client-managed NEAR public key from WebAuthnManager:', webAuthnUserData.clientNearPublicKey);
            } else {
              console.log('No client-managed NEAR public key found in WebAuthnManager for:', lastUser.username);
              setNearPublicKey(null);
            }
          } catch (webAuthnDataError) {
            console.warn('Failed to load WebAuthn user data, setting nearPublicKey to null:', webAuthnDataError);
            setNearPublicKey(null);
          }

          console.log('Loaded user data from ClientUserManager:', {
            username: lastUser.username,
            nearAccountId: lastUser.nearAccountId,
            registeredAt: new Date(lastUser.registeredAt).toISOString(),
          });
        } else {
          console.log('No previous user found in ClientUserManager');
        }
      } catch (error) {
        console.error('Error loading user data from ClientUserManager:', error);
      }
    };

    loadUserData();
  }, [setCurrentUser]);

  useEffect(() => {
    if (isLoggedIn) {
      fetchCurrentGreeting();
    }
  }, [isLoggedIn, fetchCurrentGreeting]);

  const registerPasskey = useCallback(async (currentUsername: string): Promise<{
    success: boolean;
    error?: string;
    clientNearPublicKey?: string | null;
    nearAccountId?: string | null;
    transactionId?: string | null
  }> => {
    console.log('🎯 registerPasskey CALLED for username:', currentUsername, 'at', new Date().toISOString());
    console.log('🎯 Current state:', { isProcessing, isLoggedIn, username });

    if (!currentUsername) {
      return { success: false, error: 'Username is required for registration.' };
    }
    if (!window.isSecureContext) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost).' };
    }

    // Prevent multiple concurrent registrations
    if (isProcessing) {
      console.warn('🚫 Registration already in progress, rejecting additional call');
      return { success: false, error: 'Registration already in progress. Please wait.' };
    }

    // Check if user already has credentials - warn but allow re-registration
    const existingUserData = await webAuthnManager.getUserData(currentUsername);
    if (existingUserData?.passkeyCredential) {
      console.warn(`⚠️ User '${currentUsername}' already has credential data. Attempting re-registration...`);
    }

    setIsProcessing(true);

    // Clear any existing challenges to prevent conflicts
    webAuthnManager.clearAllChallenges();

    try {
      console.log('🔄 Step 1: Starting WebAuthn credential creation & PRF...');
      console.log('🔍 Current processing state:', { isProcessing, currentUsername, optimisticAuth });

      // Show initial toast for Step 1
      const step1Toast = managedToast.loading('🔐 Step 1: Creating passkey with PRF...', {
        style: { background: MUTED_BLUE, color: 'white' },
        duration: 5000
      });

      // Step 1: WebAuthn credential creation & PRF (if applicable)
      const { credential, prfEnabled, commitmentId } = await webAuthnManager.registerWithPrf(currentUsername, optimisticAuth);
      const attestationForServer = publicKeyCredentialToJSON(credential);

      console.log('✅ Step 1 complete: WebAuthn credential created, PRF enabled:', prfEnabled);
      managedToast.success('✅ Step 1: Passkey created successfully', {
        id: step1Toast,
        style: { background: MUTED_GREEN, color: 'white' },
        duration: 5000
      });

      // Step 2: Client-side key generation/management using PRF output (if prfEnabled)
      console.log('🔄 Step 2: Starting client-side key generation...');
      // Dismiss step 1 toast to make room for processing toast
      managedToast.dismiss(step1Toast);
      const processingToast = managedToast.loading('🔐 Securing your account...', {
        style: { background: MUTED_BLUE, color: 'white' }
      });

      let clientManagedPublicKey: string | null = null;
      const userNearAccountIdToUse = ClientUserManager.generateNearAccountId(currentUsername, RELAYER_ACCOUNT_ID);

      if (prfEnabled) {
        const extensionResults = credential.getClientExtensionResults();
        const registrationPrfOutput = (extensionResults as any).prf?.results?.first;
        if (registrationPrfOutput) {
          // Call the WebAuthnManager method that uses PRF to generate/encrypt key
          // This method should return the public key string.
          const prfRegistrationResult = await webAuthnManager.secureRegistrationWithPrf(
            currentUsername,
            registrationPrfOutput,
            { nearAccountId: userNearAccountIdToUse },
            undefined, // challengeId not directly needed here as registerWithPrf handles it
            true // Skip challenge validation as WebAuthn ceremony just completed
          );
          if (prfRegistrationResult.success) {
            clientManagedPublicKey = prfRegistrationResult.publicKey;
            console.log('✅ Step 2 complete: Client-managed public key obtained/generated:', clientManagedPublicKey);
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

      // Step 3: Call server via SSE for verification and background processing
      console.log('🔄 Step 3: Starting SSE registration verification...');

      return new Promise((resolve, reject) => {
        // Store data for SSE request
        const verifyPayload = {
        username: currentUsername,
        attestationResponse: attestationForServer,
          commitmentId: commitmentId,
          useOptimistic: optimisticAuth,
          clientManagedNearPublicKey: clientManagedPublicKey,
        };

        // Use fetch but stream the response
        fetch(`${SERVER_URL}/verify-registration`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache',
          },
          body: JSON.stringify(verifyPayload),
        }).then(response => {
          if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
          }

          const reader = response.body?.getReader();
          if (!reader) {
            throw new Error('Unable to read response stream');
          }

          let buffer = '';
          let userLoggedIn = false;
          let finalResult = {
            success: false,
            clientNearPublicKey: clientManagedPublicKey,
            nearAccountId: userNearAccountIdToUse,
            transactionId: null as string | null
          };

          const processStream = () => {
            reader.read().then(({ value, done }) => {
              if (done) {
                console.log('🎉 SSE stream completed');
                if (userLoggedIn) {
                  resolve(finalResult);
                } else {
                  reject(new Error('Registration completed but user not logged in'));
                }
                return;
              }

              if (value) {
                buffer += new TextDecoder().decode(value);
                const lines = buffer.split('\n');
                buffer = lines.pop() || ''; // Keep incomplete line in buffer

                                 for (const line of lines) {
                   if (line.startsWith('data: ')) {
                     try {
                       const data = JSON.parse(line.substring(6));
                       console.log('📡 SSE Message:', data);

                                                                     // Update processing toast on first SSE message
                       if (data.step === 'webauthn-verification' && data.status === 'progress') {
                         managedToast.loading('🔐 Verifying credentials...', {
                           id: processingToast,
                           style: { background: MUTED_BLUE, color: 'white' }
                         });
                       }

                       switch (data.step) {
                         case 'webauthn-verification':
                           if (data.status === 'progress') {
                             console.log('🔄 Step 4: Verifying WebAuthn credentials...');
                             // Keep using the same processingToast
                           } else if (data.status === 'success') {
                             console.log('✅ Step 4: WebAuthn verification successful');
                             // Keep using the same processingToast
                           }
                           break;

                                                  case 'user-ready':
                           if (data.status === 'success') {
                             console.log('✅ Step 5: Registration verified - updating UI state...');
                             // Don't show toast here - will show combined message at step 6

                             // Update React state immediately for user login
                             setIsLoggedIn(true);
                             setUsername(currentUsername);
                             setNearAccountId(userNearAccountIdToUse);
                             setNearPublicKey(clientManagedPublicKey);
                             setCurrentUser(userNearAccountIdToUse);
                             setIsProcessing(false);

                             // Store user data locally
                             webAuthnManager.storeUserData({
          username: currentUsername,
                               nearAccountId: userNearAccountIdToUse,
          clientNearPublicKey: clientManagedPublicKey,
                               passkeyCredential: {
                                 id: credential.id,
                                 rawId: bufferEncode(credential.rawId)
                               },
          prfSupported: prfEnabled,
          lastUpdated: Date.now(),
      });

                             // Register user in ClientUserManager
                             ClientUserManager.registerUser(currentUsername, RELAYER_ACCOUNT_ID, {
                               preferences: {
                                 optimisticAuth: optimisticAuth,
                               },
                             });

                             userLoggedIn = true;
                             finalResult.success = true;
                           }
                           break;

                         case 'database-storage':
                           if (data.status === 'progress') {
                             console.log('🔄 Step 6a: Storing authenticator in database...');
                             managedToast.loading('✅ Account registered, storing authenticator...', {
                               id: processingToast,
                               style: { background: MUTED_BLUE, color: 'white' }
                             });
                           } else if (data.status === 'success') {
                             console.log('✅ Step 6a: Authenticator stored successfully');
                             managedToast.success('✅ Account registered, authenticator stored!', {
                               id: processingToast,
                               style: { background: MUTED_GREEN, color: 'white' },
                               duration: 5000
                             });
                           } else if (data.status === 'error') {
                             console.warn('⚠️ Step 6a: Database storage failed:', data.error);
                             managedToast.error('⚠️ Database storage failed (account still secured)', {
                               duration: 5000
                             });
                           }
                           break;

                         case 'access-key-addition':
                           if (data.status === 'progress') {
                             console.log('🔄 Step 6b: Creating NEAR account...');
                             managedToast.loading('🔑 Creating NEAR account...', {
                               style: { background: MUTED_BLUE, color: 'white' }
                             });
                           } else if (data.status === 'success') {
                             console.log('✅ Step 6b: NEAR account created successfully');
                             managedToast.success('✅ NEAR account created!', {
                               style: { background: MUTED_GREEN, color: 'white' },
                               duration: 5000
                             });
                           } else if (data.status === 'error') {
                             console.warn('⚠️ Step 6b: NEAR account creation failed:', data.error);
                             managedToast.error('⚠️ NEAR account creation failed (account still secured)', {
                               duration: 5000
                             });
                           }
                           break;

                                                  case 'contract-registration':
                           if (data.status === 'progress') {
                             console.log('🔄 Step 6c: Registering user in contract...');
                             managedToast.loading('📄 Finalizing registration...', {
                               style: { background: MUTED_BLUE, color: 'white' }
                             });
                           } else if (data.status === 'success') {
                             console.log('✅ Step 6c: User registered in contract successfully');
                             managedToast.success('✅ Registration finalized!', {
                               style: { background: MUTED_GREEN, color: 'white' },
                               duration: 5000
                             });
                           } else if (data.status === 'error') {
                             console.warn('⚠️ Step 6c: Contract registration failed (non-fatal):', data.error);
                             managedToast.error('⚠️ Registration finalization failed (account still secured)', {
                               duration: 5000
                             });
                           }
                           break;

                         case 'registration-complete':
                           if (data.status === 'success') {
                             console.log('🎉 Step 7: Registration completed successfully!');
                             managedToast.success(`🎉 Welcome ${currentUsername}! All setup complete!`, {
                               duration: 5000,
                               style: { background: MUTED_GREEN, color: 'white' }
                             });
                           }
                           break;

                         case 'registration-error':
                           console.error('❌ Registration error:', data.error);
                           reject(new Error(data.error || 'Registration failed'));
                           return;
                      }
                    } catch (parseError) {
                      console.warn('Failed to parse SSE message:', line);
                    }
                  }
                }
              }

              processStream(); // Continue reading
            }).catch(reject);
          };

          processStream();
        }).catch(reject);
      });

    } catch (err: any) {
      console.error('Registration error in PasskeyContext:', err.message, err.stack);

      // Handle specific WebAuthn errors
      let errorMessage = err.message;
      if (err.message?.includes('one of the credentials already registered')) {
        errorMessage = `A passkey for '${currentUsername}' already exists. Please try logging in instead, or clear your browser data to re-register.`;
      }

      setIsProcessing(false);
      return { success: false, error: errorMessage };
    }
  }, [optimisticAuth, setIsProcessing, setIsLoggedIn, setUsername, setNearAccountId, setNearPublicKey, setCurrentUser]);

  const loginPasskey = useCallback(async (currentUsername?: string): Promise<{ success: boolean; error?: string; loggedInUsername?: string; clientNearPublicKey?: string | null; nearAccountId?: string | null }> => {
    const userToLogin = currentUsername || username;
    if (!userToLogin) {
      return { success: false, error: 'Username is required for login.' };
    }
    if (!window.isSecureContext) {
      return { success: false, error: 'Passkey operations require a secure context (HTTPS or localhost).' };
    }
    setIsProcessing(true);

    try {
      // Step 1: Get authentication options from server
      const authOptionsResponse = await fetch(`${SERVER_URL}/generate-authentication-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userToLogin ? { username: userToLogin, useOptimistic: optimisticAuth } : { useOptimistic: optimisticAuth }),
      });
      if (!authOptionsResponse.ok) {
        const errorData = await authOptionsResponse.json().catch(() => ({ error: 'Failed to fetch auth options' }));
        throw new Error(errorData.error || `Server error ${authOptionsResponse.status}`);
      }

      const options: ServerAuthenticationOptions & { nearAccountId?: string; commitmentId?: string } = await authOptionsResponse.json();

      const commitmentId = options.commitmentId;
      console.log('PasskeyContext: Received authentication options with commitmentId:', commitmentId);

      // Step 2: Perform WebAuthn assertion ceremony
      const pkRequestOpts: PublicKeyCredentialRequestOptions = {
        challenge: bufferDecode(options.challenge),
        rpId: options.rpId,
        allowCredentials: options.allowCredentials?.map(c => ({ ...c, id: bufferDecode(c.id) })),
        userVerification: options.userVerification || "preferred",
        timeout: options.timeout || 60000,
      };
      const assertion = await navigator.credentials.get({ publicKey: pkRequestOpts }) as PublicKeyCredential | null;
      if (!assertion) throw new Error('Passkey login cancelled or no assertion.');

      // Step 3: Prepare verification payload
      const assertionJSON = publicKeyCredentialToJSON(assertion);
      const verificationPayload: any = {
        ...assertionJSON,
        commitmentId,
        useOptimistic: optimisticAuth,
      };

      // Step 4: Send assertion to server for verification
      const verifyResponse = await fetch(`${SERVER_URL}/verify-authentication`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(verificationPayload),
      });
      const serverVerifyData = await verifyResponse.json();

      if (verifyResponse.ok && serverVerifyData.verified) {
        const loggedInUsername = serverVerifyData.username;
        if (!loggedInUsername) throw new Error("Login successful but server didn't return username.");

        // Fetch comprehensive user data from local storage, which should include the clientNearPublicKey
        const localUserData = await webAuthnManager.getUserData(loggedInUsername);

        const finalNearAccountId = serverVerifyData.nearAccountId || localUserData?.nearAccountId;

        setIsLoggedIn(true);
        setUsername(loggedInUsername);
        setNearAccountId(finalNearAccountId);

        // Update ClientUserManager with login
        if (finalNearAccountId) {
          // Check if user exists in ClientUserManager, create if not
          let clientUser = ClientUserManager.getUser(finalNearAccountId);
          if (!clientUser) {
            console.log(`Creating ClientUserManager entry for existing user: ${loggedInUsername}`);
            clientUser = ClientUserManager.registerUser(loggedInUsername, RELAYER_ACCOUNT_ID);
          } else {
            // Update last login time
            ClientUserManager.updateLastLogin(finalNearAccountId);
          }

          // Update settings context
          setCurrentUser(finalNearAccountId);
        }

        // Set the UI-driving public key state from the locally stored clientNearPublicKey
        if (localUserData?.clientNearPublicKey) {
          setNearPublicKey(localUserData.clientNearPublicKey);
          console.log(`Login successful for ${loggedInUsername}. Client-managed PK set from local store: ${localUserData.clientNearPublicKey}`);
        } else {
          setNearPublicKey(null); // Explicitly set to null if not found
          console.warn(`User ${loggedInUsername} logged in, but no clientNearPublicKey found in local storage. Greeting functionality may be limited.`);
        }

        setIsProcessing(false);
        return {
          success: true,
          loggedInUsername,
          clientNearPublicKey: localUserData?.clientNearPublicKey || null,
          nearAccountId: finalNearAccountId
        };
      } else {
        throw new Error(serverVerifyData.error || 'Passkey authentication failed by server.');
      }
    } catch (err: any) {
      console.error('Login error in PasskeyContext:', err.message, err.stack);
      setIsProcessing(false);
      return { success: false, error: err.message };
    }
  }, [username, optimisticAuth, setIsProcessing, setIsLoggedIn, setUsername, setNearAccountId, setNearPublicKey]);

  const logoutPasskey = useCallback(() => {
    setIsLoggedIn(false);
    setUsername(null);
    setNearPublicKey(null);
    setCurrentGreeting(null);
    setNearAccountId(null);
    setCurrentUser(null); // Clear current user from settings
  }, [setIsLoggedIn, setUsername, setNearPublicKey, setCurrentGreeting, setNearAccountId, setCurrentUser]);

  const executeDirectActionViaWorker = useCallback(async (
    serializableActionForContract: SerializableActionArgs,
    callbacks?: ExecuteActionCallbacks
  ) => {
    callbacks?.beforeDispatch?.();
    setIsProcessing(true);
    console.log('[Direct Action] Initiating...', { serializableActionForContract });

    if (!isLoggedIn || !username || !nearAccountId) {
      const errorMsg = 'User not logged in or NEAR account ID not set for direct action.';
      console.error('[Direct Action] Error:', errorMsg, { isLoggedIn, username, nearAccountId });
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: errorMsg });
      return;
    }
    console.log('[Direct Action] User state validated:', { isLoggedIn, username, nearAccountId });

    try {
      // Check if user has PRF support
      const userData = await webAuthnManager.getUserData(username);
      const usesPrf = userData?.prfSupported === true;

      if (!usesPrf) {
        throw new Error('This application requires PRF support. Please use a PRF-capable authenticator.');
      }

      // Use the callback's auth mode if provided, otherwise fall back to global setting
      const authModeForThisAction = callbacks?.optimisticAuth ?? optimisticAuth;
      console.log('[Direct Action] User has PRF support, using PRF-based signing with auth mode:', authModeForThisAction ? 'FastAuth' : 'SecureAuth');

      // Step 1: Authenticate with PRF to get PRF output (must be first)
      const { credential: passkeyAssertion, prfOutput } = await webAuthnManager.authenticateWithPrf(username, 'signing', authModeForThisAction);

      if (!passkeyAssertion || !prfOutput) {
        throw new Error('PRF authentication failed or no PRF output');
      }

      console.log('[Direct Action] PRF authentication successful, starting concurrent operations...');

      // Get provider and public key synchronously
      const provider = getRpcProvider();
      const publicKeyStr = userData?.clientNearPublicKey;
      if (!publicKeyStr) {
        console.error('[Direct Action] Client NEAR public key not found in user data for user:', username);
        throw new Error('Client NEAR public key not found in user data');
      }
      console.log('[Direct Action] Client NEAR public key found:', publicKeyStr);

      // Steps 2, 3, 4: Run these operations concurrently for better performance
      const [
        { options, challengeId },
        accessKeyInfo,
        blockInfo
      ] = await Promise.all([
        // Step 2: Get authentication options
        webAuthnManager.getAuthenticationOptions(username, authModeForThisAction),

        // Step 3: Get access key info
        provider.query({
        request_type: 'view_access_key',
          finality: 'optimistic', // Use optimistic for more recent state
          account_id: nearAccountId,
        public_key: publicKeyStr,
        }),

        // Step 4: Get latest block info
        provider.viewBlock({ finality: 'final' })
      ]);

      console.log('[Direct Action] Concurrent operations completed');
      console.log('[Direct Action] Access key info received:', accessKeyInfo);

      const nonce = (accessKeyInfo as any).nonce + 1;
      const blockHashString = blockInfo.header.hash;
      const blockHashBytes = Array.from(bs58.decode(blockHashString));
      console.log('[Direct Action] Nonce and blockHash (base58) ready:', { nonce, blockHashString });

      console.log('[Direct Action] Calling secureTransactionSigningWithPrf...');
      const signingPayload = {
        nearAccountId,
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

      if (serializableActionForContract.method_name === 'set_greeting') {
        console.log('[Direct Action] Action was set_greeting, fetching new greeting...');
        await fetchCurrentGreeting();
      }

      setIsProcessing(false);
      callbacks?.afterDispatch?.(true, result.result);
      console.log('[Direct Action] Completed successfully.');

    } catch (error: any) {
      console.error('[Direct Action] Error during execution:', error);
      setIsProcessing(false);
      callbacks?.afterDispatch?.(false, { error: error.message });

    }
  }, [isLoggedIn, username, nearAccountId, fetchCurrentGreeting, setIsProcessing, optimisticAuth]);

  const value = {
    isLoggedIn,
    username,
    nearPublicKey,
    nearAccountId,
    isProcessing,
    currentGreeting,
    setUsernameState,
    registerPasskey,
    loginPasskey,
    logoutPasskey,
    executeDirectActionViaWorker,
    fetchCurrentGreeting,
    optimisticAuth: optimisticAuth,
    setOptimisticAuth: setOptimisticAuth,
  };

  return <PasskeyContext.Provider value={value}>{children}</PasskeyContext.Provider>;
};

export const usePasskeyContext = () => {
  const context = useContext(PasskeyContext);
  if (context === undefined) {
    throw new Error('usePasskeyContext must be used within a PasskeyContextProvider');
  }
  return context;
};