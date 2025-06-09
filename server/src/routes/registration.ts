import { Router, Request, Response } from 'express';
import {
  generateRegistrationOptions as simpleWebAuthnGenerateRegistrationOptions,
  verifyRegistrationResponse as simpleWebAuthnVerifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { RegistrationResponseJSON, PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server/script/deps';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
// decoding credential public keys
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { decodeAttestationObject, parseAuthenticatorData } from '@simplewebauthn/server/helpers';

import config, { DEFAULT_GAS_STRING, VERIFY_REGISTRATION_RESPONSE_GAS_STRING } from '../config';
import { userOperations } from '../database';
import { authenticatorService } from '../authenticatorService';
import { nearClient } from '../nearService';
import type { User } from '../types';

const router = Router();

// Interface for contract arguments (generate_registration_options)
interface ContractGenerateOptionsArgs {
  rp_name: string;
  rp_id: string;
  user_name: string;
  user_id: string; // Contract expects base64url encoded user_id from client (can be unique like passkey rawId)
  challenge: string | null; // Can be null to let contract generate
  user_display_name: string | null;
  timeout: number | null;
  attestation_type: string | null;
  exclude_credentials: { id: string; type: string; transports?: string[] }[] | null;
  authenticator_selection: ({ // Matches contract's AuthenticatorSelectionCriteria
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  }) | null;
  extensions: ({ cred_props?: boolean; }) | null; // Matches contract's AuthenticationExtensionsClientInputsJSON
  supported_algorithm_ids: number[] | null;
  preferred_authenticator_type: string | null;
}

// Interface for the response from contract's generate_registration_options
interface ContractRegistrationOptionsResponse {
  options: PublicKeyCredentialCreationOptionsJSON; // This is the standard WebAuthn options object
  nearAccountId: string | undefined;
  commitmentId: string | null;
}

// Interface for contract arguments (verify_registration_response)
interface ContractCompleteRegistrationArgs {
  registration_response: RegistrationResponseJSON; // The client's WebAuthn response
  commitment_id: string; // The commitment_id received from generate_registration_options
}

interface RegistrationSession {
  id: string;
  username: string;
  nearAccountId: string;
  status: 'pending' | 'contract_dispatched' | 'contract_confirmed' | 'error';
  result?: any;
  error?: string;
  timestamp: number;
}

// Store active registration sessions
const registrationSessions = new Map<string, RegistrationSession>();

// Cleanup old sessions every 5 minutes
setInterval(() => {
  const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
  for (const [id, session] of registrationSessions.entries()) {
    if (session.timestamp < fiveMinutesAgo) {
      registrationSessions.delete(id);
    }
  }
}, 5 * 60 * 1000);

// SSE clients for each session
const sseClients = new Map<string, Response[]>();

// Background user registration with progress updates
async function registerUserInContractWithProgress(
  sessionId: string,
  nearAccountId: string,
  username: string
): Promise<void> {
  try {
    console.log(`🔄 Background registration with progress: ${nearAccountId}`);

    // Update session and notify clients
    const session = registrationSessions.get(sessionId);
    if (session) {
      session.status = 'contract_dispatched';
      notifySSEClients(sessionId, {
        type: 'contract_dispatched',
        message: 'Contract call dispatched',
        nearAccountId,
        timestamp: Date.now()
      });
    }

    const account = nearClient.getRelayerAccount();
    const result = await account.functionCall({
      contractId: config.contractId,
      methodName: 'register_user',
      args: {
        user_id: nearAccountId,
        username: username
      },
      gas: BigInt(DEFAULT_GAS_STRING),
    });

    console.log(`✅ Background registration successful for ${nearAccountId}:`, result);

    // Update session and notify clients
    if (session) {
      session.status = 'contract_confirmed';
      session.result = result;
      notifySSEClients(sessionId, {
        type: 'contract_confirmed',
        message: 'Contract registration confirmed',
        nearAccountId,
        result: result,
        timestamp: Date.now()
      });

      // Clean up after successful completion
      setTimeout(() => {
        registrationSessions.delete(sessionId);
        sseClients.delete(sessionId);
      }, 30000); // 30 seconds
    }
  } catch (error) {
    console.error(`❌ Background registration failed for ${nearAccountId}:`, error);

    // Check if this is a method not found error (contract deployment issue)
    const isMethodNotFound = error instanceof Error &&
      (error.message.includes('MethodNotFound') || error.message.includes('method not found'));

    if (isMethodNotFound) {
      console.warn(`Method 'register_user' not found in contract. This likely means the contract needs to be redeployed with the latest code.`);
    }

    // Update session and notify clients
    const session = registrationSessions.get(sessionId);
    if (session) {
      session.status = 'error';
      session.error = isMethodNotFound
        ? 'Contract deployment issue - method not found'
        : (error instanceof Error ? error.message : String(error));
      notifySSEClients(sessionId, {
        type: 'error',
        message: isMethodNotFound
          ? 'Contract registration skipped (deployment issue)'
          : 'Contract registration failed',
        error: session.error,
        timestamp: Date.now()
      });
    }
  }
}

// Notify all SSE clients for a session
function notifySSEClients(sessionId: string, data: any) {
  const clients = sseClients.get(sessionId) || [];
  const message = `data: ${JSON.stringify(data)}\n\n`;

  clients.forEach((res, index) => {
    try {
      res.write(message);
    } catch (error) {
      console.error('Failed to write to SSE client:', error);
      // Remove failed client
      clients.splice(index, 1);
    }
  });
}

// SSE endpoint for registration progress
router.get('/registration-progress/:sessionId', (req: Request, res: Response) => {
  const { sessionId } = req.params;

  const session = registrationSessions.get(sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  // Set SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control',
  });

  // Add client to session
  if (!sseClients.has(sessionId)) {
    sseClients.set(sessionId, []);
  }
  sseClients.get(sessionId)!.push(res);

  // Send current status immediately
  const currentStatus = {
    type: 'status',
    status: session.status,
    message: `Current status: ${session.status}`,
    timestamp: Date.now()
  };
  res.write(`data: ${JSON.stringify(currentStatus)}\n\n`);

  // If already completed, send final result and close
  if (session.status === 'contract_confirmed') {
    const finalResult = {
      type: 'contract_confirmed',
      message: 'Registration completed',
      result: session.result,
      timestamp: Date.now()
    };
    res.write(`data: ${JSON.stringify(finalResult)}\n\n`);
    res.end();
    return;
  }

  if (session.status === 'error') {
    const errorResult = {
      type: 'error',
      message: 'Registration failed',
      error: session.error,
      timestamp: Date.now()
    };
    res.write(`data: ${JSON.stringify(errorResult)}\n\n`);
    res.end();
    return;
  }

  // Handle client disconnect
  req.on('close', () => {
    const clients = sseClients.get(sessionId) || [];
    const index = clients.indexOf(res);
    if (index !== -1) {
      clients.splice(index, 1);
    }
  });
});



// Generate registration options Endpoint
router.post('/generate-registration-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  const useOptimistic = (req.body as any).useOptimistic ?? config.useOptimisticAuth;

  if (!username) return res.status(400).json({ error: 'Username is required' });

  try {
    const resultFromService = await getRegistrationOptions(username, !useOptimistic && config.useContractMethod);

    const userForChallenge = userOperations.findByUsername(username);
    if (!userForChallenge) {
      console.error("User disappeared after options generation?");
      return res.status(500).json({ error: 'User context lost after options generation' });
    }

    if (!resultFromService.options || typeof resultFromService.options.challenge !== 'string') {
        console.error("Invalid result from getRegistrationOptions - missing options.challenge", resultFromService);
        throw new Error("Server failed to prepare valid registration options challenge.");
    }

    userOperations.updateChallengeAndCommitmentId(userForChallenge.id, resultFromService.options.challenge, resultFromService.commitmentId);

    const mode = useOptimistic ? 'FastAuth (Optimistic)' : 'SecureAuth (Contract Sync)';
    console.log(`Generated registration options for: ${username} using ${mode}. Sending to client:`, JSON.stringify(resultFromService, null, 2));

    // `resultFromService` already has the structure { options: {...}, nearAccountId, commitmentId }
    // which is what the frontend WebAuthnManager.getRegistrationOptions expects in serverResponseObject.
    return res.json(resultFromService);

  } catch (e: any) {
    console.error('Error in /generate-registration-options route:', e.message, e.stack, e.type, e.context, e.transaction_outcome);
    let errorMessage = e.message || 'Failed to generate registration options';
    if (e.transaction_outcome && e.transaction_outcome.outcome && e.transaction_outcome.outcome.status && typeof e.transaction_outcome.outcome.status.Failure === 'object') {
        const failure = e.transaction_outcome.outcome.status.Failure;
        // @ts-ignore
        const errorType = failure.ActionError?.kind?.FunctionCallError?.ExecutionError;
        if (errorType) {
            errorMessage = `Contract Execution Error: ${errorType}`;
        }
    }
    return res.status(500).json({ error: errorMessage });
  }
});

async function getRegistrationOptions(
  usernameInput: string,
  useContractMethod: boolean
): Promise<ContractRegistrationOptionsResponse> {
  let user: User | undefined = userOperations.findByUsername(usernameInput);
  const sanitizedUsername = usernameInput.toLowerCase().replace(/[^a-z0-9_\-]/g, '').substring(0, 32);
  const potentialNearAccountId = `${sanitizedUsername}.${config.relayerAccountId}`;

  if (!user) {
    // For a new user, their `id` will be used as `user.id` by SimpleWebAuthn
    // and as `user_id` (base64url) by the contract.
    const newUserId = `user_${Date.now()}_${isoBase64URL.fromBuffer(crypto.getRandomValues(new Uint8Array(8)))}`;
    const newUser: User = {
      id: newUserId,
      username: usernameInput,
      nearAccountId: potentialNearAccountId,
      currentChallenge: null,
      currentCommitmentId: null,
    };
    userOperations.create(newUser);
    user = newUser;
    console.log(`New user created for registration: ${usernameInput}, assigned ID: ${user.id}`);
  } else {
    if (!user.nearAccountId || !user.nearAccountId.endsWith(`.${config.relayerAccountId}`)) {
      userOperations.updateNearAccountId(user.id, potentialNearAccountId);
      user.nearAccountId = potentialNearAccountId;
    }
    console.log(`Existing user found for registration: ${usernameInput}, ID: ${user.id}`);
  }

      const rawAuthenticators = user.nearAccountId ?
      await authenticatorService.findByUserId(user.nearAccountId) : [];

  if (useContractMethod) {
    return getRegistrationOptionsContract(user, rawAuthenticators);
  } else {
    return getRegistrationOptionsSimpleWebAuthn(user, rawAuthenticators);
  }
}

// get registration options from SimpleWebAuthn (Fast mode)
async function getRegistrationOptionsSimpleWebAuthn(
  user: User,
  rawAuthenticators: any[]
): Promise<ContractRegistrationOptionsResponse> {
  console.log(`Using SimpleWebAuthn for registration options for user: ${user.username} (Fast mode)`);

  // generate options with SimpleWebAuthn to get a challenge
  const optionsFromSimpleWebAuthn = await simpleWebAuthnGenerateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: user.id,
    userName: user.username,
    userDisplayName: user.username,
    excludeCredentials: rawAuthenticators.map(auth => ({
      id: isoBase64URL.toBuffer(auth.credentialID),
      type: 'public-key' as const,
      transports: auth.transports ? (typeof auth.transports === 'string' ? auth.transports.split(',') : auth.transports) as AuthenticatorTransport[] : undefined,
    })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    supportedAlgorithmIDs: [-7, -257],
    attestationType: 'none',
    timeout: 60000,
  });

  // Return SimpleWebAuthn options immediately for fast user experience
  // No background contract sync needed - we'll handle contract integration during verification
  const response = {
    nearAccountId: user.nearAccountId || undefined,
    commitmentId: null, // FastAuth doesn't need commitmentId for options generation
    options: optionsFromSimpleWebAuthn,
  };

  console.log(`✅ FastAuth registration options generated for ${user.username} - no contract sync needed`);

  return response;
}

// NOTE: Removed syncChallengeWithContractInBackground function
// In FastAuth mode, we don't sync with contract during options generation
// This was causing double passkey prompts. Contract sync happens during verification instead.

// get registration options from NEAR Contract (Secure mode)
async function getRegistrationOptionsContract(
  user: User,
  rawAuthenticators: any[]
): Promise<ContractRegistrationOptionsResponse> {
  console.log(`Using NEAR contract for registration options for user: ${user.username}, userID for contract: ${user.id} (Secure mode)`);

  const authenticatorsForContractExclusion = rawAuthenticators.map(auth => ({
    id: auth.credentialID, // Contract expects base64url string id
    type: 'public-key' as const,
    transports: auth.transports ? (typeof auth.transports === 'string' ? auth.transports.split(',') : auth.transports).map((t: string) => String(t)) : undefined,
  }));

  const contractArgs: ContractGenerateOptionsArgs = {
    rp_name: config.rpName,
    rp_id: config.rpID,
    user_name: user.username, // For display and nearAccountId suggestion
    user_id: user.id, // This should be a unique, persistent base64url ID for the user (e.g., derived from initial passkey rawId or a server-generated UUID)
    challenge: null, // Let contract generate challenge
    user_display_name: user.username,
    timeout: 60000,
    attestation_type: "none", // Consistent with SimpleWebAuthn example
    exclude_credentials: authenticatorsForContractExclusion.length > 0 ? authenticatorsForContractExclusion : null,
    authenticator_selection: { residentKey: 'required', userVerification: 'preferred' },
    extensions: { cred_props: true }, // credProps is generally useful
    supported_algorithm_ids: [-7, -257], // ES256 and RS256
    preferred_authenticator_type: null, // Let user/browser decide or set based on UX preference
  };

  console.log('Calling contract.generate_registration_options with args:', JSON.stringify(contractArgs));

  const account = nearClient.getRelayerAccount();
  const rawResult: any = await account.callFunction({
    contractId: config.contractId,
    methodName: 'generate_registration_options',
    args: contractArgs,
    gas: BigInt(DEFAULT_GAS_STRING),
  });

  // Robust error checking for rawResult
  if (rawResult?.status && typeof rawResult.status === 'object' && 'Failure' in rawResult.status && rawResult.status.Failure) {
    const failure = rawResult.status.Failure;
    const executionError = (failure as any).ActionError?.kind?.FunctionCallError?.ExecutionError;
    const errorMessage = executionError || JSON.stringify(failure);
    console.error('Contract execution failed (panic or transaction error):', errorMessage);
    throw new Error(`Contract Error: ${errorMessage}`);
  }
  else if (rawResult && typeof (rawResult as any).error === 'object') { // Check for a direct error object from RPC call if not a standard FinalExecutionOutcome
    const rpcError = (rawResult as any).error;
    console.error('RPC/Handler error from contract.generate_registration_options call:', rpcError);
    const errorMessage = rpcError.message || rpcError.name || 'RPC error during generate_registration_options';
    const errorData = rpcError.data || JSON.stringify(rpcError.cause);
    throw new Error(`Contract Call RPC Error: ${errorMessage} (Details: ${errorData})`);
  }

  let contractResponseString: string;
  if (rawResult?.status && typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status && typeof rawResult.status.SuccessValue === 'string') {
    contractResponseString = Buffer.from(rawResult.status.SuccessValue, 'base64').toString();
  } else if (typeof rawResult === 'string' && rawResult.startsWith('{')) {
    contractResponseString = rawResult;
  } else {
    console.warn('Unexpected rawResult structure from generate_registration_options. Not a FinalExecutionOutcome with SuccessValue or a JSON string:', rawResult);
    throw new Error('Failed to parse contract response: Unexpected format.');
  }

  let contractResponse: ContractRegistrationOptionsResponse;
  try {
    contractResponse = JSON.parse(contractResponseString);
  } catch (parseError: any) {
    console.error('Failed to parse contractResponseString as JSON:', contractResponseString, parseError);
    throw new Error(`Failed to parse contract response JSON: ${parseError.message}`);
  }

  // Validate based on the nested options structure
  if (!contractResponse.options || !contractResponse.options.challenge || !contractResponse.options.rp || typeof contractResponse.commitmentId === 'undefined') {
    console.error('Invalid parsed response from contract.generate_registration_options (missing core fields or nested options):', contractResponse);
    throw new Error('Contract did not return valid core registration options (options.challenge, options.rp) or commitmentId field after parsing.');
  }

  return contractResponse;
}

// Background function to verify with contract and send SSE updates
async function verifyWithContractInBackground(
  username: string,
  attestationResponse: RegistrationResponseJSON,
  commitmentId: string
): Promise<void> {
  console.log(`🔄 Starting background contract verification for user: ${username}`);

  try {
    const contractResult = await verifyRegistrationResponseContract(attestationResponse, commitmentId);

    if (contractResult.verified) {
      console.log(`✅ Background contract verification succeeded for user: ${username}`);
      // Could send SSE notification here if needed
  } else {
      console.log(`❌ Background contract verification failed for user: ${username}`);
    }
  } catch (error: any) {
    console.error(`❌ Background contract verification error for user ${username}:`, error);
    throw error;
  }
}

// verifyRegistrationResponseSimpleWebAuthn (Fast mode)
async function verifyRegistrationResponseSimpleWebAuthn(
  attestationResponse: RegistrationResponseJSON,
  expectedChallenge: string
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using SimpleWebAuthn for registration verification (Fast mode)');
  const verification = await simpleWebAuthnVerifyRegistrationResponse({
    response: attestationResponse,
    expectedChallenge,
    expectedOrigin: config.expectedOrigin,
    expectedRPID: config.rpID,
    requireUserVerification: true,
  });
  return {
    verified: verification.verified,
    registrationInfo: verification.registrationInfo
  };
}

// Verify and complete registration via NEAR Contract (Secure mode)
async function verifyRegistrationResponseContract(
  attestationResponse: RegistrationResponseJSON,
  commitmentId: string // The commitment_id received from generate_registration_options
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using NEAR contract to complete registration with commitmentId:', commitmentId, '(Secure mode)');

  try {
    const account = nearClient.getRelayerAccount();
    const contractArgs: ContractCompleteRegistrationArgs = {
      registration_response: attestationResponse,
      commitment_id: commitmentId,
    };

    console.log("Calling contract.verify_registration_response with args:", JSON.stringify(contractArgs));

    const transactionOutcome = await account.functionCall({
      contractId: config.contractId,
      methodName: 'verify_registration_response',
      args: contractArgs,
      gas: BigInt(VERIFY_REGISTRATION_RESPONSE_GAS_STRING), // Use specific gas for this potentially complex call
    });

    console.log('Transaction outcome from verify_registration_response:', JSON.stringify(transactionOutcome, null, 2));

    // Check if the transaction itself was successful
    if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'Failure' in transactionOutcome.status) {
      // @ts-ignore
      const errorInfo = transactionOutcome.status.Failure.ActionError?.kind?.FunctionCallError?.ExecutionError || 'Unknown contract execution error';
      console.error("Contract verify_registration_response call failed:", errorInfo);
      throw new Error(`Contract verify_registration_response failed: ${errorInfo}`);
    }

    // Since we are no longer using yield-resume, the result is returned directly.
    // Ensure we are accessing the SuccessValue correctly from the status object.
    if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'SuccessValue' in transactionOutcome.status && transactionOutcome.status.SuccessValue) {
      const successValue = transactionOutcome.status.SuccessValue;
      const verificationResult = JSON.parse(Buffer.from(successValue, 'base64').toString());

      if (verificationResult && verificationResult.verified) {
          console.log("Contract verification successful. Registration Info:", verificationResult.registration_info);
      } else {
          console.warn("Contract verification failed or returned no data.");
      }

      // The result from the contract is already in the desired format.
      return {
        verified: verificationResult.verified,
        registrationInfo: verificationResult.registration_info,
      };
    } else {
      console.error("Contract call succeeded but did not return a SuccessValue.");
      throw new Error("Contract did not return a valid verification result.");
    }
  } catch (e: any) {
    console.error('Error calling contract verify_registration_response:', e.message, e.stack, e.type, e.context);
    throw new Error(`Failed to complete verify_registration via contract: ${e.message}`);
  }
}

// Enhanced SSE registration flow with step-by-step updates
async function handleRegistrationWithSSE(
  user: User,
  attestationResponse: RegistrationResponseJSON,
  expectedChallenge: string,
  storedCommitmentId: string | null,
  clientManagedNearPublicKey: string | null,
  useOptimistic: boolean,
  res: Response
): Promise<void> {
  const sessionId = `reg_${Date.now()}_${Math.random().toString(36).substring(2)}`;

  // Set SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control',
  });

  const sendSSEUpdate = (step: string, status: 'progress' | 'success' | 'error', data: any = {}) => {
    const message = {
      type: 'registration-update',
      sessionId,
      step,
      status,
      timestamp: Date.now(),
      ...data
    };
    res.write(`data: ${JSON.stringify(message)}\n\n`);
  };

  try {
    // Step 1: WebAuthn Verification
    sendSSEUpdate('webauthn-verification', 'progress', { message: 'Verifying WebAuthn credentials...' });

    let verificationResult: { verified: boolean; registrationInfo?: any };

    if (useOptimistic) {
      // Fast mode: Use SimpleWebAuthn immediately
      verificationResult = await verifyRegistrationResponseSimpleWebAuthn(attestationResponse, expectedChallenge);

      if (verificationResult.verified) {
        sendSSEUpdate('webauthn-verification', 'success', {
          message: 'WebAuthn verification successful (FastAuth)',
          mode: 'optimistic'
        });
      } else {
        throw new Error('WebAuthn verification failed');
      }
    } else {
      // Secure mode: Use contract verification
      if (!storedCommitmentId) {
        throw new Error('Missing commitment ID for secure verification');
      }
      verificationResult = await verifyRegistrationResponseContract(attestationResponse, storedCommitmentId);

      if (verificationResult.verified) {
        sendSSEUpdate('webauthn-verification', 'success', {
          message: 'WebAuthn verification successful (SecureAuth)',
          mode: 'secure'
        });
      } else {
        throw new Error('Contract verification failed');
      }
    }

    // Step 2: Send immediate success response for user login
    sendSSEUpdate('user-ready', 'success', {
      message: 'Registration verified - you can now log in!',
      verified: true,
      username: user.username,
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: clientManagedNearPublicKey,
      mode: useOptimistic ? 'FastAuth (Optimistic)' : 'SecureAuth (Contract Sync)'
    });

    // Step 3: Background database storage
    sendSSEUpdate('database-storage', 'progress', { message: 'Storing authenticator in database...' });

    const { verified, registrationInfo } = verificationResult;
    let credentialIDForDB: string;
    let publicKeyForDB: Uint8Array;
    let counterForDB: number;
    let credentialBackedUpForDB: boolean;

    if (useOptimistic) {
      const { credentialID, credentialPublicKey, counter, credentialBackedUp } = registrationInfo || {};
      if (!credentialID || !credentialPublicKey) {
        throw new Error('Incomplete registration info from SimpleWebAuthn');
      }
      credentialIDForDB = Buffer.from(credentialID).toString('base64url');
      publicKeyForDB = new Uint8Array(credentialPublicKey);
      counterForDB = counter || 0;
      credentialBackedUpForDB = credentialBackedUp || false;
    } else {
      const { credential_id: rawCredentialIDBuffer, credential_public_key: rawPublicKeyBuffer, counter, credentialBackedUp } = registrationInfo || {};
      if (!rawCredentialIDBuffer || !rawPublicKeyBuffer) {
        throw new Error('Incomplete registration info from contract');
      }
      credentialIDForDB = Buffer.from(rawCredentialIDBuffer).toString('base64url');
      publicKeyForDB = new Uint8Array(Buffer.from(rawPublicKeyBuffer));
      counterForDB = counter || 0;
      credentialBackedUpForDB = credentialBackedUp || false;
    }

    if (user.nearAccountId) {
      await authenticatorService.create({
        credentialID: credentialIDForDB,
        credentialPublicKey: publicKeyForDB,
        counter: counterForDB,
        transports: attestationResponse.response.transports || [],
        nearAccountId: user.nearAccountId,
        name: `Authenticator for ${user.username} (${attestationResponse.response.transports?.join('/') || 'unknown'})`,
        registered: new Date(),
        backedUp: credentialBackedUpForDB,
        clientManagedNearPublicKey: clientManagedNearPublicKey || null,
      });
    }

    sendSSEUpdate('database-storage', 'success', { message: 'Authenticator stored successfully' });

    // Step 4: Add access key to NEAR account
    if (clientManagedNearPublicKey && user.nearAccountId) {
      sendSSEUpdate('access-key-addition', 'progress', { message: 'Adding access key to NEAR account...' });

      try {
        // Check if account exists, create if not, and add access key
        const accountExists = await nearClient.checkAccountExists(user.nearAccountId);
        if (!accountExists) {
          console.log(`Account ${user.nearAccountId} does not exist. Creating with access key...`);
          const creationResult = await nearClient.createAccount(user.nearAccountId, clientManagedNearPublicKey);
          if (!creationResult.success) {
            throw new Error(`Failed to create account: ${creationResult.message}`);
          }
        } else {
          console.log(`Account ${user.nearAccountId} exists. Adding access key...`);
          const addKeyResult = await nearClient.addAccessKey(user.nearAccountId, clientManagedNearPublicKey);
          if (!addKeyResult.success) {
            throw new Error(`Failed to add access key: ${addKeyResult.message}`);
          }
        }

        sendSSEUpdate('access-key-addition', 'success', { message: 'Access key added to NEAR account successfully' });
      } catch (error: any) {
        console.error('Failed to add access key to NEAR account:', error);
        sendSSEUpdate('access-key-addition', 'error', {
          message: 'Failed to add access key (account still secured)',
          error: error.message
        });
      }
    }

    // Step 5: Background contract user registration (for optimistic mode)
    if (useOptimistic && user.nearAccountId) {
      sendSSEUpdate('contract-registration', 'progress', { message: 'Registering user in contract...' });

      try {
        await registerUserInContractWithProgress(sessionId, user.nearAccountId, user.username);
        sendSSEUpdate('contract-registration', 'success', { message: 'User registered in contract successfully' });
      } catch (error: any) {
        console.warn('Contract registration failed:', error);
        sendSSEUpdate('contract-registration', 'error', {
          message: 'Contract registration failed (non-fatal)',
          error: error.message
        });
      }
    }

    // Step 5: Final completion
    sendSSEUpdate('registration-complete', 'success', {
      message: 'Registration completed successfully!',
      sessionId
    });

    // Clear challenge
    userOperations.updateChallengeAndCommitmentId(user.id, null, null);

    res.end();

  } catch (error: any) {
    console.error('SSE Registration error:', error);
    sendSSEUpdate('registration-error', 'error', {
      message: error.message,
      error: error.message
    });

    // Clear challenge on error
    userOperations.updateChallengeAndCommitmentId(user.id, null, null);
    res.end();
  }
}

// Verify registration Endpoint - Modified for SSE
router.post('/verify-registration', async (req: Request, res: Response) => {
  const { username, attestationResponse, commitmentId, clientManagedNearPublicKey } = req.body as {
    username: string,
    attestationResponse: RegistrationResponseJSON,
    commitmentId?: string,
    useOptimistic?: boolean,
    clientManagedNearPublicKey?: string
  };

  const useOptimistic = (req.body as any).useOptimistic ?? config.useOptimisticAuth;

  console.log(`🔑 Registration verification for ${username}: clientManagedNearPublicKey = ${clientManagedNearPublicKey ? 'PROVIDED' : 'NOT PROVIDED'}`);
  if (clientManagedNearPublicKey) {
    console.log(`🔑 Client-managed NEAR public key: ${clientManagedNearPublicKey}`);
  }

  if (!username || !attestationResponse) {
    return res.status(400).json({ error: 'Username and attestationResponse are required' });
  }
  if (!useOptimistic && config.useContractMethod && !commitmentId) {
    return res.status(400).json({ error: 'commitmentId is required for contract method verification' });
  }

  try {
    const user = userOperations.findByUsername(username);
    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found or registration not initiated.` });
    }

    const expectedChallenge = user.currentChallenge;
    const storedCommitmentId = user.currentCommitmentId;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found. Registration might have timed out or was not initiated correctly.' });
    }
    if (!useOptimistic && config.useContractMethod && storedCommitmentId !== commitmentId) {
        console.warn(`commitmentId mismatch. Stored: ${storedCommitmentId}, Received: ${commitmentId}`);
    }

    // Handle registration via SSE
    await handleRegistrationWithSSE(
      user,
      attestationResponse,
      expectedChallenge,
      storedCommitmentId,
      clientManagedNearPublicKey || null,
      useOptimistic,
      res
    );

  } catch (e: any) {
    console.error('Error verifying registration:', e.message, e.stack);
    if (req.body.username) {
        const userToClear = userOperations.findByUsername(req.body.username);
        if (userToClear) userOperations.updateChallengeAndCommitmentId(userToClear.id, null, null);
    }
    return res.status(500).json({
      verified: false,
      error: e.message || 'Verification failed due to an unexpected server error.'
    });
  }
});

export default router;