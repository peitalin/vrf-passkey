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

import config, { DEFAULT_GAS_STRING, GENERATE_AUTHENTICATION_OPTIONS_GAS_STRING } from '../config';
import { userOperations } from '../database';
import { authenticatorService } from '../authenticatorService';
import { nearClient } from '../nearService';
import type { User } from '../types';
import type {
  GenerateRegistrationOptionsRequest,
  GenerateRegistrationOptionsResponse,
  VerifyRegistrationRequest,
  ContractGenerateRegistrationOptionsArgs,
  ContractRegistrationOptionsResponse,
  ContractVerifyRegistrationArgs
} from '../types/endpoints';
import type {
  RegistrationSSEEvent,
  RegistrationSession,
  BaseSSEEvent
} from '../types/sse';

const router = Router();

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

    // Use nearClient.callFunction() to go through the transaction queue
    const result = await nearClient.callFunction(
      config.contractId,
      'register_user',
      {
        user_id: nearAccountId,
        username: username
      },
      DEFAULT_GAS_STRING,
      '0'
    );

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
  const requestData = req.body as GenerateRegistrationOptionsRequest;
  const { accountId } = requestData;

  if (!accountId) return res.status(400).json({ error: 'accountId is required' });

  try {
    const resultFromService = await getRegistrationOptions(accountId);

    const userForChallenge = userOperations.findByNearAccountId(resultFromService.nearAccountId);
    if (!userForChallenge) {
      console.error("User disappeared after options generation?");
      return res.status(500).json({ error: 'User context lost after options generation' });
    }

    if (!resultFromService.options || typeof resultFromService.options.challenge !== 'string') {
        console.error("Invalid result from getRegistrationOptions - missing options.challenge", resultFromService);
        throw new Error("Server failed to prepare valid registration options challenge.");
    }

    userOperations.updateChallengeAndCommitmentId(
      userForChallenge.nearAccountId,
      resultFromService.options.challenge,
      resultFromService.commitmentId || null
    );

    console.log(
      `Generated registration options for: ${accountId} using Web2 mode. Sending to client:`,
      JSON.stringify(resultFromService, null, 2)
    );

    const response: GenerateRegistrationOptionsResponse = {
      options: resultFromService.options,
      nearAccountId: resultFromService.nearAccountId,
      commitmentId: resultFromService.commitmentId
    };

    return res.json(response);

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
  accountId: string
): Promise<ContractRegistrationOptionsResponse> {
  let user: User | undefined = userOperations.findByNearAccountId(accountId);

  if (!user) {
    const newUser: User = {
      nearAccountId: accountId,
    };
    userOperations.create(newUser);
    user = newUser;
    console.log(`New user created for registration: ${accountId}`);
  } else {
    console.log(`Existing user found for registration: ${accountId}`);
  }

  const rawAuthenticators = user.nearAccountId ?
    await authenticatorService.findByUserId(user.nearAccountId) : [];

  // Always use Web2 mode (SimpleWebAuthn)
  return getRegistrationOptionsSimpleWebAuthn(user, rawAuthenticators);
}

// get registration options from SimpleWebAuthn (Web2 mode)
async function getRegistrationOptionsSimpleWebAuthn(
  user: User,
  rawAuthenticators: any[]
): Promise<ContractRegistrationOptionsResponse> {
  const fullAccountId = user.nearAccountId;
  console.log(`Using SimpleWebAuthn for registration options for user: ${fullAccountId} (Web2 mode)`);

  // generate options with SimpleWebAuthn to get a challenge
  const optionsFromSimpleWebAuthn = await simpleWebAuthnGenerateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: fullAccountId, // Use the full account ID for clarity
    userName: fullAccountId,
    userDisplayName: fullAccountId,
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
  // Contract integration happens during verification in the background
  const response: ContractRegistrationOptionsResponse = {
    nearAccountId: user.nearAccountId,
    commitmentId: undefined, // Web2 mode doesn't need commitmentId for options generation
    options: optionsFromSimpleWebAuthn,
  };

  console.log(`✅ FastAuth registration options generated for ${user.nearAccountId}`);

  return response;
}

// verifyRegistrationResponseSimpleWebAuthn (Web2 Fast mode)
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

// Enhanced SSE registration flow with step-by-step updates
async function handleRegistrationWithSSE(
  user: User,
  attestationResponse: RegistrationResponseJSON,
  expectedChallenge: string,
  storedCommitmentId: string | null,
  clientNearPublicKey: string | null,
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

  const sendSSEUpdate = (stepNum: number, phase: string, status: 'progress' | 'success' | 'error', data: Partial<RegistrationSSEEvent> = {}) => {
    const message: RegistrationSSEEvent = {
      step: stepNum,
      sessionId,
      phase,
      status,
      timestamp: Date.now(),
      message: data.message || '',
      ...data
    } as RegistrationSSEEvent;
    res.write(`data: ${JSON.stringify(message)}\n\n`);
  };

  try {
    // Early validation: Check if account already exists
    if (clientNearPublicKey && user.nearAccountId) {
      const accountExists = await nearClient.checkAccountExists(user.nearAccountId);
      if (accountExists) {
        throw new Error(`Account ${user.nearAccountId} already exists. Please use a different username or login instead.`);
      }
    }

    // Step 1: WebAuthn Verification (always Web2 mode)
    sendSSEUpdate(1, 'webauthn-verification', 'progress', { message: 'Verifying WebAuthn credentials...' });

    // Web2 mode: Use SimpleWebAuthn immediately
    const verificationResult = await verifyRegistrationResponseSimpleWebAuthn(attestationResponse, expectedChallenge);

    if (verificationResult.verified) {
      sendSSEUpdate(1, 'webauthn-verification', 'success', {
        message: 'WebAuthn verification successful (Web2)',
        mode: 'web2'
      });
    } else {
      throw new Error('WebAuthn verification failed');
    }

    // Step 2: Send immediate success response for user login
    sendSSEUpdate(2, 'user-ready', 'success', {
      message: 'Registration verified - you can now log in!',
      verified: true,
      nearAccountId: user.nearAccountId,
      clientNearPublicKey: clientNearPublicKey,
      mode: 'Web2 (Background Contract Sync)'
    });

    // Steps 3, 4 & 5: Run database storage, account creation, and contract registration concurrently
    const concurrentTasks = [];

    // Task 1: Create NEAR account with access key (must complete first)
    if (clientNearPublicKey && user.nearAccountId) {
      sendSSEUpdate(3, 'access-key-addition', 'progress', { message: 'Creating NEAR account...' });
      try {
        const nearAccountId = user.nearAccountId!;
        console.log(`Creating account ${nearAccountId} with access key...`);
        const creationResult = await nearClient.createAccount(nearAccountId, clientNearPublicKey);
        if (!creationResult.success) {
          throw new Error(`Failed to create account: ${creationResult.message}`);
        }
        sendSSEUpdate(3, 'access-key-addition', 'success', { message: 'NEAR account created successfully' });
      } catch (error: any) {
        console.error('Failed to create NEAR account:', error);
        sendSSEUpdate(3, 'access-key-addition', 'error', {
          message: 'Failed to create NEAR account. Aborting remaining steps.',
          error: error.message
        });
        // Stop if account creation fails
        res.end();
        return Promise.resolve();
      }
    }

    // Task 2: Database storage (includes contract registration)
    const databaseTask = (async () => {
      sendSSEUpdate(4, 'database-storage', 'progress', { message: 'Storing authenticator in database...' });

      try {
        const { verified, registrationInfo } = verificationResult;
        let credentialIDForDB: string;
        let publicKeyForDB: Uint8Array;
        let counterForDB: number;
        let credentialBackedUpForDB: boolean;

        // Web2 mode: Extract from SimpleWebAuthn
        const { credentialID, credentialPublicKey, counter, credentialBackedUp } = registrationInfo || {};
        if (!credentialID || !credentialPublicKey) {
          throw new Error('Incomplete registration info from SimpleWebAuthn');
        }
        credentialIDForDB = Buffer.from(credentialID).toString('base64url');
        counterForDB = counter || 0;
        credentialBackedUpForDB = credentialBackedUp || false;

        // CRITICAL FIX: Extract proper COSE public key from attestation object
        // The credentialPublicKey from SimpleWebAuthn is not in COSE format
        // We need to extract the actual COSE key from the attestation object
        console.log('🔧 [COSE Key] Extracting proper COSE public key from attestation object');

        try {
          const attestationObject = decodeAttestationObject(isoBase64URL.toBuffer(attestationResponse.response.attestationObject));
          const authenticatorData = parseAuthenticatorData((attestationObject as any).authData);

          // The authenticatorData.credentialPublicKey should be the proper COSE key
          if (!authenticatorData.credentialPublicKey) {
            throw new Error('No credential public key found in authenticator data');
          }

          // Use the COSE public key from the attestation object
          publicKeyForDB = new Uint8Array(authenticatorData.credentialPublicKey);
          console.log('🔧 [COSE Key] Successfully extracted COSE public key:', publicKeyForDB.length, 'bytes');

          // Validate that this looks like a COSE key (should start with CBOR map indicator)
          if (publicKeyForDB.length > 0) {
            console.log('🔧 [COSE Key] COSE key first few bytes:', Array.from(publicKeyForDB.slice(0, 10)).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(' '));
          }

        } catch (coseError: any) {
          console.error('🔧 [COSE Key] Failed to extract COSE public key:', coseError.message);
          // Fallback to the original credentialPublicKey (this will likely fail in contract verification)
          publicKeyForDB = new Uint8Array(credentialPublicKey);
          console.warn('🔧 [COSE Key] Using fallback credentialPublicKey - this may cause contract verification failures');
        }

        if (user.nearAccountId) {
          console.log(`🔍 [Registration] Attempting to create authenticator for ${user.nearAccountId}`);

          // Send contract registration progress update
          sendSSEUpdate(5, 'contract-registration', 'progress', { message: 'Running contract registration...' });

          // Attempt to create the authenticator (writes to both contract and cache)
          const createSuccess = await authenticatorService.create({
            credentialID: credentialIDForDB,
            credentialPublicKey: publicKeyForDB,
            counter: counterForDB,
            transports: attestationResponse.response.transports || [],
            nearAccountId: user.nearAccountId,
            name: `Authenticator for ${user.nearAccountId} (${attestationResponse.response.transports?.join('/') || 'unknown'})`,
            registered: new Date(),
            backedUp: credentialBackedUpForDB,
            clientNearPublicKey: clientNearPublicKey ?? null,
          });

          if (!createSuccess) {
            console.error(`🔍 [Registration] Failed to create authenticator for ${user.nearAccountId}`);
            sendSSEUpdate(5, 'contract-registration', 'error', {
              message: 'Failed to register with contract',
              error: 'Failed to create authenticator in database/contract'
            });
            throw new Error('Failed to create authenticator in database/contract');
          }

          console.log(`🔍 [Registration] Authenticator created successfully for ${user.nearAccountId}`);
          sendSSEUpdate(4, 'database-storage', 'success', { message: 'Authenticator stored successfully' });
        }
      } catch (error: any) {
        console.error('Failed to store authenticator in database:', error);
        sendSSEUpdate(4, 'database-storage', 'error', {
          message: 'Failed to store authenticator in database',
          error: error.message
        });
        // Stop if database storage fails
        res.end();
        return Promise.resolve();
      }
    })();

    await databaseTask;

    // Step 6: Send final success response
    sendSSEUpdate(6, 'registration-complete', 'success', {
      message: 'Registration completed successfully',
      sessionId,
    });

    // Clean up session
    setTimeout(() => {
      registrationSessions.delete(sessionId);
      sseClients.delete(sessionId);
    }, 30000); // 30 seconds

  } catch (e: any) {
    console.error('Error handling registration:', e.message, e.stack);
    if (user.nearAccountId) {
        const userToClear = userOperations.findByNearAccountId(user.nearAccountId);
        if (userToClear) userOperations.updateChallengeAndCommitmentId(userToClear.nearAccountId, null, null);
    }
    sendSSEUpdate(0, 'registration-error', 'error', {
      message: 'Registration failed due to an unexpected server error.',
      error: e.message || 'Unknown error'
    });
    res.end();
  }
}

// Verify registration Endpoint - Modified for SSE
router.post('/verify-registration', async (req: Request, res: Response) => {
  const {
    accountId,
    attestationResponse,
    commitmentId,
    clientNearPublicKey
  } = req.body as VerifyRegistrationRequest;

  console.log(`🔑 Registration verification for ${accountId}: clientNearPublicKey = ${clientNearPublicKey ? 'PROVIDED' : 'NOT PROVIDED'}`);
  if (clientNearPublicKey) {
    console.log(`🔑 Client-managed NEAR public key: ${clientNearPublicKey}`);
  }

  if (!accountId || !attestationResponse) {
    return res.status(400).json({ error: 'accountId and attestationResponse are required' });
  }

  try {
    const user = userOperations.findByNearAccountId(accountId);
    if (!user) {
      return res.status(404).json({ error: `User '${accountId}' not found or registration not initiated.` });
    }

    const expectedChallenge = user.currentChallenge;
    const storedCommitmentId = user.currentCommitmentId ?? null;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found. Registration might have timed out or was not initiated correctly.' });
    }

    // Handle registration via SSE
    await handleRegistrationWithSSE(
      user,
      attestationResponse,
      expectedChallenge,
      storedCommitmentId,
      clientNearPublicKey,
      res
    );

  } catch (e: any) {
    console.error('Error verifying registration:', e.message, e.stack);
    if (req.body.accountId) {
        const userToClear = userOperations.findByNearAccountId(req.body.accountId);
        if (userToClear) userOperations.updateChallengeAndCommitmentId(userToClear.nearAccountId, null, null);
    }
    return res.status(500).json({
      verified: false,
      error: e.message || 'Verification failed due to an unexpected server error.'
    });
  }
});

export default router;