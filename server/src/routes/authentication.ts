import { Router, Request, Response } from 'express';
import {
  generateAuthenticationOptions as generateAuthenticationOptionsSimpleWebAuthn,
  verifyAuthenticationResponse as verifyAuthenticationResponseSimpleWebAuthn,
} from '@simplewebauthn/server';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server/script/deps';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { createHash, randomBytes } from 'crypto';

import config, { DEFAULT_GAS_STRING, AUTHENTICATION_VERIFICATION_GAS_STRING, NEAR_EXPLORER_BASE_URL } from '../config';
import { userOperations } from '../database';
import { actionChallengeStore } from '../challengeStore';
import { nearClient } from '../nearService';
import type { User, StoredAuthenticator, SerializableActionArgs } from '../types';
import { ActionType } from '../types'
import { authenticatorService } from '../authenticatorService';

const router = Router();

// In-memory store for transaction hashes (in production, you'd use a proper database)
const transactionHashStore = new Map<string, {
  timestamp: number;
  txHash: string;
  purpose: string;
  userId?: string;
}>();

// Store mapping of userId to their latest generate_authentication_options transaction hash
const userToGenerateAuthTxHashMap = new Map<string, {
  txHash: string;
  timestamp: number;
  yieldResumeId?: string;
}>();

// Helper function to store transaction hash for later querying
function storeTransactionHash(txHash: string, purpose: string, userId?: string): void {
  const key = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  transactionHashStore.set(key, {
    timestamp: Date.now(),
    txHash,
    purpose,
    userId
  });
  console.log(`💾 Stored transaction hash: ${txHash} (${purpose}) with key: ${key}`);

  // Clean up old entries (older than 1 hour)
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const [storedKey, value] of transactionHashStore.entries()) {
    if (value.timestamp < oneHourAgo) {
      transactionHashStore.delete(storedKey);
    }
  }
}

// Helper function to store user's generate_authentication_options transaction hash
function storeUserGenerateAuthTxHash(userId: string, txHash: string, yieldResumeId?: string): void {
  userToGenerateAuthTxHashMap.set(userId, {
    txHash,
    timestamp: Date.now(),
    yieldResumeId
  });
  console.log(`👤 Stored user auth session: ${userId} -> ${txHash} (yieldResumeId: ${yieldResumeId})`);

  // Clean up old mappings (older than 1 hour)
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const [storedUserId, value] of userToGenerateAuthTxHashMap.entries()) {
    if (value.timestamp < oneHourAgo) {
      userToGenerateAuthTxHashMap.delete(storedUserId);
    }
  }
}

// Interface for contract arguments (generate_authentication_options)
interface ContractGenerateAuthOptionsArgs {
  rp_id: string | null;
  allow_credentials: { id: string; type: string; transports?: string[] }[] | null;
  challenge: string | null; // Let contract generate
  timeout: number | null;
  user_verification: 'discouraged' | 'preferred' | 'required' | null;
  extensions: { appid?: string; cred_props?: boolean; hmac_create_secret?: boolean; min_pin_length?: boolean } | null;
  authenticator: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    transports?: string[];
  };
}

// Interface for the response from contract's generate_authentication_options
interface ContractAuthenticationOptionsResponse {
  options: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: { id: string; type: string; transports?: string[] }[];
    userVerification?: 'discouraged' | 'preferred' | 'required';
    extensions?: { appid?: string; cred_props?: boolean; hmac_create_secret?: boolean; min_pin_length?: boolean };
  };
  commitmentId?: string;
}

// Helper function to get authentication options from NEAR Contract
async function generateAuthenticationOptionsContract(
  authenticator: StoredAuthenticator,
  rpID: string = config.rpID,
  allowCredentialsList?: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[],
  userVerification: 'discouraged' | 'preferred' | 'required' = 'preferred'
): Promise<ContractAuthenticationOptionsResponse> {
  console.log('Using NEAR contract for authentication options');

  // Convert allowCredentialsList to contract format
  const allowCredentialsForContract = allowCredentialsList?.map(cred => ({
    id: isoBase64URL.fromBuffer(cred.id),
    type: cred.type,
    transports: cred.transports?.map(t => String(t)),
  })) || null;

  // Convert authenticator to contract format
  const authenticatorForContract = {
    credential_id: Array.from(Buffer.from(authenticator.credentialID, 'base64url')),
    credential_public_key: Array.from(authenticator.credentialPublicKey as Uint8Array),
    counter: authenticator.counter as number,
    transports: authenticator.transports?.map(t => String(t)),
  };

  const contractArgs = {
    rp_id: rpID,
    allow_credentials: allowCredentialsForContract,
    challenge: null, // Let contract generate challenge
    timeout: 60000,
    user_verification: userVerification,
    extensions: null,
    authenticator: authenticatorForContract,
  };

  console.log('Calling contract.generate_authentication_options with args:', JSON.stringify(contractArgs));

  const rawResult: any = await nearClient.callFunction(
    config.contractId,
    'generate_authentication_options',
    contractArgs,
    DEFAULT_GAS_STRING,
    '0'
  );

  console.log(`NearClient: Result: ${JSON.stringify(rawResult)}`);

  // Store the transaction hash from generate_authentication_options call
  const generateTxHash = rawResult?.transaction?.hash;
  if (generateTxHash) {
    console.log('🎯 generate_authentication_options Transaction Hash:', generateTxHash);
    console.log('🎯 Explorer Link:', `${NEAR_EXPLORER_BASE_URL}/txns/${generateTxHash}?tab=execution`);
    console.log('👤 Storing txHash for userId:', authenticator.userId);
    storeTransactionHash(generateTxHash, 'generate_authentication_options', authenticator.userId);
  } else {
    console.warn('⚠️  No transaction hash found in generate_authentication_options result');
  }

  // Robust error checking for rawResult
  if (rawResult?.status && typeof rawResult.status === 'object' && 'Failure' in rawResult.status && rawResult.status.Failure) {
    const failure = rawResult.status.Failure;
    const executionError = (failure as any).ActionError?.kind?.FunctionCallError?.ExecutionError;
    const errorMessage = executionError || JSON.stringify(failure);
    console.error('Contract execution failed (panic or transaction error):', errorMessage);
    throw new Error(`Contract Error: ${errorMessage}`);
  }
  else if (rawResult && typeof (rawResult as any).error === 'object') {
    const rpcError = (rawResult as any).error;
    console.error('RPC/Handler error from contract.generate_authentication_options call:', rpcError);
    const errorMessage = rpcError.message || rpcError.name || 'RPC error during generate_authentication_options';
    const errorData = rpcError.data || JSON.stringify(rpcError.cause);
    throw new Error(`Contract Call RPC Error: ${errorMessage} (Details: ${errorData})`);
  }

  let contractResponseString: string;
  if (rawResult?.status && typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status && typeof rawResult.status.SuccessValue === 'string') {
    contractResponseString = Buffer.from(rawResult.status.SuccessValue, 'base64').toString();
  } else if (typeof rawResult === 'string' && rawResult.startsWith('{')) {
    contractResponseString = rawResult;
  } else {
    console.warn('Unexpected rawResult structure from generate_authentication_options. Not a FinalExecutionOutcome with SuccessValue or a JSON string:', rawResult);
    throw new Error('Failed to parse contract response: Unexpected format.');
  }

  let contractResponse: ContractAuthenticationOptionsResponse;
  try {
    // The contract now returns a properly encoded JSON object, so we only need to parse once.
    contractResponse = JSON.parse(contractResponseString);
  } catch (parseError: any) {
    console.error('Failed to parse contractResponseString as JSON:', contractResponseString, parseError);
    throw new Error(`Failed to parse contract response JSON: ${parseError.message}`);
  }

  // Validate response structure
  if (!contractResponse.options?.challenge) {
    console.error('Invalid parsed response from contract.generate_authentication_options (missing challenge):', contractResponse);
    throw new Error('Contract did not return valid authentication options (missing challenge).');
  }

  // Store mapping of userId to their latest generate_authentication_options transaction hash
  if (contractResponse.commitmentId && generateTxHash && authenticator.userId) {
    storeUserGenerateAuthTxHash(authenticator.userId, generateTxHash, contractResponse.commitmentId);
  } else {
    console.warn('Cannot store user auth session: missing userId, commitmentId, or generateTxHash');
  }

  return contractResponse;
}

// Unified generateAuthenticationOptions function
async function generateAuthenticationOptions(
  options: {
    rpID?: string;
    userVerification?: 'discouraged' | 'preferred' | 'required';
    allowCredentials?: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[];
    authenticator?: StoredAuthenticator;
  }
): Promise<ContractAuthenticationOptionsResponse> {
  const {
    rpID = config.rpID,
    userVerification = 'preferred',
    allowCredentials,
    authenticator,
  } = options;

  if (config.useContractMethod) {
    if (!authenticator) {
      throw new Error('Authenticator is required for contract method');
    }
    return generateAuthenticationOptionsContract(
      authenticator,
      rpID,
      allowCredentials,
      userVerification
    );
  } else {
    const simpleWebAuthnResult = await generateAuthenticationOptionsSimpleWebAuthn({
      rpID,
      allowCredentials,
      userVerification,
    });

    // Convert SimpleWebAuthn response to match contract format
    return {
      options: {
        challenge: simpleWebAuthnResult.challenge,
        timeout: simpleWebAuthnResult.timeout,
        rpId: simpleWebAuthnResult.rpId,
        allowCredentials: simpleWebAuthnResult.allowCredentials?.map(cred => ({
          id: cred.id, // SimpleWebAuthn returns base64url string, pass through directly
          type: cred.type,
          transports: cred.transports,
        })),
        userVerification: simpleWebAuthnResult.userVerification,
        extensions: simpleWebAuthnResult.extensions,
      },
      commitmentId: undefined,
    };
  }
}

// Generate authentication options
router.post('/generate-authentication-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  const useOptimistic = (req.body as any).useOptimistic ?? config.useOptimisticAuth;

  try {
    let allowCredentialsList: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[] | undefined = undefined;
    let userForChallengeStorageInDB: User | undefined;
    let firstAuthenticator: StoredAuthenticator | undefined;

    if (username) {
      const userRec = userOperations.findByUsername(username);
      if (userRec) {
        userForChallengeStorageInDB = userRec;
        console.log(`🔍 Found user record for ${username}, nearAccountId: ${userRec.nearAccountId}`);

        const userAuthenticators: StoredAuthenticator[] = userRec.nearAccountId ?
          await authenticatorService.findByUserId(userRec.nearAccountId) : [];

        console.log(`🔍 Found ${userAuthenticators.length} authenticators for nearAccountId: ${userRec.nearAccountId}`);

        if (userAuthenticators.length > 0) {
          firstAuthenticator = userAuthenticators[0]; // Use first authenticator for contract call
          console.log(`🔍 Using first authenticator: ${firstAuthenticator.credentialID}`);
          allowCredentialsList = userAuthenticators.map(auth => ({
            id: isoBase64URL.toBuffer(auth.credentialID),
            type: 'public-key',
            transports: auth.transports as AuthenticatorTransport[],
          }));
        } else {
          console.warn(`🔍 No authenticators found for user ${username} with nearAccountId ${userRec.nearAccountId}`);
        }
      } else {
        console.warn(`Username '${username}' provided for auth options but not found. Treating as discoverable.`);
      }
    }

    // Only require authenticator for synchronous contract method
    if (!useOptimistic && !firstAuthenticator && config.useContractMethod) {
      return res.status(400).json({ error: 'No authenticator found for user - required for contract method' });
    }

    let response: ContractAuthenticationOptionsResponse;

    if (useOptimistic) {
      // Fast mode: Use SimpleWebAuthn without contract call
      console.log('Using fast authentication options generation (SimpleWebAuthn)');
      const simpleWebAuthnResult = await generateAuthenticationOptionsSimpleWebAuthn({
        rpID: config.rpID,
        allowCredentials: allowCredentialsList,
        userVerification: 'preferred',
      });

      // Convert SimpleWebAuthn response to match contract format
      response = {
        options: {
          challenge: simpleWebAuthnResult.challenge,
          timeout: simpleWebAuthnResult.timeout,
          rpId: simpleWebAuthnResult.rpId,
          allowCredentials: simpleWebAuthnResult.allowCredentials?.map(cred => ({
            id: cred.id, // Pass through the base64url string directly
            type: cred.type,
            transports: cred.transports,
          })),
          userVerification: simpleWebAuthnResult.userVerification,
          extensions: simpleWebAuthnResult.extensions,
        },
        commitmentId: undefined, // No commitment for fast mode
      };
    } else {
      // Secure mode: Use contract method with on-chain commitment
      console.log('Using secure authentication options generation (contract)');
      response = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: 'preferred',
      allowCredentials: allowCredentialsList,
        authenticator: firstAuthenticator!,
    });
    }

    if (userForChallengeStorageInDB) {
      userOperations.updateAuthChallengeAndCommitmentId(userForChallengeStorageInDB.id, response.options.challenge, response.commitmentId || null);
      console.log(`Stored challenge and commitmentId for user ${userForChallengeStorageInDB.username} in DB.`);
    } else {
      await actionChallengeStore.storeActionChallenge(
        response.options.challenge,
        { actionDetails: { action_type: ActionType.DiscoverableLogin } }, // Provide a default action_type
        300
      );
      console.log(`Stored challenge ${response.options.challenge} in actionChallengeStore for discoverable login.`);
    }

    console.log('Generated authentication options:', JSON.stringify(response, null, 2));

    // The contract response for options is now nested.
    // The top-level response has `options` and `commitmentId`.
    // The response to the client should be a flat object.
    const userForNearId = username ? userOperations.findByUsername(username) : undefined;
    const finalResponse = {
      ...response.options, // Spread the nested options
      nearAccountId: userForNearId?.nearAccountId,
      commitmentId: response.commitmentId, // Add commitmentId at the top level
    };

    console.log(`🔍 Final response allowCredentials: ${finalResponse.allowCredentials?.length || 0} credentials`);
    return res.json(finalResponse);

  } catch (e: any) {
    console.error('Error generating authentication options:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate authentication options' });
  }
});

// Helper function to verify authentication using NEAR Contract with on-chain commitment
async function verifyAuthenticationResponseContract(
  response: AuthenticationResponseJSON,
  commitmentId: string,
): Promise<{ verified: boolean; authenticationInfo?: any }> {
  console.log('Verifying with contract. Commitment ID:', commitmentId);
  const contractArgs = {
    authentication_response: response,
    commitment_id: commitmentId,
  };

  // Add detailed logging for the arguments being sent to the contract
  console.log('Contract `verify_authentication_response` args:', JSON.stringify(contractArgs, null, 2));

  try {
  const rawResult: any = await nearClient.callFunction(
    config.contractId,
    'verify_authentication_response',
    contractArgs,
    AUTHENTICATION_VERIFICATION_GAS_STRING,
    '0'
  );

    // Add logging for the raw result from the contract
    console.log('Raw result from `verify_authentication_response`:', JSON.stringify(rawResult, null, 2));

  // Check for transaction failures
  if (rawResult?.status && typeof rawResult.status === 'object' && 'Failure' in rawResult.status) {
    const errorInfo = (rawResult.status.Failure as any).ActionError?.kind?.FunctionCallError?.ExecutionError || 'Unknown contract execution error';
    console.error("Contract verify_authentication_response call failed:", errorInfo);
    throw new Error(`Contract verify_authentication_response failed: ${errorInfo}`);
  }

  // Parse direct result
  if (rawResult?.status && typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status && rawResult.status.SuccessValue) {
    const successValue = rawResult.status.SuccessValue;
    const verificationResult = JSON.parse(Buffer.from(successValue, 'base64').toString());
      console.log('Parsed verification result from contract:', verificationResult);
    return {
      verified: verificationResult.verified,
      authenticationInfo: verificationResult.authentication_info,
    };
  } else {
    console.error("Contract call succeeded but did not return a SuccessValue.");
    throw new Error("Contract did not return a valid verification result.");
    }
  } catch (error) {
    console.error('Caught error during `verifyAuthenticationResponseContract`:', error);
    throw error; // Re-throw the error to be handled by the route
  }
}

// Background contract update for optimistic authentication
async function updateContractInBackground(
  credentialId: string,
  newCounter: number,
  nearAccountId: string
): Promise<void> {
  try {
    console.log(`🔄 Background update: updating counter for ${credentialId} to ${newCounter}`);
    await authenticatorService.updateCounter(
      credentialId,
      newCounter,
      new Date(),
      nearAccountId
    );
    console.log(`✅ Background update successful for ${credentialId}`);
  } catch (error) {
    console.error(`❌ Background update failed for ${credentialId}:`, error);
    // Don't throw - this is fire-and-forget
  }
}

// Verify authentication
router.post('/verify-authentication', async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;

  if (!body.rawId || !body.response) {
    return res.status(400).json({ error: 'Request body error: missing rawId or response' });
  }

  const commitmentId = (req.body as any).commitmentId;
  const useOptimistic = (req.body as any).useOptimistic ?? config.useOptimisticAuth;

  if (config.useContractMethod && !useOptimistic && !commitmentId) {
    return res.status(400).json({ error: 'commitmentId is required for contract method' });
  }

  let user: User | undefined;
  let authenticator: StoredAuthenticator | undefined;

  // Try to find authenticator by credential ID
  // First try to find the user who might have this authenticator
  let potentialUser: User | undefined;

  // Global search through cache for this credential ID
  authenticator = await authenticatorService.findByCredentialId(body.rawId);
  if (!authenticator) {
    return res.status(404).json({ error: `Authenticator '${body.rawId}' not found.` });
  }

  // Note: authenticator.userId is actually the nearAccountId, not the internal user ID
  user = userOperations.findByNearAccountId(authenticator.userId);

  if (!user) {
    return res.status(404).json({ error: `User for authenticator '${body.rawId}' not found.` });
  }

  try {
    let verification: { verified: boolean; authenticationInfo?: any };

    if (useOptimistic) {
      // Optimistic mode: Use SimpleWebAuthn for immediate verification
      console.log('Using optimistic authentication with SimpleWebAuthn');

      let clientChallenge: string;
      try {
        const clientDataJSONBuffer = isoBase64URL.toBuffer(body.response.clientDataJSON);
        const clientData = JSON.parse(Buffer.from(clientDataJSONBuffer).toString('utf8'));
        clientChallenge = clientData.challenge;
        if (!clientChallenge) {
          return res.status(400).json({ verified: false, error: 'Challenge missing in clientDataJSON.' });
        }
      } catch (parseError) {
        return res.status(400).json({ verified: false, error: 'Invalid clientDataJSON.' });
      }

      const expectedChallenge = user.currentChallenge;
      if (!expectedChallenge) {
        return res.status(400).json({ error: 'No challenge found for user.' });
      }

      verification = await verifyAuthenticationResponseSimpleWebAuthn({
        response: body,
        expectedChallenge,
        expectedOrigin: config.expectedOrigin,
        expectedRPID: config.rpID,
        authenticator: {
          credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
          credentialPublicKey: Buffer.from(authenticator.credentialPublicKey as Uint8Array),
          counter: authenticator.counter as number,
          transports: authenticator.transports as AuthenticatorTransport[] | undefined,
        },
        requireUserVerification: true,
      });

      // Background contract update (fire and forget)
      if (verification.verified && verification.authenticationInfo && user?.nearAccountId) {
        updateContractInBackground(
          authenticator.credentialID,
          verification.authenticationInfo.newCounter,
          user.nearAccountId
        );
      }
    } else if (config.useContractMethod) {
      // Synchronous mode: Wait for contract verification
      console.log('Using synchronous authentication with contract verification');
      const { commitmentId: _, ...authResponseForContract } = req.body as any;
      verification = await verifyAuthenticationResponseContract(
        authResponseForContract,
        (req.body as any).commitmentId
      );
    } else {
      // Fallback to SimpleWebAuthn for non-contract flow
      let clientChallenge: string;
      try {
        const clientDataJSONBuffer = isoBase64URL.toBuffer(body.response.clientDataJSON);
        const clientData = JSON.parse(Buffer.from(clientDataJSONBuffer).toString('utf8'));
        clientChallenge = clientData.challenge;
        if (!clientChallenge) {
          return res.status(400).json({ verified: false, error: 'Challenge missing in clientDataJSON.' });
        }
      } catch (parseError) {
        return res.status(400).json({ verified: false, error: 'Invalid clientDataJSON.' });
      }

      const expectedChallenge = user.currentChallenge;
      if (!expectedChallenge) {
        return res.status(400).json({ error: 'No challenge found for user.' });
      }

      verification = await verifyAuthenticationResponseSimpleWebAuthn({
        response: body,
        expectedChallenge,
        expectedOrigin: config.expectedOrigin,
        expectedRPID: config.rpID,
        authenticator: {
          credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
          credentialPublicKey: Buffer.from(authenticator.credentialPublicKey as Uint8Array),
          counter: authenticator.counter as number,
          transports: authenticator.transports as AuthenticatorTransport[] | undefined,
        },
        requireUserVerification: true,
      });
    }

    if (verification.verified && verification.authenticationInfo) {
      // Only update counter synchronously if not using optimistic mode
      if (!useOptimistic && user?.nearAccountId) {
        await authenticatorService.updateCounter(
        authenticator.credentialID,
          verification.authenticationInfo.new_counter,
          new Date(),
          user.nearAccountId
      );
      }

      // Store the authenticator in the cache for future logins
      if (user?.nearAccountId) {
        await authenticatorService.create({
          credentialID: authenticator.credentialID,
          credentialPublicKey: authenticator.credentialPublicKey,
          counter: verification.authenticationInfo.newCounter,
          transports: authenticator.transports,
          nearAccountId: user.nearAccountId,
          name: `Authenticator for ${user.username}`,
          registered: new Date(authenticator.registered),
          backedUp: verification.authenticationInfo.credentialBackedUp,
          clientManagedNearPublicKey: authenticator.clientManagedNearPublicKey,
        });
      }

      // Clear the challenge and commitment from user record
      userOperations.updateAuthChallengeAndCommitmentId(user.id, null, null);

      console.log(`User '${user.username}' authenticated with '${authenticator.name || authenticator.credentialID}'.`);

      return res.json({
        verified: true,
        username: user.username,
        nearAccountId: user.nearAccountId,
      });
    } else {
      userOperations.updateAuthChallengeAndCommitmentId(user.id, null, null);
      const errorMessage = (verification as any).error?.message || 'Authentication failed verification';
      return res.status(400).json({ verified: false, error: errorMessage });
    }
  } catch (e: any) {
    // Add logging for any error caught by the route handler
    console.error('Error in /verify-authentication route handler:', e.message, e.stack);
    if (user) {
      userOperations.updateAuthChallengeAndCommitmentId(user.id, null, null);
    }
    return res.status(500).json({
      verified: false,
      error: e.message || 'Authentication verification failed unexpectedly.'
    });
  }
});

// Generate a challenge for signing an action
router.post('/api/action-challenge', async (req: Request, res: Response) => {
  const { username, actionDetails } = req.body as {
    username: string,
    actionDetails: SerializableActionArgs
  };

  if (!username || !actionDetails) {
    return res.status(400).json({ error: 'Username and actionDetails are required.' });
  }

  try {
    const userRecord = userOperations.findByUsername(username);
    if (!userRecord) {
      return res.status(404).json({ error: 'User not found.' });
    }

    if (!userRecord.nearAccountId) {
      return res.status(400).json({ error: 'User has no NEAR account ID.' });
    }

    const authenticatorRecord = await authenticatorService.getLatestByUserId(userRecord.nearAccountId);
    if (!authenticatorRecord) {
      return res.status(404).json({
        error: 'No registered passkey found for this user to sign the action.'
      });
    }

    const userPasskeyCredentialID = authenticatorRecord.credentialID;

    const nonce = isoBase64URL.fromBuffer(randomBytes(32));
    const payloadToSign = {
      nonce,
      actionHash: createHash('sha256').update(JSON.stringify(actionDetails)).digest('hex'),
      rpId: config.rpID,
      origin: config.expectedOrigin,
    };

    const challengeString = JSON.stringify(payloadToSign);
    const challengeForClient = isoBase64URL.fromBuffer(Buffer.from(challengeString));

    await actionChallengeStore.storeActionChallenge(
      challengeForClient,
      { actionDetails: req.body.actionDetails, expectedCredentialID: userPasskeyCredentialID },
      300
    );

    const options = {
      challenge: challengeForClient,
      rpId: config.rpID,
      allowCredentials: [{
        type: 'public-key' as const,
        id: userPasskeyCredentialID,
      }],
      userVerification: 'preferred' as const,
      timeout: 60000,
    };

    console.log(`Generated action-challenge for user ${username}, action: ${actionDetails.action_type}, challenge: ${challengeForClient}`);
    return res.json(options);

  } catch (error: any) {
    console.error('Error generating action challenge:', error);
    return res.status(500).json({ error: error.message || 'Failed to generate action challenge' });
  }
});

// Debug endpoint to query stored transaction hashes
router.get('/debug/transactions', async (req: Request, res: Response) => {
  try {
    const transactions = Array.from(transactionHashStore.values()).map(tx => ({
      txHash: tx.txHash,
      purpose: tx.purpose,
      timestamp: new Date(tx.timestamp).toISOString(),
      explorerLink: `${NEAR_EXPLORER_BASE_URL}/txns/${tx.txHash}?tab=execution`,
      userId: tx.userId
    }));

    return res.json({
      totalStored: transactions.length,
      transactions: transactions.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    });
  } catch (error: any) {
    console.error('Error fetching stored transactions:', error);
    return res.status(500).json({ error: error.message || 'Failed to fetch transactions' });
  }
});

// Debug endpoint to query a specific transaction hash
router.get('/debug/transaction/:txHash', async (req: Request, res: Response) => {
  const { txHash } = req.params;

  try {
    console.log(`🔍 Querying transaction: ${txHash}`);

    const txResult = await nearClient.getProvider().txStatus(txHash, nearClient.getRelayerAccount().accountId, 'FINAL' as any);

    // The old log counting logic is no longer relevant for the direct-response architecture.
    // We can simplify this debug endpoint.
    const hasStatus = !!txResult.status;
    const isSuccess = hasStatus && typeof (txResult.status as any).SuccessValue !== 'undefined';

    let resultData = null;
    if (isSuccess) {
        try {
            const successValue = (txResult.status as any).SuccessValue;
            resultData = JSON.parse(Buffer.from(successValue, 'base64').toString());
        } catch (e) {
            resultData = "Failed to parse SuccessValue";
        }
    }

    return res.json({
      txHash,
      explorerLink: `${NEAR_EXPLORER_BASE_URL}/txns/${txHash}?tab=execution`,
      summary: {
        isSuccess,
        finalStatus: txResult.status
      },
      result: resultData,
      fullResult: txResult
    });
  } catch (error: any) {
    console.error(`Error querying transaction ${txHash}:`, error);
    return res.status(500).json({
      error: error.message || 'Failed to query transaction',
      txHash
    });
  }
});

export default router;