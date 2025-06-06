import { Router, Request, Response } from 'express';
import {
  generateAuthenticationOptions as generateAuthenticationOptionsSimpleWebAuthn,
  verifyAuthenticationResponse as verifyAuthenticationResponseSimpleWebAuthn,
} from '@simplewebauthn/server';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server/script/deps';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { createHash, randomBytes } from 'crypto';

import config, { DEFAULT_GAS_STRING, AUTHENTICATION_VERIFICATION_GAS_STRING } from '../config';
import { userOperations, authenticatorOperations, mapToStoredAuthenticator } from '../database';
import { actionChallengeStore } from '../challengeStore';
import { nearClient } from '../nearService';
import type { User, StoredAuthenticator, SerializableActionArgs } from '../types';

const router = Router();

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
  yieldResumeId?: string;
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

  const contractArgs: ContractGenerateAuthOptionsArgs = {
    rp_id: rpID,
    allow_credentials: allowCredentialsForContract,
    challenge: null, // Let contract generate challenge
    timeout: 60000,
    user_verification: userVerification,
    extensions: null, // Use contract defaults
    authenticator: authenticatorForContract,
  };

  console.log('Calling contract.generate_authentication_options with args:', JSON.stringify(contractArgs));

  const account = nearClient.getRelayerAccount();
  const rawResult: any = await account.callFunction({
    contractId: config.contractId,
    methodName: 'generate_authentication_options',
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
    authenticator
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
          id: isoBase64URL.fromBuffer(Buffer.from(cred.id)),
          type: cred.type,
          transports: cred.transports,
        })),
        userVerification: simpleWebAuthnResult.userVerification,
        extensions: simpleWebAuthnResult.extensions,
      },
      yieldResumeId: undefined, // SimpleWebAuthn doesn't use yield-resume
    };
  }
}

// Generate authentication options
router.post('/generate-authentication-options', async (req: Request, res: Response) => {
  const { username } = req.body;

  try {
    let allowCredentialsList: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[] | undefined = undefined;
    let userForChallengeStorageInDB: User | undefined;
    let firstAuthenticator: StoredAuthenticator | undefined;

    if (username) {
      const userRec = userOperations.findByUsername(username);
      if (userRec) {
        userForChallengeStorageInDB = userRec;
        const rawUserAuthenticators = authenticatorOperations.findByUserId(userRec.id);
        const userAuthenticators: StoredAuthenticator[] = rawUserAuthenticators.map(mapToStoredAuthenticator);

        if (userAuthenticators.length > 0) {
          firstAuthenticator = userAuthenticators[0]; // Use first authenticator for yield-resume
          allowCredentialsList = userAuthenticators.map(auth => ({
            id: isoBase64URL.toBuffer(auth.credentialID),
            type: 'public-key',
            transports: auth.transports as AuthenticatorTransport[],
          }));
        }
      } else {
        console.warn(`Username '${username}' provided for auth options but not found. Treating as discoverable.`);
      }
    }

    if (!firstAuthenticator && config.useContractMethod) {
      return res.status(400).json({ error: 'No authenticator found for user - required for contract method' });
    }

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: 'preferred',
      allowCredentials: allowCredentialsList,
      authenticator: firstAuthenticator!, // Required for contract method
    });

    if (userForChallengeStorageInDB) {
      userOperations.updateChallenge(userForChallengeStorageInDB.id, options.options.challenge);
      console.log(`Stored challenge for user ${userForChallengeStorageInDB.username} in DB.`);
    } else {
      await actionChallengeStore.storeActionChallenge(
        options.options.challenge,
        { actionDetails: (req.body.actionDetails || {}) as SerializableActionArgs },
        300
      );
      console.log(`Stored challenge ${options.options.challenge} in actionChallengeStore for discoverable login.`);
    }

    console.log('Generated authentication options:', JSON.stringify(options, null, 2));

    // Include derpAccountId in response if user is found
    const userForDerpId = username ? userOperations.findByUsername(username) : undefined;
    return res.json({
      ...options.options,
      derpAccountId: userForDerpId?.derpAccountId,
      yieldResumeId: options.yieldResumeId
    });

  } catch (e: any) {
    console.error('Error generating authentication options:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate authentication options' });
  }
});

// Helper function to verify authentication using NEAR Contract with yield-resume
async function verifyAuthenticationResponseContract(
  response: AuthenticationResponseJSON,
  yieldResumeId: string
): Promise<{ verified: boolean; authenticationInfo?: any }> {
  console.log('Using NEAR contract for yield-resume authentication verification');

  const account = nearClient.getRelayerAccount();

  // Step 1: Resume yield with authentication response
  console.log('Step 1: Resuming yield with authentication response...');
  const resumeResult: any = await account.functionCall({
    contractId: config.contractId,
    methodName: 'verify_authentication_response',
    args: {
      authentication_response: response,
      yield_resume_id: yieldResumeId,
    },
    gas: BigInt(AUTHENTICATION_VERIFICATION_GAS_STRING),
  });

  console.log("resumeResult", resumeResult);

  // Check if the transaction itself was successful
  if (resumeResult.status && typeof resumeResult.status === 'object' && 'Failure' in resumeResult.status) {
    // @ts-ignore
    const errorInfo = resumeResult.status.Failure.ActionError?.kind?.FunctionCallError?.ExecutionError || 'Unknown contract execution error';
    console.error("Contract verify_authentication_response call failed:", errorInfo);
    throw new Error(`Contract verify_authentication_response failed: ${errorInfo}`);
  }

  // The verify_authentication_response method returns true if the yield resume was successful
  // The actual verification happens in the callback, so we need to wait and check the callback result
  console.log('Step 1 complete: Yield resume successful');

  // Step 2: Wait for callback and fetch the transaction to get callback logs
  console.log('Step 2: Waiting for callback execution and fetching full transaction details...');

  try {
    // Give the callback a moment to execute
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get the full transaction details including all receipts
    const txHash = resumeResult.transaction.hash;
    const fullTxResult = await nearClient.getProvider().txStatus(txHash, nearClient.getRelayerAccount().accountId, 'FINAL' as any);

    console.log("Full transaction result:", JSON.stringify(fullTxResult, null, 2));

    // Extract logs from all receipts in the transaction
    let logs: string[] = [];

    // Check transaction outcome logs
    if (fullTxResult.transaction_outcome?.outcome?.logs) {
      logs.push(...fullTxResult.transaction_outcome.outcome.logs);
    }

    // Check all receipt outcome logs
    if (fullTxResult.receipts_outcome && Array.isArray(fullTxResult.receipts_outcome)) {
      for (const receipt of fullTxResult.receipts_outcome) {
        if (receipt.outcome && receipt.outcome.logs && Array.isArray(receipt.outcome.logs)) {
          logs.push(...receipt.outcome.logs);
        }
      }
    }

    console.log('All extracted logs:', logs);

    // Look for authentication callback completion log
    let authenticationResult: any = null;
    let verified = false;

    for (const log of logs) {
      if (typeof log === 'string') {
        // Look for the structured authentication result
        if (log.startsWith('WEBAUTHN_AUTH_RESULT: ')) {
          const resultJson = log.substring('WEBAUTHN_AUTH_RESULT: '.length);
          try {
            authenticationResult = JSON.parse(resultJson);
            console.log('Found structured authentication result in log:', authenticationResult);
            break;
          } catch (parseError) {
            console.warn('Failed to parse authentication result from log:', parseError);
          }
        }
        // Fallback: Look for the callback completion log
        else if (log.includes('Authentication callback completed with result: verified=')) {
          const verifiedMatch = log.match(/verified=(\w+)/);
          if (verifiedMatch) {
            verified = verifiedMatch[1] === 'true';
            console.log('Found authentication result in callback log:', verified);

            if (verified) {
              // For successful authentication, we need to extract more details
              // The contract should be updated to log structured data, but for now we'll assume success
              authenticationResult = {
                verified: true,
                // Note: The contract doesn't currently log the detailed authentication info
                // This would need to be updated in the contract to return structured data
              };
            } else {
              authenticationResult = { verified: false };
            }
            break;
          }
        }
        // Also look for any error logs
        else if (log.includes('Authentication commitment mismatch') ||
                 log.includes('Authentication verification failed') ||
                 log.includes('Failed to')) {
          console.log('Found authentication error in log:', log);
          verified = false;
          authenticationResult = { verified: false };
          break;
        }
      }
    }

    // Process the result
    if (authenticationResult && authenticationResult.verified === true) {
      if (authenticationResult.authentication_info) {
        // Use the structured authentication info from the contract
        return {
          verified: true,
          authenticationInfo: {
            credentialID: Buffer.from(authenticationResult.authentication_info.credential_id),
            newCounter: authenticationResult.authentication_info.new_counter,
            userVerified: authenticationResult.authentication_info.user_verified,
            credentialDeviceType: authenticationResult.authentication_info.credential_device_type,
            credentialBackedUp: authenticationResult.authentication_info.credential_backed_up,
            origin: authenticationResult.authentication_info.origin,
            rpId: authenticationResult.authentication_info.rp_id,
          }
        };
      } else {
        // Fallback for when we only have verification success without detailed info
        return {
          verified: true,
          authenticationInfo: {
            // These would need to come from the contract logs if available
            newCounter: 0, // Contract should log this
            userVerified: true, // Contract should log this
            credentialDeviceType: 'singleDevice', // Contract should log this
            credentialBackedUp: false, // Contract should log this
            origin: config.expectedOrigin,
            rpId: config.rpID,
          }
        };
      }
    } else if (authenticationResult && authenticationResult.verified === false) {
      console.log('Authentication verification failed in callback');
      return { verified: false };
    } else {
      console.error('No authentication result found in transaction logs');
      return { verified: false };
    }
  } catch (error) {
    console.error('Error reading authentication result from transaction:', error);
    throw new Error(`Failed to read authentication result: ${error}`);
  }
}

// Verify authentication
router.post('/verify-authentication', async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;

  if (!body.rawId || !body.response) {
    return res.status(400).json({ error: 'Request body error: missing rawId or response' });
  }

  // Extract yieldResumeId from request body for yield-resume flow
  const yieldResumeId = (req.body as any).yieldResumeId;
  if (config.useContractMethod && !yieldResumeId) {
    return res.status(400).json({ error: 'yieldResumeId is required for contract method' });
  }

  let user: User | undefined;
  let authenticator: StoredAuthenticator | undefined;

  const rawAuth = authenticatorOperations.findByCredentialId(body.rawId);
  if (!rawAuth) {
    return res.status(404).json({ error: `Authenticator '${body.rawId}' not found.` });
  }

  authenticator = mapToStoredAuthenticator(rawAuth);
  user = userOperations.findById(authenticator.userId);

  if (!user) {
    return res.status(404).json({ error: `User for authenticator '${body.rawId}' not found.` });
  }

  try {
    let verification: { verified: boolean; authenticationInfo?: any };

    if (config.useContractMethod) {
      // Use contract-based verification with yield-resume
      console.log('Using contract yield-resume authentication verification');

      verification = await verifyAuthenticationResponseContract(
        body,
        yieldResumeId
      );
    } else {
      // Use SimpleWebAuthn verification (original flow)
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

      let expectedChallenge: string | undefined;
      if (user.currentChallenge) {
        console.log(`Attempting verification with user-specific challenge for ${user.username}`);
        expectedChallenge = user.currentChallenge;
      } else {
        console.log(`Attempting verification with actionChallengeStore for discoverable login for potential user ${user.username}`);
        const storedDetails = await actionChallengeStore.validateAndConsumeActionChallenge(clientChallenge);
        if (!storedDetails) {
          return res.status(400).json({
            verified: false,
            error: 'Challenge invalid, expired, or already used from actionChallengeStore.'
          });
        }
        expectedChallenge = clientChallenge;
      }

      if (!expectedChallenge) {
        return res.status(400).json({ error: 'Unexpected: No challenge determined for verification.' });
      }

      let args = {
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
      }
      console.log('Calling verifyAuthenticationResponseSimpleWebAuthn with args:', JSON.stringify(args));
      verification = await verifyAuthenticationResponseSimpleWebAuthn(args);
    }

    if (verification.verified && verification.authenticationInfo) {
      authenticatorOperations.updateCounter(
        authenticator.credentialID,
        verification.authenticationInfo.newCounter,
        new Date().toISOString()
      );

      if (user.currentChallenge) {
        userOperations.updateChallenge(user.id, null);
      }

      console.log(`User '${user.username}' authenticated with '${authenticator.name || authenticator.credentialID}'.`);
      console.log(`Client-managed NEAR PK: ${authenticator.clientManagedNearPublicKey}`);

      return res.json({
        verified: true,
        username: user.username,
        clientManagedNearPublicKey: authenticator.clientManagedNearPublicKey,
        derpAccountId: user.derpAccountId,
      });
    } else {
      if (user.currentChallenge) {
        userOperations.updateChallenge(user.id, null);
      }
      const errorMessage = (verification as any).error?.message || 'Authentication failed verification';
      return res.status(400).json({ verified: false, error: errorMessage });
    }
  } catch (e: any) {
    console.error('Error during verifyAuthenticationResponse call:', e);
    if (user && user.currentChallenge) {
      userOperations.updateChallenge(user.id, null);
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

    const authenticatorRecord = authenticatorOperations.getLatestByUserId(userRecord.id);
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

export default router;