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
  allow_credentials: { id: string; type: string; transports?: string[] }[] | null;
  challenge: string | null; // Let contract generate
  timeout: number | null;
  user_verification: 'discouraged' | 'preferred' | 'required' | null;
  extensions: { appid?: string; cred_props?: boolean; hmac_create_secret?: boolean; min_pin_length?: boolean } | null;
  rp_id: string | null;
}

// Interface for the response from contract's generate_authentication_options
interface ContractAuthenticationOptionsResponse {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
  userVerification?: 'discouraged' | 'preferred' | 'required';
  extensions?: { appid?: string; cred_props?: boolean; hmac_create_secret?: boolean; min_pin_length?: boolean };
}

// Helper function to get authentication options from NEAR Contract
async function generateAuthenticationOptionsContract(
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

  const contractArgs: ContractGenerateAuthOptionsArgs = {
    rp_id: rpID,
    allow_credentials: allowCredentialsForContract,
    challenge: null, // Let contract generate challenge
    timeout: 60000,
    user_verification: userVerification,
    extensions: null, // Use contract defaults
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
  if (!contractResponse.challenge) {
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
  }
): Promise<ContractAuthenticationOptionsResponse> {
  const { rpID = config.rpID, userVerification = 'preferred', allowCredentials } = options;

  if (config.useContractMethod) {
    return generateAuthenticationOptionsContract(
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
    };
  }
}

// Generate authentication options
router.post('/generate-authentication-options', async (req: Request, res: Response) => {
  const { username } = req.body;

  try {
    let allowCredentialsList: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[] | undefined = undefined;
    let userForChallengeStorageInDB: User | undefined;

    if (username) {
      const userRec = userOperations.findByUsername(username);
      if (userRec) {
        userForChallengeStorageInDB = userRec;
        const rawUserAuthenticators = authenticatorOperations.findByUserId(userRec.id);
        const userAuthenticators: StoredAuthenticator[] = rawUserAuthenticators.map(mapToStoredAuthenticator);

        if (userAuthenticators.length > 0) {
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

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      userVerification: 'preferred',
      allowCredentials: allowCredentialsList,
    });

    if (userForChallengeStorageInDB) {
      userOperations.updateChallenge(userForChallengeStorageInDB.id, options.challenge);
      console.log(`Stored challenge for user ${userForChallengeStorageInDB.username} in DB.`);
    } else {
      await actionChallengeStore.storeActionChallenge(
        options.challenge,
        { actionDetails: (req.body.actionDetails || {}) as SerializableActionArgs },
        300
      );
      console.log(`Stored challenge ${options.challenge} in actionChallengeStore for discoverable login.`);
    }

    console.log('Generated authentication options:', JSON.stringify(options, null, 2));

    // Include derpAccountId in response if user is found
    const userForDerpId = username ? userOperations.findByUsername(username) : undefined;
    return res.json({ ...options, derpAccountId: userForDerpId?.derpAccountId });

  } catch (e: any) {
    console.error('Error generating authentication options:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate authentication options' });
  }
});

// Helper function to verify authentication using NEAR Contract
async function verifyAuthenticationResponseContract(
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  expectedOrigin: string,
  expectedRpId: string,
  authenticator: {
    credentialID: string;
    credentialPublicKey: Uint8Array;
    counter: number;
    transports?: AuthenticatorTransport[];
  }
): Promise<{ verified: boolean; authenticationInfo?: any }> {
  console.log('Using NEAR contract for authentication verification');

  // Ensure credential public key is properly converted to Uint8Array
  const credentialPublicKeyArray = Buffer.isBuffer(authenticator.credentialPublicKey)
    ? new Uint8Array(authenticator.credentialPublicKey)
    : authenticator.credentialPublicKey;

  console.log('Debug: Converted to Uint8Array length:', credentialPublicKeyArray.length);
  console.log('Debug: Converted first 10 bytes:', Array.from(credentialPublicKeyArray).slice(0, 10));

  // Debug: Parse the authenticator data to see what counter is being sent
  try {
    const authenticatorDataBytes = isoBase64URL.toBuffer(response.response.authenticatorData);
    console.log('Debug: Authenticator data length:', authenticatorDataBytes.length);
    if (authenticatorDataBytes.length >= 37) {
      const flags = authenticatorDataBytes[32];
      const counter = new DataView(authenticatorDataBytes.buffer, authenticatorDataBytes.byteOffset + 33, 4).getUint32(0, false);
      console.log('Debug: Authenticator data flags:', flags.toString(16));
      console.log('Debug: Authenticator data counter:', counter);
      console.log('Debug: Stored authenticator counter:', authenticator.counter);
      console.log('Debug: Counter check would be:', counter, '>', authenticator.counter, '=', counter > authenticator.counter);
    }
  } catch (e) {
    console.log('Debug: Error parsing authenticator data:', e);
  }

  // Debug: Parse the client data to verify challenge
  try {
    const clientDataBytes = isoBase64URL.toBuffer(response.response.clientDataJSON);
    const clientData = JSON.parse(Buffer.from(clientDataBytes).toString('utf8'));
    console.log('Debug: Client data challenge:', clientData.challenge);
    console.log('Debug: Expected challenge:', expectedChallenge);
    console.log('Debug: Challenge match:', clientData.challenge === expectedChallenge);
    console.log('Debug: Client data origin:', clientData.origin);
    console.log('Debug: Expected origin:', expectedOrigin);
  } catch (e) {
    console.log('Debug: Error parsing client data:', e);
  }

  // Create AuthenticatorDevice for contract
  const authenticatorDevice = {
    credential_id: Array.from(Buffer.from(authenticator.credentialID, 'base64url')), // Convert base64url string to byte array
    credential_public_key: Array.from(credentialPublicKeyArray), // Convert Uint8Array to regular array
    counter: authenticator.counter,
    transports: authenticator.transports?.map(t => t.toString()),
  };

  console.log('Debug: Credential public key length:', authenticator.credentialPublicKey.length);
  console.log('Debug: Credential public key first 10 bytes:', Array.from(authenticator.credentialPublicKey).slice(0, 10));

  console.log('Debug: Raw credential public key type:', typeof authenticator.credentialPublicKey);
  console.log('Debug: Is Buffer?', Buffer.isBuffer(authenticator.credentialPublicKey));
  console.log('Debug: Credential public key as hex:', Buffer.from(authenticator.credentialPublicKey).toString('hex'));

  const contractArgs = {
    response,
    expected_challenge: expectedChallenge,
    expected_origin: expectedOrigin,
    expected_rp_id: expectedRpId,
    authenticator: authenticatorDevice,
    require_user_verification: true,
  };

  console.log('Calling contract.verify_authentication_response with credential_public_key length:', contractArgs.authenticator.credential_public_key.length);
  console.log('GasLimit AUTHENTICATION_VERIFICATION_GAS_STRING: ', AUTHENTICATION_VERIFICATION_GAS_STRING);

  const account = nearClient.getRelayerAccount();
  const rawResult: any = await account.callFunction({
    contractId: config.contractId,
    methodName: 'verify_authentication_response',
    args: contractArgs,
    gas: BigInt(AUTHENTICATION_VERIFICATION_GAS_STRING),
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
    console.error('RPC/Handler error from contract.verify_authentication_response call:', rpcError);
    const errorMessage = rpcError.message || rpcError.name || 'RPC error during verify_authentication_response';
    const errorData = rpcError.data || JSON.stringify(rpcError.cause);
    throw new Error(`Contract Call RPC Error: ${errorMessage} (Details: ${errorData})`);
  }

  let contractResponseString: string;
  if (rawResult?.status && typeof rawResult.status === 'object' && 'SuccessValue' in rawResult.status && typeof rawResult.status.SuccessValue === 'string') {
    contractResponseString = Buffer.from(rawResult.status.SuccessValue, 'base64').toString();
  } else if (typeof rawResult === 'string' && rawResult.startsWith('{')) {
    contractResponseString = rawResult;
  } else if (typeof rawResult === 'object' && 'verified' in rawResult) {
    // Handle direct object response from contract
    console.log('Contract authentication verification result:', rawResult);
    return {
      verified: rawResult.verified || false,
      authenticationInfo: rawResult.authentication_info ? {
        credentialID: Buffer.from(rawResult.authentication_info.credential_id),
        newCounter: rawResult.authentication_info.new_counter,
        userVerified: rawResult.authentication_info.user_verified,
        credentialDeviceType: rawResult.authentication_info.credential_device_type,
        credentialBackedUp: rawResult.authentication_info.credential_backed_up,
      } : undefined
    };
  } else {
    console.warn('Unexpected rawResult structure from verify_authentication_response. Not a FinalExecutionOutcome with SuccessValue or a JSON string:', rawResult);
    throw new Error('Failed to parse contract response: Unexpected format.');
  }

  let contractResponse: any;
  try {
    contractResponse = JSON.parse(contractResponseString);
  } catch (parseError: any) {
    console.error('Failed to parse contractResponseString as JSON:', contractResponseString, parseError);
    throw new Error(`Failed to parse contract response JSON: ${parseError.message}`);
  }

  console.log('Contract authentication verification result:', contractResponse);

  if (contractResponse.verified && contractResponse.authentication_info) {
    return {
      verified: true,
      authenticationInfo: {
        credentialID: Buffer.from(contractResponse.authentication_info.credential_id),
        newCounter: contractResponse.authentication_info.new_counter,
        userVerified: contractResponse.authentication_info.user_verified,
        credentialDeviceType: contractResponse.authentication_info.credential_device_type,
        credentialBackedUp: contractResponse.authentication_info.credential_backed_up,
      }
    };
  } else {
    return {
      verified: contractResponse.verified || false,
      authenticationInfo: undefined
    };
  }
}

// Verify authentication
router.post('/verify-authentication', async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;

  if (!body.rawId || !body.response) {
    return res.status(400).json({ error: 'Request body error: missing rawId or response' });
  }

  let expectedChallenge: string | undefined;
  let user: User | undefined;
  let authenticator: StoredAuthenticator | undefined;

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

  const rawAuth = authenticatorOperations.findByCredentialId(body.rawId);
  if (!rawAuth) {
    return res.status(404).json({ error: `Authenticator '${body.rawId}' not found.` });
  }

  authenticator = mapToStoredAuthenticator(rawAuth);
  user = userOperations.findById(authenticator.userId);

  if (!user) {
    return res.status(404).json({ error: `User for authenticator '${body.rawId}' not found.` });
  }

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

  try {
    let verification: { verified: boolean; authenticationInfo?: any };

    if (config.useContractMethod) {
      // Use contract-based verification
      verification = await verifyAuthenticationResponseContract(
        body,
        expectedChallenge,
        config.expectedOrigin,
        config.rpID,
        {
          credentialID: authenticator.credentialID,
          credentialPublicKey: Buffer.from(authenticator.credentialPublicKey as Uint8Array),
          counter: authenticator.counter as number,
          transports: authenticator.transports as AuthenticatorTransport[] | undefined,
        }
      );
    } else {
      // Use SimpleWebAuthn verification
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