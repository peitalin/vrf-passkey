import { Router, Request, Response } from 'express';
import {
  generateRegistrationOptions as simpleWebAuthnGenerateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { RegistrationResponseJSON } from '@simplewebauthn/server/script/deps';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { JsonRpcProvider } from 'near-api-js/lib/providers';

import config from '../config';
import { userOperations, authenticatorOperations } from '../database';
import { nearClient } from '../nearService';
import { deriveNearPublicKeyFromCOSE } from '../keyDerivation';
import type { User } from '../types';

const router = Router();

// Interface for contract arguments
interface ContractGenerateRegistrationOptionsArgs {
  rp_name: string;
  rp_id: string;
  user_name: string;
  user_id: string | null;
  challenge: string | null;
  user_display_name: string | null;
  timeout: number | null;
  attestation_type: string | null;
  exclude_credentials: { id: string; type: string; transports?: string[] }[] | null;
  authenticator_selection: ({
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  }) | null;
  extensions: ({ cred_props?: boolean; }) | null;
  supported_algorithm_ids: number[] | null;
  preferred_authenticator_type: string | null;
}

// Unified response type
interface UnifiedRegistrationOptionsResponse {
  options: Awaited<ReturnType<typeof simpleWebAuthnGenerateRegistrationOptions>>;
  derpAccountId: string | undefined;
}

async function getRegistrationOptionsSimpleWebAuthn(
  username: string,
  user: User,
  rawAuthenticators: any[]
): Promise<UnifiedRegistrationOptionsResponse> {
  console.log(`Using SimpleWebAuthn for registration options for user: ${user.username}`);

  const authenticatorsForSimpleWebAuthnExclusion = rawAuthenticators.map(auth => ({
    id: isoBase64URL.toBuffer(auth.credentialID),
    type: 'public-key' as const,
    transports: auth.transports ? JSON.parse(auth.transports) as AuthenticatorTransport[] : undefined,
  }));

  const options = await simpleWebAuthnGenerateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: user.id,
    userName: user.username,
    userDisplayName: user.username,
    excludeCredentials: authenticatorsForSimpleWebAuthnExclusion,
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    supportedAlgorithmIDs: [-7, -257],
    attestationType: 'none',
    timeout: 60000,
  });

  console.log('Options from SimpleWebAuthn:', JSON.stringify(options, null, 2));
  return {
    options,
    derpAccountId: user.derpAccountId,
  };
}

async function getRegistrationOptionsContract(
  username: string,
  user: User,
  rawAuthenticators: any[]
): Promise<UnifiedRegistrationOptionsResponse> {
  console.log(`Using NEAR contract for registration options for user: ${user.username}, userID: ${user.id}`);

  const authenticatorsForContractExclusion = rawAuthenticators.map(auth => ({
    id: auth.credentialID,
    type: 'public-key' as const,
    transports: auth.transports ? JSON.parse(auth.transports).map((t: any) => String(t)) : undefined,
  }));

  const contractArgs: ContractGenerateRegistrationOptionsArgs = {
    rp_name: config.rpName,
    rp_id: config.rpID,
    user_name: user.username,
    user_id: null, // Let contract generate internal userID bytes from random_seed
    challenge: null, // Let contract generate challenge bytes from random_seed
    user_display_name: user.username,
    timeout: 60000,
    attestation_type: "none",
    exclude_credentials: authenticatorsForContractExclusion,
    authenticator_selection: { residentKey: 'required', userVerification: 'preferred' },
    extensions: null,
    supported_algorithm_ids: [-7, -257],
    preferred_authenticator_type: null,
  };

  console.log('contractArgs to be stringified for contract call:', contractArgs);

  const provider = nearClient.getProvider() as JsonRpcProvider;
  const rawResult: any = await provider.query({
    request_type: 'call_function',
    account_id: 'webauthn-contract.testnet',
    method_name: 'generate_registration_options',
    args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
    finality: 'optimistic',
  });

  if (rawResult.error) {
    console.error("Contract query error:", rawResult.error);
    const errorMessage = typeof rawResult.error === 'object' ? JSON.stringify(rawResult.error) : rawResult.error;
    throw new Error(`Contract call error: ${errorMessage}`);
  }

  if (!rawResult.result || rawResult.result.length === 0) {
    console.warn('Empty result bytes from contract call. Raw result:', rawResult);
    throw new Error('Empty result bytes from contract call, or result format unexpected.');
  }

  const contractResponse = JSON.parse(Buffer.from(rawResult.result).toString());

  if (!contractResponse || !contractResponse.options) {
    console.error('Invalid structured response from contract generate_registration_options:', contractResponse);
    throw new Error('Invalid structured response from registration options contract call');
  }

  return {
    options: contractResponse.options,
    derpAccountId: contractResponse.derpAccountId,
  };
}

async function getRegistrationOptions(
  usernameInput: string,
  useContractMethod: boolean
): Promise<UnifiedRegistrationOptionsResponse> {
  let user: User | undefined = userOperations.findByUsername(usernameInput);
  const sanitizedUsername = usernameInput.toLowerCase().replace(/[^a-z0-9_\-]/g, '').substring(0, 32);
  const potentialDerpAccountId = `${sanitizedUsername}.${config.relayerAccountId}`;

  if (!user) {
    user = {
      id: `user_${Date.now()}_${usernameInput}`,
      username: usernameInput,
      derpAccountId: potentialDerpAccountId
    };
    userOperations.create(user);
  } else {
    if (!user.derpAccountId || !user.derpAccountId.endsWith(`.${config.relayerAccountId}`)) {
      userOperations.updateDerpAccountId(user.id, potentialDerpAccountId);
      user.derpAccountId = potentialDerpAccountId;
    }
  }

  const rawAuthenticators = authenticatorOperations.findByUserId(user.id);

  if (useContractMethod) {
    return getRegistrationOptionsContract(usernameInput, user, rawAuthenticators);
  } else {
    return getRegistrationOptionsSimpleWebAuthn(usernameInput, user, rawAuthenticators);
  }
}

// Generate registration options
router.post('/generate-registration-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  try {
    const result = await getRegistrationOptions(username, config.useContractMethod);

    // Get the user that was used/created to store the challenge
    const userForChallenge = userOperations.findByUsername(username);
    if (!userForChallenge) {
      console.error("User disappeared after options generation?");
      return res.status(500).json({ error: 'User context lost after options generation' });
    }

    userOperations.updateChallenge(userForChallenge.id, result.options.challenge);
    console.log('Generated registration options for:', username, 'Suggested derpAccountId:', result.derpAccountId);
    return res.json({ ...result.options, derpAccountId: result.derpAccountId });

  } catch (e: any) {
    console.error('Error in /generate-registration-options route:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate registration options' });
  }
});

// Verify registration
router.post('/verify-registration', async (req: Request, res: Response) => {
  const { username, attestationResponse } = req.body as {
    username: string,
    attestationResponse: RegistrationResponseJSON
  };

  if (!username || !attestationResponse) {
    return res.status(400).json({ error: 'Username and attestationResponse are required' });
  }

  let userForChallengeClear: User | undefined;

  try {
    const user = userOperations.findByUsername(username);
    userForChallengeClear = user;

    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found or registration not initiated.` });
    }

    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found. Registration might have timed out.' });
    }

    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter, credentialBackedUp, credentialDeviceType } = registrationInfo;
      const transportsString = JSON.stringify(attestationResponse.response.transports || []);
      const nearPublicKeyFromCOSE = deriveNearPublicKeyFromCOSE(Buffer.from(credentialPublicKey));

      // Store authenticator with COSE-derived key
      authenticatorOperations.create({
        credentialID: isoBase64URL.fromBuffer(credentialID),
        credentialPublicKey: Buffer.from(credentialPublicKey),
        counter,
        transports: transportsString,
        userId: user.id,
        name: `Authenticator on ${credentialDeviceType}`,
        registered: new Date().toISOString(),
        backedUp: credentialBackedUp ? 1 : 0,
        derivedNearPublicKey: nearPublicKeyFromCOSE,
      });

      userOperations.updateChallenge(user.id, null);
      console.log('New authenticator hardware registered for user:', username, ", COSE-derived NEAR PK:", nearPublicKeyFromCOSE);

      return res.json({
        verified: true,
        username: user.username,
        derpAccountId: user.derpAccountId
      });
    } else {
      if (user) userOperations.updateChallenge(user.id, null);
      return res.status(400).json({
        verified: false,
        error: 'Could not verify attestation with passkey hardware.'
      });
    }
  } catch (e: any) {
    console.error('Error verifying registration:', e);
    if (userForChallengeClear) {
      userOperations.updateChallenge(userForChallengeClear.id, null);
    }
    return res.status(500).json({
      verified: false,
      error: e.message || 'Verification failed due to an unexpected server error.'
    });
  }
});

// Check if username is already registered
router.get('/check-username', (req: Request, res: Response) => {
  const { username } = req.query;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username query parameter is required and must be a string.' });
  }

  try {
    const userEntry = userOperations.findByUsername(username);
    return res.json({ registered: !!userEntry });
  } catch (e: any) {
    console.error('Error checking username:', e);
    return res.status(500).json({ error: 'Failed to check username status.' });
  }
});

export default router;