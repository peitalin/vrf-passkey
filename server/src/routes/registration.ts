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
    user_id: user.id, // Let contract generate internal userID bytes from random_seed
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

  const account = nearClient.getRelayerAccount();
  const rawResult: any = await account.callFunction({
    contractId: 'webauthn-contract.testnet',
    methodName: 'generate_registration_options',
    args: contractArgs,
  });


  if (!rawResult.challenge || !rawResult.authenticatorSelection) {
    console.warn('Empty result bytes from contract call. Raw result:', rawResult);
    throw new Error('Empty result bytes from contract call, or result format unexpected.');
  }

  return {
    options: rawResult,
    derpAccountId: user.derpAccountId,
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
    // ALTERNATIVE APPROACH WITH YIELD-RESUME:
    // Instead of storing challenge on server, use contract yield-resume:
    //
    // 1. Call contract.start_registration(username)
    // 2. Contract generates options and yields with challenge
    // 3. Return options + data_id to client
    // 4. Client creates attestation using options
    // 5. Client calls contract.resume_registration(data_id, attestation)
    // 6. Contract verifies attestation against yielded challenge
    //
    // SECURITY ENHANCEMENT: Challenge Protection from Node Operators
    // =============================================================
    //
    // Problem: Node runners might be able to peek at yielded challenge data
    // Solution: Use hash-based commitment scheme
    //
    // Secure Flow:
    // 1. contract.start_registration(username) → {
    //      challenge = generate_challenge()
    //      commitment = sha256(challenge + salt)
    //      yield_create(commitment)  // Only hash stored, not plaintext!
    //      return { options, challenge }  // Challenge sent to client
    //    }
    //
    // 2. Client creates attestation with challenge (normal WebAuthn flow)
    //
    // 3. contract.resume_registration(data_id, attestation, original_challenge) → {
    //      promise_yield_resume(data_id, {attestation, original_challenge})
    //    }
    //
    // 4. finish_registration() → {
    //      stored_commitment = promise_result(0)
    //      {attestation, provided_challenge} = promise_result(1)
    //
    //      // Verify commitment first
    //      computed_commitment = sha256(provided_challenge + salt)
    //      assert_eq!(stored_commitment, computed_commitment)
    //
    //      // Then verify WebAuthn attestation
    //      verify_webauthn_attestation(attestation, provided_challenge)
    //    }
    //
    // Client-Side Changes Required:
    // - Store the original challenge during registration flow
    // - Provide both attestation AND original challenge when resuming
    // - No other changes to WebAuthn API usage
    //
    // Benefits:
    // - No server-side challenge storage needed
    // - Challenge is cryptographically protected in contract state
    // - More decentralized architecture
    // - Automatic timeout handling (200 blocks)
    // - Challenge remains hidden from node operators during yield phase

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

// Unified verification function
async function verifyRegistrationResponseUnified(
  verification: {
    response: RegistrationResponseJSON,
    expectedChallenge: string,
    expectedOrigin: string,
    expectedRPID: string,
    requireUserVerification: boolean,
  },
  useContractMethod: boolean
): Promise<{ verified: boolean; registrationInfo?: any }> {

  let {
    response: attestationResponse,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification,
  } = verification;

  if (useContractMethod) {
    return verifyRegistrationResponseContract(attestationResponse, expectedChallenge);
  } else {
    return verifyRegistrationResponseSimpleWebAuthn(attestationResponse, expectedChallenge);
  }
}

async function verifyRegistrationResponseSimpleWebAuthn(
  attestationResponse: RegistrationResponseJSON,
  expectedChallenge: string
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using SimpleWebAuthn for registration verification');

  const verification = await verifyRegistrationResponse({
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

async function verifyRegistrationResponseContract(
  attestationResponse: RegistrationResponseJSON,
  expectedChallenge: string
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using NEAR contract for registration verification');

  try {
    const provider = nearClient.getProvider() as JsonRpcProvider;

    // Call contract's verify_registration_response method
    const contractArgs = {
      attestation_response: attestationResponse,
      expected_challenge: expectedChallenge,
      expected_origin: config.expectedOrigin,
      expected_rp_id: config.rpID,
      require_user_verification: true
    };

    console.log("contractArgs:", JSON.stringify(contractArgs));

    const rawResult: any = await provider.query({
      request_type: 'call_function',
      account_id: 'webauthn-contract.testnet',
      method_name: 'verify_registration_response_internal',
      args_base64: Buffer.from(JSON.stringify(contractArgs)).toString('base64'),
      finality: 'optimistic',
    });

    if (rawResult.error) {
      console.error("Contract verification error:", rawResult.error);
      const errorMessage = typeof rawResult.error === 'object' ? JSON.stringify(rawResult.error) : rawResult.error;
      throw new Error(`Contract verification error: ${errorMessage}`);
    }

    if (!rawResult.result || rawResult.result.length === 0) {
      console.warn('Empty result from contract verification. Raw result:', rawResult);
      throw new Error('Empty result from contract verification call');
    }

    const contractResponse = JSON.parse(Buffer.from(rawResult.result).toString());

    if (!contractResponse) {
      console.error('Invalid response from contract verify_registration_response_internal:', contractResponse);
      throw new Error('Invalid response from contract verification call');
    }

    // Convert contract response to match SimpleWebAuthn format
    const registrationInfo = contractResponse.registration_info ? {
      credentialPublicKey: new Uint8Array(contractResponse.registration_info.credential_public_key),
      credentialID: new Uint8Array(contractResponse.registration_info.credential_id),
      counter: contractResponse.registration_info.counter,
      credentialBackedUp: false, // Contract doesn't track this yet
      credentialDeviceType: 'unknown', // Contract doesn't track this yet
    } : undefined;

    return {
      verified: contractResponse.verified,
      registrationInfo
    };

  } catch (e: any) {
    console.error('Error calling contract verify_registration_response_internal:', e);
    throw new Error(`Failed to verify via contract: ${e.message}`);
  }
}

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

    const verification = await verifyRegistrationResponseUnified({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    }, config.useContractMethod);

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