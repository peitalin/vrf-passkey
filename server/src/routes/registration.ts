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
import { userOperations, authenticatorOperations } from '../database';
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
  derpAccountId: string | undefined;
  commitmentId: string | null;
}

// Interface for contract arguments (verify_registration_response)
interface ContractCompleteRegistrationArgs {
  registration_response: RegistrationResponseJSON; // The client's WebAuthn response
  commitment_id: string; // The commitment_id received from generate_registration_options
}

// Helper function to get registration options from SimpleWebAuthn
async function getRegistrationOptionsSimpleWebAuthn(
  username: string,
  user: User,
  rawAuthenticators: any[]
): Promise<ContractRegistrationOptionsResponse> { // Update return type to match contract for consistency
  console.log(`Using SimpleWebAuthn for registration options for user: ${user.username}`);

  const authenticatorsForSimpleWebAuthnExclusion = rawAuthenticators.map(auth => ({
    id: isoBase64URL.toBuffer(auth.credentialID),
    type: 'public-key' as const,
    transports: auth.transports ? JSON.parse(auth.transports) as AuthenticatorTransport[] : undefined,
  }));

  const optionsFromSimpleWebAuthn = await simpleWebAuthnGenerateRegistrationOptions({
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

  console.log('Options from SimpleWebAuthn:', JSON.stringify(optionsFromSimpleWebAuthn, null, 2));

  return {
    options: optionsFromSimpleWebAuthn,
    derpAccountId: user.derpAccountId || undefined,
    commitmentId: `simplewebauthn_unused_${Date.now()}`,
  };
}

// Updated helper function to get registration options from NEAR Contract
async function getRegistrationOptionsContract(
  username: string,
  user: User,
  rawAuthenticators: any[]
): Promise<ContractRegistrationOptionsResponse> {
  console.log(`Using NEAR contract for registration options for user: ${user.username}, userID for contract: ${user.id}`);

  const authenticatorsForContractExclusion = rawAuthenticators.map(auth => ({
    id: auth.credentialID, // Contract expects base64url string id
    type: 'public-key' as const,
    transports: auth.transports ? JSON.parse(auth.transports).map((t: string) => String(t)) : undefined,
  }));

  const contractArgs: ContractGenerateOptionsArgs = {
    rp_name: config.rpName,
    rp_id: config.rpID,
    user_name: user.username, // For display and derpAccountId suggestion
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

// Unified getRegistrationOptions
async function getRegistrationOptions(
  usernameInput: string,
  useContractMethod: boolean
): Promise<ContractRegistrationOptionsResponse> {
  let user: User | undefined = userOperations.findByUsername(usernameInput);
  const sanitizedUsername = usernameInput.toLowerCase().replace(/[^a-z0-9_\-]/g, '').substring(0, 32);
  const potentialDerpAccountId = `${sanitizedUsername}.${config.relayerAccountId}`;

  if (!user) {
    // For a new user, their `id` will be used as `user.id` by SimpleWebAuthn
    // and as `user_id` (base64url) by the contract.
    // This ID should be persistent and unique for the user.
    // Using a server-generated UUID or deriving from the first passkey's rawId are options.
    // For simplicity here, we'll use a timestamped ID, but this is NOT suitable for production if it needs to be guess-resistant or perfectly stable before first credential.
    const newUserId = `user_${Date.now()}_${isoBase64URL.fromBuffer(crypto.getRandomValues(new Uint8Array(8)))}`;
    const newUser: User = {
      id: newUserId,
      username: usernameInput,
      derpAccountId: potentialDerpAccountId,
      currentChallenge: null,
      currentCommitmentId: null,
    };
    userOperations.create(newUser);
    user = newUser;
    console.log(`New user created for registration: ${usernameInput}, assigned ID: ${user.id}`);
  } else {
    if (!user.derpAccountId || !user.derpAccountId.endsWith(`.${config.relayerAccountId}`)) {
      userOperations.updateDerpAccountId(user.id, potentialDerpAccountId);
      user.derpAccountId = potentialDerpAccountId;
    }
    console.log(`Existing user found for registration: ${usernameInput}, ID: ${user.id}`);
  }

  const rawAuthenticators = authenticatorOperations.findByUserId(user.id);

  if (useContractMethod) {
    return getRegistrationOptionsContract(usernameInput, user, rawAuthenticators);
  } else {
    return getRegistrationOptionsSimpleWebAuthn(usernameInput, user, rawAuthenticators);
  }
}

// Generate registration options Endpoint
router.post('/generate-registration-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  try {
    const resultFromService = await getRegistrationOptions(username, config.useContractMethod);

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
    console.log('Generated registration options for:', username, 'Sending to client:', JSON.stringify(resultFromService, null, 2));

    // `resultFromService` already has the structure { options: {...}, derpAccountId, commitmentId }
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

// verifyRegistrationResponseSimpleWebAuthn
async function verifyRegistrationResponseSimpleWebAuthn(
  attestationResponse: RegistrationResponseJSON,
  expectedChallenge: string
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using SimpleWebAuthn for registration verification');
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

// Verify and complete registration via NEAR Contract
async function verifyRegistrationResponseContract(
  attestationResponse: RegistrationResponseJSON,
  commitmentId: string // The commitment_id received from generate_registration_options
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using NEAR contract to complete registration with commitmentId:', commitmentId);

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

// Verify registration Endpoint
router.post('/verify-registration', async (req: Request, res: Response) => {
  const { username, attestationResponse, commitmentId } = req.body as {
    username: string,
    attestationResponse: RegistrationResponseJSON,
    commitmentId?: string
  };

  if (!username || !attestationResponse) {
    return res.status(400).json({ error: 'Username and attestationResponse are required' });
  }
  if (config.useContractMethod && !commitmentId) {
    return res.status(400).json({ error: 'commitmentId is required for contract method verification' });
  }

  let userForChallengeClear: User | undefined;

  try {
    const user = userOperations.findByUsername(username);
    userForChallengeClear = user;

    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found or registration not initiated.` });
    }

    const expectedChallenge = user.currentChallenge;
    const storedCommitmentId = user.currentCommitmentId;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found. Registration might have timed out or was not initiated correctly.' });
    }
    if (config.useContractMethod && storedCommitmentId !== commitmentId) {
        console.warn(`commitmentId mismatch. Stored: ${storedCommitmentId}, Received: ${commitmentId}`);
        // If commitmentId is echoed by client, it should match what server stored from generate_registration_options.
    }

    let verificationResult: { verified: boolean; registrationInfo?: any };

    if (config.useContractMethod && commitmentId) {
      verificationResult = await verifyRegistrationResponseContract(attestationResponse, commitmentId);
    } else if (!config.useContractMethod && expectedChallenge) {
      verificationResult = await verifyRegistrationResponseSimpleWebAuthn(attestationResponse, expectedChallenge);
    } else {
      return res.status(400).json({ error: 'Invalid state for verification process.'});
    }

    const { verified, registrationInfo } = verificationResult;

    if (verified) {
      // Construct the authenticator object for DB insertion based on the simplified schema
      const {
        credentialID: rawCredentialIDBuffer,
        credentialPublicKey: rawPublicKeyBuffer,
        counter
      } = registrationInfo || {};

      // Ensure we have the necessary info, especially from SimpleWebAuthn path
      const credentialIDForDB = rawCredentialIDBuffer ? isoBase64URL.fromBuffer(rawCredentialIDBuffer) : attestationResponse.id;
      const publicKeyForDB = rawPublicKeyBuffer ? Buffer.from(rawPublicKeyBuffer) : Buffer.from(new Uint8Array()); // Default to empty if not present
      const counterForDB = counter || 0;

      authenticatorOperations.create({
        credentialID: credentialIDForDB,
        credentialPublicKey: publicKeyForDB,
        counter: counterForDB,
        transports: JSON.stringify(attestationResponse.response.transports || []),
        userId: user.id,
        name: `Authenticator for ${user.username} (${attestationResponse.response.transports?.join('/') || 'unknown'})`,
        registered: new Date().toISOString(),
        backedUp: registrationInfo?.credentialBackedUp ? 1 : 0,
        clientManagedNearPublicKey: null,
        // Set to null initially, to be updated by a separate key association flow
      });

      userOperations.updateChallengeAndCommitmentId(user.id, null, null);
      console.log('Registration verification successful for:', username);

      return res.json({
        verified: true,
        username: user.username,
        derpAccountId: user.derpAccountId,
      });
    } else {
      if (user) userOperations.updateChallengeAndCommitmentId(user.id, null, null);
      return res.status(400).json({
        verified: false,
        error: 'Could not verify attestation with passkey hardware.'
      });
    }
  } catch (e: any) {
    console.error('Error verifying registration:', e.message, e.stack);
    if (req.body.username) { // Check if user was determined to clear their challenge
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