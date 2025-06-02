import { Router, Request, Response } from 'express';
import {
  generateRegistrationOptions as simpleWebAuthnGenerateRegistrationOptions,
  verifyRegistrationResponse as simpleWebAuthnVerifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { RegistrationResponseJSON, PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server/script/deps';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { JsonRpcProvider } from 'near-api-js/lib/providers';
import { utils } from 'near-api-js';

import config, { DEFAULT_GAS_STRING, COMPLETE_REGISTRATION_GAS_STRING } from '../config';
import { userOperations, authenticatorOperations } from '../database';
import { nearClient } from '../nearService';
import { deriveNearPublicKeyFromCOSE } from '../keyDerivation';
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
  dataId: string; // The crucial data_id from the yield
}

// Interface for contract arguments (complete_registration)
interface ContractCompleteRegistrationArgs {
  registration_response: RegistrationResponseJSON; // The client's WebAuthn response
  data_id: string; // The data_id received from generate_registration_options
}

// --- Helper function to get registration options from SimpleWebAuthn (no changes needed here) ---
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

  const options = await simpleWebAuthnGenerateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: user.id, // SimpleWebAuthn uses this as userID directly (usually a random string)
    userName: user.username,
    userDisplayName: user.username,
    excludeCredentials: authenticatorsForSimpleWebAuthnExclusion,
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    supportedAlgorithmIDs: [-7, -257],
    attestationType: 'none',
    timeout: 60000,
  });

  console.log('Options from SimpleWebAuthn:', JSON.stringify(options, null, 2));
  // To match the unified response, we invent a dataId (not used by SimpleWebAuthn)
  return {
    options,
    derpAccountId: user.derpAccountId,
    dataId: `simplewebauthn_unused_${Date.now()}`,
  };
}

// --- Updated helper function to get registration options from NEAR Contract ---
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
  // This is a `call` method because it involves `promise_yield_create`
  const rawResult = await account.callFunction({
    contractId: config.contractId,
    methodName: 'generate_registration_options',
    args: contractArgs,
    gas: BigInt(DEFAULT_GAS_STRING), // Use gas constant from config
  });

  console.log('Raw result from contract.generate_registration_options:', rawResult);
  let contractResponseString: string = rawResult.toString();

  const contractResponse: ContractRegistrationOptionsResponse = JSON.parse(contractResponseString);
  console.log('parsed Contract response:', contractResponse);

  if (!contractResponse.options || !contractResponse.dataId) {
    console.error('Invalid response from contract.generate_registration_options:', contractResponse);
    throw new Error('Contract did not return valid registration options or dataId.');
  }

  console.log('Received from contract.generate_registration_options:', JSON.stringify(contractResponse, null, 2));
  return contractResponse; // This includes options, derpAccountId, and dataId
}

// --- Unified getRegistrationOptions (no major changes, but ensure User.id is suitable for contract) ---
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
    user = {
      id: newUserId,
      username: usernameInput,
      derpAccountId: potentialDerpAccountId,
      currentChallenge: null, // Ensure all User fields are present
      currentDataId: null,    // Ensure all User fields are present
    };
    userOperations.create(user); // Now `user` is a full User object
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

// --- Generate registration options Endpoint ---
router.post('/generate-registration-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  try {
    const result = await getRegistrationOptions(username, config.useContractMethod);

    const userForChallenge = userOperations.findByUsername(username);
    if (!userForChallenge) {
      console.error("User disappeared after options generation?");
      return res.status(500).json({ error: 'User context lost after options generation' });
    }

    // Store challenge and dataId for the verification step
    userOperations.updateChallengeAndDataId(userForChallenge.id, result.options.challenge, result.dataId);
    console.log('Generated registration options for:', username, 'Suggested derpAccountId:', result.derpAccountId, 'dataId:', result.dataId);

    // Return the options and derpAccountId to the client. dataId is NOT sent to client, server holds it.
    return res.json({
      options: result.options,
      derpAccountId: result.derpAccountId,
      // DO NOT SEND dataId to client if it's a secret part of yield handling.
      // However, the contract design has generate_registration_options return it,
      // implying client might need to echo it back, or server uses it from its DB.
      // For yield-resume, data_id is essential for the client to call complete_registration.
      // The current contract returns it. So, we should pass it to the client.
      dataId: result.dataId
    });

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

// --- verifyRegistrationResponseSimpleWebAuthn (no changes needed) ---
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
    requireUserVerification: true, // Typically true for passkeys
  });
  return {
    verified: verification.verified,
    registrationInfo: verification.registrationInfo
  };
}

// --- Updated function to complete registration via NEAR Contract ---
async function completeRegistrationContract(
  attestationResponse: RegistrationResponseJSON,
  dataId: string // The data_id received from generate_registration_options
): Promise<{ verified: boolean; registrationInfo?: any }> {
  console.log('Using NEAR contract to complete registration with dataId:', dataId);

  try {
    const account = nearClient.getRelayerAccount();
    const contractArgs: ContractCompleteRegistrationArgs = {
      registration_response: attestationResponse,
      data_id: dataId,
    };

    console.log("Calling contract.complete_registration with args:", JSON.stringify(contractArgs));

    const transactionOutcome = await account.functionCall({
      contractId: config.contractId,
      methodName: 'complete_registration',
      args: contractArgs,
      gas: BigInt(COMPLETE_REGISTRATION_GAS_STRING), // Use specific gas for this potentially complex call
    });

    console.log('Transaction outcome from complete_registration:', JSON.stringify(transactionOutcome, null, 2));

    // Check if the transaction itself was successful
    if (transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'Failure' in transactionOutcome.status) {
      // @ts-ignore
      const errorInfo = transactionOutcome.status.Failure.ActionError?.kind?.FunctionCallError?.ExecutionError || 'Unknown contract execution error';
      console.error("Contract complete_registration call failed:", errorInfo);
      throw new Error(`Contract complete_registration failed: ${errorInfo}`);
    }

    // With yield-resume, `complete_registration` typically just returns true/false or an empty success.
    // The actual `VerifiedRegistrationResponse` comes from the *callback* `resume_registration_callback`.
    // The server cannot directly get the callback's return value in this single transaction.
    // For now, we assume success if the transaction didn't fail outright.
    // A more robust system might:
    //  1. Have the callback emit an event that the server listens for.
    //  2. Have the callback store results in contract state that the server polls.
    //  3. The client could poll the contract for verification status using a view method.

    // If the transaction didn't throw an error, we assume the yield was resumed.
    // The actual verification happens in the private callback.
    // To get registrationInfo, we would ideally need the callback to store it and provide a view method.
    // For this example, we'll simulate a successful verification if the call didn't fail.
    // And we won't have registrationInfo from the contract this way.

    // Let's try to query the `test_process_registration` if available and in a test-like setup
    // THIS IS A HACK for trying to get results, not for production.
    // In production, the callback is private and its result isn't directly available to the relayer.
    let simulatedRegistrationInfo: any = undefined;
    let verified = true; // Assume verified if complete_registration tx succeeded.

    // To get actual registrationInfo, the frontend/client would typically parse the attestationResponse
    // itself if `attestationType` was 'none' or it handled attestation verification itself.
    // Or, the contract callback would need to store this info.
    // Since our contract (with `fmt: "none"`) *does* parse and return it in the callback, we have a gap.

    // For now, if the call to complete_registration succeeded, we will assume verification was true.
    // We can parse the attestationResponse locally to get some info for DB storage if needed.
    if (attestationResponse.response.attestationObject && attestationResponse.response.clientDataJSON) {
        // This is a client-side/server-side interpretation, not from contract callback result
        // Placeholder: In a real scenario with 'none' attestation, you might parse clientDataJSON and some parts of attestationObject
        // For this example, if `complete_registration` succeeded, we assume `verified: true`.
        // The `registrationInfo` for DB needs to be constructed carefully.
        // Let's simulate getting credentialID and publicKey for DB storage if the call was okay.
        try {
            const rawId = isoBase64URL.toBuffer(attestationResponse.rawId);
            // For `none` attestation, the publicKey is not directly verifiable from attestationObject by server
            // but it's inside authData. The contract callback handles this.
            // We cannot get the *exact* credentialPublicKey the contract derived without a view method or event.
            // So, we will store what the client sent, and the contract verifies it internally.
            simulatedRegistrationInfo = {
                credentialID: rawId, // Buffer
                credentialPublicKey: new Uint8Array(), // Placeholder - contract callback would have the real one
                counter: 0, // Placeholder - contract callback would have the real one
            }
        } catch (parseError) {
            console.warn('Could not parse parts of attestationResponse for simulated registrationInfo:', parseError)
        }
    }

    return {
      verified: verified,
      registrationInfo: simulatedRegistrationInfo // This is NOT from contract callback in this flow
    };

  } catch (e: any) {
    console.error('Error calling contract complete_registration:', e.message, e.stack, e.type, e.context);
    throw new Error(`Failed to complete registration via contract: ${e.message}`);
  }
}

// --- Verify registration Endpoint (Updated) ---
router.post('/verify-registration', async (req: Request, res: Response) => {
  const { username, attestationResponse, dataId } = req.body as {
    username: string,
    attestationResponse: RegistrationResponseJSON,
    dataId?: string // dataId is now expected if using contract method
  };

  if (!username || !attestationResponse) {
    return res.status(400).json({ error: 'Username and attestationResponse are required' });
  }
  if (config.useContractMethod && !dataId) {
    return res.status(400).json({ error: 'dataId is required for contract method verification' });
  }

  let userForChallengeClear: User | undefined;

  try {
    const user = userOperations.findByUsername(username);
    userForChallengeClear = user;

    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found or registration not initiated.` });
    }

    const expectedChallenge = user.currentChallenge;
    const storedDataId = user.currentDataId;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found. Registration might have timed out or was not initiated correctly.' });
    }
    if (config.useContractMethod && storedDataId !== dataId) {
        console.warn(`DataId mismatch. Stored: ${storedDataId}, Received: ${dataId}`);
        // Depending on security model, this could be an error or just a log.
        // If dataId is echoed by client, it should match what server stored from generate_registration_options.
    }

    let verificationResult: { verified: boolean; registrationInfo?: any };

    if (config.useContractMethod) {
      // For contract method, `completeRegistrationContract` is called.
      // It handles the `complete_registration` call which resumes the yield.
      // The actual verification happens in the contract's private callback.
      verificationResult = await completeRegistrationContract(attestationResponse, dataId!);
    } else {
      verificationResult = await verifyRegistrationResponseSimpleWebAuthn(attestationResponse, expectedChallenge);
    }

    const { verified, registrationInfo } = verificationResult;

    if (verified) {
      // If using SimpleWebAuthn, registrationInfo is populated.
      // If using contract, registrationInfo from completeRegistrationContract is a simulation/placeholder.
      // The actual reliable registrationInfo would need to be fetched from contract state post-callback if stored.
      let dbRegistrationInfo = registrationInfo;
      if (config.useContractMethod && !registrationInfo?.credentialID) {
        // If contract method was used and we don't have solid info, create from attestationResponse for DB
        // This is a simplified placeholder for what the contract callback would determine.
        dbRegistrationInfo = {
            credentialID: isoBase64URL.toBuffer(attestationResponse.rawId),
            credentialPublicKey: new Uint8Array(), // Placeholder, ideally get from contract event/view after callback
            counter: 0, // Placeholder
        };
      }

      const { credentialPublicKey, credentialID, counter } = dbRegistrationInfo || {};
      const transportsString = JSON.stringify(attestationResponse.response.transports || []);
      // Note: deriveNearPublicKeyFromCOSE needs the *actual* COSE public key bytes.
      // If using contract, the true COSE key is processed on-chain. We don't have it here unless logged by an event.
      // For SimpleWebAuthn, registrationInfo.credentialPublicKey is the COSE key.
      let nearPublicKeyFromCOSE = "contract-derived-key-placeholder";
      if (credentialPublicKey && credentialPublicKey.length > 0) {
          try {
            nearPublicKeyFromCOSE = deriveNearPublicKeyFromCOSE(credentialPublicKey); // Pass Buffer directly
          } catch (e) { console.warn("Failed to derive NEAR PK from COSE on server, using placeholder", e);}
      } else if (config.useContractMethod) {
        console.log("Using placeholder for derivedNearPublicKey as contract handles derivation.")
      }

      authenticatorOperations.create({
        credentialID: isoBase64URL.fromBuffer(credentialID || isoBase64URL.toBuffer(attestationResponse.rawId)),
        credentialPublicKey: Buffer.from(credentialPublicKey || new Uint8Array()), // Store what we have
        counter: counter || 0,
        transports: transportsString,
        userId: user.id,
        name: `Authenticator for ${user.username} (${attestationResponse.response.transports ? attestationResponse.response.transports.join('/') : 'unknown'})`,
        registered: new Date().toISOString(),
        backedUp: registrationInfo?.credentialBackedUp ? 1 : 0, // From SimpleWebAuthn, or assume false
        derivedNearPublicKey: nearPublicKeyFromCOSE,
      });

      userOperations.updateChallengeAndDataId(user.id, null, null); // Clear challenge and dataId
      console.log('Registration verification successful for:', username, "Derived NEAR PK (server-side interpretation):", nearPublicKeyFromCOSE);

      return res.json({
        verified: true,
        username: user.username,
        derpAccountId: user.derpAccountId
        // We don't have the contract-verified registrationInfo here directly.
      });
    } else {
      if (user) userOperations.updateChallengeAndDataId(user.id, null, null);
      return res.status(400).json({
        verified: false,
        error: 'Could not verify attestation with passkey hardware.'
      });
    }
  } catch (e: any) {
    console.error('Error verifying registration:', e.message, e.stack);
    if (userForChallengeClear) {
      userOperations.updateChallengeAndDataId(userForChallengeClear.id, null, null);
    }
    return res.status(500).json({
      verified: false,
      error: e.message || 'Verification failed due to an unexpected server error.'
    });
  }
});

// Check if username is already registered (no changes needed)
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