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
  yieldResumeId?: string;
}

// Helper function to get authentication options from NEAR Contract
async function generateAuthenticationOptionsContract(
  authenticator: StoredAuthenticator,
  rpID: string = config.rpID,
  allowCredentialsList?: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[],
  userVerification: 'discouraged' | 'preferred' | 'required' = 'preferred',
  userId?: string
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
    console.log('🎯 Explorer Link:', `https://testnet.nearblocks.io/txns/${generateTxHash}?tab=execution`);
    console.log('👤 Storing txHash for userId:', userId);
    storeTransactionHash(generateTxHash, 'generate_authentication_options', userId);
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
  if (contractResponse.yieldResumeId && generateTxHash && userId) {
    storeUserGenerateAuthTxHash(userId, generateTxHash, contractResponse.yieldResumeId);
  } else {
    console.warn('Cannot store user auth session: missing userId, yieldResumeId, or generateTxHash');
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
    userId?: string;
  }
): Promise<ContractAuthenticationOptionsResponse> {
  const {
    rpID = config.rpID,
    userVerification = 'preferred',
    allowCredentials,
    authenticator,
    userId
  } = options;

  if (config.useContractMethod) {
    if (!authenticator) {
      throw new Error('Authenticator is required for contract method');
    }
    return generateAuthenticationOptionsContract(
      authenticator,
      rpID,
      allowCredentials,
      userVerification,
      userId
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
          // Set the userId on the authenticator for tracking
          firstAuthenticator.userId = userRec.id;
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
      userId: userForChallengeStorageInDB?.id, // Pass the actual user ID, not username
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

// Helper function to extract additional callback results from contract state
async function extractCallbackResults(txHash: string): Promise<{greeting?: string}> {
  try {
    // Give callbacks time to complete and update contract state
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Query the contract state to see what resume_authentication_callback set
    const greeting = await nearClient.getGreeting();
    console.log('📋 Contract greeting after callbacks:', greeting);

    return { greeting };
  } catch (error) {
    console.warn('Could not extract additional callback results:', error);
    return {};
  }
}

// Helper function to count logs in transaction result
function extractLogCount(txResult: any): number {
  let logCount = 0;

  // Count transaction outcome logs
  if (txResult.transaction_outcome?.outcome?.logs) {
    logCount += txResult.transaction_outcome.outcome.logs.length;
  }

  // Count receipt outcome logs
  if (txResult.receipts_outcome && Array.isArray(txResult.receipts_outcome)) {
    for (const receipt of txResult.receipts_outcome) {
      if (receipt.outcome && receipt.outcome.logs && Array.isArray(receipt.outcome.logs)) {
        logCount += receipt.outcome.logs.length;
      }
    }
  }

  return logCount;
}

// Helper function to verify authentication using NEAR Contract with yield-resume
async function verifyAuthenticationResponseContract(
  response: AuthenticationResponseJSON,
  yieldResumeId: string,
  userId?: string
): Promise<{ verified: boolean; authenticationInfo?: any }> {
  console.log('Using NEAR contract for yield-resume authentication verification');

  // Step 1: Resume yield with authentication response
  console.log('Step 1: Resuming yield with authentication response...');
  const resumeResult: any = await nearClient.callFunction(
    config.contractId,
    'verify_authentication_response',
    {
      authentication_response: response,
      yield_resume_id: yieldResumeId,
    },
    AUTHENTICATION_VERIFICATION_GAS_STRING,
    '0'
  );

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

  // Log current transaction hash for reference
  const currentTxHash = resumeResult.transaction.hash;
  console.log('🔗 Current (resume) Transaction Hash:', currentTxHash);
  console.log('🔗 Current Explorer Link:', `https://testnet.nearblocks.io/txns/${currentTxHash}?tab=execution`);

  // Look up the original transaction hash where callbacks will execute
  console.log('🔍 Looking up user session for userId:', userId);
  const userAuthSession = userToGenerateAuthTxHashMap.get(userId || 'unknown');
  const originalTxHash = userAuthSession?.txHash;

  if (!originalTxHash) {
    console.error('❌ Could not find original transaction hash for user:', userId);
    console.log('Available user sessions:', Array.from(userToGenerateAuthTxHashMap.keys()));
    console.log('Full user sessions map:', Array.from(userToGenerateAuthTxHashMap.entries()));
    throw new Error('Could not find original transaction hash for callback querying. User may need to call generate-authentication-options first.');
  }

  console.log('✅ Found user session for userId:', userId);
  console.log('🎯 Original (callbacks) Transaction Hash:', originalTxHash);
  console.log('🎯 Original Explorer Link:', `https://testnet.nearblocks.io/txns/${originalTxHash}?tab=execution`);
  if (userAuthSession.yieldResumeId) {
    console.log('🔑 Associated Yield Resume ID:', userAuthSession.yieldResumeId);
  }

  // Store current transaction hash for reference
  storeTransactionHash(currentTxHash, 'verify_authentication_response', userId);

  console.log('🔄 AUTOMATIC CALLBACK QUERYING:');
  console.log('   ├── Resume transaction triggers callbacks in original transaction');
  console.log(`   ├── Original txHash: ${originalTxHash}`);
  console.log('   ├── Will automatically query original transaction after 5 seconds');
  console.log('   ├── Tracking by user session instead of yield_resume_id');
  console.log('   └── Looking for: resume_authentication_callback logs');

  // Step 2: Wait 5 seconds then query the original transaction for callback results
  console.log('Step 2: Waiting 5 seconds for callback execution in original transaction...');

  try {
    await new Promise(resolve => setTimeout(resolve, 5000)); // 5 second delay

    console.log('Step 3: Fetching callback results from original transaction...');
    const fullTxResult = await nearClient.getProvider().txStatus(originalTxHash, nearClient.getRelayerAccount().accountId, 'FINAL' as any);

    const logCount = extractLogCount(fullTxResult);
    console.log(`📊 Total logs found in original transaction: ${logCount} logs`);

    console.log("📄 Full original transaction result:", JSON.stringify(fullTxResult, null, 2));

    // Extract logs from all receipts in the transaction
    let allLogs: string[] = [];
    let receiptInfo: Array<{receiptId: string, methodName?: string, logs: string[]}> = [];

    // Check transaction outcome logs
    if (fullTxResult.transaction_outcome?.outcome?.logs) {
      allLogs.push(...fullTxResult.transaction_outcome.outcome.logs);
      receiptInfo.push({
        receiptId: 'transaction_outcome',
        logs: fullTxResult.transaction_outcome.outcome.logs
      });
    }

    // Check all receipt outcome logs
    if (fullTxResult.receipts_outcome && Array.isArray(fullTxResult.receipts_outcome)) {
      for (const receipt of fullTxResult.receipts_outcome) {
        if (receipt.outcome && receipt.outcome.logs && Array.isArray(receipt.outcome.logs)) {
          allLogs.push(...receipt.outcome.logs);

          // Try to extract method name from receipt if available
          let methodName = 'unknown';
          if (receipt.outcome.executor_id && receipt.id) {
            // We could try to match against known callback method names
            if (receipt.outcome.logs.some(log => log.includes('Processing authentication callback'))) {
              methodName = 'resume_authentication_callback';
            }
          }

          receiptInfo.push({
            receiptId: receipt.id,
            methodName,
            logs: receipt.outcome.logs
          });
        }
      }
    }

    console.log('=== EXTRACTED LOGS FROM ALL RECEIPTS ===');
    console.log('Total logs found:', allLogs.length);
    receiptInfo.forEach((info, index) => {
      console.log(`\nReceipt ${index + 1}: ${info.receiptId}`);
      console.log(`Method: ${info.methodName}`);
      console.log(`Logs (${info.logs.length}):`);
      info.logs.forEach((log, logIndex) => {
        console.log(`  [${logIndex}] ${log}`);
      });
    });
    console.log('=== END EXTRACTED LOGS ===');

    // Look for authentication callback completion log
    let authenticationResult: any = null;
    let finallyResult: any = null;

    for (const log of allLogs) {
      if (typeof log === 'string') {
        // Look for the structured authentication result
        if (log.startsWith('WEBAUTHN_AUTH_RESULT: ')) {
          const resultJson = log.substring('WEBAUTHN_AUTH_RESULT: '.length);
          try {
            authenticationResult = JSON.parse(resultJson);
            console.log('🎯 Found structured authentication result:', authenticationResult);
          } catch (parseError) {
            console.warn('Failed to parse authentication result from log:', parseError);
          }
        }
        // Look for callback completion logs
        else if (log.includes('Authentication callback completed with result: verified=')) {
          const verifiedMatch = log.match(/verified=(\w+)/);
          if (verifiedMatch) {
            const verified = verifiedMatch[1] === 'true';
            console.log('✅ Found authentication callback completion:', verified);

            if (!authenticationResult) {
              // Fallback if we didn't get structured result
              authenticationResult = verified ? { verified: true } : { verified: false };
            }
          }
        }
        // Look for any other interesting logs
        else if (log.includes('FINAL RESULT:')) {
          console.log('🏁 Found final result log:', log);
        }
        // Look for any error logs
        else if (log.includes('Authentication commitment mismatch') ||
                 log.includes('Authentication verification failed') ||
                 log.includes('Failed to')) {
          console.log('❌ Found authentication error:', log);
          authenticationResult = { verified: false, error: log };
        }
      }
    }

    // Log summary of what we found
    console.log('\n=== CALLBACK RESULTS SUMMARY ===');
    console.log('Authentication Result:', authenticationResult);
    console.log('Finally Result:', finallyResult);
    console.log('=== END SUMMARY ===');

    // Extract additional results from contract state (like greeting set by resume_authentication_response)
    const additionalResults = await extractCallbackResults(originalTxHash);
    console.log('📋 Additional callback results from contract state:', additionalResults);

    // Verification of automatic querying success
    console.log('\n✅ AUTOMATIC QUERYING VERIFICATION:');
    console.log(`   ├── Original Transaction (generate_authentication_options): ${originalTxHash}`);
    console.log(`   ├── Current Transaction (verify_authentication_response): ${currentTxHash}`);
    console.log(`   ├── Callback Logs Found: ${authenticationResult ? '✓' : '✗'} resume_authentication_callback`);
    console.log(`   ├── Finally Logs Found: ${finallyResult ? '✓' : '✗'} finally_do_something`);
    console.log(`   ├── Contract State Updated: ${additionalResults.greeting ? '✓' : '✗'} greeting`);
    console.log(`   └── Total Logs Extracted: ${logCount} logs from ${receiptInfo.length} receipts`);

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
        yieldResumeId,
        user?.id
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

// Debug endpoint to query stored transaction hashes
router.get('/debug/transactions', async (req: Request, res: Response) => {
  try {
    const transactions = Array.from(transactionHashStore.values()).map(tx => ({
      txHash: tx.txHash,
      purpose: tx.purpose,
      timestamp: new Date(tx.timestamp).toISOString(),
      explorerLink: `https://testnet.nearblocks.io/txns/${tx.txHash}?tab=execution`,
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
    const logCount = extractLogCount(txResult);

    // Extract logs using the same logic as authentication verification
    let allLogs: string[] = [];
    let receiptInfo: Array<{receiptId: string, methodName?: string, logs: string[]}> = [];

    // Check transaction outcome logs
    if (txResult.transaction_outcome?.outcome?.logs) {
      allLogs.push(...txResult.transaction_outcome.outcome.logs);
      receiptInfo.push({
        receiptId: 'transaction_outcome',
        logs: txResult.transaction_outcome.outcome.logs
      });
    }

    // Check all receipt outcome logs
    if (txResult.receipts_outcome && Array.isArray(txResult.receipts_outcome)) {
      for (const receipt of txResult.receipts_outcome) {
        if (receipt.outcome && receipt.outcome.logs && Array.isArray(receipt.outcome.logs)) {
          allLogs.push(...receipt.outcome.logs);

          // Try to extract method name from receipt if available
          let methodName = 'unknown';
          if (receipt.outcome.executor_id && receipt.id) {
            if (receipt.outcome.logs.some(log => log.includes('Processing authentication callback'))) {
              methodName = 'resume_authentication_callback';
            } else if (receipt.outcome.logs.some(log => log.includes('fn finally_do_something'))) {
              methodName = 'finally_do_something';
            } else if (receipt.outcome.logs.some(log => log.includes('Generating authentication options'))) {
              methodName = 'generate_authentication_options';
            } else if (receipt.outcome.logs.some(log => log.includes('Resuming authentication'))) {
              methodName = 'verify_authentication_response';
            }
          }

          receiptInfo.push({
            receiptId: receipt.id,
            methodName,
            logs: receipt.outcome.logs
          });
        }
      }
    }

    // Look for structured results
    let authResult = null;
    let finallyResult = null;

    for (const log of allLogs) {
      if (typeof log === 'string') {
        if (log.startsWith('WEBAUTHN_AUTH_RESULT: ')) {
          try {
            authResult = JSON.parse(log.substring('WEBAUTHN_AUTH_RESULT: '.length));
          } catch (e) {
            console.warn('Failed to parse auth result:', e);
          }
        } else if (log.includes('fn finally_do_something')) {
          finallyResult = log;
        }
      }
    }

    return res.json({
      txHash,
      explorerLink: `https://testnet.nearblocks.io/txns/${txHash}?tab=execution`,
      summary: {
        totalLogs: logCount,
        totalReceipts: receiptInfo.length,
        hasAuthResult: !!authResult,
        hasFinallyResult: !!finallyResult
      },
      results: {
        authenticationResult: authResult,
        finallyResult: finallyResult
      },
      receipts: receiptInfo,
      allLogs: allLogs
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