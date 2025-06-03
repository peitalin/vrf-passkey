import { Router, Request, Response } from 'express';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server/script/deps';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { createHash, randomBytes } from 'crypto';

import config from '../config';
import { userOperations, authenticatorOperations, mapToStoredAuthenticator } from '../database';
import { actionChallengeStore } from '../challengeStore';
import type { User, StoredAuthenticator, SerializableActionArgs } from '../types';

const router = Router();

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
    const verification = await verifyAuthenticationResponse({
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