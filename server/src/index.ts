import dotenv from 'dotenv';
dotenv.config(); // Call this at the very top

import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import Database from 'better-sqlite3';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON
} from '@simplewebauthn/server/script/deps';
import type { User, StoredAuthenticator } from './types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { initNear, addPasskeyPk, executeActions } from './nearService';
import { deriveNearPublicKeyFromCOSE } from './keyDerivation';
import { challengeStore } from './challengeStore';
import type { SerializableActionArgs } from './types';

const app: Express = express();
const port = process.env.PORT || 3001;

// Initialize SQLite database
const dbFilePath = path.join(__dirname, '../database.sqlite');
const db = new Database(dbFilePath, { verbose: console.log });

// Create tables if they don't exist
const initDB = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      currentChallenge TEXT -- This will only be used for username-first flows now
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS authenticators (
      credentialID TEXT PRIMARY KEY,
      credentialPublicKey BLOB NOT NULL,
      counter INTEGER NOT NULL,
      transports TEXT,
      userId TEXT NOT NULL,
      name TEXT,
      registered TEXT NOT NULL,
      lastUsed TEXT,
      backedUp INTEGER NOT NULL,
      derivedNearPublicKey TEXT,
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `);
  console.log('Database initialized (tables created if not exist) at', dbFilePath);
};

initDB();

app.use(express.json());
app.use(cors({
  origin: 'https://example.localhost',
  credentials: true,
}));

const rpID = 'example.localhost';
const rpName = 'My Passkey App';
const expectedOrigin = `https://example.localhost`;

app.get('/', (req: Request, res: Response) => {
  res.send('WebAuthn Server is running with SQLite!');
});

// --- WebAuthn Registration Routes ---
app.post('/generate-registration-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  try {
    let user: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
    if (!user) {
      user = { id: `user_${Date.now()}_${username}`, username };
      db.prepare('INSERT INTO users (id, username) VALUES (?, ?)').run(user.id, user.username);
    }
    const rawAuthenticators: any[] = db.prepare('SELECT * FROM authenticators WHERE userId = ?').all(user.id);
    const userAuthenticators: StoredAuthenticator[] = rawAuthenticators.map(auth => ({
      credentialID: auth.credentialID,
      credentialPublicKey: auth.credentialPublicKey,
      counter: auth.counter,
      transports: auth.transports ? JSON.parse(auth.transports) : [],
      userId: auth.userId,
      name: auth.name,
      registered: new Date(auth.registered),
      lastUsed: auth.lastUsed ? new Date(auth.lastUsed) : undefined,
      backedUp: auth.backedUp === 1,
    }));
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: user.id,
      userName: user.username,
      userDisplayName: user.username,
      excludeCredentials: userAuthenticators.map(auth => ({
        id: isoBase64URL.toBuffer(auth.credentialID),
        type: 'public-key',
        transports: auth.transports as AuthenticatorTransport[],
      })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      supportedAlgorithmIDs: [-7, -257],
    });
    db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?').run(options.challenge, user.id);
    console.log('Generated registration options for:', username, JSON.stringify(options, null, 2));
    return res.json(options);
  } catch (e: any) {
    console.error('Error generating registration options:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate registration options' });
  }
});

app.post('/verify-registration', async (req: Request, res: Response) => {
  const { username, attestationResponse } = req.body as { username: string, attestationResponse: RegistrationResponseJSON };
  if (!username || !attestationResponse) return res.status(400).json({ error: 'Username and attestationResponse are required' });
  let userForChallengeClear: User | undefined;
  try {
    const user: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
    userForChallengeClear = user;
    if (!user) return res.status(404).json({ error: `User '${username}' not found or registration not initiated.` });
    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No challenge found. Registration might have timed out.' });
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter, credentialBackedUp, credentialDeviceType } = registrationInfo;
      const transportsString = JSON.stringify(attestationResponse.response.transports || []);
      const nearPublicKeyToStore = deriveNearPublicKeyFromCOSE(Buffer.from(credentialPublicKey));
      if (nearPublicKeyToStore) {
        try {
          await addPasskeyPk(nearPublicKeyToStore);
          console.log(`Successfully added passkey PK ${nearPublicKeyToStore} to the smart contract.`);
        } catch (contractError: any) {
            console.error(`Failed to add passkey PK ${nearPublicKeyToStore} to contract:`, contractError);
            if (user) db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
            return res.status(500).json({
              verified: false,
              error: `Passkey hardware registered, but failed to link to on-chain account: ${contractError.message || contractError}`
            });
        }
      } else {
        if (user) db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
        return res.status(500).json({ verified: false, error: 'Failed to derive NEAR public key from passkey or unsupported key type.' });
      }
      db.prepare('INSERT INTO authenticators (credentialID, credentialPublicKey, counter, transports, userId, name, registered, backedUp, derivedNearPublicKey) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        isoBase64URL.fromBuffer(credentialID),
        Buffer.from(credentialPublicKey),
        counter,
        transportsString,
        user.id,
        `Authenticator on ${credentialDeviceType}`,
        new Date().toISOString(),
        credentialBackedUp ? 1 : 0,
        nearPublicKeyToStore
      );
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      console.log('New authenticator registered for user:', username);
      return res.json({ verified: true });
    } else {
      if (user) db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      return res.status(400).json({ verified: false, error: 'Could not verify attestation with passkey hardware.' });
    }
  } catch (e: any) {
    console.error('Error verifying registration:', e);
    if(userForChallengeClear) db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(userForChallengeClear.id);
    return res.status(500).json({ verified: false, error: e.message || 'Verification failed due to an unexpected server error.' });
  }
});

app.post('/generate-authentication-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  try {
    let allowCredentialsList: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[] | undefined = undefined;
    let userForChallengeStorageInDB: User | undefined; // Renamed for clarity

    if (username) {
      const userRec: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
      if (userRec) {
        userForChallengeStorageInDB = userRec;
        const rawUserAuthenticators: any[] = db.prepare('SELECT * FROM authenticators WHERE userId = ?').all(userRec.id);
        const userAuthenticators: StoredAuthenticator[] = rawUserAuthenticators.map(auth => ({
          credentialID: auth.credentialID,
          credentialPublicKey: auth.credentialPublicKey,
          counter: auth.counter,
          transports: auth.transports ? JSON.parse(auth.transports) : [],
          userId: auth.userId,
          name: auth.name,
          registered: new Date(auth.registered),
          lastUsed: auth.lastUsed ? new Date(auth.lastUsed) : undefined,
          backedUp: auth.backedUp === 1,
          derivedNearPublicKey: auth.derivedNearPublicKey,
        }));
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
      rpID,
      userVerification: 'preferred',
      allowCredentials: allowCredentialsList,
    });

    if (userForChallengeStorageInDB) {
      // Username-first flow: store challenge against the specific user in DB
      db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?').run(options.challenge, userForChallengeStorageInDB.id);
      console.log(`Stored challenge for user ${userForChallengeStorageInDB.username} in DB.`);
    } else {
      // Discoverable credential flow (no username, or username not found): store challenge in the challengeStore
      await challengeStore.storeChallenge(options.challenge, 300);
      console.log(`Stored challenge ${options.challenge} in challengeStore for discoverable login.`);
    }
    console.log('Generated authentication options:', JSON.stringify(options, null, 2));
    return res.json(options);
  } catch (e: any) {
    console.error('Error generating authentication options:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate authentication options' });
  }
});

app.post('/verify-authentication', async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;
  if (!body.rawId || !body.response) return res.status(400).json({ error: 'Request body error: missing rawId or response' });

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

  const rawAuth: any | undefined = db.prepare('SELECT *, derivedNearPublicKey FROM authenticators WHERE credentialID = ?').get(body.rawId);
  if (!rawAuth) return res.status(404).json({ error: `Authenticator '${body.rawId}' not found.` });

  authenticator = {
      credentialID: rawAuth.credentialID,
      credentialPublicKey: rawAuth.credentialPublicKey,
      counter: rawAuth.counter,
      transports: rawAuth.transports ? JSON.parse(rawAuth.transports) : [],
      userId: rawAuth.userId,
      name: rawAuth.name,
      registered: new Date(rawAuth.registered),
      lastUsed: rawAuth.lastUsed ? new Date(rawAuth.lastUsed) : undefined,
      backedUp: rawAuth.backedUp === 1,
      derivedNearPublicKey: rawAuth.derivedNearPublicKey,
  };

  user = db.prepare('SELECT * FROM users WHERE id = ?').get(authenticator.userId) as User | undefined;
  if (!user) return res.status(404).json({ error: `User for authenticator '${body.rawId}' not found.` });

  // Determine if this was a username-first login or discoverable
  if (user.currentChallenge) {
    console.log(`Attempting verification with user-specific challenge for ${user.username}`);
    expectedChallenge = user.currentChallenge;
  } else {
    console.log(`Attempting verification with challengeStore for discoverable login for potential user ${user.username}`);
    const isValidStoredChallenge = await challengeStore.validateAndConsumeChallenge(clientChallenge);
    if (!isValidStoredChallenge) {
      return res.status(400).json({ verified: false, error: 'Challenge invalid, expired, or already used from challengeStore.' });
    }
    expectedChallenge = clientChallenge;
  }

  if (!expectedChallenge) {
    // This should ideally not be reached if logic above is correct
    return res.status(400).json({ error: 'Unexpected: No challenge determined for verification.' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
        credentialPublicKey: Buffer.from(authenticator.credentialPublicKey as Uint8Array),
        counter: authenticator.counter as number,
        transports: authenticator.transports as AuthenticatorTransport[] | undefined,
      },
      requireUserVerification: true,
    });

    if (verification.verified && verification.authenticationInfo) {
      db.prepare('UPDATE authenticators SET counter = ?, lastUsed = ? WHERE credentialID = ?').run(
        verification.authenticationInfo.newCounter,
        new Date().toISOString(),
        authenticator.credentialID
      );
      // If challenge was user-specific, clear it from DB
      if (user.currentChallenge) {
          db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      }
      // Challenge from challengeStore was already consumed by validateAndConsumeChallenge

      console.log(`User '${user.username}' authenticated with '${authenticator.name || authenticator.credentialID}'. Derived NEAR PK: ${authenticator.derivedNearPublicKey}`);
      return res.json({
        verified: true,
        username: user.username,
        derivedNearPublicKey: authenticator.derivedNearPublicKey
      });
    } else {
      // Verification failed
      if (user.currentChallenge) {
        db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      } // No need to interact with challengeStore here as it was either invalid or already consumed
      const errorMessage = (verification as { error?: Error }).error?.message || 'Authentication failed verification';
      return res.status(400).json({ verified: false, error: errorMessage });
    }
  } catch (e: any) {
    console.error('Error during verifyAuthenticationResponse call:', e);
    // Clear user-specific challenge on error if it existed and we know the user
    if (user && user.currentChallenge) {
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
    }
    return res.status(500).json({ verified: false, error: e.message || 'Authentication verification failed unexpectedly.' });
  }
});

// New endpoint to check username
app.get('/check-username', (req: Request, res: Response) => {
  const { username } = req.query;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username query parameter is required and must be a string.' });
  }

  try {
    const userEntry: User | undefined = db.prepare('SELECT id FROM users WHERE username = ?').get(username) as User | undefined;
    if (userEntry) {
      return res.json({ registered: true });
    } else {
      return res.json({ registered: false });
    }
  } catch (e: any) {
    console.error('Error checking username:', e);
    return res.status(500).json({ error: 'Failed to check username status.' });
  }
});

// --- Endpoint for Relayed Actions ---
app.post('/api/execute-action', async (req: Request, res: Response) => {
  // TODO: Implement proper session/token-based authentication here
  // For now, let's assume we can get userId and their derivedNearPublicKey if authenticated.
  // This is a placeholder and needs to be replaced with actual auth logic.
  const { userId, action } = req.body as { userId?: string, action: SerializableActionArgs };

  if (!userId) { // Replace with actual authentication check
    return res.status(401).json({ error: 'User not authenticated' });
  }
  if (!action) {
    return res.status(400).json({ error: 'Action details not provided' });
  }

  try {
    // Fetch the user's derivedNearPublicKey from your DB
    // This key was stored when their passkey was registered and linked.
    const userRecord: { derivedNearPublicKey?: string } | undefined = db.prepare(
      'SELECT derivedNearPublicKey FROM authenticators WHERE userId = (SELECT id FROM users WHERE id = ?) AND derivedNearPublicKey IS NOT NULL'
    ).get(userId) as { derivedNearPublicKey?: string } | undefined;
    // Note: A user might have multiple authenticators. You might need a more specific way
    // to determine WHICH derivedNearPublicKey to use if a user has multiple passkeys linked.
    // For simplicity, this example takes the first one found associated with the userId.
    // In a real app, you might get this from session data established during passkey login.

    if (!userRecord || !userRecord.derivedNearPublicKey) {
      return res.status(404).json({ error: 'No derived NEAR public key found for this user, or passkey not fully registered.' });
    }
    const passkeyPkUsed = userRecord.derivedNearPublicKey;

    console.log(`Executing action for user ${userId} with passkey PK ${passkeyPkUsed}:`, action);

    const transactionOutcome = await executeActions(passkeyPkUsed, action);

    console.log('Transaction Outcome:', JSON.stringify(transactionOutcome, null, 2));

    // The structure of transactionOutcome can be complex.
    // You might want to simplify it or pass it through.
    // Check for success based on transactionOutcome.status or lack of errors.
    // For example, near-api-js FinalExecutionStatus includes successValue or failure.
    if (transactionOutcome && transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'SuccessValue' in transactionOutcome.status) {
      let successValue = '';
      if (transactionOutcome.status.SuccessValue && transactionOutcome.status.SuccessValue !== '') {
        try {
          successValue = Buffer.from(transactionOutcome.status.SuccessValue, 'base64').toString('utf-8');
        } catch (e) {
          console.warn('Could not decode SuccessValue as UTF-8 string from base64', e);
          successValue = transactionOutcome.status.SuccessValue; // Keep as base64 if not decodable
        }
      }
      return res.json({
        success: true,
        message: 'Action executed successfully.',
        transactionId: transactionOutcome.transaction_outcome?.id,
        receipts_outcome: transactionOutcome.receipts_outcome,
        status: transactionOutcome.status,
        successValue: successValue // Decoded result from contract if any
      });
    } else if (transactionOutcome && transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'Failure' in transactionOutcome.status) {
      console.error('Action execution failed:', transactionOutcome.status.Failure);
      return res.status(500).json({
        success: false,
        error: 'Action execution failed on-chain.',
        details: transactionOutcome.status.Failure,
        transactionId: transactionOutcome.transaction_outcome?.id
      });
    } else {
      // Fallback for unexpected outcome structure
      console.warn('Action executed, but outcome status is unexpected:', transactionOutcome);
      return res.json({
        success: true, // Or false, depending on how you interpret an unknown status
        message: 'Action sent, but final status is unclear from outcome.',
        transactionOutcome
      });
    }

  } catch (error: any) {
    console.error('Error executing action:', error);
    let errorMessage = 'Failed to execute action.';
    if (error.message) {
        errorMessage += `: ${error.message}`;
    }
    // Check for specific NEAR error types if possible to give better client feedback
    if (error.type === 'UntypedError' || error.kind?.ExecutionError) { // Example check
        return res.status(500).json({ success: false, error: 'Action execution failed on-chain.', details: error.toString() });
    }
    return res.status(500).json({ success: false, error: errorMessage });
  }
});

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Initialize NEAR and start the server
initNear()
  .then(() => {
    app.listen(port, () => {
      console.log(`Server listening on http://localhost:${port}`);
      console.log(`Relying Party ID: ${rpID}`);
      console.log(`Expected Frontend Origin: ${expectedOrigin}`);
    });
  })
  .catch(error => {
    console.error("Failed to initialize NEAR connection or start server:", error);
    process.exit(1);
  });