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
import type { User, StoredAuthenticator, SerializableActionArgs } from './types';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import type { AuthenticatorTransport } from '@simplewebauthn/types';
import { initNear, addPasskeyPk, executeActions, getGreeting, setGreeting } from './nearService';
import { deriveNearPublicKeyFromCOSE } from './keyDerivation';
import { actionChallengeStore } from './challengeStore';
import { createHash, randomBytes } from 'crypto';
import { PublicKey } from '@near-js/crypto';

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
      currentChallenge TEXT,
      derpAccountId TEXT
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
      clientManagedNearPublicKey TEXT,
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `);
  console.log('Database initialized (tables created if not exist) at', dbFilePath);
  // Add new columns if they don't exist (simple alter for sqlite)
  try { db.exec("ALTER TABLE users ADD COLUMN derpAccountId TEXT;"); } catch (e) { /* ignore if already exists */ }
  try { db.exec("ALTER TABLE authenticators ADD COLUMN clientManagedNearPublicKey TEXT;"); } catch (e) { /* ignore if already exists */ }
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

// API Endpoints:
//
// GET /
// Health check endpoint that confirms the WebAuthn server is running
//
// POST /generate-registration-options
// Creates registration options for a new passkey. If user doesn't exist, creates them.
// Returns WebAuthn registration options including challenge.
//
// POST /verify-registration
// Verifies a passkey registration attestation and stores the new authenticator.
// Derives a NEAR key pair from the attestation for future transaction signing.
//
// POST /generate-authentication-options
// Creates authentication options for an existing passkey.
// Returns WebAuthn authentication options including challenge.
//
// POST /verify-authentication
// Verifies a passkey authentication assertion.
// Returns session info on success.
//
// POST /api/execute-action
// Executes a NEAR transaction using the derived key from passkey.
// Requires passkey authentication before executing the action.


// --- WebAuthn Registration Routes ---
app.post('/generate-registration-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  try {
    let user: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
    // For Option 1, we can suggest a derpAccountId pattern or let client decide and inform us via /associate-account-pk
    const potentialDerpAccountId = `${username.toLowerCase().replace(/[^a-z0-9]/g, '')}.passkeyfactory.testnet`; // Example

    if (!user) {
      user = { id: `user_${Date.now()}_${username}`, username, derpAccountId: potentialDerpAccountId }; // Store potential derpId
      db.prepare('INSERT INTO users (id, username, derpAccountId) VALUES (?, ?, ?)').run(user.id, user.username, user.derpAccountId);
    } else if (!user.derpAccountId) {
      db.prepare('UPDATE users SET derpAccountId = ? WHERE id = ?').run(potentialDerpAccountId, user.id);
      user.derpAccountId = potentialDerpAccountId;
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
      derivedNearPublicKey: auth.derivedNearPublicKey,
      clientManagedNearPublicKey: auth.clientManagedNearPublicKey,
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
    // Return derpAccountId to the client so it knows what account its generated key will be for
    return res.json({ ...options, derpAccountId: user.derpAccountId });
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
    const user: User | undefined = db.prepare('SELECT id, username, currentChallenge, derpAccountId FROM users WHERE username = ?').get(username) as User | undefined;
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
      const nearPublicKeyFromCOSE = deriveNearPublicKeyFromCOSE(Buffer.from(credentialPublicKey));

      // Store authenticator with COSE-derived key, but DO NOT register it with PasskeyController yet.
      db.prepare('INSERT INTO authenticators (credentialID, credentialPublicKey, counter, transports, userId, name, registered, backedUp, derivedNearPublicKey) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
        isoBase64URL.fromBuffer(credentialID),
        Buffer.from(credentialPublicKey),
        counter,
        transportsString,
        user.id,
        `Authenticator on ${credentialDeviceType}`,
        new Date().toISOString(),
        credentialBackedUp ? 1 : 0,
        nearPublicKeyFromCOSE // Store the COSE-derived key for server reference
      );
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      console.log('New authenticator hardware registered for user:', username, ", COSE-derived NEAR PK:", nearPublicKeyFromCOSE);
      // Return success and the derpAccountId that the client should use for its own key generation.
      return res.json({ verified: true, username: user.username, derpAccountId: user.derpAccountId });
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

// New endpoint for client to tell server its generated NEAR key
app.post('/api/associate-account-pk', async (req: Request, res: Response) => {
  const { username, derpAccountId, clientNearPublicKey } = req.body;

  if (!username || !derpAccountId || !clientNearPublicKey) {
    return res.status(400).json({ error: 'Username, derpAccountId, and clientNearPublicKey are required.' });
  }

  try {
    // 1. Validate user (optional, but good practice)
    const user: User | undefined = db.prepare('SELECT id, derpAccountId FROM users WHERE username = ?').get(username) as User | undefined;
    if (!user) {
      return res.status(404).json({ error: `User '${username}' not found.` });
    }
    // Optionally, verify that the provided derpAccountId matches what the server expects for this user
    if (user.derpAccountId !== derpAccountId) {
        console.warn(`Potential derpAccountId mismatch for ${username}. Server expected: ${user.derpAccountId}, client provided: ${derpAccountId}`);
        // Decide on policy: error out, or update server record, or just log.
        // For now, we'll proceed but this could be a security check.
    }

    // 2. Validate clientNearPublicKey format
    let nearPublicKeyToRegister: PublicKey;
    try {
      nearPublicKeyToRegister = PublicKey.fromString(clientNearPublicKey);
      // We could also check keyPair.getPublicKey().keyType === KeyType.ED25519 if we only want ed25519
    } catch (keyError: any) {
      console.error("Invalid clientNearPublicKey format:", clientNearPublicKey, keyError);
      return res.status(400).json({ error: `Invalid clientNearPublicKey format: ${keyError.message}` });
    }

    // 3. Register this client-generated public key with the PasskeyController contract
    await addPasskeyPk(nearPublicKeyToRegister.toString()); // addPasskeyPk expects a string
    console.log(`Successfully registered client-generated NEAR PK ${clientNearPublicKey} for ${derpAccountId} on PasskeyController.`);

    // 4. (Optional) Store this clientManagedNearPublicKey against the user's authenticator or user record
    // This requires identifying which authenticator this key corresponds to if multiple exist,
    // or associating it directly with the user if a user has one primary derpAccountId.
    // For simplicity, let's assume one primary derpAccountId per user for now and store it with the user or a primary authenticator.
    // If storing with authenticator, you might need credentialID from client.
    // For now, let's try to update the most recently registered authenticator for the user.
    const stmt = db.prepare('UPDATE authenticators SET clientManagedNearPublicKey = ? WHERE userId = ? ORDER BY registered DESC LIMIT 1');
    const info = stmt.run(clientNearPublicKey, user.id);
    if (info.changes === 0) {
        console.warn(`No authenticator found for user ${username} to associate clientManagedNearPublicKey, or no update made.`);
        // This isn't necessarily an error for the flow if the PK is registered on-chain, but good to note.
    }

    return res.json({ success: true, message: `Client NEAR public key ${clientNearPublicKey} associated and registered on-chain for ${derpAccountId}.` });

  } catch (error: any) {
    console.error('Error in /api/associate-account-pk:', error);
    return res.status(500).json({ success: false, error: error.message || 'Failed to associate client public key.' });
  }
});


app.post('/generate-authentication-options', async (req: Request, res: Response) => {
  const { username } = req.body;
  try {
    let allowCredentialsList: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[] | undefined = undefined;
    let userForChallengeStorageInDB: User | undefined;

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
          clientManagedNearPublicKey: auth.clientManagedNearPublicKey,
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
      db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?').run(options.challenge, userForChallengeStorageInDB.id);
      console.log(`Stored challenge for user ${userForChallengeStorageInDB.username} in DB.`);
    } else {
      await actionChallengeStore.storeActionChallenge(options.challenge,
        { actionDetails: (req.body.actionDetails || {}) as SerializableActionArgs },
        300);
      console.log(`Stored challenge ${options.challenge} in actionChallengeStore for discoverable login.`);
    }
    console.log('Generated authentication options:', JSON.stringify(options, null, 2));
    // Include derpAccountId in response if user is found, client might need it.
    const userForDerpId: User | undefined = username ? db.prepare('SELECT derpAccountId FROM users WHERE username = ?').get(username) as User : undefined;
    return res.json({ ...options, derpAccountId: userForDerpId?.derpAccountId });
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

  const rawAuth: any | undefined = db.prepare('SELECT *, derivedNearPublicKey, clientManagedNearPublicKey FROM authenticators WHERE credentialID = ?').get(body.rawId);
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
      clientManagedNearPublicKey: rawAuth.clientManagedNearPublicKey,
  };

  user = db.prepare('SELECT id, username, currentChallenge, derpAccountId FROM users WHERE id = ?').get(authenticator.userId) as User | undefined;
  if (!user) return res.status(404).json({ error: `User for authenticator '${body.rawId}' not found.` });

  if (user.currentChallenge) {
    console.log(`Attempting verification with user-specific challenge for ${user.username}`);
    expectedChallenge = user.currentChallenge;
  } else {
    console.log(`Attempting verification with actionChallengeStore for discoverable login for potential user ${user.username}`);
    const storedDetails = await actionChallengeStore.validateAndConsumeActionChallenge(clientChallenge);
    if (!storedDetails) {
      return res.status(400).json({ verified: false, error: 'Challenge invalid, expired, or already used from actionChallengeStore.' });
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
      if (user.currentChallenge) {
          db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      }
      console.log(`User '${user.username}' authenticated with '${authenticator.name || authenticator.credentialID}'. Stored COSE-derived NEAR PK: ${authenticator.derivedNearPublicKey}, Client-managed NEAR PK: ${authenticator.clientManagedNearPublicKey}`);
      return res.json({
        verified: true,
        username: user.username,
        // Return both types of public keys if available for client context
        derivedNearPublicKey: authenticator.derivedNearPublicKey, // COSE-derived key
        clientManagedNearPublicKey: authenticator.clientManagedNearPublicKey, // Key client generated for its derpAccount
        derpAccountId: user.derpAccountId // The account ID client should be using for Option 1
      });
    } else {
      if (user.currentChallenge) {
        db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      }
      const errorMessage = (verification as { error?: Error }).error?.message || 'Authentication failed verification';
      return res.status(400).json({ verified: false, error: errorMessage });
    }
  } catch (e: any) {
    console.error('Error during verifyAuthenticationResponse call:', e);
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

// New endpoint to generate a challenge for signing an action
app.post('/api/action-challenge', async (req: Request, res: Response) => {
  const { username, actionDetails } = req.body as { username: string, actionDetails: SerializableActionArgs };

  if (!username || !actionDetails) {
    return res.status(400).json({ error: 'Username and actionDetails are required.' });
  }

  try {
    const userRecord: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
    if (!userRecord) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const authenticatorRecord: { credentialID: string } | undefined = db.prepare(
      'SELECT credentialID FROM authenticators WHERE userId = ? ORDER BY registered ASC LIMIT 1'
    ).get(userRecord.id) as { credentialID: string } | undefined;
    if (!authenticatorRecord) {
      return res.status(404).json({ error: 'No registered passkey found for this user to sign the action.' });
    }
    const userPasskeyCredentialID = authenticatorRecord.credentialID;

    const nonce = isoBase64URL.fromBuffer(randomBytes(32));
    const payloadToSign = {
      nonce,
      actionHash: createHash('sha256').update(JSON.stringify(actionDetails)).digest('hex'),
      rpId: rpID,
      origin: expectedOrigin,
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
      rpId: rpID,
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

// Refactor /api/execute-action
app.post('/api/execute-action', async (req: Request, res: Response) => {
  const { username, passkeyAssertion, actionToExecute } = req.body as {
    username: string;
    passkeyAssertion: AuthenticationResponseJSON;
    actionToExecute: SerializableActionArgs;
  };

  if (!username || !passkeyAssertion || !actionToExecute) {
    return res.status(400).json({ error: 'Username, passkeyAssertion, and actionToExecute are required.' });
  }

  try {
    let clientChallenge: string;
    let clientSignedPayload: any;
    try {
      const clientDataJSONBuffer = isoBase64URL.toBuffer(passkeyAssertion.response.clientDataJSON);
      const clientData = JSON.parse(Buffer.from(clientDataJSONBuffer).toString('utf8'));
      clientChallenge = clientData.challenge;
      if (!clientChallenge) {
        return res.status(400).json({ verified: false, error: 'Challenge missing in clientDataJSON from assertion.' });
      }
      clientSignedPayload = JSON.parse(Buffer.from(isoBase64URL.toBuffer(clientChallenge)).toString('utf8'));
    } catch (parseError) {
      return res.status(400).json({ verified: false, error: 'Invalid clientDataJSON or challenge format.' });
    }

    const storedChallengeData = await actionChallengeStore.validateAndConsumeActionChallenge(clientChallenge);
    if (!storedChallengeData) {
      return res.status(400).json({ verified: false, error: 'Action challenge invalid, expired, or already used.' });
    }
    const { actionDetails: storedActionDetails, expectedCredentialID } = storedChallengeData;

    const currentActionHash = createHash('sha256').update(JSON.stringify(actionToExecute)).digest('hex');
    if (currentActionHash !== clientSignedPayload.actionHash) {
      console.warn('Action mismatch! Current action does not match action signed in challenge.', { currentActionHash, signedPayload: clientSignedPayload });
      return res.status(400).json({ verified: false, error: 'Action details mismatch. The signed action does not match the requested action.'});
    }
    if (expectedCredentialID && passkeyAssertion.id !== expectedCredentialID) {
        return res.status(400).json({ verified: false, error: 'Passkey credential ID mismatch.'});
    }

    const rawAuth: any | undefined = db.prepare('SELECT *, derivedNearPublicKey FROM authenticators WHERE credentialID = ?').get(passkeyAssertion.id);
    if (!rawAuth) {
      return res.status(404).json({ error: `Authenticator '${passkeyAssertion.id}' not found.` });
    }
    const authenticator: StoredAuthenticator = {
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
    if (!authenticator.derivedNearPublicKey) {
      return res.status(500).json({ error: 'User authenticator is missing COSE-derived NEAR public key for this action flow.'});
    }

    const verification = await verifyAuthenticationResponse({
      response: passkeyAssertion,
      expectedChallenge: clientChallenge,
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
      db.prepare('UPDATE authenticators SET counter = ? WHERE credentialID = ?').run(verification.authenticationInfo.newCounter, authenticator.credentialID);

      // Use the COSE-derived key for this server-orchestrated action
      const transactionOutcome = await executeActions(authenticator.derivedNearPublicKey, storedActionDetails);

      if (transactionOutcome && transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'SuccessValue' in transactionOutcome.status) {
        let successValue = '';
        if (transactionOutcome.status.SuccessValue && transactionOutcome.status.SuccessValue !== '') {
          try { successValue = Buffer.from(transactionOutcome.status.SuccessValue, 'base64').toString('utf-8'); } catch (e) { successValue = transactionOutcome.status.SuccessValue; }
        }
        console.log("transactionOutcome", transactionOutcome)
        return res.json({ success: true, message: 'Action executed successfully.', transactionId: transactionOutcome.transaction_outcome?.id, successValue });
      } else if (transactionOutcome && transactionOutcome.status && typeof transactionOutcome.status === 'object' && 'Failure' in transactionOutcome.status) {
        console.log("transactionOutcome", transactionOutcome)
        return res.status(500).json({ success: false, error: 'Action execution failed on-chain.', details: transactionOutcome.status.Failure });
      } else {
        console.log("transactionOutcome", transactionOutcome)
        return res.json({ success: true, message: 'Action sent, but final status is unclear.', transactionOutcome });
      }
    } else {
      const errorMessage = (verification as any).error?.message || 'Passkey assertion verification failed';
      return res.status(400).json({ verified: false, error: errorMessage });
    }
  } catch (error: any) {
    console.error('Error in /api/execute-action:', error);
    return res.status(500).json({ success: false, error: error.message || 'Failed to execute action due to an unexpected server error.' });
  }
});

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Initialize NEAR and start the server
initNear()
  .then(async () => {
    console.log('NEAR initialized successfully.');
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