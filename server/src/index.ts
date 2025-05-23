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
      currentChallenge TEXT
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS authenticators (
      credentialID TEXT PRIMARY KEY,
      credentialPublicKey BLOB NOT NULL,
      counter INTEGER NOT NULL,
      transports TEXT, -- JSON string array: e.g., '["internal", "hybrid"]'
      userId TEXT NOT NULL,
      name TEXT,
      registered TEXT NOT NULL, -- ISO8601 string
      lastUsed TEXT, -- ISO8601 string
      backedUp INTEGER NOT NULL, -- 0 for false, 1 for true
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `);
  console.log('Database initialized (tables created if not exist) at', dbFilePath);
};

initDB(); // Initialize DB on server start

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
      credentialPublicKey: auth.credentialPublicKey, // Assuming this is already a Buffer/correct type from DB driver
      counter: auth.counter,
      transports: auth.transports ? JSON.parse(auth.transports) : [],
      userId: auth.userId,
      name: auth.name,
      registered: new Date(auth.registered), // Ensure this is valid ISO string from DB
      lastUsed: auth.lastUsed ? new Date(auth.lastUsed) : undefined,
      backedUp: auth.backedUp === 1, // Convert 0/1 to boolean
      // Ensure all other fields from StoredAuthenticator are present or explicitly undefined
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

    // Store challenge for the user
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

  try {
    const user: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
    if (!user) return res.status(404).json({ error: `User '${username}' not found or registration not initiated.` });

    const expectedChallenge = user.currentChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No challenge found. Registration might have timed out.' });

    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true, // Or based on your policy
    });

    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter, credentialBackedUp, credentialDeviceType } = registrationInfo;
      const transportsString = JSON.stringify(attestationResponse.response.transports || []);

      db.prepare('INSERT INTO authenticators (credentialID, credentialPublicKey, counter, transports, userId, name, registered, backedUp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
        isoBase64URL.fromBuffer(credentialID),
        Buffer.from(credentialPublicKey), // Store as BLOB
        counter,
        transportsString,
        user.id,
        `Authenticator on ${credentialDeviceType}`,
        new Date().toISOString(),
        credentialBackedUp ? 1 : 0
      );

      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id); // Clear challenge
      console.log('New authenticator registered for user:', username);
      return res.json({ verified: true });
    } else {
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id); // Clear challenge on failure too
      return res.status(400).json({ verified: false, error: 'Could not verify attestation' });
    }
  } catch (e: any) {
    console.error('Error verifying registration:', e);
    // Attempt to clear challenge if user exists
    const userOnError: User | undefined = db.prepare('SELECT id FROM users WHERE username = ?').get(username) as User | undefined;
    if(userOnError) db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(userOnError.id);
    return res.status(500).json({ verified: false, error: e.message || 'Verification failed' });
  }
});

// Temporary storage for challenges of discoverable credentials (if not tied to a username upfront)
// This part needs careful consideration in a multi-user, production system.
// For simplicity, we might still use a specific user ID or handle this differently.
const TEMP_DISCOVERABLE_CHALLENGE_USER_ID = 'temp_discoverable_challenge_user';

// Ensure temp user exists for challenges, or create if not
const ensureTempUserExists = () => {
  let tempUser = db.prepare('SELECT * FROM users WHERE id = ?').get(TEMP_DISCOVERABLE_CHALLENGE_USER_ID);
  if (!tempUser) {
    db.prepare('INSERT INTO users (id, username) VALUES (?, ?)').run(TEMP_DISCOVERABLE_CHALLENGE_USER_ID, '_temp_discoverable_user_');
    console.log('Created temporary user for discoverable credential challenges.');
  }
};
ensureTempUserExists();

app.post('/generate-authentication-options', async (req: Request, res: Response) => {
  const { username } = req.body; // Username is optional

  try {
    let allowCredentialsList: { id: Uint8Array; type: 'public-key'; transports?: AuthenticatorTransport[] }[] | undefined = undefined;
    let userIdForChallenge: string | undefined = undefined;

    if (username) {
      const user: User | undefined = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
      if (user) {
        userIdForChallenge = user.id;
        const rawUserAuthenticators: any[] = db.prepare('SELECT * FROM authenticators WHERE userId = ?').all(user.id);
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
        }));
        if (userAuthenticators.length > 0) {
          allowCredentialsList = userAuthenticators.map(auth => ({
            id: isoBase64URL.toBuffer(auth.credentialID),
            type: 'public-key',
            transports: auth.transports as AuthenticatorTransport[],
          }));
        }
      }
    } // If no username, it's a discoverable credential request

    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
      allowCredentials: allowCredentialsList,
    });

    // Store challenge
    const challengeUser = userIdForChallenge || TEMP_DISCOVERABLE_CHALLENGE_USER_ID;
    db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?').run(options.challenge, challengeUser);
    if (!userIdForChallenge) console.warn('Storing challenge for a discoverable credential login against temp user.');

    console.log('Generated authentication options:', JSON.stringify(options, null, 2));
    return res.json(options);
  } catch (e: any) {
    console.error('Error generating authentication options:', e);
    return res.status(500).json({ error: e.message || 'Failed to generate authentication options' });
  }
});

app.post('/verify-authentication', async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;
  const effectiveRawId = body.rawId || body.id;
  if (!effectiveRawId || !body.response) return res.status(400).json({ error: 'Request body error' });

  try {
    const rawAuthenticator: any | undefined =
      db.prepare('SELECT * FROM authenticators WHERE credentialID = ?').get(effectiveRawId);

    if (!rawAuthenticator) return res.status(404).json({ error: `Authenticator '${effectiveRawId}' not found.` });

    // Map rawAuthenticator to StoredAuthenticator type correctly
    const authenticator: StoredAuthenticator = {
        credentialID: rawAuthenticator.credentialID,
        credentialPublicKey: rawAuthenticator.credentialPublicKey, // This should be a Buffer from better-sqlite3
        counter: rawAuthenticator.counter,
        transports: rawAuthenticator.transports ? JSON.parse(rawAuthenticator.transports) : [],
        userId: rawAuthenticator.userId,
        name: rawAuthenticator.name,
        registered: new Date(rawAuthenticator.registered),
        lastUsed: rawAuthenticator.lastUsed ? new Date(rawAuthenticator.lastUsed) : undefined,
        backedUp: rawAuthenticator.backedUp === 1,
    };

    const user: User | undefined = db.prepare('SELECT * FROM users WHERE id = ?').get(authenticator.userId) as User | undefined;
    if (!user) return res.status(404).json({ error: `User for authenticator '${effectiveRawId}' not found.` });

    let expectedChallenge = user.currentChallenge;
    if (!expectedChallenge && user.id !== TEMP_DISCOVERABLE_CHALLENGE_USER_ID) {
        // If a specific user was identified by the authenticator, but that user has no challenge,
        // check if the challenge was stored against the temp user (for a discoverable login scenario)
        const tempUser: User | undefined = db.prepare('SELECT currentChallenge FROM users WHERE id = ?').get(TEMP_DISCOVERABLE_CHALLENGE_USER_ID) as User | undefined;
        if (tempUser?.currentChallenge) {
            expectedChallenge = tempUser.currentChallenge;
            console.warn('Using challenge from temp user for discoverable credential login.');
        }
    }
    if (!expectedChallenge) return res.status(400).json({ error: 'No challenge found. Authentication might have timed out.' });

    // Ensure credentialPublicKey is a Buffer for verifyAuthenticationResponse
    const credentialPublicKeyBuffer = Buffer.isBuffer(authenticator.credentialPublicKey)
        ? authenticator.credentialPublicKey
        : Buffer.from(authenticator.credentialPublicKey as any, 'hex'); // Assuming it might be hex if not buffer

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
        credentialPublicKey: credentialPublicKeyBuffer,
        counter: authenticator.counter as number,
        transports: authenticator.transports as AuthenticatorTransport[] | undefined,
      },
      requireUserVerification: true, // Or based on your policy
    });

    const { verified, authenticationInfo } = verification;
    if (verified && authenticationInfo) {
      db.prepare('UPDATE authenticators SET counter = ?, lastUsed = ? WHERE credentialID = ?').run(authenticationInfo.newCounter, new Date().toISOString(), authenticator.credentialID);

      // Clear challenge for the user who owned the authenticator AND the temp user
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(TEMP_DISCOVERABLE_CHALLENGE_USER_ID);

      console.log(`User '${user.username}' authenticated with '${authenticator.name || authenticator.credentialID}'.`);
      return res.json({ verified: true, username: user.username });
    } else {
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(user.id);
      db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(TEMP_DISCOVERABLE_CHALLENGE_USER_ID);
      return res.status(400).json({ verified: false, error: 'Authentication failed verification' });
    }
  } catch (e: any) {
    console.error('Error verifying authentication:', e);
    // Attempt to clear challenges on error
    const bodyAuthenticator = db.prepare('SELECT userId FROM authenticators WHERE credentialID = ?').get(effectiveRawId) as {userId: string} | undefined;
    if (bodyAuthenticator?.userId) db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(bodyAuthenticator.userId);
    db.prepare('UPDATE users SET currentChallenge = NULL WHERE id = ?').run(TEMP_DISCOVERABLE_CHALLENGE_USER_ID);
    return res.status(500).json({ verified: false, error: e.message || 'Authentication verification failed' });
  }
});

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
  console.log(`Relying Party ID: ${rpID}`);
  console.log(`Expected Frontend Origin: ${expectedOrigin}`);
});