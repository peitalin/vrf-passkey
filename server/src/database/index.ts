import Database from 'better-sqlite3';
import path from 'path';
import config from '../config';
import type { User, StoredAuthenticator } from '../types';

export { userOperations } from './userOperations';

const dbFilePath = path.join(__dirname, config.databasePath);
console.log(`Attempting to initialize database at: ${dbFilePath}`);

export let db: Database.Database;
try {
  db = new Database(dbFilePath, { verbose: console.log });
  console.log(`Successfully opened/created database at: ${dbFilePath}`);
} catch (error) {
  console.error(`Failed to open/create database at: ${dbFilePath}`, error);
  throw error;
}

export const initDB = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      derpAccountId TEXT NULLABLE,
      currentChallenge TEXT NULLABLE,
      currentCommitmentId TEXT NULLABLE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS authenticators (
      credentialID TEXT PRIMARY KEY,       -- Base64URL encoded string
      credentialPublicKey BLOB NOT NULL, -- Raw COSE key bytes
      counter INTEGER NOT NULL,
      transports TEXT NULLABLE,          -- JSON string array of AuthenticatorTransportFuture[]
      userId TEXT NOT NULL,              -- Foreign key to users.id
      clientManagedNearPublicKey TEXT NULLABLE, -- Client-managed NEAR public key
      name TEXT NULLABLE,                -- User-friendly authenticator name
      registered TEXT NOT NULL,          -- ISO date string
      lastUsed TEXT NULLABLE,            -- ISO date string
      backedUp INTEGER NOT NULL,         -- 0 for false, 1 for true
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `);

  console.log('Simplified database tables initialized at', dbFilePath);
};

export const authenticatorOperations = {
  findByUserId: (userId: string): any[] => {
    return db.prepare('SELECT * FROM authenticators WHERE userId = ?').all(userId);
  },

  findByCredentialId: (credentialId: string): any | undefined => {
    return db.prepare('SELECT * FROM authenticators WHERE credentialID = ?').get(credentialId);
  },

  create: (authenticator: {
    credentialID: string;
    credentialPublicKey: Buffer;
    counter: number;
    transports: string;
    userId: string;
    name?: string | null;
    registered: string;
    backedUp: number; // 0 or 1
    clientManagedNearPublicKey?: string | null;
  }) => {
    return db.prepare(`
      INSERT INTO authenticators (
        credentialID, credentialPublicKey, counter, transports, userId,
        name, registered, lastUsed, backedUp, clientManagedNearPublicKey
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      authenticator.credentialID,
      authenticator.credentialPublicKey,
      authenticator.counter,
      authenticator.transports,
      authenticator.userId,
      authenticator.name || null,
      authenticator.registered,
      null, // lastUsed is null on creation
      authenticator.backedUp,
      authenticator.clientManagedNearPublicKey || null
    );
  },

  updateCounter: (credentialId: string, counter: number, lastUsed: string) => {
    return db.prepare('UPDATE authenticators SET counter = ?, lastUsed = ? WHERE credentialID = ?').run(
      counter,
      lastUsed,
      credentialId
    );
  },
  // This is the primary way to link a client's NEAR key to their passkey/authenticator record
  updateClientManagedKey: (credentialID: string, clientNearPublicKey: string) => {
    return db.prepare('UPDATE authenticators SET clientManagedNearPublicKey = ? WHERE credentialID = ?').run(
      clientNearPublicKey,
      credentialID
    );
  },
  getLatestByUserId: (userId: string): { credentialID: string } | undefined => {
    return db.prepare('SELECT credentialID FROM authenticators WHERE userId = ? ORDER BY registered ASC LIMIT 1').get(userId) as { credentialID: string } | undefined;
  },
};

export const mapToStoredAuthenticator = (rawAuth: any): StoredAuthenticator => ({
  credentialID: rawAuth.credentialID,
  credentialPublicKey: new Uint8Array(rawAuth.credentialPublicKey), // Convert Buffer from SQLite to Uint8Array
  counter: rawAuth.counter,
  transports: rawAuth.transports ? JSON.parse(rawAuth.transports) : undefined,
  userId: rawAuth.userId,
  name: rawAuth.name,
  registered: new Date(rawAuth.registered),
  lastUsed: rawAuth.lastUsed ? new Date(rawAuth.lastUsed) : undefined,
  backedUp: rawAuth.backedUp === 1,
  clientManagedNearPublicKey: rawAuth.clientManagedNearPublicKey,
});

export default db;