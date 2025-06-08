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
      nearAccountId TEXT NULLABLE,
      currentChallenge TEXT NULLABLE,
      currentCommitmentId TEXT NULLABLE
    );
  `);

  // Authenticators cache table - mirrors on-chain state
  db.exec(`
    CREATE TABLE IF NOT EXISTS authenticators_cache (
      nearAccountId TEXT NOT NULL,
      credentialID TEXT NOT NULL,
      credentialPublicKey BLOB NOT NULL,
      counter INTEGER NOT NULL,
      transports TEXT NULLABLE,          -- JSON string array
      clientManagedNearPublicKey TEXT NULLABLE,
      name TEXT NULLABLE,
      registered TEXT NOT NULL,          -- ISO date string
      lastUsed TEXT NULLABLE,            -- ISO date string
      backedUp INTEGER NOT NULL,         -- 0 for false, 1 for true
      syncedAt TEXT NOT NULL,            -- When this cache entry was last synced with contract
      PRIMARY KEY (nearAccountId, credentialID)
    );
  `);

  console.log('Database tables (including authenticators cache) initialized at', dbFilePath);
};

export const authenticatorCacheOperations = {
  findByUserId: (nearAccountId: string): any[] => {
    return db.prepare('SELECT * FROM authenticators_cache WHERE nearAccountId = ?').all(nearAccountId);
  },

  findByCredentialId: (nearAccountId: string, credentialId: string): any | undefined => {
    return db.prepare('SELECT * FROM authenticators_cache WHERE nearAccountId = ? AND credentialID = ?').get(nearAccountId, credentialId);
  },

  findByCredentialIdGlobal: (credentialId: string): any | undefined => {
    return db.prepare('SELECT * FROM authenticators_cache WHERE credentialID = ?').get(credentialId);
  },

  upsert: (authenticator: {
    nearAccountId: string;
    credentialID: string;
    credentialPublicKey: Buffer;
    counter: number;
    transports: string | null;
    clientManagedNearPublicKey: string | null;
    name: string | null;
    registered: string;
    lastUsed: string | null;
    backedUp: number;
  }) => {
    const syncedAt = new Date().toISOString();
    return db.prepare(`
      INSERT OR REPLACE INTO authenticators_cache (
        nearAccountId, credentialID, credentialPublicKey, counter, transports,
        clientManagedNearPublicKey, name, registered, lastUsed, backedUp, syncedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      authenticator.nearAccountId,
      authenticator.credentialID,
      authenticator.credentialPublicKey,
      authenticator.counter,
      authenticator.transports,
      authenticator.clientManagedNearPublicKey,
      authenticator.name,
      authenticator.registered,
      authenticator.lastUsed,
      authenticator.backedUp,
      syncedAt
    );
  },

  updateCounter: (nearAccountId: string, credentialId: string, counter: number, lastUsed: string) => {
    const syncedAt = new Date().toISOString();
    return db.prepare(`
      UPDATE authenticators_cache
      SET counter = ?, lastUsed = ?, syncedAt = ?
      WHERE nearAccountId = ? AND credentialID = ?
    `).run(counter, lastUsed, syncedAt, nearAccountId, credentialId);
  },

  updateClientManagedKey: (nearAccountId: string, credentialID: string, clientNearPublicKey: string) => {
    const syncedAt = new Date().toISOString();
    return db.prepare(`
      UPDATE authenticators_cache
      SET clientManagedNearPublicKey = ?, syncedAt = ?
      WHERE nearAccountId = ? AND credentialID = ?
    `).run(clientNearPublicKey, syncedAt, nearAccountId, credentialID);
  },

  getLatestByUserId: (nearAccountId: string): { credentialID: string } | undefined => {
    return db.prepare(`
      SELECT credentialID
      FROM authenticators_cache
      WHERE nearAccountId = ?
      ORDER BY registered ASC
      LIMIT 1
    `).get(nearAccountId) as { credentialID: string } | undefined;
  },

  deleteStale: (nearAccountId: string, validCredentialIds: string[]) => {
    if (validCredentialIds.length === 0) {
      // Delete all entries for this user
      return db.prepare('DELETE FROM authenticators_cache WHERE nearAccountId = ?').run(nearAccountId);
    } else {
      // Delete entries not in the valid list
      const placeholders = validCredentialIds.map(() => '?').join(',');
      return db.prepare(`
        DELETE FROM authenticators_cache
        WHERE nearAccountId = ? AND credentialID NOT IN (${placeholders})
      `).run(nearAccountId, ...validCredentialIds);
    }
  },

  clear: (nearAccountId: string) => {
    return db.prepare('DELETE FROM authenticators_cache WHERE nearAccountId = ?').run(nearAccountId);
  },
};

export const mapCachedToStoredAuthenticator = (rawAuth: any): StoredAuthenticator => ({
  credentialID: rawAuth.credentialID,
  credentialPublicKey: new Uint8Array(rawAuth.credentialPublicKey),
  counter: rawAuth.counter,
  transports: rawAuth.transports ? JSON.parse(rawAuth.transports) : undefined,
  userId: rawAuth.nearAccountId, // Map nearAccountId to userId for compatibility
  name: rawAuth.name,
  registered: new Date(rawAuth.registered),
  lastUsed: rawAuth.lastUsed ? new Date(rawAuth.lastUsed) : undefined,
  backedUp: rawAuth.backedUp === 1,
  clientManagedNearPublicKey: rawAuth.clientManagedNearPublicKey,
});

export default db;