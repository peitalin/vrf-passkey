import Database from 'better-sqlite3';
import path from 'path';
import config from '../config';
import type { User, StoredAuthenticator } from '../types';

// Initialize SQLite database
const dbFilePath = path.join(__dirname, config.databasePath);
export const db = new Database(dbFilePath, { verbose: console.log });

// Initialize database tables
export const initDB = () => {
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
  try {
    db.exec("ALTER TABLE users ADD COLUMN derpAccountId TEXT;");
  } catch (e) {
    /* ignore if already exists */
  }

  try {
    db.exec("ALTER TABLE authenticators ADD COLUMN clientManagedNearPublicKey TEXT;");
  } catch (e) {
    /* ignore if already exists */
  }
};

// Database operations
export const userOperations = {
  findByUsername: (username: string): User | undefined => {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined;
  },

  findById: (id: string): User | undefined => {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id) as User | undefined;
  },

  create: (user: Omit<User, 'currentChallenge'> & { currentChallenge?: string }) => {
    return db.prepare('INSERT INTO users (id, username, derpAccountId) VALUES (?, ?, ?)').run(
      user.id,
      user.username,
      user.derpAccountId
    );
  },

  updateChallenge: (userId: string, challenge: string | null) => {
    return db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?').run(challenge, userId);
  },

  updateDerpAccountId: (userId: string, derpAccountId: string) => {
    return db.prepare('UPDATE users SET derpAccountId = ? WHERE id = ?').run(derpAccountId, userId);
  },
};

export const authenticatorOperations = {
  findByUserId: (userId: string): any[] => {
    return db.prepare('SELECT * FROM authenticators WHERE userId = ?').all(userId);
  },

  findByCredentialId: (credentialId: string): any | undefined => {
    return db.prepare('SELECT *, derivedNearPublicKey, clientManagedNearPublicKey FROM authenticators WHERE credentialID = ?').get(credentialId);
  },

  create: (authenticator: {
    credentialID: string;
    credentialPublicKey: Buffer;
    counter: number;
    transports: string;
    userId: string;
    name: string;
    registered: string;
    backedUp: number;
    derivedNearPublicKey: string | null;
  }) => {
    return db.prepare(`
      INSERT INTO authenticators (
        credentialID, credentialPublicKey, counter, transports, userId,
        name, registered, backedUp, derivedNearPublicKey
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      authenticator.credentialID,
      authenticator.credentialPublicKey,
      authenticator.counter,
      authenticator.transports,
      authenticator.userId,
      authenticator.name,
      authenticator.registered,
      authenticator.backedUp,
      authenticator.derivedNearPublicKey
    );
  },

  updateCounter: (credentialId: string, counter: number, lastUsed: string) => {
    return db.prepare('UPDATE authenticators SET counter = ?, lastUsed = ? WHERE credentialID = ?').run(
      counter,
      lastUsed,
      credentialId
    );
  },

  updateClientManagedKey: (userId: string, clientNearPublicKey: string) => {
    return db.prepare('UPDATE authenticators SET clientManagedNearPublicKey = ? WHERE userId = ? ORDER BY registered DESC LIMIT 1').run(
      clientNearPublicKey,
      userId
    );
  },

  getLatestByUserId: (userId: string): { credentialID: string } | undefined => {
    return db.prepare('SELECT credentialID FROM authenticators WHERE userId = ? ORDER BY registered ASC LIMIT 1').get(userId) as { credentialID: string } | undefined;
  },
};

// Convert raw authenticator data to StoredAuthenticator
export const mapToStoredAuthenticator = (rawAuth: any): StoredAuthenticator => ({
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
});

export default db;