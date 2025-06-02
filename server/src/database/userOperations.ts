import db from './index';
import type { User } from '../types';
import type { RunResult } from 'better-sqlite3';

export const userOperations = {
  findByUsername: (username: string): User | undefined => {
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    return stmt.get(username) as User | undefined;
  },
  findById: (id: string): User | undefined => {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.get(id) as User | undefined;
  },
  create: (user: User): RunResult => {
    const stmt = db.prepare(
      'INSERT INTO users (id, username, derpAccountId, currentChallenge, currentDataId) VALUES (?, ?, ?, ?, ?)'
    );
    return stmt.run(
        user.id,
        user.username,
        user.derpAccountId || null,
        user.currentChallenge || null,
        user.currentDataId || null
    );
  },
  updateChallenge: (userId: string, challenge: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?');
    return stmt.run(challenge, userId);
  },
  updateChallengeAndDataId: (userId: string, challenge: string | null, dataId: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ?, currentDataId = ? WHERE id = ?');
    return stmt.run(challenge, dataId, userId);
  },
  updateDerpAccountId: (userId: string, derpAccountId: string): RunResult => {
    const stmt = db.prepare('UPDATE users SET derpAccountId = ? WHERE id = ?');
    return stmt.run(derpAccountId, userId);
  },
};