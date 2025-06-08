import { db } from './index';
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

  findByNearAccountId: (nearAccountId: string): User | undefined => {
    const stmt = db.prepare('SELECT * FROM users WHERE nearAccountId = ?');
    return stmt.get(nearAccountId) as User | undefined;
  },

  create: (user: User): RunResult => {
    const stmt = db.prepare('INSERT INTO users (id, username, nearAccountId) VALUES (?, ?, ?)');
    return stmt.run(user.id, user.username, user.nearAccountId) as RunResult;
  },

  updateChallenge: (userId: string, challenge: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ? WHERE id = ?');
    return stmt.run(challenge, userId) as RunResult;
  },

  updateChallengeAndCommitmentId: (userId: string, challenge: string | null, commitmentId: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ?, currentCommitmentId = ? WHERE id = ?');
    return stmt.run(challenge, commitmentId, userId) as RunResult;
  },

  updateAuthChallengeAndCommitmentId: (userId: string, challenge: string | null, commitmentId: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ?, currentCommitmentId = ? WHERE id = ?');
    return stmt.run(challenge, commitmentId, userId) as RunResult;
  },

  updateNearAccountId: (userId: string, nearAccountId: string): RunResult => {
    const stmt = db.prepare('UPDATE users SET nearAccountId = ? WHERE id = ?');
    return stmt.run(nearAccountId, userId) as RunResult;
  },
};