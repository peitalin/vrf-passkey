import { db } from './index';
import type { User } from '../types';
import type { RunResult } from 'better-sqlite3';

export const userOperations = {
  findByNearAccountId: (nearAccountId: string): User | undefined => {
    const stmt = db.prepare('SELECT * FROM users WHERE nearAccountId = ?');
    return stmt.get(nearAccountId) as User | undefined;
  },

  create: (user: User): RunResult => {
    const stmt = db.prepare('INSERT INTO users (nearAccountId) VALUES (?)');
    return stmt.run(user.nearAccountId);
  },

  updateChallenge: (nearAccountId: string, challenge: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ? WHERE nearAccountId = ?');
    return stmt.run(challenge, nearAccountId) as RunResult;
  },

  updateChallengeAndCommitmentId: (nearAccountId: string, challenge: string | null, commitmentId: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ?, currentCommitmentId = ? WHERE nearAccountId = ?');
    return stmt.run(challenge, commitmentId, nearAccountId) as RunResult;
  },

  updateAuthChallengeAndCommitmentId: (nearAccountId: string, challenge: string | null, commitmentId: string | null): RunResult => {
    const stmt = db.prepare('UPDATE users SET currentChallenge = ?, currentCommitmentId = ? WHERE nearAccountId = ?');
    return stmt.run(challenge, commitmentId, nearAccountId) as RunResult;
  },
};