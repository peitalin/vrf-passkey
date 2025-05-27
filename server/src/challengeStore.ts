import type { SerializableActionArgs } from './types'; // Assuming this type is defined

interface StoredChallengeData {
  actionDetails: SerializableActionArgs;
  expectedCredentialID?: string; // The base64url credential ID that is expected to sign this
  expiresAt: number;
}

/**
 * Interface for a generic challenge store for action signing.
 */
export interface ActionChallengeStoreService {
  /**
   * Stores a challenge and its associated action details with a given Time-To-Live (TTL).
   * @param challenge The challenge string to store.
   * @param details The details to associate with the challenge.
   * @param ttlSeconds The time in seconds for how long the challenge should be valid.
   * @returns A Promise that resolves when the challenge is stored.
   */
  storeActionChallenge(challenge: string, details: { actionDetails: SerializableActionArgs, expectedCredentialID?: string }, ttlSeconds: number): Promise<void>;

  /**
   * Validates a challenge. If valid, it should consume the challenge
   * (i.e., mark it as used or delete it) to prevent replay attacks.
   * @param challenge The challenge string to validate.
   * @returns A Promise that resolves to the stored StoredChallengeData (excluding expiresAt) if valid and consumed, or null otherwise.
   */
  validateAndConsumeActionChallenge(challenge: string): Promise<Omit<StoredChallengeData, 'expiresAt'> | null>;
}

// In-memory implementation of ActionChallengeStoreService
class InMemoryActionChallengeStore implements ActionChallengeStoreService {
  // Store: challenge string -> { details, timeoutId }
  private store: Map<string, { data: StoredChallengeData; timeoutId: NodeJS.Timeout }> = new Map();
  private readonly MAX_CHALLENGES_BEFORE_WARNING = 5; // Threshold for warning

  async storeActionChallenge(
    challenge: string,
    details: { actionDetails: SerializableActionArgs, expectedCredentialID?: string },
    ttlSeconds: number
  ): Promise<void> {
    if (this.store.has(challenge)) {
      const existingEntry = this.store.get(challenge);
      if (existingEntry?.timeoutId) {
        clearTimeout(existingEntry.timeoutId);
      }
    }

    const expiresAt = Date.now() + ttlSeconds * 1000;
    const timeoutId = setTimeout(() => {
      this.store.delete(challenge);
      console.log(`ActionChallenge ${challenge} expired and removed from in-memory store.`);
    }, ttlSeconds * 1000);

    this.store.set(challenge, { data: { ...details, expiresAt }, timeoutId });
    console.log(`ActionChallenge ${challenge} stored in-memory, will expire in ${ttlSeconds} seconds.`);

    if (this.store.size > this.MAX_CHALLENGES_BEFORE_WARNING) {
      console.warn(
        `InMemoryActionChallengeStore: Number of active challenges (${this.store.size}) has exceeded the warning threshold of ${this.MAX_CHALLENGES_BEFORE_WARNING}.`
      );
    }
  }

  async validateAndConsumeActionChallenge(challenge: string): Promise<Omit<StoredChallengeData, 'expiresAt'> | null> {
    const entry = this.store.get(challenge);
    if (entry) {
      if (Date.now() > entry.data.expiresAt) {
        console.log(`ActionChallenge ${challenge} found but has expired.`);
        clearTimeout(entry.timeoutId);
        this.store.delete(challenge);
        return null;
      }
      clearTimeout(entry.timeoutId);
      this.store.delete(challenge);
      console.log(`ActionChallenge ${challenge} validated and consumed from in-memory store.`);
      const { expiresAt, ...detailsToReturn } = entry.data; // Exclude expiresAt from returned object
      return detailsToReturn;
    }
    console.log(`ActionChallenge ${challenge} not found or already consumed/expired.`);
    return null;
  }
}

export const actionChallengeStore: ActionChallengeStoreService = new InMemoryActionChallengeStore();