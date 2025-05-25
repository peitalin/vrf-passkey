/**
 * Interface for a generic challenge store.
 */
export interface ChallengeStoreService {
  /**
   * Stores a challenge with a given Time-To-Live (TTL).
   * @param challenge The challenge string to store.
   * @param ttlSeconds The time in seconds for how long the challenge should be valid.
   * @returns A Promise that resolves when the challenge is stored.
   */
  storeChallenge(challenge: string, ttlSeconds: number): Promise<void>;

  /**
   * Validates a challenge. If valid, it should consume the challenge
   * (i.e., mark it as used or delete it) to prevent replay attacks.
   * @param challenge The challenge string to validate.
   * @returns A Promise that resolves to true if the challenge is valid and was successfully consumed, false otherwise.
   */
  validateAndConsumeChallenge(challenge: string): Promise<boolean>;
}

// In-memory implementation of ChallengeStoreService
class InMemoryChallengeStore implements ChallengeStoreService {
  private store: Map<string, { challenge: string; timeoutId: NodeJS.Timeout }> = new Map();
  private readonly MAX_CHALLENGES_BEFORE_WARNING = 5; // Threshold for warning

  async storeChallenge(challenge: string, ttlSeconds: number): Promise<void> {
    // If challenge already exists, clear its old timeout to prevent memory leaks
    if (this.store.has(challenge)) {
      const existingEntry = this.store.get(challenge);
      if (existingEntry && existingEntry.timeoutId) {
        clearTimeout(existingEntry.timeoutId);
      }
    }

    const timeoutId = setTimeout(() => {
      this.store.delete(challenge);
      console.log(`Challenge ${challenge} expired and removed from in-memory store.`);
    }, ttlSeconds * 1000);

    this.store.set(challenge, { challenge, timeoutId });
    console.log(`Challenge ${challenge} stored in-memory, will expire in ${ttlSeconds} seconds.`);

    // Log a warning if the store size exceeds the threshold
    if (this.store.size > this.MAX_CHALLENGES_BEFORE_WARNING) {
      console.warn(
        `InMemoryChallengeStore: Number of active challenges (${this.store.size}) has exceeded the warning threshold of ${this.MAX_CHALLENGES_BEFORE_WARNING}. ` +
        `Consider if this is expected for your testing scenario or if challenges are not being consumed/expired correctly.`
      );
    }
  }

  async validateAndConsumeChallenge(challenge: string): Promise<boolean> {
    if (this.store.has(challenge)) {
      const entry = this.store.get(challenge);
      if (entry && entry.timeoutId) {
        clearTimeout(entry.timeoutId); // Clear the expiry timeout as it's being consumed
      }
      this.store.delete(challenge); // Consume the challenge
      console.log(`Challenge ${challenge} validated and consumed from in-memory store.`);
      return true;
    }
    console.log(`Challenge ${challenge} not found or already consumed/expired.`);
    return false;
  }
}

// Export a singleton instance of the in-memory store.
// This can be replaced later with a Redis implementation or other store
// by changing what this `challengeStore` constant is assigned to.
export const challengeStore: ChallengeStoreService = new InMemoryChallengeStore();