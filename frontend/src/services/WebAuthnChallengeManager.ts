export interface StoredChallenge {
  challenge: string;
  timestamp: number;
  expires: number;
  type: 'registration' | 'authentication';
  username?: string;
  commitmentId?: string;
}

export class WebAuthnChallengeManager {
  private static readonly STORAGE_PREFIX = 'webauthn_challenge_';
  private static readonly DEFAULT_TIMEOUT = 60000; // 60 seconds

  /**
   * Store a challenge with automatic expiration
   */
  static storeChallenge(
    challenge: string,
    type: 'registration' | 'authentication',
    options?: {
      username?: string;
      commitmentId?: string;
      timeout?: number;
    }
  ): void {
    const now = Date.now();
    const timeout = options?.timeout || this.DEFAULT_TIMEOUT;

    const challengeData: StoredChallenge = {
      challenge,
      type,
      timestamp: now,
      expires: now + timeout,
      username: options?.username,
      commitmentId: options?.commitmentId,
    };

    const key = this.getChallengeKey(type, options?.username);
    sessionStorage.setItem(key, JSON.stringify(challengeData));

    console.log(`Stored ${type} challenge for ${options?.username || 'unknown'}, expires in ${timeout}ms`);
  }

  /**
   * Get a challenge if it hasn't expired
   */
  static getChallenge(
    type: 'registration' | 'authentication',
    username?: string
  ): StoredChallenge | null {
    const key = this.getChallengeKey(type, username);
    const stored = sessionStorage.getItem(key);

    if (!stored) {
      return null;
    }

    try {
      const challengeData: StoredChallenge = JSON.parse(stored);

      // Check if expired
      if (Date.now() > challengeData.expires) {
        console.log(`Challenge expired for ${type}/${username || 'unknown'}, removing`);
        sessionStorage.removeItem(key);
        return null;
      }

      return challengeData;
    } catch (error) {
      console.error('Error parsing stored challenge:', error);
      sessionStorage.removeItem(key);
      return null;
    }
  }

  /**
   * Validate a challenge matches what's stored
   */
  static validateChallenge(
    receivedChallenge: string,
    type: 'registration' | 'authentication',
    username?: string
  ): boolean {
    const stored = this.getChallenge(type, username);

    if (!stored) {
      console.warn(`No stored challenge found for ${type}/${username || 'unknown'}`);
      return false;
    }

    const isValid = stored.challenge === receivedChallenge;

    if (isValid) {
      console.log(`Challenge validated successfully for ${type}/${username || 'unknown'}`);
      // Clear the challenge after successful validation
      this.clearChallenge(type, username);
    } else {
      console.warn(`Challenge validation failed for ${type}/${username || 'unknown'}`);
    }

    return isValid;
  }

  /**
   * Clear a specific challenge
   */
  static clearChallenge(type: 'registration' | 'authentication', username?: string): void {
    const key = this.getChallengeKey(type, username);
    sessionStorage.removeItem(key);
    console.log(`Cleared ${type} challenge for ${username || 'unknown'}`);
  }

  /**
   * Clear all challenges
   */
  static clearAllChallenges(): void {
    // Get all sessionStorage keys that match our pattern
    const keysToRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(this.STORAGE_PREFIX)) {
        keysToRemove.push(key);
      }
    }

    keysToRemove.forEach(key => sessionStorage.removeItem(key));
    console.log(`Cleared ${keysToRemove.length} stored challenges`);
  }

  /**
   * Clean up expired challenges
   */
  static cleanupExpiredChallenges(): void {
    const now = Date.now();
    const keysToRemove: string[] = [];

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(this.STORAGE_PREFIX)) {
        try {
          const stored = sessionStorage.getItem(key);
          if (stored) {
            const challengeData: StoredChallenge = JSON.parse(stored);
            if (now > challengeData.expires) {
              keysToRemove.push(key);
            }
          }
        } catch (error) {
          // If we can't parse it, remove it
          keysToRemove.push(key);
        }
      }
    }

    keysToRemove.forEach(key => sessionStorage.removeItem(key));

    if (keysToRemove.length > 0) {
      console.log(`Cleaned up ${keysToRemove.length} expired challenges`);
    }
  }

  /**
   * Get all active challenges (for debugging)
   */
  static getAllChallenges(): StoredChallenge[] {
    const challenges: StoredChallenge[] = [];

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(this.STORAGE_PREFIX)) {
        try {
          const stored = sessionStorage.getItem(key);
          if (stored) {
            const challengeData: StoredChallenge = JSON.parse(stored);
            challenges.push(challengeData);
          }
        } catch (error) {
          console.warn('Failed to parse challenge data:', error);
        }
      }
    }

    return challenges;
  }

  /**
   * Get commitment ID for a stored challenge
   */
  static getCommitmentId(type: 'registration' | 'authentication', username?: string): string | null {
    const stored = this.getChallenge(type, username);
    return stored?.commitmentId || null;
  }

  // Private helpers

  private static getChallengeKey(type: 'registration' | 'authentication', username?: string): string {
    const suffix = username ? `${type}_${username}` : type;
    return `${this.STORAGE_PREFIX}${suffix}`;
  }
}

// Auto-cleanup expired challenges when the page loads
if (typeof window !== 'undefined') {
  // Clean up on page load
  WebAuthnChallengeManager.cleanupExpiredChallenges();

  // Set up periodic cleanup every 30 seconds
  setInterval(() => {
    WebAuthnChallengeManager.cleanupExpiredChallenges();
  }, 30000);
}