export interface ClientUserData {
  nearAccountId: string;
  username: string;
  displayName?: string;
  registeredAt: number;
  lastLogin?: number;
  preferences?: {
    optimisticAuth: boolean;
  };
}

export interface UserRegistrationData {
  username: string;
  nearAccountId: string;
  clientNearPublicKey?: string;
  passkeyCredential: {
    id: string;
    rawId: string;
  };
  prfSupported: boolean;
}

export class ClientUserManager {
  private static readonly STORAGE_PREFIX = 'webauthn_user_';
  private static readonly LAST_USER_KEY = 'webauthn_last_user';
  private static readonly REGISTERED_USERS_KEY = 'webauthn_registered_users';

  /**
   * Derive username from NEAR account ID
   */
  static deriveUsername(nearAccountId: string): string {
    return nearAccountId.split('.')[0]; // "derp27.webauthn-contract.testnet" → "derp27"
  }

  /**
   * Generate NEAR account ID from username
   */
  static generateNearAccountId(username: string, relayerAccountId: string): string {
    const sanitized = username.toLowerCase().replace(/[^a-z0-9_\-]/g, '').substring(0, 32);
    return `${sanitized}.${relayerAccountId}`;
  }

  /**
   * Store user data locally
   */
  static storeUser(userData: ClientUserData): void {
    const key = this.STORAGE_PREFIX + userData.nearAccountId;
    localStorage.setItem(key, JSON.stringify(userData));

    // Update last used user
    localStorage.setItem(this.LAST_USER_KEY, userData.nearAccountId);

    // Add to registered users list
    this.addToRegisteredUsers(userData.nearAccountId);
  }

  /**
   * Get user data by NEAR account ID
   */
  static getUser(nearAccountId: string): ClientUserData | null {
    const key = this.STORAGE_PREFIX + nearAccountId;
    const stored = localStorage.getItem(key);
    if (!stored) return null;

    try {
      return JSON.parse(stored);
    } catch (error) {
      console.error('Error parsing user data:', error);
      return null;
    }
  }

  /**
   * Get user data by username
   */
  static getUserByUsername(username: string, relayerAccountId: string): ClientUserData | null {
    const nearAccountId = this.generateNearAccountId(username, relayerAccountId);
    return this.getUser(nearAccountId);
  }

  /**
   * Get the last used user
   */
  static getLastUser(): ClientUserData | null {
    const lastUserAccount = localStorage.getItem(this.LAST_USER_KEY);
    if (!lastUserAccount) return null;
    return this.getUser(lastUserAccount);
  }

  /**
   * Get all registered users
   */
  static getAllUsers(): ClientUserData[] {
    const registeredUsers = this.getRegisteredUsers();
    return registeredUsers
      .map(accountId => this.getUser(accountId))
      .filter(user => user !== null) as ClientUserData[];
  }

  /**
   * Register a new user
   */
  static registerUser(
    username: string,
    relayerAccountId: string,
    additionalData?: Partial<ClientUserData>
  ): ClientUserData {
    const nearAccountId = this.generateNearAccountId(username, relayerAccountId);
    const userData: ClientUserData = {
      nearAccountId,
      username: this.deriveUsername(nearAccountId),
      displayName: username,
      registeredAt: Date.now(),
      lastLogin: Date.now(),
      preferences: {
        optimisticAuth: true, // Default to Fast mode for better UX
      },
      ...additionalData,
    };

    this.storeUser(userData);
    return userData;
  }

  /**
   * Update user's last login time
   */
  static updateLastLogin(nearAccountId: string): void {
    const user = this.getUser(nearAccountId);
    if (user) {
      user.lastLogin = Date.now();
      this.storeUser(user);
    }
  }

  /**
   * Update user preferences
   */
  static updatePreferences(nearAccountId: string, preferences: Partial<ClientUserData['preferences']>): void {
    const user = this.getUser(nearAccountId);
    if (user) {
      user.preferences = { ...user.preferences, ...preferences };
      this.storeUser(user);
    }
  }

  /**
   * Check if user exists locally
   */
  static userExists(nearAccountId: string): boolean {
    return this.getUser(nearAccountId) !== null;
  }

  /**
   * Remove user data (for logout/cleanup)
   */
  static removeUser(nearAccountId: string): void {
    const key = this.STORAGE_PREFIX + nearAccountId;
    localStorage.removeItem(key);
    this.removeFromRegisteredUsers(nearAccountId);

    // If this was the last user, clear it
    const lastUser = localStorage.getItem(this.LAST_USER_KEY);
    if (lastUser === nearAccountId) {
      localStorage.removeItem(this.LAST_USER_KEY);
    }
  }

  /**
   * Clear all user data
   */
  static clearAllUsers(): void {
    const users = this.getAllUsers();
    users.forEach(user => this.removeUser(user.nearAccountId));
    localStorage.removeItem(this.REGISTERED_USERS_KEY);
    localStorage.removeItem(this.LAST_USER_KEY);
  }

  // Private helper methods

  private static addToRegisteredUsers(nearAccountId: string): void {
    const registeredUsers = this.getRegisteredUsers();
    if (!registeredUsers.includes(nearAccountId)) {
      registeredUsers.push(nearAccountId);
      localStorage.setItem(this.REGISTERED_USERS_KEY, JSON.stringify(registeredUsers));
    }
  }

  private static removeFromRegisteredUsers(nearAccountId: string): void {
    const registeredUsers = this.getRegisteredUsers();
    const filtered = registeredUsers.filter(id => id !== nearAccountId);
    localStorage.setItem(this.REGISTERED_USERS_KEY, JSON.stringify(filtered));
  }

  private static getRegisteredUsers(): string[] {
    const stored = localStorage.getItem(this.REGISTERED_USERS_KEY);
    if (!stored) return [];

    try {
      return JSON.parse(stored);
    } catch {
      return [];
    }
  }
}