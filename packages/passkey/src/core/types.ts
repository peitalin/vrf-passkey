// === CONFIGURATION TYPES ===
export interface PasskeyConfig {
  serverUrl?: string;
  nearNetwork: 'testnet' | 'mainnet';
  relayerAccount: string;
  optimisticAuth?: boolean;
  debugMode?: boolean;
  wasmWorkerUrl?: string;
}

// === USER DATA TYPES ===
export interface UserData {
  username: string;
  nearAccountId?: string;
  clientNearPublicKey?: string;
  lastUpdated: number;
  prfSupported?: boolean;
  deterministicKey?: boolean;
  passkeyCredential?: {
    id: string;
    rawId: string;
  };
}

// === RESULT TYPES ===
export interface BaseResult {
  success: boolean;
  error?: string;
}

export interface RegisterResult extends BaseResult {
  nearAccountId?: string;
  publicKey?: string;
  clientNearPublicKey?: string;
  transactionId?: string | null;
}

export interface LoginResult extends BaseResult {
  loggedInUsername?: string;
  clientNearPublicKey?: string | null;
  nearAccountId?: string;
}

export interface SignTransactionResult extends BaseResult {
  signedTransactionBorsh?: number[];
  nearAccountId?: string;
  transactionId?: string;
}

// === TRANSACTION TYPES ===
export interface TransactionParams {
  receiverId: string;
  methodName: string;
  args: Record<string, any>;
  gas?: string;
  deposit?: string;
}

export interface SignedTransaction {
  transaction: any;
  signature: any;
  serialized: Uint8Array;
}

// === WEBAUTHN TYPES ===
export interface WebAuthnChallenge {
  id: string;
  challenge: string;
  timestamp: number;
  used: boolean;
  operation: 'registration' | 'authentication';
  timeout: number;
}

export interface WebAuthnRegistrationWithPrf {
  credential: PublicKeyCredential;
  prfEnabled: boolean;
  commitmentId?: string;
}

export interface WebAuthnAuthenticationWithPrf {
  credential: PublicKeyCredential;
  prfOutput?: ArrayBuffer;
}

export interface RegistrationOptions {
  options: PublicKeyCredentialCreationOptions;
  challengeId: string;
  commitmentId?: string;
}

export interface AuthenticationOptions {
  options: PublicKeyCredentialRequestOptions;
  challengeId: string;
}

// === WORKER TYPES ===
export interface WorkerResponse {
  type: string;
  payload: {
    error?: string;
    publicKey?: string;
    nearAccountId?: string;
    signedTransactionBorsh?: number[];
    stored?: boolean;
  };
}

export interface RegistrationPayload {
  nearAccountId: string;
}

export interface SigningPayload {
  nearAccountId: string;
  receiverId: string;
  contractMethodName: string;
  contractArgs: Record<string, any>;
  gasAmount: string;
  depositAmount: string;
  nonce: string;
  blockHashBytes: number[];
}

// === PRF TYPES ===
export interface PrfSaltConfig {
  nearKeyEncryption: Uint8Array;
}

// === SERVER TYPES ===
export interface ServerAuthenticationOptions {
  challenge: string;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: string;
  }>;
  userVerification?: UserVerificationRequirement;
  timeout?: number;
}

// === STORAGE TYPES ===
export interface ClientUserData {
  nearAccountId: string;
  username: string;
  displayName?: string;
  registeredAt: number;
  lastLogin?: number;
  preferences?: UserPreferences;
}

export interface UserPreferences {
  optimisticAuth: boolean;
}

// === ERROR TYPES ===
export class PasskeyError extends Error {
  constructor(
    message: string,
    public code?: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'PasskeyError';
  }
}

export class AuthenticationError extends PasskeyError {
  constructor(message: string, cause?: Error) {
    super(message, 'AUTHENTICATION_ERROR', cause);
    this.name = 'AuthenticationError';
  }
}

export class RegistrationError extends PasskeyError {
  constructor(message: string, cause?: Error) {
    super(message, 'REGISTRATION_ERROR', cause);
    this.name = 'RegistrationError';
  }
}

export class TransactionError extends PasskeyError {
  constructor(message: string, cause?: Error) {
    super(message, 'TRANSACTION_ERROR', cause);
    this.name = 'TransactionError';
  }
}