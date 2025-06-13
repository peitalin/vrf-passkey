// Base event callback type
export type EventCallback<T> = (event: T) => void;

// Operation hooks for before/after call customization
export interface OperationHooks {
  beforeCall?: () => void | Promise<void>;
  afterCall?: (
    success: boolean,
    result?: ActionResult | LoginResult | RegistrationResult | Error
  ) => void | Promise<void>;
}

// SSE Registration Event Types (matching server structure)
export interface BaseSSERegistrationEvent {
  step: number;
  sessionId: string;
  phase: string;
  status: 'progress' | 'success' | 'error';
  timestamp: number;
  message: string;
}

export interface WebAuthnVerificationSSEEvent extends BaseSSERegistrationEvent {
  step: 1;
  phase: 'webauthn-verification';
  mode?: 'optimistic' | 'secure';
}

export interface UserReadySSEEvent extends BaseSSERegistrationEvent {
  step: 2;
  phase: 'user-ready';
  status: 'success';
  verified: boolean;
  username: string;
  nearAccountId: string | undefined;
  clientNearPublicKey: string | null | undefined;
  mode: string;
}

export interface AccessKeyAdditionSSEEvent extends BaseSSERegistrationEvent {
  step: 3;
  phase: 'access-key-addition';
  error?: string;
}

export interface DatabaseStorageSSEEvent extends BaseSSERegistrationEvent {
  step: 4;
  phase: 'database-storage';
  error?: string;
}

export interface ContractRegistrationSSEEvent extends BaseSSERegistrationEvent {
  step: 5;
  phase: 'contract-registration';
  error?: string;
}

export interface RegistrationCompleteSSEEvent extends BaseSSERegistrationEvent {
  step: 6;
  phase: 'registration-complete';
  status: 'success';
  sessionId: string;
}

export interface RegistrationErrorSSEEvent extends BaseSSERegistrationEvent {
  step: 0;
  phase: 'registration-error';
  status: 'error';
  error: string;
}

export type RegistrationSSEEvent =
  | WebAuthnVerificationSSEEvent
  | UserReadySSEEvent
  | AccessKeyAdditionSSEEvent
  | DatabaseStorageSSEEvent
  | ContractRegistrationSSEEvent
  | RegistrationCompleteSSEEvent
  | RegistrationErrorSSEEvent;

// Login Events
export interface LoginStartedEvent {
  username?: string;
}

export interface LoginProgressEvent {
  step: 'getting-options' | 'webauthn-assertion' | 'verifying-server';
  message: string;
}

export interface LoginCompletedEvent {
  username: string;
  nearAccountId?: string;
  publicKey?: string;
}

export interface LoginFailedEvent {
  error: string;
  username?: string;
}

export type LoginEvent =
  | { type: 'loginStarted'; data: LoginStartedEvent }
  | { type: 'loginProgress'; data: LoginProgressEvent }
  | { type: 'loginCompleted'; data: LoginCompletedEvent }
  | { type: 'loginFailed'; data: LoginFailedEvent };

// Action Events
export interface ActionStartedEvent {
  actionType: string;
  receiverId: string;
}

export interface ActionProgressEvent {
  step: 'preparing' | 'authenticating' | 'signing' | 'broadcasting';
  message: string;
}

export interface ActionCompletedEvent {
  transactionId?: string;
  result: any;
}

export interface ActionFailedEvent {
  error: string;
  actionType?: string;
}

export type ActionEvent =
  | { type: 'actionStarted'; data: ActionStartedEvent }
  | { type: 'actionProgress'; data: ActionProgressEvent }
  | { type: 'actionCompleted'; data: ActionCompletedEvent }
  | { type: 'actionFailed'; data: ActionFailedEvent };

// Function Options
export interface RegistrationOptions {
  optimisticAuth: boolean;
  onEvent?: EventCallback<RegistrationSSEEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

export interface LoginOptions {
  optimisticAuth: boolean;
  onEvent?: EventCallback<LoginEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

export interface ActionOptions {
  optimisticAuth?: boolean;
  onEvent?: EventCallback<ActionEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

// Result Types (reusing existing types)
export interface RegistrationResult {
  success: boolean;
  error?: string;
  clientNearPublicKey?: string | null;
  nearAccountId?: string;
  transactionId?: string | null;
}

export interface LoginResult {
  success: boolean;
  error?: string;
  loggedInUsername?: string;
  clientNearPublicKey?: string | null;
  nearAccountId?: string;
}

export interface ActionResult {
  success: boolean;
  error?: string;
  transactionId?: string;
  result?: any;
}

// PasskeyManager Configuration
export interface PasskeyManagerConfig {
  serverUrl?: string; // Optional - enables serverless mode when not provided
  nearNetwork: 'testnet' | 'mainnet';
  relayerAccount: string;
  optimisticAuth: boolean;
}