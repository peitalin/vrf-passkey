import { TxExecutionStatus } from "@near-js/types";

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

// Base SSE Event Types (unified for Registration and Actions)
export interface BaseSSEEvent {
  step: number;
  phase: string;
  status: 'progress' | 'success' | 'error';
  timestamp: number;
  message: string;
}

// Registration-specific events
export interface BaseSSERegistrationEvent extends BaseSSEEvent {
  phase: 'webauthn-verification' | 'user-ready' | 'access-key-addition' | 'account-verification' | 'database-storage' | 'contract-registration' | 'registration-complete' | 'registration-error';
}

// Action-specific events
export interface BaseSSEActionEvent extends BaseSSEEvent {
  phase: 'preparation' | 'authentication' | 'contract-verification' | 'transaction-signing' | 'broadcasting' | 'action-complete' | 'action-error';
}

// Registration Event Types
export interface WebAuthnVerificationSSEEvent extends BaseSSERegistrationEvent {
  step: 1;
  phase: 'webauthn-verification';
}

export interface UserReadySSEEvent extends BaseSSERegistrationEvent {
  step: 2;
  phase: 'user-ready';
  status: 'success';
  verified: boolean;
  nearAccountId: string;
  clientNearPublicKey: string | null | undefined;
}

export interface AccessKeyAdditionSSEEvent extends BaseSSERegistrationEvent {
  step: 3;
  phase: 'access-key-addition';
  error?: string;
}

export interface AccountVerificationSSEEvent extends BaseSSERegistrationEvent {
  step: 4;
  phase: 'account-verification';
  error?: string;
}

export interface DatabaseStorageSSEEvent extends BaseSSERegistrationEvent {
  step: 5;
  phase: 'database-storage';
  error?: string;
}

export interface ContractRegistrationSSEEvent extends BaseSSERegistrationEvent {
  step: 6;
  phase: 'contract-registration';
  error?: string;
}

export interface RegistrationCompleteSSEEvent extends BaseSSERegistrationEvent {
  step: 7;
  phase: 'registration-complete';
  status: 'success';
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
  | AccountVerificationSSEEvent
  | DatabaseStorageSSEEvent
  | ContractRegistrationSSEEvent
  | RegistrationCompleteSSEEvent
  | RegistrationErrorSSEEvent;

// Action Event Types
export interface ActionPreparationSSEEvent extends BaseSSEActionEvent {
  step: 1;
  phase: 'preparation';
}

export interface ActionAuthenticationSSEEvent extends BaseSSEActionEvent {
  step: 2;
  phase: 'authentication';
}

export interface ActionContractVerificationSSEEvent extends BaseSSEActionEvent {
  step: 3;
  phase: 'contract-verification';
  data?: any;
  logs?: string[];
}

export interface ActionTransactionSigningSSEEvent extends BaseSSEActionEvent {
  step: 4;
  phase: 'transaction-signing';
  data?: any;
  logs?: string[];
}

export interface ActionBroadcastingSSEEvent extends BaseSSEActionEvent {
  step: 5;
  phase: 'broadcasting';
}

export interface ActionCompleteSSEEvent extends BaseSSEActionEvent {
  step: 6;
  phase: 'action-complete';
  status: 'success';
  data?: any;
}

export interface ActionErrorSSEEvent extends BaseSSEActionEvent {
  step: 0;
  phase: 'action-error';
  status: 'error';
  error: string;
}

export type ActionSSEEvent =
  | ActionPreparationSSEEvent
  | ActionAuthenticationSSEEvent
  | ActionContractVerificationSSEEvent
  | ActionTransactionSigningSSEEvent
  | ActionBroadcastingSSEEvent
  | ActionCompleteSSEEvent
  | ActionErrorSSEEvent;

// Login Events (SSE format)
export interface BaseSSELoginEvent extends BaseSSEEvent {
  phase: 'preparation' | 'webauthn-assertion' | 'vrf-unlock' | 'login-complete' | 'login-error';
}

export interface LoginPreparationSSEEvent extends BaseSSELoginEvent {
  step: 1;
  phase: 'preparation';
}

export interface LoginWebAuthnAssertionSSEEvent extends BaseSSELoginEvent {
  step: 2;
  phase: 'webauthn-assertion';
}

export interface LoginVrfUnlockSSEEvent extends BaseSSELoginEvent {
  step: 3;
  phase: 'vrf-unlock';
}

export interface LoginCompleteSSEEvent extends BaseSSELoginEvent {
  step: 4;
  phase: 'login-complete';
  status: 'success';
  nearAccountId: string;
  clientNearPublicKey: string;
}

export interface LoginErrorSSEEvent extends BaseSSELoginEvent {
  step: 0;
  phase: 'login-error';
  status: 'error';
  error: string;
}

export type LoginEvent =
  | LoginPreparationSSEEvent
  | LoginWebAuthnAssertionSSEEvent
  | LoginVrfUnlockSSEEvent
  | LoginCompleteSSEEvent
  | LoginErrorSSEEvent;

// Legacy Action Events (for backward compatibility - to be deprecated)
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
  onEvent?: EventCallback<RegistrationSSEEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

export interface LoginOptions {
  onEvent?: EventCallback<LoginEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

export interface LoginState {
  isLoggedIn: boolean;
  nearAccountId: string | null;
  publicKey: string | null;
  userData: any | null;
  vrfActive: boolean;
  vrfSessionDuration?: number;
}

export interface ActionOptions {
  onEvent?: EventCallback<ActionSSEEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
  waitUntil?: TxExecutionStatus;
}

// Result Types
export interface RegistrationResult {
  success: boolean;
  error?: string;
  clientNearPublicKey?: string | null;
  nearAccountId?: string;
  transactionId?: string | null;
  vrfRegistration?: {
    success: boolean;
    vrfPublicKey?: string;
    encryptedVrfKeypair?: any;
    contractVerified?: boolean;
    error?: string;
  };
}

export interface LoginResult {
  success: boolean;
  error?: string;
  loggedInNearAccountId?: string;
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
export interface PasskeyManagerConfigs {
  nearRpcUrl: string;
  nearNetwork: 'testnet' | 'mainnet';
  contractId: 'web3-authn.testnet' | 'web3-authn.near' | string;
  relayerAccount: string;
  // Relay Server is used to create new NEAR accounts
  // Optional: defaults to testnet faucet
  relayServerUrl?: string;
  // Whether to use the relayer by default on initial load
  initialUseRelayer?: boolean;
}

// === TRANSACTION TYPES ===
export interface TransactionParams {
  receiverId: string;
  methodName: string;
  args: Record<string, any>;
  gas?: string;
  deposit?: string;
}