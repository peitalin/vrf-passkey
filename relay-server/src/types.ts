// Result type for NearClient.createAccount method
export interface CreateAccountResult {
  success: boolean;
  message: string;
  result?: { // Present on success
    accountId: string;
    publicKey: string;
    transactionOutcome?: any; // Optionally include full transaction outcome if needed
  };
  error?: any;
  details?: string;
}

// Interfaces for relay server API
export interface AccountCreationResult {
  success: boolean;
  transactionHash?: string;
  accountId?: string;
  error?: string;
  message?: string;
}

export interface AccountCreationRequest {
  accountId: string;
  publicKey: string;
}

// Interface for atomic account creation and registration
export interface CreateAccountAndRegisterRequest {
  new_account_id: string;
  new_public_key: string;
  vrf_data: any; // VRFVerificationData from contract
  webauthn_registration: any; // WebAuthnRegistrationCredential from contract
  deterministic_vrf_public_key?: Uint8Array;
}

// Result type for atomic account creation and registration
export interface CreateAccountAndRegisterResult {
  success: boolean;
  transactionHash?: string;
  error?: string;
  message?: string;
  contractResult?: any; // FinalExecutionOutcome
}

// SSE Registration Event Types
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
}

export interface UserReadySSEEvent extends BaseSSERegistrationEvent {
  step: 2;
  phase: 'user-ready';
  status: 'success';
  verified: boolean;
  nearAccountId: string;
  clientNearPublicKey: string | null | undefined;
  mode: string;
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
  step: 4 | 5;
  phase: 'database-storage';
  error?: string;
}

export interface ContractRegistrationSSEEvent extends BaseSSERegistrationEvent {
  step: 5 | 6;
  phase: 'contract-registration';
  error?: string;
}

export interface RegistrationCompleteSSEEvent extends BaseSSERegistrationEvent {
  step: 6 | 7;
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
  | AccountVerificationSSEEvent
  | DatabaseStorageSSEEvent
  | ContractRegistrationSSEEvent
  | RegistrationCompleteSSEEvent
  | RegistrationErrorSSEEvent;

// SSE Event emission callback type
export type SSEEventEmitter = (event: RegistrationSSEEvent) => void;


// Runtime-tested NEAR error types (based on actual on-chain observations)
export interface NearActionErrorKind {
  AccountAlreadyExists?: {
    accountId: string;
  };
  AccountDoesNotExist?: {
    account_id: string;
  };
  InsufficientStake?: {
    account_id: string;
    stake: string;
    minimum_stake: string;
  };
  LackBalanceForState?: {
    account_id: string;
    balance: string;
  };
  // Add more error types as we discover them
  [key: string]: any;
}

export interface NearActionError {
  kind: NearActionErrorKind;
  index: string; // NEAR uses string indexes, not numbers
}

export interface NearExecutionFailure {
  ActionError?: NearActionError;
  // Add other failure types as needed
  [key: string]: any;
}

export interface NearReceiptStatus {
  SuccessValue?: string;
  SuccessReceiptId?: string;
  Failure?: NearExecutionFailure;
}

export interface NearReceiptOutcomeWithId {
  id: string;
  outcome: {
    logs: string[];
    receipt_ids: string[];
    gas_burnt: number;
    tokens_burnt: string;
    executor_id: string;
    status: NearReceiptStatus;
  };
}

