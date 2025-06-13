// SSE Event Types for Registration Flow

export interface BaseSSEEvent {
  step: number;
  sessionId: string;
  phase: string;
  status: 'progress' | 'success' | 'error';
  timestamp: number;
  message: string;
}

export interface WebAuthnVerificationSSEEvent extends BaseSSEEvent {
  step: 1;
  phase: 'webauthn-verification';
  mode?: 'optimistic' | 'secure';
}

export interface UserReadySSEEvent extends BaseSSEEvent {
  step: 2;
  phase: 'user-ready';
  status: 'success';
  verified: boolean;
  username: string;
  nearAccountId: string | null;
  clientNearPublicKey: string | null;
  mode: string;
}

export interface AccessKeyAdditionSSEEvent extends BaseSSEEvent {
  step: 3;
  phase: 'access-key-addition';
  error?: string;
}

export interface DatabaseStorageSSEEvent extends BaseSSEEvent {
  step: 4;
  phase: 'database-storage';
  error?: string;
}

export interface ContractRegistrationSSEEvent extends BaseSSEEvent {
  step: 5;
  phase: 'contract-registration';
  error?: string;
}

export interface RegistrationCompleteSSEEvent extends BaseSSEEvent {
  step: 6;
  phase: 'registration-complete';
  status: 'success';
  sessionId: string;
}

export interface RegistrationErrorSSEEvent extends BaseSSEEvent {
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

// Session management types
export interface RegistrationSession {
  id: string;
  username: string;
  nearAccountId: string;
  status: 'pending' | 'contract_dispatched' | 'contract_confirmed' | 'error';
  result?: any;
  error?: string;
  timestamp: number;
}

// SSE Client management
export interface SSEClientManager {
  addClient(sessionId: string, response: any): void;
  removeClient(sessionId: string, response: any): void;
  notifyClients(sessionId: string, data: any): void;
  cleanup(): void;
}