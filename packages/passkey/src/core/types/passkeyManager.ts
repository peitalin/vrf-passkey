import { TxExecutionStatus } from "@near-js/types";
import type { EncryptedVRFKeypair } from './vrf-worker';
import { AccountId } from "./accountIds";

// Device Linking Enums
export enum DeviceLinkingPhase {
  STEP_1_QR_CODE_GENERATED = 'qr-code-generated',   // Device2: QR code created and displayed
  STEP_2_SCANNING = 'scanning',                     // Device1: Scanning QR code
  STEP_3_AUTHORIZATION = 'authorization',           // Device1: TouchID authorization
  STEP_4_POLLING = 'polling',                       // Device2: Polling contract for mapping
  STEP_5_ADDKEY_DETECTED = 'addkey-detected',       // Device2: AddKey transaction detected
  STEP_6_REGISTRATION = 'registration',             // Device2: Registration and credential storage
  STEP_7_LINKING_COMPLETE = 'linking-complete',     // Final completion
  STEP_8_AUTO_LOGIN = 'auto-login',                 // Auto-login after registration
  IDLE = 'idle',                                    // Idle state
  REGISTRATION_ERROR = 'registration-error',        // Error during registration
  LOGIN_ERROR = 'login-error',                      // Error during login
  DEVICE_LINKING_ERROR = 'error',                   // General error state
}

export enum DeviceLinkingStatus {
  PROGRESS = 'progress',
  SUCCESS = 'success',
  ERROR = 'error',
}

// Registration Enums
export enum RegistrationPhase {
  STEP_1_WEBAUTHN_VERIFICATION = 'webauthn-verification',
  STEP_2_KEY_GENERATION = 'key-generation',
  STEP_3_ACCESS_KEY_ADDITION = 'access-key-addition',
  STEP_4_ACCOUNT_VERIFICATION = 'account-verification',
  STEP_5_DATABASE_STORAGE = 'database-storage',
  STEP_6_CONTRACT_REGISTRATION = 'contract-registration',
  STEP_7_REGISTRATION_COMPLETE = 'registration-complete',
  REGISTRATION_ERROR = 'error',
}

export enum RegistrationStatus {
  PROGRESS = 'progress',
  SUCCESS = 'success',
  ERROR = 'error',
}

// Login Enums
export enum LoginPhase {
  STEP_1_PREPARATION = 'preparation',
  STEP_2_WEBAUTHN_ASSERTION = 'webauthn-assertion',
  STEP_3_VRF_UNLOCK = 'vrf-unlock',
  STEP_4_LOGIN_COMPLETE = 'login-complete',
  LOGIN_ERROR = 'login-error',
}

export enum LoginStatus {
  PROGRESS = 'progress',
  SUCCESS = 'success',
  ERROR = 'error',
}

// Action Enums
export enum ActionPhase {
  STEP_1_PREPARATION = 'preparation',
  STEP_2_AUTHENTICATION = 'authentication',
  STEP_3_CONTRACT_VERIFICATION = 'contract-verification',
  STEP_4_TRANSACTION_SIGNING = 'transaction-signing',
  STEP_5_DEVICE_LINKING = 'device-linking',
  STEP_6_VERIFICATION_COMPLETE = 'verification-complete',   // Rust WASM worker phase
  STEP_7_SIGNING_COMPLETE = 'signing-complete',             // Rust WASM worker phase
  WASM_ERROR = 'wasm-error',                                // Rust WASM worker phase
  STEP_8_BROADCASTING = 'broadcasting',
  STEP_9_ACTION_COMPLETE = 'action-complete',
  ACTION_ERROR = 'action-error',
}

export enum ActionStatus {
  PROGRESS = 'progress',
  SUCCESS = 'success',
  ERROR = 'error',
}

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
  phase: RegistrationPhase | LoginPhase | ActionPhase | DeviceLinkingPhase;
  status: RegistrationStatus | LoginStatus | ActionStatus | DeviceLinkingStatus;
  message: string;
}

// Registration-specific events
export interface BaseSSERegistrationEvent extends BaseSSEEvent {
  phase: RegistrationPhase;
  status: RegistrationStatus;
}

// Action-specific events
export interface BaseSSEActionEvent extends BaseSSEEvent {
  phase: ActionPhase;
  status: ActionStatus;
}

// Login-specific events
export interface BaseSSELoginEvent extends BaseSSEEvent {
  phase: LoginPhase;
  status: LoginStatus;
}

export interface DeviceLinkingEvent extends BaseSSEEvent {
  phase: DeviceLinkingPhase;
  status: DeviceLinkingStatus;
}

// Registration Event Types
export interface RegistrationEventStep1 extends BaseSSERegistrationEvent {
  step: 1;
  phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION;
}

export interface RegistrationEventStep2 extends BaseSSERegistrationEvent {
  step: 2;
  phase: RegistrationPhase.STEP_2_KEY_GENERATION;
  status: RegistrationStatus.SUCCESS;
  verified: boolean;
  nearAccountId: string;
  nearPublicKey: string | null | undefined;
  vrfPublicKey: string | null | undefined;
}

export interface RegistrationEventStep3 extends BaseSSERegistrationEvent {
  step: 3;
  phase: RegistrationPhase.STEP_3_ACCESS_KEY_ADDITION;
  error?: string;
}

export interface RegistrationEventStep4 extends BaseSSERegistrationEvent {
  step: 4;
  phase: RegistrationPhase.STEP_4_ACCOUNT_VERIFICATION;
  error?: string;
}

export interface RegistrationEventStep5 extends BaseSSERegistrationEvent {
  step: 5;
  phase: RegistrationPhase.STEP_5_DATABASE_STORAGE;
  error?: string;
}

export interface RegistrationEventStep6 extends BaseSSERegistrationEvent {
  step: 6;
  phase: RegistrationPhase.STEP_6_CONTRACT_REGISTRATION;
  error?: string;
}

export interface RegistrationEventStep7 extends BaseSSERegistrationEvent {
  step: 7;
  phase: RegistrationPhase.STEP_7_REGISTRATION_COMPLETE;
  status: RegistrationStatus.SUCCESS;
}

export interface RegistrationEventStep0 extends BaseSSERegistrationEvent {
  step: 0;
  phase: RegistrationPhase.REGISTRATION_ERROR;
  status: RegistrationStatus.ERROR;
  error: string;
}

export type RegistrationSSEEvent =
  | RegistrationEventStep1
  | RegistrationEventStep2
  | RegistrationEventStep3
  | RegistrationEventStep4
  | RegistrationEventStep5
  | RegistrationEventStep6
  | RegistrationEventStep7
  | RegistrationEventStep0;

// Action Event Types
export interface ActionEventStep1 extends BaseSSEActionEvent {
  step: 1;
  phase: ActionPhase.STEP_1_PREPARATION;
}

export interface ActionEventStep2 extends BaseSSEActionEvent {
  step: 2;
  phase: ActionPhase.STEP_2_AUTHENTICATION;
}

export interface ActionEventStep3 extends BaseSSEActionEvent {
  step: 3;
  phase: ActionPhase.STEP_3_CONTRACT_VERIFICATION;
  data?: any;
  logs?: string[];
}

export interface ActionEventStep4 extends BaseSSEActionEvent {
  step: 4;
  phase: ActionPhase.STEP_4_TRANSACTION_SIGNING;
  data?: any;
  logs?: string[];
}

export interface ActionEventStep5 extends BaseSSEActionEvent {
  step: 5;
  phase: ActionPhase.STEP_8_BROADCASTING;
}

export interface ActionEventStep6 extends BaseSSEActionEvent {
  step: 6;
  phase: ActionPhase.STEP_9_ACTION_COMPLETE;
  status: ActionStatus.SUCCESS;
  data?: any;
}

export interface ActionEventStep0 extends BaseSSEActionEvent {
  step: 0;
  phase: ActionPhase.ACTION_ERROR;
  status: ActionStatus.ERROR;
  error: string;
}

export type ActionSSEEvent =
  | ActionEventStep1
  | ActionEventStep2
  | ActionEventStep3
  | ActionEventStep4
  | ActionEventStep5
  | ActionEventStep6
  | ActionEventStep0;

// Login Event Types
export interface LoginEventStep1 extends BaseSSELoginEvent {
  step: 1;
  phase: LoginPhase.STEP_1_PREPARATION;
}

export interface LoginEventStep2 extends BaseSSELoginEvent {
  step: 2;
  phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION;
}

export interface LoginEventStep3 extends BaseSSELoginEvent {
  step: 3;
  phase: LoginPhase.STEP_3_VRF_UNLOCK;
}

export interface LoginEventStep4 extends BaseSSELoginEvent {
  step: 4;
  phase: LoginPhase.STEP_4_LOGIN_COMPLETE;
  status: LoginStatus.SUCCESS;
  nearAccountId: string;
  clientNearPublicKey: string;
}

export interface LoginEventStep0 extends BaseSSELoginEvent {
  step: 0;
  phase: LoginPhase.LOGIN_ERROR;
  status: LoginStatus.ERROR;
  error: string;
}

export type LoginEvent =
  | LoginEventStep1
  | LoginEventStep2
  | LoginEventStep3
  | LoginEventStep4
  | LoginEventStep0;

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
  useRelayer?: boolean;
  hooks?: OperationHooks;
}

export interface LoginOptions {
  onEvent?: EventCallback<LoginEvent>;
  onError?: (error: Error) => void;
  hooks?: OperationHooks;
}

export interface LoginState {
  isLoggedIn: boolean;
  nearAccountId: AccountId | null;
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
  nearAccountId?: AccountId;
  transactionId?: string | null;
  vrfRegistration?: {
    success: boolean;
    vrfPublicKey?: string;
    encryptedVrfKeypair?: EncryptedVRFKeypair;
    contractVerified?: boolean;
    error?: string;
  };
}

export interface LoginResult {
  success: boolean;
  error?: string;
  loggedInNearAccountId?: string;
  clientNearPublicKey?: string | null;
  nearAccountId?: AccountId;
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
  contractId: 'web3-authn-v2.testnet' | 'web3-authn.near' | string;
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
