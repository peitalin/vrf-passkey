import type { SerializableActionArgs } from '../types';

// Define AuthenticatorTransport locally to avoid external dependency
export type AuthenticatorTransport = 'ble' | 'hybrid' | 'internal' | 'nfc' | 'usb';

// ===== COMMON TYPES =====

export interface BaseResponse {
  success?: boolean;
  error?: string;
}

export interface BaseRequest {
  useOptimistic?: boolean;
}

// ===== GENERATE REGISTRATION OPTIONS ENDPOINT =====

export interface GenerateRegistrationOptionsRequest extends BaseRequest {
  username: string;
}

export interface GenerateRegistrationOptionsResponse extends BaseResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId?: string;
  commitmentId?: string;
}

// ===== VERIFY REGISTRATION RESPONSE ENDPOINT =====

export interface VerifyRegistrationRequest extends BaseRequest {
  username: string;
  attestationResponse: RegistrationResponseJSON;
  commitmentId?: string;
  clientNearPublicKey?: string;
}

// SSE Event Types for Registration
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
  nearAccountId?: string;
  clientNearPublicKey?: string;
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

// ===== GENERATE AUTHENTICATION OPTIONS ENDPOINT =====

export interface GenerateAuthenticationOptionsRequest extends BaseRequest {
  username?: string;
}

export interface GenerateAuthenticationOptionsResponse extends BaseResponse {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  userVerification?: 'discouraged' | 'preferred' | 'required';
  extensions?: {
    appid?: string;
    credProps?: boolean;
    hmacCreateSecret?: boolean;
    minPinLength?: boolean;
  };
  nearAccountId?: string;
  commitmentId?: string;
}

// ===== VERIFY AUTHENTICATION RESPONSE ENDPOINT =====

export interface VerifyAuthenticationRequest extends BaseRequest {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
  commitmentId?: string;
}

export interface VerifyAuthenticationResponse extends BaseResponse {
  verified: boolean;
  username?: string;
  nearAccountId?: string;
}

// ===== ACTION CHALLENGE ENDPOINT =====

export interface ActionChallengeRequest {
  username: string;
  actionDetails: SerializableActionArgs;
}

export interface ActionChallengeResponse extends BaseResponse {
  challenge: string;
  rpId: string;
  allowCredentials: Array<{
    type: 'public-key';
    id: string;
  }>;
  userVerification: 'preferred';
  timeout: number;
}

// ===== CLIENT-SPECIFIC TYPES =====

// WebAuthn types that match browser APIs
export interface PublicKeyCredentialCreationOptionsJSON {
  challenge: string;
  rp: {
    name: string;
    id?: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{
    type: 'public-key';
    alg: number;
  }>;
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey?: 'discouraged' | 'preferred' | 'required';
    requireResidentKey?: boolean;
    userVerification?: 'discouraged' | 'preferred' | 'required';
  };
  timeout?: number;
  attestation?: 'none' | 'indirect' | 'direct' | 'enterprise';
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  extensions?: Record<string, any>;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  userVerification?: 'discouraged' | 'preferred' | 'required';
  extensions?: Record<string, any>;
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
    transports?: AuthenticatorTransport[];
  };
  authenticatorAttachment?: string;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  type: 'public-key';
  clientExtensionResults?: Record<string, any>;
}

// ===== ERROR TYPES =====

export interface EndpointError extends Error {
  status?: number;
  code?: string;
  details?: Record<string, any>;
}

export interface ValidationError extends EndpointError {
  field?: string;
  value?: any;
}

export interface NetworkError extends EndpointError {
  url?: string;
  method?: string;
  timeout?: boolean;
}

// ===== UTILITY TYPES =====

export type EndpointMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

export interface EndpointConfig {
  method: EndpointMethod;
  path: string;
  description: string;
  requiresAuth?: boolean;
  timeout?: number;
}

// ===== ENDPOINT REGISTRY =====

export const CLIENT_ENDPOINTS = {
  GENERATE_REGISTRATION_OPTIONS: {
    method: 'POST' as const,
    path: '/generate-registration-options',
    description: 'Generate WebAuthn registration options for a new user',
    requiresAuth: false,
    timeout: 10000,
  },
  VERIFY_REGISTRATION: {
    method: 'POST' as const,
    path: '/verify-registration',
    description: 'Verify WebAuthn registration response and complete user registration',
    requiresAuth: false,
    timeout: 30000, // Longer timeout for SSE
  },
  GENERATE_AUTHENTICATION_OPTIONS: {
    method: 'POST' as const,
    path: '/generate-authentication-options',
    description: 'Generate WebAuthn authentication options for user login',
    requiresAuth: false,
    timeout: 10000,
  },
  VERIFY_AUTHENTICATION: {
    method: 'POST' as const,
    path: '/verify-authentication',
    description: 'Verify WebAuthn authentication response and log user in',
    requiresAuth: false,
    timeout: 15000,
  },
  ACTION_CHALLENGE: {
    method: 'POST' as const,
    path: '/api/action-challenge',
    description: 'Generate a challenge for signing blockchain actions',
    requiresAuth: true,
    timeout: 10000,
  },
} as const;

// ===== TYPE GUARDS =====

export function isRegistrationSSEEvent(event: any): event is RegistrationSSEEvent {
  return (
    event &&
    typeof event === 'object' &&
    typeof event.step === 'number' &&
    typeof event.sessionId === 'string' &&
    typeof event.phase === 'string' &&
    ['progress', 'success', 'error'].includes(event.status) &&
    typeof event.timestamp === 'number' &&
    typeof event.message === 'string'
  );
}

export function isErrorResponse(response: any): response is BaseResponse & { error: string } {
  return response && typeof response === 'object' && typeof response.error === 'string';
}

export function isSuccessResponse(response: any): response is BaseResponse & { success: true } {
  return response && typeof response === 'object' && response.success === true;
}

// ===== FETCH HELPERS =====

export interface FetchOptions {
  timeout?: number;
  retries?: number;
  retryDelay?: number;
}

export interface TypedFetchResponse<T> {
  data?: T;
  error?: string;
  status: number;
  ok: boolean;
}

// Helper type for creating typed fetch functions
export type TypedFetch = <TRequest, TResponse>(
  endpoint: EndpointConfig,
  data?: TRequest,
  options?: FetchOptions
) => Promise<TypedFetchResponse<TResponse>>;