import type { AuthenticatorTransport } from '@simplewebauthn/types';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON
} from '@simplewebauthn/server/script/deps';
import type { SerializableActionArgs } from '../types';

// ===== COMMON TYPES =====

export interface BaseResponse {
  success?: boolean;
  error?: string;
}

export interface BaseRequest {}

// ===== GENERATE REGISTRATION OPTIONS ENDPOINT =====

export interface GenerateRegistrationOptionsRequest {
  accountId: string;
}

export interface GenerateRegistrationOptionsResponse extends BaseResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId?: string;
  commitmentId?: string | null;
}

// ===== VERIFY REGISTRATION RESPONSE ENDPOINT =====

export interface VerifyRegistrationRequest {
  accountId: string;
  attestationResponse: RegistrationResponseJSON;
  commitmentId: string | null;
  clientNearPublicKey: string | null;
}

// ===== GENERATE AUTHENTICATION OPTIONS ENDPOINT =====

export interface GenerateAuthenticationOptionsRequest {
  accountId?: string;
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
  commitmentId?: string | null;
}

// ===== VERIFY AUTHENTICATION RESPONSE ENDPOINT =====

export interface VerifyAuthenticationRequest {
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
  commitmentId?: string | null;
}

export interface VerifyAuthenticationResponse extends BaseResponse {
  verified: boolean;
  nearAccountId?: string;
}

// ===== ACTION CHALLENGE ENDPOINT =====

export interface ActionChallengeRequest {
  accountId: string;
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

// ===== CONTRACT SPECIFIC TYPES =====

// Contract arguments for generate_registration_options
export interface ContractGenerateRegistrationOptionsArgs {
  rp_name: string;
  rp_id: string;
  user_name: string;
  user_id: string;
  challenge?: string | null;
  user_display_name?: string | null;
  timeout?: number | null;
  attestation_type?: string | null;
  exclude_credentials?: Array<{
    id: string;
    type: string;
    transports?: string[];
  }> | null;
  authenticator_selection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  } | null;
  extensions?: {
    credProps?: boolean;
  } | null;
  supported_algorithm_ids?: number[] | null;
  preferred_authenticator_type?: string | null;
}

// Contract arguments for verify_registration_response
export interface ContractVerifyRegistrationArgs {
  registration_response: RegistrationResponseJSON;
  commitment_id: string;
}

// Contract arguments for generate_authentication_options
export interface ContractGenerateAuthenticationOptionsArgs {
  rp_id?: string | null;
  allow_credentials?: Array<{
    id: string;
    type: string;
    transports?: string[];
  }> | null;
  challenge?: string | null;
  timeout?: number | null;
  user_verification?: 'discouraged' | 'preferred' | 'required' | null;
  extensions?: {
    appid?: string;
    credProps?: boolean;
    hmacCreateSecret?: boolean;
    minPinLength?: boolean;
  } | null;
  authenticator: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    transports?: string[];
  };
}

// Contract arguments for verify_authentication_response
export interface ContractVerifyAuthenticationArgs {
  authentication_response: AuthenticationResponseJSON;
  commitment_id: string;
}

// Contract response types
export interface ContractRegistrationOptionsResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId: string;
  commitmentId?: string | null;
}

export interface ContractAuthenticationOptionsResponse {
  options: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: Array<{
      id: string;
      type: string;
      transports?: string[];
    }>;
    userVerification?: 'discouraged' | 'preferred' | 'required';
    extensions?: {
      appid?: string;
      credProps?: boolean;
      hmacCreateSecret?: boolean;
      minPinLength?: boolean;
    };
  };
  commitmentId?: string | null;
}

export interface ContractVerificationResponse {
  verified: boolean;
  registration_info?: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    user_id: string;
  };
  authentication_info?: {
    new_counter: number;
    user_verified: boolean;
  };
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

export interface ContractError extends EndpointError {
  contractMethod?: string;
  contractArgs?: Record<string, any>;
  transactionHash?: string;
}

// ===== UTILITY TYPES =====

export type EndpointMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

export interface EndpointDefinition<TRequest = any, TResponse = any> {
  method: EndpointMethod;
  path: string;
  requestType: TRequest;
  responseType: TResponse;
  description: string;
  requiresAuth?: boolean;
  rateLimit?: {
    windowMs: number;
    maxRequests: number;
  };
}

// ===== ENDPOINT REGISTRY =====

export const ENDPOINTS = {
  GENERATE_REGISTRATION_OPTIONS: {
    method: 'POST' as const,
    path: '/generate-registration-options',
    description: 'Generate WebAuthn registration options for a new user',
    requiresAuth: false,
  },
  VERIFY_REGISTRATION: {
    method: 'POST' as const,
    path: '/verify-registration',
    description: 'Verify WebAuthn registration response and complete user registration',
    requiresAuth: false,
  },
  GENERATE_AUTHENTICATION_OPTIONS: {
    method: 'POST' as const,
    path: '/generate-authentication-options',
    description: 'Generate WebAuthn authentication options for user login',
    requiresAuth: false,
  },
  VERIFY_AUTHENTICATION: {
    method: 'POST' as const,
    path: '/verify-authentication',
    description: 'Verify WebAuthn authentication response and log user in',
    requiresAuth: false,
  },
  ACTION_CHALLENGE: {
    method: 'POST' as const,
    path: '/api/action-challenge',
    description: 'Generate a challenge for signing blockchain actions',
    requiresAuth: true,
  },
} as const;

// Type helpers for endpoint usage
export type GenerateRegistrationOptionsEndpoint = EndpointDefinition<
  GenerateRegistrationOptionsRequest,
  GenerateRegistrationOptionsResponse
>;

export type VerifyRegistrationEndpoint = EndpointDefinition<
  VerifyRegistrationRequest,
  any // SSE stream - type defined in sse.ts
>;

export type GenerateAuthenticationOptionsEndpoint = EndpointDefinition<
  GenerateAuthenticationOptionsRequest,
  GenerateAuthenticationOptionsResponse
>;

export type VerifyAuthenticationEndpoint = EndpointDefinition<
  VerifyAuthenticationRequest,
  VerifyAuthenticationResponse
>;

export type ActionChallengeEndpoint = EndpointDefinition<
  ActionChallengeRequest,
  ActionChallengeResponse
>;