# Server Endpoint Types Documentation

This document provides comprehensive type definitions and usage examples for all server endpoints in the WebAuthn Passkey system.

## Type Organization

The types are now organized into separate files for better maintainability:

- **`endpoints.ts`** - Request/response types for HTTP endpoints
- **`sse.ts`** - Server-Sent Events types for real-time communication
- **`index.ts`** - Main types file that re-exports all endpoint types

## Overview

The server provides the following main endpoints:

1. **Registration Flow**
   - `POST /generate-registration-options` - Generate WebAuthn registration options
   - `POST /verify-registration` - Verify registration and complete user setup (SSE)

2. **Authentication Flow**
   - `POST /generate-authentication-options` - Generate WebAuthn authentication options
   - `POST /verify-authentication` - Verify authentication and log user in

3. **Action Execution**
   - `POST /api/action-challenge` - Generate challenge for blockchain actions

## Type Definitions

## Registration Endpoints

### Generate Registration Options

**Endpoint:** `POST /generate-registration-options`

```typescript
// Request
interface GenerateRegistrationOptionsRequest extends BaseRequest {
  username: string;
}

// Response
interface GenerateRegistrationOptionsResponse extends BaseResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
  nearAccountId?: string;
  commitmentId?: string | null; // Flexible null/undefined handling
}
```

**Example Usage:**

```typescript
// Client request
const request: GenerateRegistrationOptionsRequest = {
  username: "alice",
  useOptimistic: true // Fast mode
};

const response = await fetch('/generate-registration-options', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(request)
});

const data: GenerateRegistrationOptionsResponse = await response.json();
```

### Verify Registration

**Endpoint:** `POST /verify-registration` (Server-Sent Events)

```typescript
// Request
interface VerifyRegistrationRequest extends BaseRequest {
  username: string;
  attestationResponse: RegistrationResponseJSON;
  commitmentId?: string | null; // Flexible null/undefined handling
  clientNearPublicKey?: string | null; // Client-managed public key
}

// SSE Events (streamed response) - defined in sse.ts
type RegistrationSSEEvent =
  | WebAuthnVerificationSSEEvent   // Step 1: WebAuthn verification
  | UserReadySSEEvent              // Step 2: User ready for login
  | AccessKeyAdditionSSEEvent      // Step 3: NEAR account creation
  | DatabaseStorageSSEEvent        // Step 4: Database storage
  | ContractRegistrationSSEEvent   // Step 5: Contract registration
  | RegistrationCompleteSSEEvent   // Step 6: Complete
  | RegistrationErrorSSEEvent;     // Error handling
```

## Authentication Endpoints

### Generate Authentication Options

**Endpoint:** `POST /generate-authentication-options`

```typescript
// Request
interface GenerateAuthenticationOptionsRequest extends BaseRequest {
  username?: string; // Optional for discoverable credentials
}

// Response
interface GenerateAuthenticationOptionsResponse extends BaseResponse {
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
  nearAccountId?: string;
  commitmentId?: string | null; // Flexible null/undefined handling
}
```

### Verify Authentication

**Endpoint:** `POST /verify-authentication`

```typescript
// Request
interface VerifyAuthenticationRequest extends BaseRequest {
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
  commitmentId?: string | null; // Flexible null/undefined handling
}

// Response
interface VerifyAuthenticationResponse extends BaseResponse {
  verified: boolean;
  username?: string;
  nearAccountId?: string;
}
```

## Action Challenge Endpoint

### Generate Action Challenge

**Endpoint:** `POST /api/action-challenge`

```typescript
// Request
interface ActionChallengeRequest {
  username: string;
  actionDetails: SerializableActionArgs;
}

// Response
interface ActionChallengeResponse extends BaseResponse {
  challenge: string;
  rpId: string;
  allowCredentials: Array<{
    type: 'public-key';
    id: string;
  }>;
  userVerification: 'preferred';
  timeout: number;
}
```

## Contract-Specific Types

### Contract Method Arguments

```typescript
// For contract.generate_registration_options
interface ContractGenerateRegistrationOptionsArgs {
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
  extensions?: { credProps?: boolean; } | null;
  supported_algorithm_ids?: number[] | null;
  preferred_authenticator_type?: string | null;
}

// For contract.verify_registration_response
interface ContractVerifyRegistrationArgs {
  registration_response: RegistrationResponseJSON;
  commitment_id: string;
}

// For contract.generate_authentication_options
interface ContractGenerateAuthenticationOptionsArgs {
  rp_id?: string | null;
  allow_credentials?: Array<{
    id: string;
    type: string;
    transports?: string[];
  }> | null;
  challenge?: string | null;
  timeout?: number | null;
  user_verification?: 'discouraged' | 'preferred' | 'required' | null;
  extensions?: Record<string, any> | null;
  authenticator: {
    credential_id: number[];
    credential_public_key: number[];
    counter: number;
    transports?: string[];
  };
}

// For contract.verify_authentication_response
interface ContractVerifyAuthenticationArgs {
  authentication_response: AuthenticationResponseJSON;
  commitment_id: string;
}
```

### Contract Response Types

```typescript
interface ContractVerificationResponse {
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
```

## SSE Types (sse.ts)

```typescript
// Base SSE event structure
interface BaseSSEEvent {
  step: number;
  sessionId: string;
  phase: string;
  status: 'progress' | 'success' | 'error';
  timestamp: number;
  message: string;
}

// Registration flow events
type RegistrationSSEEvent =
  | WebAuthnVerificationSSEEvent
  | UserReadySSEEvent
  | AccessKeyAdditionSSEEvent
  | DatabaseStorageSSEEvent
  | ContractRegistrationSSEEvent
  | RegistrationCompleteSSEEvent
  | RegistrationErrorSSEEvent;

// Session management
interface RegistrationSession {
  id: string;
  username: string;
  nearAccountId: string;
  status: 'pending' | 'contract_dispatched' | 'contract_confirmed' | 'error';
  result?: any;
  error?: string;
  timestamp: number;
}
```
