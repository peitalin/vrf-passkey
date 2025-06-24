
// Result type for NearClient.createAccount method
export interface CreateAccountResult {
  success: boolean;
  message: string;
  result?: { // Present on success
    accountId: string;
    publicKey: string;
    // transactionOutcome?: any; // Optionally include full transaction outcome if needed
  };
  error?: any; // Present on failure, can be an Error object or other structured error info
  details?: string; // Additional details for errors, similar to how it's used in API responses
}

// Delegate Action Types
export interface DelegateActionRequest {
  senderAccountId: string;
  receiverAccountId: string;
  senderPrivateKey: string;
}

export interface DelegateActionResponse {
  success: boolean;
  transactionHash?: string;
  outcome?: any;
  error?: string;
  message?: string;
  encodedDelegateBase64?: string;
  encodedDelegateBytes?: number;
  mockDelegateBytes?: number;
}

export interface MockDelegateRequest {
  senderAccountId: string;
  receiverAccountId: string;
  senderPrivateKey: string;
}

export interface DiagnosticsResponse {
  success: boolean;
  diagnostics?: {
    pending: number;
    completed: number;
    failed: number;
    queueEmpty: boolean;
    timestamp: string;
    service: string;
  };
  message?: string;
  error?: string;
}
