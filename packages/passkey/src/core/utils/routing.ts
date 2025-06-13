import type { PasskeyManagerConfig } from '../PasskeyManager/types';

export type OperationMode = 'web2' | 'web3' | 'serverless';

export interface RoutingResult {
  mode: OperationMode;
  serverUrl?: string;
  requiresServer: boolean;
}

export interface RoutingOptions {
  optimisticAuth: boolean;
  config?: PasskeyManagerConfig;
  operation: 'registration' | 'login' | 'action';
}

/**
 * Determine the operation mode based on configuration
 */
export function determineOperationMode(options: RoutingOptions): RoutingResult {
  const { optimisticAuth, config, operation } = options;
  const serverUrl = config?.serverUrl;

  if (optimisticAuth) {
    // Optimistic mode always requires a server
    return {
      mode: 'web2',
      serverUrl,
      requiresServer: true
    };
  } else {
    // Secure mode: use server if available, otherwise go serverless
    if (serverUrl) {
      return {
        mode: 'web3',
        serverUrl,
        requiresServer: false
      };
    } else {
      return {
        mode: 'serverless',
        requiresServer: false
      };
    }
  }
}

/**
 * Validate that mode requirements are met
 */
export function validateModeRequirements(
  routing: RoutingResult,
  nearRpcProvider?: any
): { valid: boolean; error?: string } {
  // Check if server is required but not provided
  if (routing.requiresServer && !routing.serverUrl) {
    return {
      valid: false,
      error: 'Optimistic authentication requires a server URL. Please provide config.serverUrl or disable optimistic mode.'
    };
  }

  // Check if serverless mode has required dependencies
  if (routing.mode === 'serverless' && !nearRpcProvider) {
    return {
      valid: false,
      error: 'Serverless mode requires a NEAR RPC provider. Please provide nearRpcProvider parameter.'
    };
  }

  return { valid: true };
}

/**
 * Build server URL for specific endpoints
 */
export function buildServerUrl(baseUrl: string, endpoint: string): string {
  return `${baseUrl}${endpoint}`;
}

/**
 * Get user-friendly mode description for logging
 */
export function getModeDescription(routing: RoutingResult): string {
  switch (routing.mode) {
    case 'web2':
      return `🚀 Using optimistic (web2) mode with server: ${routing.serverUrl}`;
    case 'web3':
      return `🔒 Using secure (web3) mode with server: ${routing.serverUrl}`;
    case 'serverless':
      return '⚡ Using serverless mode - direct contract calls';
    default:
      return 'Unknown mode';
  }
}

/**
 * Standardized error messages for different scenarios
 */
export const RoutingErrors = {
  OPTIMISTIC_REQUIRES_SERVER: 'Optimistic authentication requires a server URL. Please provide config.serverUrl or disable optimistic mode.',
  SERVERLESS_REQUIRES_RPC: 'Serverless mode requires a NEAR RPC provider. Please provide nearRpcProvider parameter.',
  SERVERLESS_NOT_IMPLEMENTED: 'Serverless mode not yet implemented for this operation. Please provide a serverUrl in config.',
} as const;