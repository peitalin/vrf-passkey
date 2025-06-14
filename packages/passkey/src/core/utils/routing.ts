import type { PasskeyManagerConfig } from '../PasskeyManager/types';

export type OperationMode = 'web2' | 'serverless';

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
 * - optimisticAuth = true: Use web2 mode (server endpoints)
 * - optimisticAuth = false: Use serverless mode (direct contract calls)
 */
export function determineOperationMode(options: RoutingOptions): RoutingResult {
  const { optimisticAuth, config } = options;
  const serverUrl = config?.serverUrl;

  if (optimisticAuth) {
    // Optimistic mode: use server endpoints (web2 mode)
    return {
      mode: 'web2',
      serverUrl,
      requiresServer: true
    };
  } else {
    // Non-optimistic mode: use direct contract calls (serverless mode)
    return {
      mode: 'serverless',
      requiresServer: false
    };
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
      error: 'Web2 mode requires a server URL. Please provide config.serverUrl or use serverless mode (optimisticAuth: false).'
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
      return `🚀 Using Web2 mode (optimistic) with server: ${routing.serverUrl}`;
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
  WEB2_REQUIRES_SERVER: 'Web2 mode requires a server URL. Please provide config.serverUrl or use serverless mode (optimisticAuth: false).',
  SERVERLESS_REQUIRES_RPC: 'Serverless mode requires a NEAR RPC provider. Please provide nearRpcProvider parameter.',
  SERVERLESS_NOT_IMPLEMENTED: 'Serverless mode not yet implemented for this operation. Please provide a serverUrl in config.',
} as const;