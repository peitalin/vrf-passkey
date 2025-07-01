import { RegistrationSSEEvent } from '../../types/passkeyManager';
/**
 * Create NEAR account using relayer server
 *
 * @param nearAccountId - The account ID to create (e.g., "username.testnet")
 * @param publicKey - The user's public key for the new account
 * @param serverUrl - The relayer server URL
 * @param onEvent - Event callback for progress updates
 * @returns Promise with success status and details
 */
export declare function createAccountRelayServer(nearAccountId: string, publicKey: string, serverUrl: string, onEvent?: (event: RegistrationSSEEvent) => void): Promise<{
    success: boolean;
    message: string;
    transactionId?: string;
    error?: string;
}>;
//# sourceMappingURL=createAccountRelayServer.d.ts.map