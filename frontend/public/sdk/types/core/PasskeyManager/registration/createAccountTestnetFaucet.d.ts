import { RegistrationSSEEvent } from '../../types/passkeyManager';
/**
 * Create NEAR account using testnet faucet service
 * This only works on testnet, for production use the relayer server
 */
export declare function createAccountTestnetFaucet(nearAccountId: string, publicKey: string, onEvent?: (event: RegistrationSSEEvent) => void): Promise<{
    success: boolean;
    message: string;
    error?: string;
}>;
//# sourceMappingURL=createAccountTestnetFaucet.d.ts.map