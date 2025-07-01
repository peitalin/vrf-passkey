import type { PasskeyManager } from '../../core/PasskeyManager';
export interface AccountInputState {
    inputUsername: string;
    lastLoggedInUsername: string;
    lastLoggedInDomain: string;
    targetAccountId: string;
    displayPostfix: string;
    isUsingExistingAccount: boolean;
    accountExists: boolean;
    indexDBAccounts: string[];
}
export interface UseAccountInputOptions {
    passkeyManager: PasskeyManager;
    relayerAccount: string;
    useRelayer: boolean;
    currentNearAccountId?: string | null;
    isLoggedIn: boolean;
}
export interface UseAccountInputReturn extends AccountInputState {
    setInputUsername: (username: string) => void;
    refreshAccountData: () => Promise<void>;
}
export declare function useAccountInput({ passkeyManager, relayerAccount, useRelayer, currentNearAccountId, isLoggedIn }: UseAccountInputOptions): UseAccountInputReturn;
//# sourceMappingURL=useAccountInput.d.ts.map