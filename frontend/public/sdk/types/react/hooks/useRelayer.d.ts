export interface UseRelayerOptions {
    initialValue?: boolean;
}
export interface UseRelayerReturn {
    useRelayer: boolean;
    setUseRelayer: (value: boolean) => void;
    toggleRelayer: () => void;
}
/**
 * Hook for managing relayer usage state
 *
 * @param options - Configuration options
 * @returns Object with relayer state and setters
 */
export declare function useRelayer(options?: UseRelayerOptions): UseRelayerReturn;
//# sourceMappingURL=useRelayer.d.ts.map