import { useState, useCallback } from 'react';

/**
 * Hook for managing relayer usage state
 *
 * @param options - Configuration options
 * @returns Object with relayer state and setters
 */
function useRelayer(options = {}) {
    const { initialValue = false } = options;
    const [useRelayer, setUseRelayer] = useState(initialValue);
    const toggleRelayer = useCallback(() => {
        setUseRelayer(prev => !prev);
    }, []);
    return {
        useRelayer,
        setUseRelayer,
        toggleRelayer
    };
}

export { useRelayer };
//# sourceMappingURL=useRelayer.js.map
