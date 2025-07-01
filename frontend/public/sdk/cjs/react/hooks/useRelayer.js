'use strict';

var require$$0 = require('react');

/**
 * Hook for managing relayer usage state
 *
 * @param options - Configuration options
 * @returns Object with relayer state and setters
 */
function useRelayer(options = {}) {
    const { initialValue = false } = options;
    const [useRelayer, setUseRelayer] = require$$0.useState(initialValue);
    const toggleRelayer = require$$0.useCallback(() => {
        setUseRelayer(prev => !prev);
    }, []);
    return {
        useRelayer,
        setUseRelayer,
        toggleRelayer
    };
}

exports.useRelayer = useRelayer;
//# sourceMappingURL=useRelayer.js.map
