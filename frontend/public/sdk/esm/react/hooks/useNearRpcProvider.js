import { useCallback } from 'react';
import { getTestnetRpcProvider } from '@near-js/client';

let frontendRpcProvider;
const useNearRpcProvider = () => {
    const getNearRpcProvider = useCallback(() => {
        if (!frontendRpcProvider) {
            frontendRpcProvider = getTestnetRpcProvider();
        }
        return frontendRpcProvider;
    }, []); // Empty deps array since the provider is a singleton
    return { getNearRpcProvider };
};

export { useNearRpcProvider };
//# sourceMappingURL=useNearRpcProvider.js.map
