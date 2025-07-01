'use strict';

var require$$0 = require('react');
var client = require('@near-js/client');

let frontendRpcProvider;
const useNearRpcProvider = () => {
    const getNearRpcProvider = require$$0.useCallback(() => {
        if (!frontendRpcProvider) {
            frontendRpcProvider = client.getTestnetRpcProvider();
        }
        return frontendRpcProvider;
    }, []); // Empty deps array since the provider is a singleton
    return { getNearRpcProvider };
};

exports.useNearRpcProvider = useNearRpcProvider;
//# sourceMappingURL=useNearRpcProvider.js.map
