import { useCallback } from 'react';
import { getTestnetRpcProvider } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import type { RpcProviderHook } from '../types';

let frontendRpcProvider: Provider;

export const useRpcProvider = (): RpcProviderHook => {
  const getRpcProvider = useCallback((): Provider => {
    if (!frontendRpcProvider) {
      frontendRpcProvider = getTestnetRpcProvider();
    }
    return frontendRpcProvider;
  }, []); // Empty deps array since the provider is a singleton

  return { getRpcProvider };
};