import { useCallback } from 'react';
import { getTestnetRpcProvider } from '@near-js/client';
import type { Provider } from '@near-js/providers';
import type { NearRpcProviderHook } from '../types';

let frontendRpcProvider: Provider;

export const useNearRpcProvider = (): NearRpcProviderHook => {
  const getNearRpcProvider = useCallback((): Provider => {
    if (!frontendRpcProvider) {
      frontendRpcProvider = getTestnetRpcProvider();
    }
    return frontendRpcProvider;
  }, []); // Empty deps array since the provider is a singleton

  return { getNearRpcProvider };
};