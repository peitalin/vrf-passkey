import { useCallback } from 'react';
import { DefaultNearClient, type NearClient } from '../../core/NearClient';
import type { NearRpcProviderHook } from '../types';

let frontendNearClient: NearClient;

export const useNearRpcProvider = (): NearRpcProviderHook => {
  const getNearRpcProvider = useCallback((): NearClient => {
    if (!frontendNearClient) {
      frontendNearClient = new DefaultNearClient('https://rpc.testnet.near.org');
    }
    return frontendNearClient;
  }, []); // Empty deps array since the client is a singleton

  return { getNearRpcProvider };
};