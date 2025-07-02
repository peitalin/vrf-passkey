import { useMemo } from 'react';
import { MinimalNearClient, type NearClient } from '../../core/NearClient';

export const useNearClient = (): NearClient => {
  const nearClient = useMemo(() => {
    return new MinimalNearClient('https://rpc.testnet.near.org');
  }, []);

  return nearClient;
};