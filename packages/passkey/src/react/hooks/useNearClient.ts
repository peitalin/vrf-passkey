import { MinimalNearClient, type NearClient } from '../../core/NearClient';
import { useMemo } from 'react';

export const useNearClient = (): NearClient => {
  const nearClient = useMemo(() => {
    return new MinimalNearClient('https://rpc.testnet.near.org');
  }, []);

  return nearClient;
};