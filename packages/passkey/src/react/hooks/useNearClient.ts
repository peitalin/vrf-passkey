import { useMemo } from 'react';
import { MinimalNearClient, type NearClient } from '../../core/NearClient';
import { RPC_NODE_URL } from '../../config';

export const useNearClient = (): NearClient => {
  const nearClient = useMemo(() => {
    return new MinimalNearClient(RPC_NODE_URL);
  }, []);

  return nearClient;
};