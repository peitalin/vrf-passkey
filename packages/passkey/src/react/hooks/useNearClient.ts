import { useMemo } from 'react';
import { MinimalNearClient, type NearClient } from '@/index';
import { RPC_NODE_URL } from '@/config';

export const useNearClient = (rpcNodeURL: string = RPC_NODE_URL): NearClient => {
  const nearClient = useMemo(() => {
    return new MinimalNearClient(rpcNodeURL);
  }, []);

  return nearClient;
};