import { useCallback, useRef } from 'react';
import { view } from '@near-js/client';
import { WEBAUTHN_CONTRACT_ID } from '../../../config';
import { useRpcProvider } from './useNearRpcProvider';
import type { GreetingResult } from '../types';

interface GreetingServiceHook {
  fetchCurrentGreeting: () => Promise<GreetingResult>;
}

export const useGreetingService = (
  setCurrentGreeting: (greeting: string | null) => void,
  setIsProcessing: (isProcessing: boolean) => void
): GreetingServiceHook => {
  const { getRpcProvider } = useRpcProvider();
  const lastFetchTime = useRef<number>(0);
  const isCurrentlyFetching = useRef<boolean>(false);

  // Minimum time between API calls (1 second)
  const MIN_FETCH_INTERVAL = 1000;

  const fetchCurrentGreeting = useCallback(async (): Promise<GreetingResult> => {
    const now = Date.now();

    // Rate limiting: prevent calls within 1 second of each other
    if (now - lastFetchTime.current < MIN_FETCH_INTERVAL) {
      console.log('Greeting fetch rate limited');
      return { success: false, error: 'Rate limited' };
    }

    // Prevent concurrent calls
    if (isCurrentlyFetching.current) {
      console.log('Greeting fetch already in progress');
      return { success: false, error: 'Already fetching' };
    }

    isCurrentlyFetching.current = true;
    lastFetchTime.current = now;
    setIsProcessing(true);

    try {
      const provider = getRpcProvider();
      const result = await view({
        account: WEBAUTHN_CONTRACT_ID,
        method: 'get_greeting',
        args: {},
        deps: { rpcProvider: provider }
      });

      const greeting = result as string;
      setCurrentGreeting(greeting);
      setIsProcessing(false);
      isCurrentlyFetching.current = false;

      return { success: true, greeting };
    } catch (err: any) {
      console.error("Error fetching greeting directly:", err);
      const errorMessage = "Error fetching greeting.";
      setCurrentGreeting(errorMessage);
      setIsProcessing(false);
      isCurrentlyFetching.current = false;

      return {
        success: false,
        error: err.message || 'Failed to fetch greeting.'
      };
    }
  }, [getRpcProvider, setCurrentGreeting, setIsProcessing]);

  return { fetchCurrentGreeting };
};