import { useCallback, useRef, useState, useEffect } from 'react';
import { view } from '@near-js/client';
import { WEBAUTHN_CONTRACT_ID } from '../config';
import { useNearRpcProvider } from '@web3authn/passkey/react';

export interface GreetingResult {
  success: boolean;
  error?: string;
  greeting?: string;
}

interface SetGreetingHook {
  onchainGreeting: string | null;
  isLoading: boolean;
  error: string | null;
  fetchGreeting: () => Promise<GreetingResult>;
}

export const useSetGreeting = (): SetGreetingHook => {
  const { getNearRpcProvider } = useNearRpcProvider();
  const [onchainGreeting, setOnchainGreeting] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Rate limiting
  const lastFetchTime = useRef<number>(0);
  const isCurrentlyFetching = useRef<boolean>(false);
  const MIN_FETCH_INTERVAL = 500; // 0.5 second

  const fetchGreeting = useCallback(async (): Promise<GreetingResult> => {
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
    setIsLoading(true);
    setError(null);

    try {
      const provider = getNearRpcProvider();
      const result = await view({
        account: WEBAUTHN_CONTRACT_ID,
        method: 'get_greeting',
        args: {},
        deps: { rpcProvider: provider as any }
      });

      const greeting = result as string;
      setOnchainGreeting(greeting);

      return { success: true, greeting };
    } catch (err: any) {
      console.error("Error fetching greeting:", err);
      const errorMessage = err.message || 'Failed to fetch greeting';
      setError(errorMessage);

      return {
        success: false,
        error: errorMessage
      };
    } finally {
      setIsLoading(false);
      isCurrentlyFetching.current = false;
    }
  }, [onchainGreeting]);

  return {
    onchainGreeting,
    isLoading,
    error,
    fetchGreeting
  };
};