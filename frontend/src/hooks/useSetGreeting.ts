import { useRef, useState, useEffect } from 'react';
import { WEBAUTHN_CONTRACT_ID } from '../config';
import { useNearClient, type NearClient } from '@web3authn/passkey/react';

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
  const nearClient: NearClient = useNearClient();
  const [onchainGreeting, setOnchainGreeting] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Rate limiting
  const lastFetchTime = useRef<number>(0);
  const isCurrentlyFetching = useRef<boolean>(false);

  const fetchGreeting = async (): Promise<GreetingResult> => {
    const now = Date.now();

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
      const result = await nearClient.view({
        account: WEBAUTHN_CONTRACT_ID,
        method: 'get_greeting',
        args: {}
      });

      const greeting = result as string;
      console.log('✅ Greeting fetched successfully:', greeting);
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
  };

  // Auto-fetch greeting on mount
  useEffect(() => {
    const loadInitialGreeting = async () => {
      await fetchGreeting();
    };
    loadInitialGreeting();
  }, []); // Empty dependency array - only run on mount

  return {
    onchainGreeting,
    isLoading,
    error,
    fetchGreeting
  };
};