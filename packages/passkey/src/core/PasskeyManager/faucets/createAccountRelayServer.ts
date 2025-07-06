import { RegistrationSSEEvent } from '../../types/passkeyManager';

/**
 * Create NEAR account using relayer server
 *
 * @param nearAccountId - The account ID to create (e.g., "username.testnet")
 * @param publicKey - The user's public key for the new account
 * @param serverUrl - The relayer server URL
 * @param onEvent - Event callback for progress updates
 * @returns Promise with success status and details
 */
export async function createAccountRelayServer(
  nearAccountId: string,
  publicKey: string,
  serverUrl: string,
  onEvent?: (event: RegistrationSSEEvent) => void,
): Promise<{ success: boolean; message: string; transactionId?: string; error?: string }> {
  try {
    console.log('Creating NEAR account via relay server SSE');

    // Create promise to handle SSE response from fetch stream
    const accountCreationPromise = new Promise<{
      success: boolean;
      message: string;
      transactionId?: string;
      error?: string
    }>((resolve, reject) => {

      // Make POST request and handle SSE response stream
      fetch(`${serverUrl}/relay/create-account-sse`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream'
        },
        body: JSON.stringify({
          accountId: nearAccountId,
          publicKey: publicKey, // Remove ed25519: prefix - server handles format
        })
      })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        if (!response.body) {
          throw new Error('No response body for SSE stream');
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        try {
          while (true) {
            const { done, value } = await reader.read();

            if (done) break;

            buffer += decoder.decode(value, { stream: true });

            // Process complete SSE messages
            const lines = buffer.split('\n');
            buffer = lines.pop() || ''; // Keep incomplete line in buffer

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const eventData = line.slice(6); // Remove 'data: ' prefix

                if (eventData === '[DONE]') {
                  // End of stream
                  return;
                }

                try {
                  const data = JSON.parse(eventData);
                  console.log('SSE event received:', data);

                  // Handle different event types
                  if (data.type === 'final-result') {
                    // Final result from server
                    if (data.success) {
                      resolve({
                        success: true,
                        message: data.message || `Account ${nearAccountId} created successfully`,
                        transactionId: data.transactionHash
                      });
                    } else {
                      reject(new Error(data.error || 'Account creation failed'));
                    }
                    return;
                  } else if (data.type === 'error') {
                    reject(new Error(data.error || 'SSE stream error'));
                    return;
                  } else if (data.step !== undefined) {
                    // Forward registration SSE events with proper structure
                    onEvent?.({
                      step: data.step,
                      phase: data.phase,
                      status: data.status,
                      timestamp: data.timestamp || Date.now(),
                      message: data.message,
                      error: data.error,
                      // Include additional fields for specific event types
                      ...(data.verified !== undefined && { verified: data.verified }),
                      ...(data.nearAccountId && { nearAccountId: data.nearAccountId }),
                      ...(data.clientNearPublicKey && { clientNearPublicKey: data.clientNearPublicKey }),
                      ...(data.mode && { mode: data.mode })
                    } as RegistrationSSEEvent);
                  }
                } catch (parseErr) {
                  console.warn('Failed to parse SSE event data:', eventData, parseErr);
                }
              }
            }
          }
        } finally {
          reader.releaseLock();
        }
      })
      .catch(error => {
        console.error('Fetch request failed:', error);
        reject(error);
      });
    });

    // Wait for account creation to complete
    const result = await accountCreationPromise;
    console.log('Account creation completed:', result);
    return result;

  } catch (error: any) {
    console.error('Account creation error:', error);

    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: 'Account creation failed',
      error: error.message
    } as RegistrationSSEEvent);

    return {
      success: false,
      message: 'Account creation failed',
      error: error.message
    };
  }
}