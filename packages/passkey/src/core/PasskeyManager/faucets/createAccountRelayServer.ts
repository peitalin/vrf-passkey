import { VRFChallenge } from '../../../core/types/webauthn';
import { RegistrationSSEEvent } from '../../types/passkeyManager';
import { PasskeyManagerContext } from '..';
import { base64UrlDecode } from '../../../utils/encoders';
import { serializeCredentialWithPRF, WebAuthnRegistrationCredential } from '../../types/signer-worker';

/**
 * Create account and register user using relay-server atomic endpoint
 * Makes a single call to the relay-server's /create_account_and_register_user endpoint
 * which calls the contract's atomic create_account_and_register_user function
 */
export async function createAccountAndRegisterWithRelayServer(
  context: PasskeyManagerContext,
  nearAccountId: string,
  publicKey: string,
  credential: PublicKeyCredential,
  vrfChallenge: VRFChallenge,
  deterministicVrfPublicKey: string,
  onEvent?: (event: RegistrationSSEEvent) => void
): Promise<{
  success: boolean;
  transactionId?: string;
  error?: string;
  preSignedDeleteTransaction?: any;
}> {
  const { configs } = context;

  if (!configs.relayServerUrl) {
    throw new Error('Relay server URL is required for atomic registration');
  }

  try {
    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Creating account and registering with atomic transaction...'
    });

    // Serialize the WebAuthn credential properly for the contract
    const serializedCredential = serializeCredentialWithPRF<WebAuthnRegistrationCredential>(credential);

    // Prepare data for atomic endpoint
    const requestData = {
      new_account_id: nearAccountId,
      new_public_key: publicKey,
      vrf_data: {
        vrf_input_data: Array.from(base64UrlDecode(vrfChallenge.vrfInput)),
        vrf_output: Array.from(base64UrlDecode(vrfChallenge.vrfOutput)),
        vrf_proof: Array.from(base64UrlDecode(vrfChallenge.vrfProof)),
        public_key: Array.from(base64UrlDecode(vrfChallenge.vrfPublicKey)),
        user_id: vrfChallenge.userId,
        rp_id: vrfChallenge.rpId,
        block_height: vrfChallenge.blockHeight,
        block_hash: Array.from(base64UrlDecode(vrfChallenge.blockHash)),
      },
      webauthn_registration: serializedCredential,
      deterministic_vrf_public_key: Array.from(base64UrlDecode(deterministicVrfPublicKey))
    };

    onEvent?.({
      step: 5,
      phase: 'contract-registration',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Calling atomic registration endpoint...'
    });

    // Call the atomic endpoint
    const response = await fetch(`${configs.relayServerUrl}/create_account_and_register_user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    });

    // Handle both successful and failed responses
    const result = await response.json();

    if (!response.ok) {
      // Extract specific error message from relay server response
      const errorMessage = result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;
      throw new Error(errorMessage);
    }

    if (!result.success) {
      throw new Error(result.error || 'Atomic registration failed');
    }

    onEvent?.({
      step: 5,
      phase: 'contract-registration',
      status: 'success',
      timestamp: Date.now(),
      message: `Atomic registration successful, transaction ID: ${result.transactionHash}`
    });

    return {
      success: true,
      transactionId: result.transactionHash,
      // No preSignedDeleteTransaction needed for atomic transactions
      preSignedDeleteTransaction: null
    };

  } catch (error: any) {
    console.error('Atomic registration failed:', error);

    onEvent?.({
      step: 0,
      phase: 'registration-error',
      status: 'error',
      timestamp: Date.now(),
      message: `Atomic registration failed: ${error.message}`,
      error: error.message
    });

    return {
      success: false,
      error: error.message,
      preSignedDeleteTransaction: null
    };
  }
}

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
    console.debug('Creating NEAR account via relay server');

    // Emit access key addition start event
    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'progress',
      timestamp: Date.now(),
      message: 'Starting account creation with access key...'
    } as RegistrationSSEEvent);

    // Make simple POST request to create account
    const response = await fetch(`${serverUrl}/accounts/create-account`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        accountId: nearAccountId,
        publicKey: publicKey, // Server handles ed25519: prefix
      })
    });

    // Handle both successful and failed responses
    const result = await response.json();

    if (!response.ok) {
      // Extract specific error message from relay server response
      const errorMessage = result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;
      throw new Error(errorMessage);
    }

    if (!result.success) {
      throw new Error(result.error || 'Account creation failed');
    }

    // Emit access key addition success event
    onEvent?.({
      step: 3,
      phase: 'access-key-addition',
      status: 'success',
      timestamp: Date.now(),
      message: `Account ${nearAccountId} created successfully with access key`
    } as RegistrationSSEEvent);

    // Emit account verification event
    onEvent?.({
      step: 4,
      phase: 'account-verification',
      status: 'success',
      timestamp: Date.now(),
      message: 'Account creation verified on NEAR blockchain'
    } as RegistrationSSEEvent);

    console.debug('Account creation completed:', result);
    return {
      success: true,
      message: result.message || `Account ${nearAccountId} created successfully`,
      transactionId: result.transactionHash
    };

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

