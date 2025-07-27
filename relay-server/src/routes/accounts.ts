import { Router, Request, Response } from 'express';
import { nearAccountService } from '../index';
import type { CreateAccountAndRegisterRequest } from '@web3authn/passkey/server';

const router = Router();

/**
 * POST /create_account_and_register_user
 * Atomic account creation and WebAuthn registration using the contract's create_account_and_register_user function
 *
 * Body: JSON with account creation and registration parameters
 * {
 *   "new_account_id": "user.testnet",
 *   "new_public_key": "ed25519:ABC123...",
 *   "vrf_data": { VRFVerificationData },
 *   "webauthn_registration": { WebAuthnRegistrationCredential },
 *   "deterministic_vrf_public_key": [optional Uint8Array]
 * }
 *
 * Returns: JSON response with success/error status
 * Note: initial_balance is controlled by the server (0.1 NEAR)
 */
router.post('/create_account_and_register_user', async (req: Request<any, any, CreateAccountAndRegisterRequest>, res: Response) => {
  try {
    console.log('POST /create_account_and_register_user', {
      account: req.body.new_account_id,
      publicKey: req.body.new_public_key?.substring(0, 20) + '...',
      hasVrfData: !!req.body.vrf_data,
      hasWebAuthnRegistration: !!req.body.webauthn_registration
    });

    const { new_account_id, new_public_key, vrf_data, webauthn_registration, deterministic_vrf_public_key } = req.body;

    // Validate required parameters
    if (!new_account_id || typeof new_account_id !== 'string') {
      throw new Error('Missing or invalid new_account_id');
    }
    if (!new_public_key || typeof new_public_key !== 'string') {
      throw new Error('Missing or invalid new_public_key');
    }
    if (!vrf_data || typeof vrf_data !== 'object') {
      throw new Error('Missing or invalid vrf_data');
    }
    if (!webauthn_registration || typeof webauthn_registration !== 'object') {
      throw new Error('Missing or invalid webauthn_registration');
    }

    // Call the atomic contract function via accountService
    const result = await nearAccountService.createAccountAndRegisterUser({
      new_account_id,
      new_public_key,
      vrf_data,
      webauthn_registration,
      deterministic_vrf_public_key
    });

    // Return the result directly - don't throw if unsuccessful
    if (result.success) {
      res.status(200).json(result);
    } else {
      // Return error response with appropriate HTTP status code
      console.error('Atomic account creation and registration failed:', result.error);
      res.status(400).json(result); // Use 400 for client errors like "account already exists"
    }

  } catch (error: any) {
    console.error('Atomic account creation and registration failed:', error.message);
    res.status(500).json({
      success: false,
      error: error.message || 'Unknown server error'
    });
  }
});

export default router;