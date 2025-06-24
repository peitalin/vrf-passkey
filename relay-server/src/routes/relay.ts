import { Router, Request, Response } from 'express';
import { nearAccountService } from '../accountService';

const router = Router();

/**
 * POST /relay/create-account
 * Create a new account directly using relay server authority
 *
 * Body: JSON with accountId, publicKey, and optional initialBalance
 * {
 *   "accountId": "user.near",
 *   "publicKey": "ed25519:ABC123...",
 *   "initialBalance": "20000000000000000000000" // Optional, in yoctoNEAR (defaults to 0.02 NEAR)
 * }
 */
router.post('/relay/create-account', async (req: Request, res: Response) => {
  try {
    console.log('POST /relay/create-account');
    console.log('Request body:', req.body);

    const { accountId, publicKey, initialBalance } = req.body;

    if (!accountId || typeof accountId !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid accountId',
        message: 'accountId is required in request body'
      });
    }

    if (!publicKey || typeof publicKey !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid publicKey',
        message: 'publicKey is required in request body'
      });
    }

    // Optional validation for initialBalance
    if (initialBalance !== undefined && typeof initialBalance !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid initialBalance',
        message: 'initialBalance must be a string (in yoctoNEAR) if provided'
      });
    }

    const result = await nearAccountService.createAccount({
      accountId,
      publicKey,
      initialBalance
    });

    if (result.success) {
      res.status(200).json(result);
    } else {
      console.log(`Account creation failed: ${result.error}`);
      res.status(500).json(result);
    }

  } catch (error: any) {
    console.error('Account creation endpoint error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Unknown server error',
      message: 'Failed to create account'
    });
  }
});

export default router;