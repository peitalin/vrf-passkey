import { Router, Request, Response } from 'express';
import { accountCreationService } from '../services/accountCreationService';

const router = Router();

/**
 * POST /relay/create-account
 * Create a new account directly using relay server authority
 *
 * Body: JSON with accountId and publicKey
 * {
 *   "accountId": "user.near",
 *   "publicKey": "ed25519:ABC123..."
 * }
 */
router.post('/relay/create-account', async (req: Request, res: Response) => {
  try {
    console.log('POST /relay/create-account');
    console.log('Request body:', req.body);

    const { accountId, publicKey } = req.body;

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

    const result = await accountCreationService.createAccount({
      accountId,
      publicKey
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